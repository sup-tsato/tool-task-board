/*
 * Basic認証（ブラウザ標準のID・パスワード入力窓で、入れる人を制限する仕組み）
 *
 * Cloudflare Pages Functions の _middleware は、すべてのページを表示する前に必ず通る「門番」です。
 * ID・パスワードはコードに書かず、Cloudflareに登録した環境変数から読みます。
 *   BASIC_AUTH_USER … ユーザー名
 *   BASIC_AUTH_PASS … パスワード
 */

const NOINDEX = 'noindex, nofollow';

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);

  // robots.txt は検索エンジンが読めないと効果がないため、認証なしで返す
  if (url.pathname === '/robots.txt') {
    return withNoIndex(await next());
  }

  // 環境変数が未登録のときは、開けっぱなしにせず閉じる（設定漏れ対策）
  if (!env.BASIC_AUTH_USER || !env.BASIC_AUTH_PASS) {
    return textResponse('認証の設定が完了していません。', 503);
  }

  const ok = await isAuthorized(request.headers.get('Authorization'), env.BASIC_AUTH_USER, env.BASIC_AUTH_PASS);
  if (!ok) {
    return textResponse('ユーザー名またはパスワードが違います。', 401, {
      // ブラウザにID・パスワードの入力窓を出させる
      'WWW-Authenticate': 'Basic realm="tool-task-board", charset="UTF-8"',
    });
  }

  return withNoIndex(await next());
}

// 「Basic xxxxx」形式の送信内容を取り出し、登録値と照合する
async function isAuthorized(header, expectedUser, expectedPass) {
  if (!header || !header.startsWith('Basic ')) return false;

  let decoded;
  try {
    const bytes = Uint8Array.from(atob(header.slice(6).trim()), (c) => c.charCodeAt(0));
    decoded = new TextDecoder().decode(bytes);
  } catch (e) {
    return false;
  }

  const sep = decoded.indexOf(':');
  if (sep < 0) return false;
  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);

  // ユーザー名・パスワードの両方を必ず比較する（片方だけ先に判定しない）
  const userOk = await safeEqual(user, expectedUser);
  const passOk = await safeEqual(pass, expectedPass);
  return userOk && passOk;
}

// 文字列を比較する。一致するまでの時間差から推測されないよう、
// ハッシュ（同じ長さの要約値）にしてから一定時間で比べる
async function safeEqual(a, b) {
  const encoder = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// 検索エンジン向けの「載せないで」をヘッダーにも付ける
function withNoIndex(response) {
  const res = new Response(response.body, response);
  res.headers.set('X-Robots-Tag', NOINDEX);
  return res;
}

function textResponse(message, status, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': NOINDEX,
      ...extraHeaders,
    },
  });
}
