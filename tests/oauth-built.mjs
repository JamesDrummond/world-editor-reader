// src/oauth.ts
async function pkceChallenge(verifier) {
  const data = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function validCallback(pending, params, now = Date.now()) {
  return !!pending && pending.expires >= now && params.state === pending.state && params.iss === pending.issuer && !!params.code;
}
export {
  pkceChallenge,
  validCallback
};
