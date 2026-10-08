// src/status.ts
function readerStatus(input, now = Date.now()) {
  const canDownload = input.dedicated && (input.hasToken && input.accessExpiry > now || !!input.hasRefresh);
  if (input.authorizationExpired) return { phase: "expired", label: "30-day read-only authorization expired \u2014 sign in once to renew", canDownload: false };
  if (input.refreshing) return { phase: "authenticating", label: "Refreshing read-only access\u2026", canDownload };
  if (input.error) return { phase: "error", label: "Error \u2014 see details below", canDownload };
  if (input.authenticating || input.pendingExpiry !== null && input.pendingExpiry > now) return { phase: "authenticating", label: "Authenticating \u2014 finish browser login and consent", canDownload };
  if (input.hasToken && input.accessExpiry > now) return { phase: "signed-in", label: "Signed in \u2014 read-only (vault:read)", canDownload };
  if (input.hasRefresh) return { phase: "signed-in", label: "Saved read-only sign-in \u2014 refresh before download", canDownload };
  if (input.hasToken || input.pendingExpiry !== null) return { phase: "expired", label: "Token or sign-in request expired \u2014 sign in again", canDownload: false };
  return { phase: "signed-out", label: "Signed out", canDownload: false };
}
export {
  readerStatus
};
