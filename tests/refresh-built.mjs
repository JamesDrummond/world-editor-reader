// src/refresh.ts
var READER_AUTHORIZATION_MAX_MS = 30 * 24 * 60 * 60 * 1e3;
function savedAuthorization(raw, now = Date.now()) {
  const value = JSON.parse(raw);
  if (typeof value.refreshToken !== "string" || !value.refreshToken || value.refreshToken.length > 8192 || !Number.isSafeInteger(value.startedAt) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt !== value.startedAt + READER_AUTHORIZATION_MAX_MS || value.startedAt > now + 6e4)
    throw Error("Invalid saved reader authorization");
  return value;
}
function readGrant(value, refreshRequired) {
  const scopes = typeof value.scope === "string" ? value.scope.split(" ") : [];
  if (value.token_type?.toLowerCase() !== "bearer" || typeof value.access_token !== "string" || !value.access_token || !scopes.includes("vault:read") || scopes.some((s) => !["vault:read", "offline_access"].includes(s)) || !Number.isFinite(value.expires_in) || value.expires_in <= 0 || value.expires_in > 600 || refreshRequired && (typeof value.refresh_token !== "string" || !value.refresh_token || value.refresh_token.length > 8192))
    throw Error("Unexpected read-only token grant");
  return { accessToken: value.access_token, expiresIn: value.expires_in, refreshToken: typeof value.refresh_token === "string" ? value.refresh_token : "" };
}
function encryptedSecretStorage(storage, isLinux) {
  try {
    if (!storage || typeof storage.isEncryptionAvailable !== "function" || !storage.isEncryptionAvailable()) return false;
    if (isLinux && !["gnome_libsecret", "kwallet", "kwallet5", "kwallet6"].includes(storage.adapter?.getSelectedStorageBackend?.() ?? "")) return false;
    return true;
  } catch {
    return false;
  }
}
var RefreshCoordinator = class {
  constructor() {
    this.inFlight = null;
  }
  run(exchange) {
    if (this.inFlight) return this.inFlight;
    this.inFlight = exchange().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }
};
export {
  READER_AUTHORIZATION_MAX_MS,
  RefreshCoordinator,
  encryptedSecretStorage,
  readGrant,
  savedAuthorization
};
