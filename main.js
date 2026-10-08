"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => Reader
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");

// src/sync.ts
var allowed = /* @__PURE__ */ new Set(["md", "canvas", "base", "png", "jpg", "jpeg", "webp", "gif", "pdf", "mp3", "wav", "ogg", "m4a"]);
function validPath(p) {
  return typeof p === "string" && p.length <= 1024 && p.normalize("NFC") === p && !/[\\%:\x00-\x1f\x7f]/.test(p) && p.split("/").every((x) => !!x && !x.startsWith(".") && x !== ".." && x.length <= 255) && allowed.has(p.split(".").pop().toLowerCase()) && !p.startsWith("Reader Conflicts/") && !p.startsWith("Reader Archive/");
}
async function sha256(data) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function validateSnapshot(s) {
  if (s.version !== 1 || !/^[a-f0-9]{32}$/.test(s.snapshotId) || !Array.isArray(s.files) || s.files.length > 4096) throw Error("Invalid snapshot");
  const seen = /* @__PURE__ */ new Set();
  let total = 0;
  for (const f of s.files) {
    if (!validPath(f.path) || !/^[a-f0-9]{64}$/.test(f.sha256) || !Number.isSafeInteger(f.bytes) || f.bytes < 0 || f.bytes > 16 * 1024 * 1024 || seen.has(f.path.toLowerCase())) throw Error("Unsafe or duplicate snapshot path");
    seen.add(f.path.toLowerCase());
    total += f.bytes;
  }
  if (total > 128 * 1024 * 1024) throw Error("Snapshot exceeds viewing vault limit");
  for (const p of seen) for (const q of seen) if (q.startsWith(p + "/")) throw Error("Conflicting file/folder paths");
}
async function downloadLatest(snapshot, state, local, fetchFile, checkpoint) {
  validateSnapshot(snapshot);
  for (const [p, hash] of Object.entries(state.files)) if (!validPath(p) || !/^[a-f0-9]{64}$/.test(hash)) throw Error("Invalid local mirror state");
  const result = { downloaded: 0, preserved: 0, archived: 0 };
  const wanted = new Set(snapshot.files.map((f) => f.path));
  for (const f of snapshot.files) {
    const current = await local.read(f.path);
    if (current && await sha256(current) === f.sha256) {
      state.files[f.path] = f.sha256;
      await checkpoint(state);
      continue;
    }
    const data = await fetchFile(f);
    if (data.byteLength !== f.bytes || await sha256(data) !== f.sha256) throw Error("Download verification failed; retry Download latest");
    const before = await local.read(f.path);
    if (before && await sha256(before) !== state.files[f.path]) {
      await local.preserve(f.path, before);
      result.preserved++;
    }
    await local.write(f.path, data);
    state.files[f.path] = f.sha256;
    await checkpoint(state);
    result.downloaded++;
  }
  for (const p of Object.keys(state.files)) {
    if (wanted.has(p)) continue;
    const current = await local.read(p);
    if (current && await sha256(current) === state.files[p]) {
      await local.archive(p);
      result.archived++;
    }
    delete state.files[p];
    await checkpoint(state);
  }
  return result;
}

// src/oauth.ts
async function pkceChallenge(verifier) {
  const data = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function validCallback(pending, params, now = Date.now()) {
  return !!pending && pending.expires >= now && params.state === pending.state && params.iss === pending.issuer && !!params.code;
}

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

// src/main.ts
var defaults = { origin: "", issuer: "", clientId: "world-editor-reader", dedicated: false, rememberSignIn: true };
var callback = "obsidian://world-editor-reader-oauth";
function https(value) {
  const u = new URL(value);
  if (u.protocol !== "https:" || u.username || u.password || u.hash || u.search) throw Error("Use an HTTPS URL without credentials, query or fragment");
  return u;
}
function random() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
var Reader = class extends import_obsidian.Plugin {
  constructor() {
    super(...arguments);
    this.settings = { ...defaults };
    this.state = { files: {} };
    this.pending = null;
    this.accessToken = "";
    // Access tokens are memory only. Refresh credentials use verified encrypted storage or memory.
    this.accessExpiry = 0;
    this.revocationEndpoint = "";
    this.tokenEndpoint = "";
    this.refreshToken = "";
    this.authorizationStartedAt = 0;
    this.authorizationExpiresAt = 0;
    this.secretId = "";
    this.persistenceAvailable = false;
    this.refreshing = false;
    this.refreshCoordinator = new RefreshCoordinator();
    this.sessionEpoch = 0;
    this.downloading = false;
    this.authenticating = false;
    this.statusError = "";
    this.lastSuccessfulDownloadAt = 0;
  }
  status() {
    return readerStatus({
      hasToken: !!this.accessToken,
      accessExpiry: this.accessExpiry,
      authenticating: this.authenticating,
      refreshing: this.refreshing,
      pendingExpiry: this.pending?.expires ?? null,
      error: !!this.statusError,
      dedicated: this.settings.dedicated,
      hasRefresh: !!this.refreshToken,
      authorizationExpired: !!this.authorizationExpiresAt && Date.now() >= this.authorizationExpiresAt
    });
  }
  refreshStatus() {
    this.settingsTab?.refreshStatus();
  }
  reportError(message) {
    this.authenticating = false;
    this.statusError = message;
    this.refreshStatus();
    new import_obsidian.Notice(message);
  }
  resetSignIn() {
    this.accessToken = "";
    this.accessExpiry = 0;
    this.pending = null;
    this.authenticating = false;
    this.statusError = "";
    this.refreshStatus();
  }
  async prepareSecretStorage() {
    const binding = [this.app.vault.getName(), this.settings.origin, this.settings.issuer, this.settings.clientId, this.settings.origin ? this.resource() : ""].join("\n");
    this.secretId = "world-reader-" + (await sha256(new TextEncoder().encode(binding).buffer)).slice(0, 48);
    this.persistenceAvailable = encryptedSecretStorage(this.app.secretStorage, import_obsidian.Platform.isLinux);
  }
  clearSavedRefresh() {
    this.sessionEpoch++;
    this.refreshToken = "";
    this.authorizationStartedAt = 0;
    this.authorizationExpiresAt = 0;
    if (this.secretId && this.persistenceAvailable && this.app.secretStorage) try {
      this.app.secretStorage.setSecret(this.secretId, "");
    } catch {
      this.statusError = "Encrypted saved authorization could not be cleared; server revocation is required.";
    }
  }
  async acceptGrant(value, initial = true) {
    const grant = readGrant(value, true);
    const startedAt = initial ? Date.now() : this.authorizationStartedAt;
    const expiresAt = startedAt + READER_AUTHORIZATION_MAX_MS;
    if (!startedAt || Date.now() >= expiresAt) throw Error("Thirty-day reader authorization expired");
    if (initial) this.sessionEpoch++;
    const epoch = this.sessionEpoch;
    await this.prepareSecretStorage();
    if (epoch !== this.sessionEpoch) throw Error("Reader authorization changed during storage preparation");
    if (this.settings.rememberSignIn && this.persistenceAvailable) {
      const stored = JSON.stringify({ refreshToken: grant.refreshToken, startedAt, expiresAt });
      this.app.secretStorage.setSecret(this.secretId, stored);
      if (this.app.secretStorage.getSecret(this.secretId) !== stored) throw Error("Secure credential storage failed");
    }
    this.refreshToken = grant.refreshToken;
    this.authorizationStartedAt = startedAt;
    this.authorizationExpiresAt = expiresAt;
    this.accessToken = grant.accessToken;
    this.accessExpiry = Date.now() + grant.expiresIn * 1e3;
    this.statusError = "";
    this.refreshStatus();
  }
  async discover() {
    const issuer = this.settings.issuer, u = https(issuer);
    const response = await (0, import_obsidian.requestUrl)({ url: u.origin + "/.well-known/oauth-authorization-server" + u.pathname.replace(/\/$/, ""), method: "GET", throw: false });
    if (response.status !== 200) throw Error("Issuer metadata unavailable");
    const meta = response.json;
    if (meta.issuer !== issuer || !meta.code_challenge_methods_supported?.includes("S256") || meta.authorization_response_iss_parameter_supported !== true) throw Error("Unexpected OAuth issuer");
    for (const key of ["authorization_endpoint", "token_endpoint", "revocation_endpoint"]) if (https(meta[key]).origin !== u.origin) throw Error("Unexpected OAuth endpoint origin");
    this.tokenEndpoint = meta.token_endpoint;
    this.revocationEndpoint = meta.revocation_endpoint;
    return meta;
  }
  async ensureAccessToken(force = false) {
    if (this.authorizationExpiresAt && Date.now() >= this.authorizationExpiresAt) {
      await this.signOut();
      throw Error("Thirty-day reader authorization expired");
    }
    if (!force && this.accessToken && Date.now() + 6e4 < this.accessExpiry) return this.accessToken;
    if (!this.refreshToken) {
      if (!force && this.accessToken && Date.now() < this.accessExpiry) return this.accessToken;
      throw Error("Reader authorization needs sign-in");
    }
    await this.refreshCoordinator.run(async () => {
      const epoch = this.sessionEpoch;
      this.refreshing = true;
      this.refreshStatus();
      try {
        if (!this.tokenEndpoint) await this.discover();
        const response = await (0, import_obsidian.requestUrl)({
          url: this.tokenEndpoint,
          method: "POST",
          contentType: "application/x-www-form-urlencoded",
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: this.refreshToken,
            client_id: this.settings.clientId,
            resource: this.resource(),
            scope: "vault:read offline_access"
          }).toString(),
          throw: false
        });
        if (response.status !== 200) {
          if (response.status === 400 || response.status === 401) {
            this.clearSavedRefresh();
            this.resetSignIn();
          }
          throw Error("Reader refresh failed");
        }
        if (epoch !== this.sessionEpoch) throw Error("Reader sign-in changed during refresh");
        try {
          await this.acceptGrant(response.json, false);
        } catch {
          this.clearSavedRefresh();
          this.resetSignIn();
          throw Error("Reader refresh could not be retained safely");
        }
        return readGrant(response.json, true);
      } finally {
        this.refreshing = false;
        this.refreshStatus();
      }
    });
    return this.accessToken;
  }
  async authorizedGet(url) {
    let token = await this.ensureAccessToken();
    let response = await (0, import_obsidian.requestUrl)({ url, method: "GET", headers: { Authorization: "Bearer " + token }, throw: false });
    if (response.status === 401 && this.refreshToken) {
      token = await this.ensureAccessToken(true);
      response = await (0, import_obsidian.requestUrl)({ url, method: "GET", headers: { Authorization: "Bearer " + token }, throw: false });
    }
    return response;
  }
  async startSignIn() {
    this.statusError = "";
    this.authenticating = true;
    this.refreshStatus();
    try {
      await this.signIn();
    } catch {
      this.pending = null;
      this.reportError("Sign-in setup failed. Check the approved OAuth issuer.");
    } finally {
      this.authenticating = false;
      this.refreshStatus();
    }
  }
  async startDownload() {
    this.statusError = "";
    this.refreshStatus();
    try {
      await this.download();
    } catch {
      this.reportError("Download stopped. Existing notes and conflict backups are preserved. A saved authorization may be expired/revoked, or the server may be offline. Check status; sign in only if required.");
    }
  }
  async onload() {
    const stored = await this.loadData();
    this.settings = { ...defaults, ...stored?.settings };
    this.state = stored?.state ?? { files: {} };
    this.lastSuccessfulDownloadAt = Number.isFinite(stored?.lastSuccessfulDownloadAt) ? stored.lastSuccessfulDownloadAt : 0;
    this.settingsTab = new ReaderSettings(this.app, this);
    this.addSettingTab(this.settingsTab);
    await this.prepareSecretStorage();
    if (this.settings.rememberSignIn && this.persistenceAvailable) {
      const raw = this.app.secretStorage.getSecret(this.secretId);
      if (raw) try {
        const stored2 = savedAuthorization(raw);
        this.refreshToken = stored2.refreshToken;
        this.authorizationStartedAt = stored2.startedAt;
        this.authorizationExpiresAt = stored2.expiresAt;
        if (Date.now() >= stored2.expiresAt) await this.signOut();
      } catch {
        this.clearSavedRefresh();
        this.statusError = "Saved reader authorization is invalid or expired. Sign in once to renew it.";
      }
    }
    this.addCommand({ id: "sign-in", name: "Sign in to server (read-only)", callback: () => {
      void this.startSignIn();
    } });
    this.addCommand({ id: "download-latest", name: "Download latest", callback: () => {
      void this.startDownload();
    } });
    this.addCommand({ id: "sign-out", name: "Sign out and revoke reader token", callback: () => {
      void this.signOut();
    } });
    this.registerObsidianProtocolHandler("world-editor-reader-oauth", (params) => {
      void this.finishSignIn(params).catch(() => {
        this.pending = null;
        this.reportError("Sign-in rejected. Start Sign in again.");
      });
    });
  }
  onunload() {
    this.sessionEpoch++;
    this.settingsTab?.hide();
    this.accessToken = "";
    this.refreshToken = "";
    this.pending = null;
  }
  async save() {
    await this.saveData({ settings: this.settings, state: this.state, lastSuccessfulDownloadAt: this.lastSuccessfulDownloadAt });
  }
  resource() {
    return https(this.settings.origin).origin + "/reader/v1";
  }
  async signIn() {
    if (!this.settings.dedicated) throw Error("Confirm dedicated viewing vault first");
    const issuer = this.settings.issuer;
    const meta = await this.discover();
    const authorize = https(meta.authorization_endpoint), token = https(meta.token_endpoint);
    const verifier = random(), state = random();
    this.pending = { verifier, state, expires: Date.now() + 3e5, tokenEndpoint: token.href, issuer };
    const challenge = await pkceChallenge(verifier);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: this.settings.clientId,
      redirect_uri: callback,
      scope: "vault:read offline_access",
      resource: this.resource(),
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    }).toString();
    this.refreshStatus();
    window.open(authorize.href, "_blank");
    new import_obsidian.Notice("Sign in through the server account page, then return to Obsidian.");
  }
  async finishSignIn(params) {
    const pending = this.pending;
    if (!pending || !validCallback(pending, params)) throw Error("Invalid OAuth callback");
    this.pending = null;
    const epoch = this.sessionEpoch;
    const response = await (0, import_obsidian.requestUrl)({
      url: pending.tokenEndpoint,
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: params.code,
        client_id: this.settings.clientId,
        redirect_uri: callback,
        code_verifier: pending.verifier,
        resource: this.resource()
      }).toString(),
      throw: false
    });
    if (response.status !== 200) throw Error("Token exchange failed");
    if (epoch !== this.sessionEpoch) throw Error("Reader sign-in was cleared during code exchange");
    await this.acceptGrant(response.json);
    this.authenticating = false;
    this.refreshStatus();
    new import_obsidian.Notice("Signed in with read-only access. Run Download latest.");
  }
  async signOut() {
    const token = this.refreshToken || this.accessToken;
    const hint = this.refreshToken ? "refresh_token" : "access_token";
    this.clearSavedRefresh();
    this.resetSignIn();
    if (!token) {
      new import_obsidian.Notice("Local sign-in cleared.");
      return;
    }
    try {
      if (!this.revocationEndpoint) await this.discover();
      const response = await (0, import_obsidian.requestUrl)({
        url: this.revocationEndpoint,
        method: "POST",
        contentType: "application/x-www-form-urlencoded",
        body: new URLSearchParams({ token, token_type_hint: hint, client_id: this.settings.clientId }).toString(),
        throw: false
      });
      if (response.status !== 200) throw Error("Revocation unavailable");
      new import_obsidian.Notice("Reader token revoked and local sign-in cleared.");
    } catch {
      this.reportError("Local sign-in cleared; server revocation could not be confirmed. The server authorization may remain active until revoked or expired.");
    }
  }
  async folders(path) {
    const parts = path.split("/").slice(0, -1);
    let prefix = "";
    for (const p of parts) {
      prefix = prefix ? prefix + "/" + p : p;
      const existing = this.app.vault.getAbstractFileByPath(prefix);
      if (!existing) await this.app.vault.createFolder(prefix);
      else if (!(existing instanceof import_obsidian.TFolder)) throw Error("A file blocks the required folder");
    }
  }
  async read(path) {
    const f = this.app.vault.getAbstractFileByPath(path);
    if (!f) return null;
    if (!(f instanceof import_obsidian.TFile)) throw Error("A folder blocks the note");
    return await this.app.vault.readBinary(f);
  }
  async write(path, data) {
    await this.folders(path);
    const f = this.app.vault.getAbstractFileByPath(path);
    if (f instanceof import_obsidian.TFile) await this.app.vault.modifyBinary(f, data);
    else if (!f) await this.app.vault.createBinary(path, data);
    else throw Error("Cannot overwrite a folder");
  }
  async download() {
    if (this.downloading) {
      new import_obsidian.Notice("Download already running.");
      return;
    }
    if (!this.settings.dedicated || !this.refreshToken && (!this.accessToken || Date.now() >= this.accessExpiry)) {
      new import_obsidian.Notice("Confirm a dedicated viewing vault and sign in first.");
      return;
    }
    this.downloading = true;
    this.refreshStatus();
    const resource = this.resource();
    try {
      new import_obsidian.Notice("Downloading server snapshot\u2026");
      const manifest = await this.authorizedGet(resource + "/snapshot");
      if (manifest.status !== 200 || manifest.arrayBuffer.byteLength > 2 * 1024 * 1024) throw Error("Snapshot request failed");
      const snapshot = manifest.json;
      const run = Date.now().toString() + "-" + random().slice(0, 8);
      const result = await downloadLatest(snapshot, this.state, {
        read: (p) => this.read(p),
        write: (p, b) => this.write(p, b),
        preserve: async (p, b) => {
          const target = "Reader Conflicts/" + run + "/" + p;
          await this.write(target, b);
          if (await sha256(await this.read(target)) !== await sha256(b)) throw Error("Conflict backup failed");
        },
        archive: async (p) => {
          const target = "Reader Archive/" + run + "/" + p;
          await this.folders(target);
          const f = this.app.vault.getAbstractFileByPath(p);
          if (!(f instanceof import_obsidian.TFile)) throw Error("File changed");
          await this.app.vault.rename(f, target);
        }
      }, async (f) => {
        const url = resource + "/snapshots/" + snapshot.snapshotId + "/files/" + f.path.split("/").map(encodeURIComponent).join("/");
        const response = await this.authorizedGet(url);
        if (response.status !== 200) throw Error("Snapshot file expired or unavailable");
        return response.arrayBuffer;
      }, async () => this.save());
      this.lastSuccessfulDownloadAt = Date.now();
      await this.save();
      this.refreshStatus();
      new import_obsidian.Notice(`Latest snapshot downloaded: ${result.downloaded} files; ${result.preserved} local edits saved in Reader Conflicts; ${result.archived} old files moved to Reader Archive.`, 12e3);
    } finally {
      this.downloading = false;
      this.refreshStatus();
    }
  }
};
var ReaderSettings = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
    this.statusEl = null;
    this.lastDownloadEl = null;
    this.errorEl = null;
    this.timer = null;
    this.downloadButton = null;
  }
  refreshStatus() {
    if (!this.statusEl) return;
    const status = this.plugin.status();
    this.statusEl.setText(status.label);
    this.statusEl.dataset.readerStatus = status.phase;
    this.errorEl?.setText(this.plugin.statusError || (this.plugin.settings.rememberSignIn && !this.plugin.persistenceAvailable ? "Encrypted storage unavailable: refresh works in memory only until Obsidian closes." : ""));
    this.lastDownloadEl?.setText((this.plugin.lastSuccessfulDownloadAt > 0 ? "Last successful download: " + new Date(this.plugin.lastSuccessfulDownloadAt).toLocaleString() : "Last successful download: none yet") + (this.plugin.authorizationExpiresAt ? " \xB7 Read-only authorization ends: " + new Date(this.plugin.authorizationExpiresAt).toLocaleString() : ""));
    this.downloadButton?.setDisabled(!status.canDownload || this.plugin.downloading);
    this.downloadButton?.setButtonText(this.plugin.downloading ? "Downloading\u2026" : "Download latest");
  }
  hide() {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
    this.statusEl = null;
    this.lastDownloadEl = null;
    this.errorEl = null;
    this.downloadButton = null;
  }
  display() {
    this.hide();
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "World Editor Reader" });
    containerEl.createEl("p", { text: "Use a separate viewing vault. Download latest never uploads. Local edits are preserved before replacement. Access tokens refresh automatically. Refresh credentials stay in verified encrypted device storage when available; otherwise they stay in memory. Sign out revokes reader authorization." });
    new import_obsidian.Setting(containerEl).setName("Dedicated viewing vault").setDesc("Confirm this is a separate vault for server copies, with no other sync tool running.").addToggle((t) => t.setValue(this.plugin.settings.dedicated).onChange(async (v) => {
      this.plugin.settings.dedicated = v;
      this.plugin.refreshStatus();
      await this.plugin.save();
    }));
    new import_obsidian.Setting(containerEl).setName("Server HTTPS origin").addText((t) => t.setValue(this.plugin.settings.origin).onChange(async (v) => {
      this.plugin.clearSavedRefresh();
      this.plugin.resetSignIn();
      this.plugin.settings.origin = v.trim();
      await this.plugin.save();
    }));
    new import_obsidian.Setting(containerEl).setName("Approved OAuth issuer").setDesc("The approved authentication service for this viewing vault.").addText((t) => t.setValue(this.plugin.settings.issuer).onChange(async (v) => {
      this.plugin.clearSavedRefresh();
      this.plugin.resetSignIn();
      this.plugin.settings.issuer = v.trim();
      await this.plugin.save();
    }));
    new import_obsidian.Setting(containerEl).setName("Keep reader signed in securely").setDesc("Uses encrypted device storage only. Authorization adds offline_access while remaining read-only, capped at 30 days from sign-in. If secure storage is unavailable, automatic refresh works only until Obsidian closes.").addToggle((t) => t.setValue(this.plugin.settings.rememberSignIn).onChange(async (v) => {
      this.plugin.settings.rememberSignIn = v;
      if (!v && this.plugin.persistenceAvailable && this.plugin.secretId) this.plugin.app.secretStorage?.setSecret(this.plugin.secretId, "");
      await this.plugin.save();
      this.plugin.refreshStatus();
    }));
    this.statusEl = containerEl.createEl("p");
    containerEl.createEl("p", { text: "Requested scopes: vault:read and offline_access (automatic refresh). This reader cannot upload or write to the server." });
    this.errorEl = containerEl.createEl("p");
    this.lastDownloadEl = containerEl.createEl("p");
    new import_obsidian.Setting(containerEl).setName("Sign in").addButton((b) => b.setButtonText("Sign in (read-only)").onClick(() => {
      void this.plugin.startSignIn();
    }));
    new import_obsidian.Setting(containerEl).setName("Download").setDesc("Copy the latest server snapshot into this vault; preserve local edits.").addButton((b) => {
      this.downloadButton = b;
      b.setButtonText("Download latest").onClick(() => {
        void this.plugin.startDownload();
      });
    });
    new import_obsidian.Setting(containerEl).setName("Sign out").addButton((b) => b.setButtonText("Sign out and revoke reader token").onClick(() => {
      void this.plugin.signOut();
    }));
    this.refreshStatus();
    this.timer = window.setInterval(() => this.refreshStatus(), 1e3);
  }
};
