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
export {
  downloadLatest,
  sha256,
  validPath,
  validateSnapshot
};
