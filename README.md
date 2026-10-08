# World Editor Reader

Manually download a read-only server-vault snapshot into a separate Obsidian
viewing vault. The reader never uploads. It verifies downloaded hashes and
preserves local edits before replacement. Desktop and mobile are permitted;
Obsidian 1.11.4 or later is required. Android device testing is still pending.

## Install inside Obsidian with BRAT

1. Open a separate viewing vault in Obsidian.
2. In Settings → Community plugins, turn off Restricted mode if necessary.
3. Browse for **BRAT**, install it, and enable it.
4. Open BRAT settings and choose **Add a beta plugin for testing**.
5. Enter `JamesDrummond/world-editor-reader`. Select version `0.1.2` and enable
   the plugin after installation. No GitHub token is required for this public
   repository under normal rate limits.
6. Open World Editor Reader settings. Enable **Dedicated viewing vault**, then
   enter the **Server HTTPS origin** and **Approved OAuth issuer** supplied by
   your server administrator. This public package has no built-in server address.
7. Click **Sign in (read-only)**. Complete login and consent only in the server
   browser page, return to Obsidian, then click **Download latest**.

No file-manager copying is required for BRAT installation. Do not enter account
passwords in plugin settings or chats. This plugin is not in the community
plugin directory; BRAT installs it from GitHub release assets.

## Read-only renewal

Authorization requests `vault:read` and `offline_access` with PKCE S256 for the
reader resource. The server must pre-register the public `world-editor-reader`
client, the callback `obsidian://world-editor-reader-oauth`, and the appropriate
read-only audience. This plugin does not configure or deploy a server.

Access credentials stay in memory. Refresh credentials and the original
30-day deadline are retained only when encrypted native storage is verified.
Unknown or plaintext storage falls back to memory-only renewal until Obsidian
closes. Automatic renewal runs before downloads; it does not schedule downloads.
The plugin enforces a 30-day limit measured from initial sign-in even if the
issuer's rotating refresh lifespan is sliding. Sign out revokes authorization.
No credentials are stored in vault notes or plugin data.json. Other installed
plugins share Obsidian's native secret storage.

## Build and release

Run `npm ci`, `npm run build`, and `npm test`. Development dependencies are
pinned in the lockfile. Tests use fixture credentials and synthetic vault data.
The 0.1.2 public distribution passes 25 tests, including a fresh install with no
configured server. The diagnostics used to verify encryption are guarded;
missing diagnostics cause memory-only renewal.

BRAT release tag/title/manifest version: `0.1.2`.
Required release assets: **main.js** and **manifest.json** as individual files,
not only a ZIP. There is no styles.css because no stylesheet is needed.

[BRAT developer guide](https://github.com/TfTHacker/obsidian42-brat/blob/main/BRAT-DEVELOPER-GUIDE.md)
