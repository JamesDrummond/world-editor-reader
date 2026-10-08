Read-only Obsidian viewing-vault reader, version 0.1.2.

- Manual snapshot downloads with hash checks and local-conflict preservation.
- OAuth PKCE sign-in and rotating refresh authorization.
- Verified encrypted native storage when available; memory-only fallback.
- Absolute 30-day reader authorization deadline from initial sign-in.
- Live sign-in/download status and sign-out/revocation controls.
- Desktop and mobile permitted; requires Obsidian 1.11.4+.

Public distribution starts with empty server and issuer settings. Obtain those
addresses from your server administrator. No credentials or vault content are
included. Android device testing remains pending; build and 25 fixture tests pass.

BRAT installs the separate main.js and manifest.json release assets.
