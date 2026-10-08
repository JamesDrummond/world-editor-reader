import * as esbuild from 'esbuild';
await esbuild.build({entryPoints:['src/main.ts'], bundle:true, external:['obsidian'], format:'cjs', platform:'browser', target:'es2020', outfile:'main.js', minify:false});
await esbuild.build({entryPoints:['src/sync.ts'], bundle:true, format:'esm', platform:'browser', target:'es2020', outfile:'tests/sync-built.mjs'});
await esbuild.build({entryPoints:['src/oauth.ts'], bundle:true, format:'esm', platform:'browser', target:'es2020', outfile:'tests/oauth-built.mjs'});

await esbuild.build({entryPoints:['src/status.ts'], bundle:true, format:'esm', platform:'browser', target:'es2020', outfile:'tests/status-built.mjs'});

await esbuild.build({entryPoints:['src/refresh.ts'], bundle:true, format:'esm', platform:'browser', target:'es2020', outfile:'tests/refresh-built.mjs'});
