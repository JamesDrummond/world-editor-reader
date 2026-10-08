import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {downloadLatest,sha256,validateSnapshot,validPath} from './sync-built.mjs';
const buffer=s=>new TextEncoder().encode(s).buffer;
const snapshot=async entries=>({version:1,snapshotId:'a'.repeat(32),files:await Promise.all(Object.entries(entries).map(async([path,data])=>({path,bytes:data.byteLength,sha256:await sha256(data)})))});
function local(initial={}) {
  const files=new Map(Object.entries(initial)),conflicts=new Map(),archived=new Map();
  return {files,conflicts,archived,read:async p=>files.get(p)??null,write:async(p,d)=>{files.set(p,d);},
    preserve:async(p,d)=>{conflicts.set(p,d);},archive:async p=>{archived.set(p,files.get(p));files.delete(p);}};
}
test('download creates notes and verifies hashes',async()=>{
  const data={'Notes/A.md':buffer('Kale')},l=local(),state={files:{}};
  const result=await downloadLatest(await snapshot(data),state,l,async f=>data[f.path],async()=>{});
  assert.equal(result.downloaded,1);assert.equal(await sha256(l.files.get('Notes/A.md')),state.files['Notes/A.md']);
});
test('locally edited and untracked files are preserved before overwrite',async()=>{
  for(const tracked of [true,false]){
    const l=local({'A.md':buffer('my edit')}),state={files:tracked?{'A.md':await sha256(buffer('old server'))}:{}};
    const result=await downloadLatest(await snapshot({'A.md':buffer('new server')}),state,l,async()=>buffer('new server'),async()=>{});
    assert.equal(result.preserved,1);assert.equal(new TextDecoder().decode(l.conflicts.get('A.md')),'my edit');
  }
});
test('server deletion archives unchanged copies and leaves edited/untracked files',async()=>{
  const l=local({'A.md':buffer('unchanged'),'B.md':buffer('edited'),'C.md':buffer('untracked')});
  const state={files:{'A.md':await sha256(buffer('unchanged')),'B.md':await sha256(buffer('previous'))}};
  const result=await downloadLatest(await snapshot({}),state,l,async()=>{throw Error('must not fetch');},async()=>{});
  assert.equal(result.archived,1);assert.ok(l.archived.has('A.md'));assert.ok(l.files.has('B.md'));assert.ok(l.files.has('C.md'));
});
test('bad network content never overwrites the local note',async()=>{
  const l=local({'A.md':buffer('keep')}),state={files:{}};
  await assert.rejects(downloadLatest(await snapshot({'A.md':buffer('expected')}),state,l,async()=>buffer('corrupt'),async()=>{}));
  assert.equal(new TextDecoder().decode(l.files.get('A.md')),'keep');assert.equal(l.conflicts.size,0);
});
test('failed preservation prevents replacement',async()=>{
  const l=local({'A.md':buffer('keep')});l.preserve=async()=>{throw Error('disk full');};
  await assert.rejects(downloadLatest(await snapshot({'A.md':buffer('new')}),{files:{}},l,async()=>buffer('new'),async()=>{}));
  assert.equal(new TextDecoder().decode(l.files.get('A.md')),'keep');
});
test('interruption checkpoints and can resume',async()=>{
  const data={'A.md':buffer('a'),'B.md':buffer('b')},s=await snapshot(data),state={files:{}},l=local();let saved=0;
  await assert.rejects(downloadLatest(s,state,l,async f=>{if(f.path==='B.md')throw Error('offline');return data[f.path];},async()=>{saved++;}));
  assert.equal(saved,1);assert.ok(state.files['A.md']);
  await downloadLatest(s,state,l,async f=>data[f.path],async()=>{});assert.equal(l.files.size,2);
});
test('reject hidden settings, traversal, executable and conflicting paths',async()=>{
  for(const p of ['../A.md','.obsidian/secret.md','/A.md','A%2fB.md','A\\B.md','A.js','A.svg','Reader Conflicts/A.md'])assert.equal(validPath(p),false);
  for(const data of [{'A.md':buffer('a'),'a.md':buffer('b')},{'A.md':buffer('a'),'A.md/B.md':buffer('b')}])assert.throws(()=>validateSnapshot(data));
  const s=await snapshot({'A.md':buffer('a'),'a.md':buffer('b')});assert.throws(()=>validateSnapshot(s));
});
test('production plugin has no Node filesystem/Electron APIs or vault upload request',async()=>{
  const main=await readFile('main.js','utf8');
  assert.doesNotMatch(main,/require\(["'](?:fs|node:fs|electron|child_process)["']\)/);
  const source=await readFile('src/main.ts','utf8');
  assert.equal((source.match(/method:\s*['"]POST['"]/g)||[]).length,3); // Code exchange, refresh exchange, and revocation only.
  assert.doesNotMatch(source,/method:\s*['"](?:PUT|PATCH|DELETE)['"]/);
  assert.ok(source.includes('url:pending.tokenEndpoint,method:\'POST\''));
  assert.ok(source.includes('url:this.revocationEndpoint,method:\'POST\''));
  assert.ok(source.includes('url:this.tokenEndpoint,method:\'POST\''));
});
