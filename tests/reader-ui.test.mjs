import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
import {sha256} from './sync-built.mjs';

function harness(request,{encrypted=false,backend='basic_text',secrets=new Map()}={}) {
 const saves=[],buttons=[],elements=[];
 const element=()=>({dataset:{},text:'',setText(v){this.text=v;},empty(){},createEl(tag,opts){const el=element();el.text=opts?.text??'';elements.push(el);return el;}});
 class Plugin {
  app={vault:{getName:()=> 'World_Reader'},secretStorage:{isEncryptionAvailable:()=>encrypted,adapter:{getSelectedStorageBackend:()=>backend},getSecret:id=>secrets.get(id)??null,setSecret:(id,v)=>secrets.set(id,v)}};
  async loadData(){return {settings:{origin:'https://vault.test',issuer:'https://vault.test/auth',clientId:'world-editor-reader',dedicated:true},state:{files:{}},lastSuccessfulDownloadAt:123};}
  async saveData(value){saves.push(JSON.parse(JSON.stringify(value)));}
  addSettingTab(){} addCommand(){} registerObsidianProtocolHandler(){}
 }
 class PluginSettingTab {containerEl=element();}
 class Setting {
  setName(){return this;} setDesc(){return this;}
  addToggle(cb){cb({setValue(){return this;},onChange(){return this;}});return this;}
  addText(cb){cb({setValue(){return this;},onChange(){return this;}});return this;}
  addButton(cb){const b={text:'',disabled:false,setButtonText(t){this.text=t;return this;},setDisabled(v){this.disabled=v;return this;},onClick(f){this.click=f;return this;}};buttons.push(b);cb(b);return this;}
 }
 const ob={Plugin,PluginSettingTab,Setting,Notice:class{},requestUrl:request,TFile:class{},TFolder:class{},Platform:{isLinux:true}};
 const module={exports:{}};
 const context={module,exports:module.exports,require:()=>ob,crypto:webcrypto,TextEncoder,Uint8Array,ArrayBuffer,btoa,URL,URLSearchParams,
  window:{setInterval:()=>1,clearInterval(){},open(){}}};
 vm.runInNewContext(readFileSync('main.js','utf8'),context);
 return {reader:new module.exports.default(),saves,buttons,elements,secrets};
}

test('fresh public install loads with no server address and makes no credential or network request',async()=>{
 let requests=0;
 const h=harness(async()=>{requests++;throw Error('Unexpected network');});
 const p=h.reader;p.loadData=async()=>null;await p.onload();p.settingsTab.display();
 assert.equal(p.settings.origin,'');assert.equal(p.settings.issuer,'');assert.equal(p.settings.dedicated,false);
 assert.equal(requests,0);assert.equal(h.secrets.size,0);p.onunload();
});
test('OAuth callback immediately refreshes signed-in UI; download button records successful transfer without persisting credentials',async()=>{
 const bytes=new TextEncoder().encode('Verified reader fixture.');
 const hash=await sha256(bytes.buffer);
 const h=harness(async req=>{
  if(req.url.endsWith('/token'))return {status:200,json:{access_token:'fixture-reader-token',refresh_token:'fixture-reader-refresh',token_type:'Bearer',scope:'vault:read offline_access',expires_in:600}};
  if(req.url.endsWith('/snapshot'))return {status:200,arrayBuffer:new ArrayBuffer(0),json:{version:1,snapshotId:'a'.repeat(32),files:[{path:'A.md',bytes:bytes.byteLength,sha256:hash}]}};
  return {status:200,arrayBuffer:bytes.buffer};
 });
 const p=h.reader;await p.onload();p.settingsTab.display();
 const download=h.buttons.find(b=>b.text==='Download latest');
 assert.equal(download.disabled,true);
 p.pending={state:'fixture-state',verifier:'fixture-verifier',issuer:'https://vault.test/auth',tokenEndpoint:'https://vault.test/token',expires:Date.now()+300000};
 p.refreshStatus();assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'authenticating');
 await p.finishSignIn({state:'fixture-state',iss:'https://vault.test/auth',code:'fixture-code'});
 assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'signed-in');
 assert.match(p.settingsTab.statusEl.text,/vault:read/);
 assert.equal(download.disabled,false);
 const files=new Map();p.read=async path=>files.get(path)??null;p.write=async(path,data)=>files.set(path,data);
 await p.startDownload();
 assert.equal(new TextDecoder().decode(files.get('A.md')),'Verified reader fixture.');
 assert.ok(p.lastSuccessfulDownloadAt>123);
 assert.match(p.settingsTab.lastDownloadEl.text,/Last successful download:/);
 assert.equal(Object.keys(h.saves.at(-1).state.files).length,1);
 assert.ok(h.saves.at(-1).lastSuccessfulDownloadAt>123);
 assert.ok(!JSON.stringify(h.saves).includes('fixture-reader-token'));
 p.onunload();
});

const metadata={issuer:'https://vault.test/auth',authorization_endpoint:'https://vault.test/authorization',token_endpoint:'https://vault.test/token',revocation_endpoint:'https://vault.test/revocation',code_challenge_methods_supported:['S256'],authorization_response_iss_parameter_supported:true};
const grant=(n)=>({access_token:'fixture-access-'+n,refresh_token:'fixture-refresh-'+n,token_type:'Bearer',scope:'vault:read offline_access',expires_in:600});
test('expired reader access refreshes once before concurrent downloads, rotates encrypted storage, and survives restart',async()=>{
 const requests=[];let exchanges=0;
 const request=async req=>{
  requests.push(req);
  if(req.url.includes('well-known'))return {status:200,json:metadata};
  if(req.url.endsWith('/token')){exchanges++;return {status:200,json:grant(exchanges)};}
  return {status:200,json:{ok:true}};
 };
 const h=harness(request,{encrypted:true,backend:'gnome_libsecret'}),p=h.reader;await p.onload();
 await p.acceptGrant(grant(0));p.accessExpiry=Date.now()-1;
 await Promise.all([p.authorizedGet('https://vault.test/reader/v1/snapshot'),p.authorizedGet('https://vault.test/reader/v1/snapshot')]);
 assert.equal(exchanges,1);
 assert.equal(JSON.parse(h.secrets.get(p.secretId)).refreshToken,'fixture-refresh-1');
 const absoluteDeadline=p.authorizationExpiresAt;assert.equal(absoluteDeadline,p.authorizationStartedAt+30*24*60*60*1000);
 const tokenRequest=requests.find(r=>r.url.endsWith('/token'));
 const form=new URLSearchParams(tokenRequest.body);
 assert.equal(form.get('grant_type'),'refresh_token');assert.equal(form.get('resource'),'https://vault.test/reader/v1');
 assert.equal(form.get('scope'),'vault:read offline_access');
 assert.ok(requests.filter(r=>r.url.includes('/reader/')).every(r=>r.method==='GET'));
 await p.save();assert.ok(!JSON.stringify(h.saves).includes('fixture-refresh'));
 p.onunload();
 const resumed=harness(request,{encrypted:true,backend:'gnome_libsecret',secrets:h.secrets}).reader;await resumed.onload();
 assert.equal(resumed.refreshToken,'fixture-refresh-1');assert.equal(resumed.authorizationExpiresAt,absoluteDeadline);
 await resumed.authorizedGet('https://vault.test/reader/v1/snapshot');assert.equal(exchanges,2);assert.equal(resumed.authorizationExpiresAt,absoluteDeadline);
 resumed.onunload();
});
test('a resource 401 triggers one refresh retry; revocation uses the refresh grant and clears saved authorization',async()=>{
 let gets=0,refreshes=0,revoked=null;
 const h=harness(async req=>{
  if(req.url.includes('well-known'))return {status:200,json:metadata};
  if(req.url.endsWith('/token')){refreshes++;return {status:200,json:grant(refreshes)};}
  if(req.url.endsWith('/revocation')){revoked=new URLSearchParams(req.body);return {status:200};}
  gets++;return {status:gets===1?401:200};
 },{encrypted:true,backend:'kwallet6'});
 const p=h.reader;await p.onload();await p.acceptGrant(grant(0));
 assert.equal((await p.authorizedGet('https://vault.test/reader/v1/snapshot')).status,200);
 assert.equal(gets,2);assert.equal(refreshes,1);
 await p.signOut();assert.equal(revoked.get('token_type_hint'),'refresh_token');
 assert.equal(revoked.get('token'),'fixture-refresh-1');assert.equal(p.refreshToken,'');assert.equal(h.secrets.get(p.secretId),'');
 p.onunload();
});
test('plaintext keychain never stores or restores refresh credentials; expired/revoked refresh stops without a consent loop',async()=>{
 const h=harness(async req=>req.url.includes('well-known')?{status:200,json:metadata}:{status:400},{encrypted:true,backend:'basic_text'});
 const p=h.reader;await p.onload();await p.acceptGrant(grant(0));
 assert.equal(p.refreshToken,'fixture-refresh-0');assert.equal(h.secrets.size,0);
 p.accessExpiry=Date.now()-1;await assert.rejects(p.ensureAccessToken());
 assert.equal(p.refreshToken,'');assert.equal(p.accessToken,'');
 assert.equal(h.secrets.size,0); // Even clearing must not invoke a plaintext storage fallback.
 assert.ok(!JSON.stringify(h.saves).includes('fixture-refresh'));
 p.onunload();
});
test('30-day absolute cutoff stops downloads despite a live access token; no refresh extends it',async()=>{
 let resourceGets=0,refreshes=0;
 const h=harness(async req=>{
  if(req.url.includes('well-known'))return {status:200,json:metadata};
  if(req.url.endsWith('/token'))refreshes++;
  if(req.url.includes('/reader/'))resourceGets++;
  return {status:200};
 },{encrypted:true,backend:'gnome_libsecret'});
 const p=h.reader;await p.onload();await p.acceptGrant(grant(0));
 p.authorizationStartedAt=Date.now()-30*24*60*60*1000-1;p.authorizationExpiresAt=p.authorizationStartedAt+30*24*60*60*1000;
 p.settingsTab.display();assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'expired');
 await assert.rejects(p.authorizedGet('https://vault.test/reader/v1/snapshot'));
 assert.equal(resourceGets,0);assert.equal(refreshes,0);assert.equal(p.refreshToken,'');
 p.onunload();
});
test('a delayed refresh response cannot restore authorization after sign-out',async()=>{
 let finish;
 const h=harness(async req=>{
  if(req.url.includes('well-known'))return {status:200,json:metadata};
  if(req.url.endsWith('/token'))return new Promise(resolve=>{finish=resolve;});
  return {status:200};
 },{encrypted:true,backend:'gnome_libsecret'});
 const p=h.reader;await p.onload();await p.acceptGrant(grant(0));p.tokenEndpoint=metadata.token_endpoint;p.revocationEndpoint=metadata.revocation_endpoint;
 p.accessExpiry=Date.now()-1;
 const pending=p.ensureAccessToken();
 await p.signOut();finish({status:200,json:grant(1)});
 await assert.rejects(pending);assert.equal(p.accessToken,'');assert.equal(p.refreshToken,'');assert.equal(h.secrets.get(p.secretId),'');
 p.onunload();
});

test('sign-out during asynchronous storage preparation cannot retain or restore a grant',async()=>{
 const h=harness(async()=>({status:200}),{encrypted:true,backend:'gnome_libsecret'});
 const p=h.reader;await p.onload();
 const prepare=p.prepareSecretStorage.bind(p);let finish;
 p.prepareSecretStorage=async()=>{await prepare();await new Promise(resolve=>{finish=resolve;});};
 const pending=p.acceptGrant(grant(0));
 while(!finish)await new Promise(resolve=>setTimeout(resolve,0));
 await p.signOut();finish();await assert.rejects(pending);
 assert.equal(p.accessToken,'');assert.equal(p.refreshToken,'');assert.equal(h.secrets.get(p.secretId),'');p.onunload();
});
test('UI refresh and a failed re-sign-in preserve an existing grant; expiry disables downloads',async()=>{
 const h=harness(async()=>{throw Error('fixture network failure');});
 const p=h.reader;await p.onload();p.accessToken='existing-fixture-token';p.accessExpiry=Date.now()+60000;p.settingsTab.display();
 const download=h.buttons.find(b=>b.text==='Download latest');
 assert.equal(download.disabled,false);
 p.refreshStatus();assert.equal(p.accessToken,'existing-fixture-token');
 await p.startSignIn();
 assert.equal(p.accessToken,'existing-fixture-token');
 assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'error');
 assert.equal(download.disabled,false);
 p.statusError='';p.accessExpiry=Date.now()-1;p.refreshStatus();
 assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'expired');assert.equal(download.disabled,true);
 assert.equal(p.accessToken,'existing-fixture-token');
 await p.signOut();assert.equal(p.accessToken,'');assert.equal(p.settingsTab.statusEl.dataset.readerStatus,'error');
 assert.match(p.statusError,/revocation could not be confirmed/);
 p.onunload();
});
