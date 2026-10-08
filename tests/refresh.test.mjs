import test from 'node:test';
import assert from 'node:assert/strict';
import {readGrant,encryptedSecretStorage,RefreshCoordinator,READER_AUTHORIZATION_MAX_MS,savedAuthorization} from './refresh-built.mjs';
const good={access_token:'fixture-access',refresh_token:'fixture-refresh',token_type:'Bearer',scope:'vault:read offline_access',expires_in:600};
test('saved reader authorization is exactly 30 days and cannot extend its original absolute deadline',()=>{
 assert.equal(READER_AUTHORIZATION_MAX_MS,2592000000);
 const original={refreshToken:'fixture-refresh',startedAt:1000,expiresAt:1000+READER_AUTHORIZATION_MAX_MS};
 assert.equal(savedAuthorization(JSON.stringify(original),2000).expiresAt,original.expiresAt);
 assert.throws(()=>savedAuthorization(JSON.stringify({...original,expiresAt:original.expiresAt+1}),2000));
 assert.throws(()=>savedAuthorization(JSON.stringify({...original,startedAt:999}),2000));
});
test('renewed grants stay read-only, bounded, and require a rotating refresh credential',()=>{
 assert.equal(readGrant(good,true).expiresIn,600);
 for(const changed of [{scope:'vault:read vault:write offline_access'},{scope:'vault:read openid'},{expires_in:601},{refresh_token:''},{token_type:'DPoP'}])
  assert.throws(()=>readGrant({...good,...changed},true));
});
test('secure persistence refuses missing encryption and Linux plaintext fallback',()=>{
 const storage={getSecret(){},setSecret(){},isEncryptionAvailable:()=>true,adapter:{getSelectedStorageBackend:()=> 'basic_text'}};
 assert.equal(encryptedSecretStorage(undefined,true),false);
 assert.equal(encryptedSecretStorage(storage,true),false);
 storage.adapter.getSelectedStorageBackend=()=> 'gnome_libsecret';
 assert.equal(encryptedSecretStorage(storage,true),true);
 storage.isEncryptionAvailable=()=> false;
 assert.equal(encryptedSecretStorage(storage,true),false);
});
test('simultaneous access renewal shares one exchange and does not reuse a rotated token',async()=>{
 const coordinator=new RefreshCoordinator();let exchanges=0,finish;
 const exchange=()=>{exchanges++;return new Promise(resolve=>{finish=resolve;});};
 const a=coordinator.run(exchange),b=coordinator.run(exchange);
 assert.equal(a,b);assert.equal(exchanges,1);finish(readGrant(good,true));
 await Promise.all([a,b]);
 const c=coordinator.run(async()=>{exchanges++;return readGrant({...good,refresh_token:'rotated-fixture'},true);});
 assert.equal((await c).refreshToken,'rotated-fixture');assert.equal(exchanges,2);
});
