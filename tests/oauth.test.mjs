import test from 'node:test';
import assert from 'node:assert/strict';
import {pkceChallenge,validCallback} from './oauth-built.mjs';
test('PKCE matches RFC 7636 S256 test vector',async()=>{
 assert.equal(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});
test('OAuth callback rejects wrong state, issuer, expiry and missing code',()=>{
 const p={state:'fixture-state',issuer:'https://vault.test/auth',expires:1000};
 const v={state:p.state,iss:p.issuer,code:'fixture-code'};
 assert.equal(validCallback(p,v,999),true);
 for(const x of [{...v,state:'wrong'},{...v,iss:p.issuer+'/'},{...v,code:''}])assert.equal(validCallback(p,x,999),false);
 assert.equal(validCallback(p,v,1001),false);assert.equal(validCallback(null,v,999),false);
});
