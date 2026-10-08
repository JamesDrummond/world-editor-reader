import test from 'node:test';
import assert from 'node:assert/strict';
import {readerStatus} from './status-built.mjs';
const initial={hasToken:false,accessExpiry:0,authenticating:false,pendingExpiry:null,error:false,dedicated:true};
test('reader status follows sign-in, consent, expiration and sign-out without persisting a token',()=>{
 assert.equal(readerStatus(initial,100).phase,'signed-out');
 assert.equal(readerStatus({...initial,authenticating:true},100).phase,'authenticating');
 assert.equal(readerStatus({...initial,pendingExpiry:200},100).phase,'authenticating');
 const granted={...initial,hasToken:true,accessExpiry:200};
 assert.equal(readerStatus(granted,100).phase,'signed-in');
 assert.equal(readerStatus(granted,100).canDownload,true);
 assert.equal(readerStatus(granted,200).phase,'expired');
 assert.equal(readerStatus(granted,200).canDownload,false);
 assert.equal(readerStatus(initial,201).phase,'signed-out');
});
test('pending callback timeout and an error are visible, while a valid prior grant remains usable',()=>{
 assert.equal(readerStatus({...initial,pendingExpiry:200},200).phase,'expired');
 const errored={...initial,hasToken:true,accessExpiry:300,error:true};
 assert.equal(readerStatus(errored,200).phase,'error');
 assert.equal(readerStatus(errored,200).canDownload,true);
 assert.equal(readerStatus({...errored,error:false,dedicated:false},200).phase,'signed-in');
 assert.equal(readerStatus({...errored,error:false,dedicated:false},200).canDownload,false);
});
