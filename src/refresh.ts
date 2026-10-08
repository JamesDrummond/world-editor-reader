export type ReadGrant={accessToken:string;expiresIn:number;refreshToken:string};
export const READER_AUTHORIZATION_MAX_MS=30*24*60*60*1000;
export type SavedReaderAuthorization={refreshToken:string;startedAt:number;expiresAt:number};
export function savedAuthorization(raw:string,now=Date.now()):SavedReaderAuthorization {
  const value=JSON.parse(raw);
  if(typeof value.refreshToken!=='string' || !value.refreshToken || value.refreshToken.length>8192 ||
    !Number.isSafeInteger(value.startedAt) || !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt!==value.startedAt+READER_AUTHORIZATION_MAX_MS || value.startedAt>now+60000)
    throw Error('Invalid saved reader authorization');
  return value;
}
export function readGrant(value:any,refreshRequired:boolean):ReadGrant {
  const scopes=typeof value.scope==='string'?value.scope.split(' '):[];
  if(value.token_type?.toLowerCase()!=='bearer' || typeof value.access_token!=='string' || !value.access_token ||
    !scopes.includes('vault:read') || scopes.some((s:string)=>!['vault:read','offline_access'].includes(s)) ||
    !Number.isFinite(value.expires_in) || value.expires_in<=0 || value.expires_in>600 ||
    (refreshRequired && (typeof value.refresh_token!=='string' || !value.refresh_token || value.refresh_token.length>8192)))
    throw Error('Unexpected read-only token grant');
  return {accessToken:value.access_token,expiresIn:value.expires_in,refreshToken:typeof value.refresh_token==='string'?value.refresh_token:''};
}
export type NativeSecrets={getSecret(id:string):string|null;setSecret(id:string,value:string):void;
  isEncryptionAvailable?:()=>boolean;adapter?:{getSelectedStorageBackend?:()=>string}};
export function encryptedSecretStorage(storage:NativeSecrets|undefined,isLinux:boolean):boolean {
  try {
    if(!storage || typeof storage.isEncryptionAvailable!=='function' || !storage.isEncryptionAvailable())return false;
    if(isLinux && !['gnome_libsecret','kwallet','kwallet5','kwallet6'].includes(storage.adapter?.getSelectedStorageBackend?.()??''))return false;
    return true;
  } catch {return false;}
}

// The caller owns validated endpoints and storage. Concurrent downloads share
// one refresh exchange, so rotating credentials cannot be reused by this client.
export class RefreshCoordinator {
  private inFlight:Promise<ReadGrant>|null=null;
  run(exchange:()=>Promise<ReadGrant>):Promise<ReadGrant> {
    if(this.inFlight)return this.inFlight;
    this.inFlight=exchange().finally(()=>{this.inFlight=null;});
    return this.inFlight;
  }
}
