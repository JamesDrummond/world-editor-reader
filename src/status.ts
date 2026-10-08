export type ReaderPhase = 'signed-out' | 'authenticating' | 'signed-in' | 'expired' | 'error';
export type ReaderStatus = {phase:ReaderPhase; label:string; canDownload:boolean};
export function readerStatus(input:{hasToken:boolean;accessExpiry:number;authenticating:boolean;pendingExpiry:number|null;error:boolean;dedicated:boolean;refreshing?:boolean;hasRefresh?:boolean;authorizationExpired?:boolean},now=Date.now()):ReaderStatus {
  const canDownload=input.dedicated && ((input.hasToken && input.accessExpiry>now) || !!input.hasRefresh);
  if(input.authorizationExpired)return {phase:'expired',label:'30-day read-only authorization expired — sign in once to renew',canDownload:false};
  if(input.refreshing)return {phase:'authenticating',label:'Refreshing read-only access…',canDownload};
  if (input.error) return {phase:'error',label:'Error — see details below',canDownload};
  if (input.authenticating || (input.pendingExpiry!==null && input.pendingExpiry>now)) return {phase:'authenticating',label:'Authenticating — finish browser login and consent',canDownload};
  if (input.hasToken && input.accessExpiry>now) return {phase:'signed-in',label:'Signed in — read-only (vault:read)',canDownload};
  if(input.hasRefresh)return {phase:'signed-in',label:'Saved read-only sign-in — refresh before download',canDownload};
  if (input.hasToken || input.pendingExpiry!==null) return {phase:'expired',label:'Token or sign-in request expired — sign in again',canDownload:false};
  return {phase:'signed-out',label:'Signed out',canDownload:false};
}
