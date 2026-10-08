export async function pkceChallenge(verifier:string):Promise<string> {
  const data=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
export function validCallback(pending:{state:string;expires:number;issuer:string}|null,params:Record<string,string>,now=Date.now()):boolean {
  return !!pending && pending.expires>=now && params.state===pending.state && params.iss===pending.issuer && !!params.code;
}
