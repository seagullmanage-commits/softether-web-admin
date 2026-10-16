import {X509Certificate} from 'node:crypto';
import type {Reader} from './client.js';
import {UserError} from './users.js';
export class Downloads {
 private certificate:string;
 constructor(private rpc:Reader,pem:string,private host:string,private tlsName:string){
  if(!/^[a-zA-Z0-9.-]+$/.test(host)||!/^[a-zA-Z0-9.-]+$/.test(tlsName))throw Error('Invalid VPN hostname');
  this.certificate=new X509Certificate(pem).toString()+'\n';
 }
 cert(){return this.certificate;}
 async openvpn():Promise<string>{
  try{
   const settings=await this.rpc.call('GetOpenVpnSstpConfig');
   if(settings.EnableOpenVPN_bool!==true)throw new UserError(409,'OpenVPN is disabled. Enable the service and its network port before downloading a profile.');
   const ports=settings.OpenVPNPortList_str;
   if(typeof ports!=='string'||!ports.split(',').map(p=>p.trim()).includes('1194'))throw new UserError(409,'The expected OpenVPN UDP port 1194 is not configured.');
   // Match the deployed SoftEther remote-access sample, without its commented demo key.
   // A dedicated trust certificate and exact server name verify the server identity.
   return `# SoftEther VPN remote access\n# Sign in with username@hub and your VPN user password.\n# Requires OpenVPN 2.5 or later, or a compatible client.\nclient\ndev tun\nproto udp\nremote ${this.host} 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\ncipher AES-128-CBC\ndata-ciphers AES-128-CBC\nauth SHA1\nauth-user-pass\nauth-nocache\nverify-x509-name ${this.tlsName} name\nverb 3\n<ca>\n${this.certificate}</ca>\n`;
  }catch(e){if(e instanceof UserError)throw e;throw new UserError(502,'Could not prepare the OpenVPN profile. Check server connectivity and try again.');}
 }
}
