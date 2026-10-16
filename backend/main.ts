import { readFileSync } from 'node:fs';
import { createApp } from './app.js';
import { parseHash } from './auth.js';
import { SoftEtherClient } from './softether/client.js';
import { Downloads } from './softether/downloads.js';
import { Users } from './softether/users.js';
import { FileAudit } from './audit.js';
import { Dashboard } from './softether/dashboard.js';
const required=(key:string)=>{const value=process.env[key];if(!value)throw new Error(`Missing ${key}`);return value;};
const secret=(key:string)=>readFileSync(required(key),'utf8').replace(/\r?\n$/,'');
const audit=(event:string,detail?:string)=>process.stdout.write(JSON.stringify({time:new Date().toISOString(),event,detail})+'\n');
try {
  const password=secret('SOFTETHER_PASSWORD_FILE');
  if(!password||/[\r\n]/.test(password))throw new Error('Invalid SoftEther password file');
  const client=new SoftEtherClient({host:required('SOFTETHER_HOST'),port:Number(process.env.SOFTETHER_PORT??443),servername:required('SOFTETHER_TLS_NAME'),ca:secret('SOFTETHER_CA_FILE'),password});
  const app=await createApp({origin:required('PUBLIC_ORIGIN'),username:process.env.ADMIN_USERNAME??'admin',passwordHash:parseHash(secret('ADMIN_HASH_FILE')),trustedProxies:(process.env.TRUSTED_PROXIES??'').split(',').filter(Boolean),dashboard:new Dashboard(client,audit),downloads:new Downloads(client,secret('SOFTETHER_CA_FILE'),required('VPN_PUBLIC_HOST'),required('SOFTETHER_TLS_NAME')),users:new Users(client,new FileAudit(required('AUDIT_FILE'))),audit});
  const close=async()=>{await app.close();client.close();process.exit(0);};
  process.on('SIGTERM',close);process.on('SIGINT',close);
  await app.listen({host:'0.0.0.0',port:3000});audit('startup','openvpn-downloads');
} catch {audit('startup_failed','Check required configuration, certificates and secret files.');process.exitCode=1;}
