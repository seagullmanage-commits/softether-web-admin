import {test} from 'node:test';
import assert from 'node:assert/strict';
import {scryptSync} from 'node:crypto';
import {createApp} from '../dist/backend/app.js';
import {Sessions,LoginLimit} from '../dist/backend/auth.js';
import {Dashboard} from '../dist/backend/softether/dashboard.js';
import {SoftEtherClient,RpcError} from '../dist/backend/softether/client.js';
const origin='https://console.test';
const password='test-only-password-12345';
const salt='0123456789abcdef0123456789abcdef';
const hash={salt,hash:scryptSync(password,Buffer.from(salt,'hex'),64).toString('hex')};
const headers={host:'console.test','x-forwarded-proto':'https',origin};
async function fixture(extra={}){const app=await createApp({origin,username:'admin',passwordHash:hash,trustedProxies:['127.0.0.1'],dashboard:{get:async()=>({online:true})},...extra});await app.ready();return app;}
async function login(app){return app.inject({method:'POST',url:'/api/login',headers,payload:{username:'admin',password}});}
test('authentication, cookie flags, CSRF, expiry and logout',async()=>{
 let now=0;const app=await fixture({sessions:new Sessions(()=>now)});
 try{
  assert.equal((await app.inject({url:'/api/dashboard',headers})).statusCode,401);
  let r=await login(app);assert.equal(r.statusCode,200);
  const cookie=r.headers['set-cookie'];assert.match(cookie,/Secure/);assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Strict/);assert.match(cookie,/^__Host-/);
  const h={...headers,cookie:cookie.split(';')[0]};
  assert.equal((await app.inject({url:'/api/dashboard',headers:h})).statusCode,200);
  assert.equal((await app.inject({method:'POST',url:'/api/logout',headers:h,payload:{}})).statusCode,403);
  assert.equal((await app.inject({method:'POST',url:'/api/logout',headers:{...h,origin:'https://evil.test','x-csrf-token':r.json().csrf},payload:{}})).statusCode,403);
  assert.equal((await app.inject({method:'POST',url:'/api/logout',headers:{...h,'x-csrf-token':r.json().csrf},payload:{}})).statusCode,200);
  assert.equal((await app.inject({url:'/api/dashboard',headers:h})).statusCode,401);
  r=await login(app);h.cookie=r.headers['set-cookie'].split(';')[0];now=30*60_000;
  assert.equal((await app.inject({url:'/api/dashboard',headers:h})).statusCode,401);
 }finally{await app.close();}
});
test('absolute expiration survives activity',()=>{let now=0;const sessions=new Sessions(()=>now);const {id}=sessions.create();for(let i=1;i<16;i++){now=i*29*60_000;assert.ok(sessions.get(id));}now=8*60*60_000;assert.equal(sessions.get(id),undefined);});
test('untrusted forwarded headers cannot bypass HTTPS',async()=>{const app=await fixture({trustedProxies:[]});try{assert.equal((await app.inject({url:'/',headers})).statusCode,400);assert.equal((await app.inject({url:'/healthz'})).statusCode,200);}finally{await app.close();}});
test('login validation, origin checks, rate limit and safe error logging',async()=>{const events=[];const app=await fixture({audit:(...args)=>events.push(args)});try{
 assert.equal((await app.inject({method:'POST',url:'/api/login',headers:{...headers,origin:'https://evil.test'},payload:{username:'admin',password}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/api/login',headers,payload:{username:'admin',password,method:'DeleteHub'}})).statusCode,400);
 for(let i=0;i<5;i++)assert.equal((await app.inject({method:'POST',url:'/api/login',headers,payload:{username:'admin',password:'wrong-secret'}})).statusCode,401);
 assert.equal((await login(app)).statusCode,429);assert.ok(!JSON.stringify(events).includes('wrong-secret'));
 }finally{await app.close();}});
test('no arbitrary RPC or mutation endpoints and security headers',async()=>{const app=await fixture();try{const r=await login(app);const h={...headers,cookie:r.headers['set-cookie'].split(';')[0]};for(const url of ['/api/','/api/rpc','/api/users','/api/disconnect'])assert.equal((await app.inject({method:'POST',url,headers:h,payload:{method:'SetServerPassword'}})).statusCode,404);const response=await app.inject({url:'/',headers});assert.match(response.headers['content-security-policy'],/frame-ancestors 'none'/);assert.equal(response.headers['cache-control'],'no-store');assert.equal((await app.inject({url:'/.env',headers})).statusCode,404);}finally{await app.close();}});
test('dashboard projects only safe fields, handles partial failure, coalesces refresh',async()=>{let count=0;const calls=[];const rpc={call:async(method)=>{count++;calls.push(method);switch(method){case'GetServerInfo':return{ServerVersionString_str:'test',ServerProductName_str:'VPN',Password_str:'do-not-leak'};case'GetServerStatus':return{NumUsers_u32:3,'Recv.BroadcastBytes_u64':1,'Recv.UnicastBytes_u64':2};case'EnumHub':return{HubList:[{HubName_str:'<img src=x onerror=alert(1)>',Online_bool:true}]};case'EnumListener':return{ListenerList:[{Ports_u32:443,Enables_bool:true,Errors_bool:false}]};case'GetIPsecServices':return{L2TP_IPsec_bool:true,IPsec_Secret_str:'do-not-leak'};case'GetOpenVpnSstpConfig':throw new RpcError('unsupported');case'GetHubStatus':return{SecureNATEnabled_bool:true};case'EnumSession':return{SessionList:[]};case'EnumIPTable':return{IpTable:[]};case'EnumDHCP':return{DhcpTable:[]};}}};const d=new Dashboard(rpc);const [a,b]=await Promise.all([d.get(),d.get()]);assert.deepEqual(a,b);assert.equal(count,10);assert.equal(a.stats.received,3);assert.equal(a.protocols.openvpn,null);assert.equal(a.hubs[0].secureNat,true);assert.ok(a.warnings.length);assert.ok(!JSON.stringify(a).includes('do-not-leak'));await d.get();assert.equal(count,10);assert.ok(!calls.some(x=>x.startsWith('Set')));});
test('unavailable API never masquerades as an empty healthy VPN',async()=>{const result=await new Dashboard({call:async()=>{throw new RpcError('authentication');}}).get();assert.equal(result.online,false);assert.equal(result.stats,null);assert.match(result.warnings[0],/authentication/);});
test('client rejects writes and unexpected parameters before transport',async()=>{const client=new SoftEtherClient({host:'127.0.0.1',port:1,servername:'localhost',ca:'',password:'test'});try{await assert.rejects(client.call('DeleteHub'),/unsupported/);await assert.rejects(client.call('GetServerInfo',{method:'DeleteHub'}),/unsupported/);await assert.rejects(client.call('EnumSession',{HubName_str:''}),/unsupported/);}finally{client.close();}});
