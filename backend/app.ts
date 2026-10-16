import Fastify from 'fastify';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Sessions,LoginLimit,verify,type PasswordHash } from './auth.js';
import { UserError, type Users } from './softether/users.js';
import type { Downloads } from './softether/downloads.js';
import type { Dashboard } from './softether/dashboard.js';
export interface AppConfig {downloads?:Downloads; users?:Users; origin:string; username:string; passwordHash:PasswordHash; trustedProxies:string[]; dashboard:Pick<Dashboard,'get'>; audit?:(event:string,detail?:string)=>void; sessions?:Sessions; limiter?:LoginLimit; assetsDirectory?:string}
const cookieName='__Host-vpnadmin';
const cookie=(id:string,maxAge=28800)=>`${cookieName}=${id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
function sessionId(header:string|undefined) { return header?.split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='))?.slice(cookieName.length+1); }
export async function createApp(config:AppConfig) {
  const origin=new URL(config.origin);
  if(origin.protocol!=='https:'||origin.origin!==config.origin)throw new Error('PUBLIC_ORIGIN must be an HTTPS origin without a trailing slash');
  const app=Fastify({logger:false,ajv:{customOptions:{removeAdditional:false,coerceTypes:false}},bodyLimit:4096,trustProxy:config.trustedProxies.length?config.trustedProxies:false,requestTimeout:10000,connectionTimeout:10000,keepAliveTimeout:5000});
  const sessions=config.sessions??new Sessions(), limiter=config.limiter??new LoginLimit(),audit=config.audit??(()=>{});
  app.addHook('onRequest',async(req,reply)=>{
    reply.headers({'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Cache-Control':'no-store','Strict-Transport-Security':'max-age=31536000'});
    if(req.url==='/healthz')return;
    if(req.protocol!=='https'||req.headers.host!==origin.host)return reply.code(400).send({error:'Use the configured HTTPS address.'});
    if(!['GET','HEAD'].includes(req.method)&&req.headers.origin!==config.origin)return reply.code(403).send({error:'Invalid request origin.'});
  });
  app.setErrorHandler((error,req,reply)=>{
    if(error instanceof UserError)return reply.code(error.status).send({error:error.message});
    const code=(error as {statusCode?:number}).statusCode;
    const status=typeof code==='number'&&code>=400&&code<500?code:500;
    audit('request_error',String(status));reply.code(status).send({error:status===500?'Request failed.':'Invalid request.'});
  });
  app.get('/healthz',async()=>({status:'ok'}));
  app.post<{Body:{username:string;password:string}}>('/api/login',{schema:{body:{type:'object',additionalProperties:false,required:['username','password'],properties:{username:{type:'string',maxLength:128},password:{type:'string',minLength:1,maxLength:1024}}}}},async(req,reply)=>{
    if(!limiter.allow(req.ip)){audit('login_rate_limited');return reply.header('Retry-After','900').code(429).send({error:'Too many attempts. Try again in 15 minutes.'});}
    const valid=await verify(req.body.password,config.passwordHash);
    if(!valid||req.body.username!==config.username){audit('login_failed');return reply.code(401).send({error:'Incorrect username or password.'});}
    sessions.delete(sessionId(req.headers.cookie));const {id,session}=sessions.create();audit('login_success');
    return reply.header('Set-Cookie',cookie(id)).send({csrf:session.csrf});
  });
  app.get('/api/session',async(req,reply)=>{
    const s=sessions.get(sessionId(req.headers.cookie));if(!s)return reply.code(401).send({error:'Sign in to continue.'});return {csrf:s.csrf};
  });
  app.post('/api/logout',async(req,reply)=>{
    const id=sessionId(req.headers.cookie),s=sessions.get(id);
    if(!s)return reply.code(401).send({error:'Session expired.'});
    if(req.headers['x-csrf-token']!==s.csrf)return reply.code(403).send({error:'Invalid request token.'});
    sessions.delete(id);audit('logout');return reply.header('Set-Cookie',cookie('',0)).send({ok:true});
  });
  app.get('/api/dashboard',async(req,reply)=>{
    if(!sessions.get(sessionId(req.headers.cookie)))return reply.code(401).send({error:'Sign in to continue.'});
    return config.dashboard.get();
  });
  if(config.downloads){
    for(const [route,filename,mime,read] of [
      ['/api/downloads/certificate','softether-server.crt','application/x-pem-file',()=>config.downloads!.cert()],
      ['/api/downloads/openvpn','softether-openvpn.ovpn','application/x-openvpn-profile',()=>config.downloads!.openvpn()]
    ] as const){
      app.get(route,async(req,reply)=>{
        if(!sessions.get(sessionId(req.headers.cookie)))return reply.code(401).send({error:'Sign in to continue.'});
        const content=await read();
        audit('download',filename);
        return reply.header('Content-Disposition',`attachment; filename="${filename}"`).type(mime).send(content);
      });
    }
  }
  if(config.users) {
    const name={type:'string',minLength:1,maxLength:255,pattern:'^[^\\u0000-\\u001f\\u007f]+$'};
    const secret={type:'string',minLength:10,maxLength:255};
    const protect:import('fastify').preHandlerHookHandler=async(req,reply)=>{
      const session=sessions.get(sessionId(req.headers.cookie));
      if(!session)return reply.code(401).send({error:'Sign in to continue.'});
      if(req.method!=='GET'&&req.headers['x-csrf-token']!==session.csrf)return reply.code(403).send({error:'Invalid request token.'});
    };
    app.get<{Querystring:{hub:string}}>('/api/users',{preHandler:protect,schema:{querystring:{type:'object',additionalProperties:false,required:['hub'],properties:{hub:name}}}},async(req)=>config.users!.list(req.query.hub));
    app.post<{Body:{hub:string;name:string;password:string;realName:string;note:string}}>('/api/users/create',{preHandler:protect,schema:{body:{type:'object',additionalProperties:false,required:['hub','name','password','realName','note'],properties:{hub:name,name:{type:'string',pattern:'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'},password:secret,realName:{type:'string',maxLength:255},note:{type:'string',maxLength:1000}}}}},async(req)=>config.users!.create(req.body,config.username));
    app.post<{Body:{hub:string;name:string;password:string;confirmName:string}}>('/api/users/password',{preHandler:protect,schema:{body:{type:'object',additionalProperties:false,required:['hub','name','password','confirmName'],properties:{hub:name,name,password:secret,confirmName:name}}}},async(req)=>config.users!.reset(req.body,config.username));
    app.post<{Body:{hub:string;name:string;confirmName:string}}>('/api/users/delete',{preHandler:protect,schema:{body:{type:'object',additionalProperties:false,required:['hub','name','confirmName'],properties:{hub:name,name,confirmName:name}}}},async(req)=>config.users!.remove(req.body,config.username));
  }
  const dir=config.assetsDirectory??fileURLToPath(new URL('../frontend/',import.meta.url));
  for(const [route,file,type] of [['/','index.html','text/html; charset=utf-8'],['/app.js','app.js','text/javascript; charset=utf-8'],['/styles.css','styles.css','text/css; charset=utf-8']]) {
    const content=await readFile(`${dir}/${file}`);
    app.get(route!,async(_req,reply)=>reply.type(type!).send(content));
  }
  return app;
}
