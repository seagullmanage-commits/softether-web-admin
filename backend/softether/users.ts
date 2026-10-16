import {randomUUID} from 'node:crypto';
import {object,type Reader,type RecordValue as R} from './client.js';
import type {Audit,AuditEntry} from '../audit.js';
export class UserError extends Error {constructor(public status:number,message:string){super(message);}}
const string=(r:R,k:string)=>typeof r[k]==='string'?r[k] as string:'';
export class Users {
 private busy=false;
 constructor(private rpc:Reader,private audit:Audit){}
 private async hub(name:string){const result=await this.rpc.call('EnumHub');if(!Array.isArray(result.HubList)||!result.HubList.some(h=>object(h).HubName_str===name))throw new UserError(404,'Virtual hub not found. Refresh the hub list.');}
 async list(hub:string){
  try{await this.hub(hub);const r=await this.rpc.call('EnumUser',{HubName_str:hub});if(!Array.isArray(r.UserList)||r.UserList.length>10000)throw Error();
   let connected:Set<string>|null=null;
   const sessionUsers=new Map<string,string>();let userIps:Map<string,Set<string>>|null=null;
   try{const sessions=await this.rpc.call('EnumSession',{HubName_str:hub});
    if(!Array.isArray(sessions.SessionList)||sessions.SessionList.length>10000)throw Error();
    connected=new Set(sessions.SessionList.map(v=>{const row=object(v);if(typeof row.Username_str!=='string')throw Error();const user=row.Username_str.toLowerCase();if(typeof row.Name_str==='string')sessionUsers.set(row.Name_str,user);return user;}));
   }catch{connected=null;}
   if(connected!==null){try{
    const result=await this.rpc.call('EnumIPTable',{HubName_str:hub});
    if(!Array.isArray(result.IpTable)||result.IpTable.length>10000)throw Error();
    userIps=new Map();for(const value of result.IpTable){const row=object(value);if(typeof row.SessionName_str!=='string'||typeof row.IpAddress_ip!=='string')throw Error();const user=sessionUsers.get(row.SessionName_str);if(user&&row.IpAddress_ip){const ips=userIps.get(user)??new Set<string>();ips.add(row.IpAddress_ip);userIps.set(user,ips);}}
   }catch{userIps=null;}}
   return {statusAvailable:connected!==null,users:r.UserList.map(v=>{const u=object(v);return {name:string(u,'Name_str'),online:connected===null?null:connected.has(string(u,'Name_str').toLowerCase()),vpnIps:userIps===null?null:[...(userIps.get(string(u,'Name_str').toLowerCase())??[])],realName:string(u,'Realname_utf'),group:string(u,'GroupName_str'),note:string(u,'Note_utf'),authType:typeof u.AuthType_u32==='number'?u.AuthType_u32:null,denied:typeof u.DenyAccess_bool==='boolean'?u.DenyAccess_bool:null,lastLogin:string(u,'LastLoginTime_dt')||null,logins:typeof u.NumLogin_u32==='number'?u.NumLogin_u32:null};})};
  }catch(e){if(e instanceof UserError)throw e;throw new UserError(502,'Could not load users. Retry after checking server connectivity.');}
 }
 private async mutate(action:string,hub:string,name:string,actor:string,run:()=>Promise<void>){
  if(name==='*')throw new UserError(400,'Wildcard authentication accounts must be managed in SoftEther Manager.');
  if(this.busy)throw new UserError(409,'Another account change is in progress. Wait and refresh.');
  this.busy=true;const entry:AuditEntry={id:randomUUID(),actor,action,hub,user:name,outcome:'requested'};
  try {
   await this.hub(hub);
   try{this.audit.write(entry);}catch{throw new UserError(503,'Audit storage is unavailable. No change was attempted.');}
   try{await run();this.audit.write({...entry,outcome:'success'});return {ok:true};}
   catch(e){try{this.audit.write({...entry,outcome:'not_confirmed'});}catch{}if(e instanceof UserError)throw e;throw new UserError(502,'The operation could not be confirmed. Refresh the user list before retrying; the change may have reached the server.');}
  } finally {this.busy=false;}
 }
 private password(value:string){if(value.length<10||Buffer.byteLength(value,'utf8')>255||/[\x00\r\n]/.test(value))throw new UserError(400,'Use at least 10 characters and no more than 255 UTF-8 bytes, without line breaks.');}
 async create(input:{hub:string;name:string;password:string;realName:string;note:string},actor:string){
  this.password(input.password);
  return this.mutate('USER_CREATE',input.hub,input.name,actor,async()=>{
   const existing=await this.rpc.call('EnumUser',{HubName_str:input.hub});
   if(!Array.isArray(existing.UserList))throw Error();
   if(existing.UserList.some(u=>string(object(u),'Name_str').toLowerCase()===input.name.toLowerCase()))throw new UserError(409,'That username already exists.');
   await this.rpc.call('CreateUser',{HubName_str:input.hub,Name_str:input.name,AuthType_u32:1,Auth_Password_str:input.password,GroupName_str:'',Realname_utf:input.realName,Note_utf:input.note,UsePolicy_bool:false});
  });
 }
 async reset(input:{hub:string;name:string;password:string;confirmName:string},actor:string){
  this.password(input.password);
  if(input.confirmName!==input.name)throw new UserError(400,'Type the exact username to confirm.');
  return this.mutate('USER_PASSWORD_RESET',input.hub,input.name,actor,async()=>{
   const current=await this.rpc.call('GetUser',{HubName_str:input.hub,Name_str:input.name});
   if(current.AuthType_u32!==1)throw new UserError(409,'Only password-authenticated users can be reset here. Other authentication methods are unchanged.');
   const params:R={HubName_str:input.hub,Name_str:input.name,AuthType_u32:1,Auth_Password_str:input.password};
   for(const key of ['GroupName_str','Realname_utf','Note_utf','ExpireTime_dt']){if(typeof current[key]!=='string')throw Error();params[key]=current[key];}
   params.UsePolicy_bool=current.UsePolicy_bool===true;
   if(params.UsePolicy_bool){
    const policy=Object.entries(current).filter(([k])=>/^policy:[A-Za-z0-9]+_(bool|u32)$/.test(k));
    if(!policy.length)throw Error();
    for(const [k,v] of policy){if(k.endsWith('_bool')?typeof v!=='boolean':typeof v!=='number'||!Number.isInteger(v)||v<0)throw Error();params[k]=v;}
   }
   // Never replay HashedKey/NtLmSecureHash: they would override the new password.
   await this.rpc.call('SetUser',params);
  });
 }
 private preserved(current:R):R{
  if(current.AuthType_u32!==1)throw new UserError(409,'Editing currently supports password-authenticated accounts only.');
  const params:R={AuthType_u32:1};
  for(const key of ['GroupName_str','Realname_utf','Note_utf','ExpireTime_dt']){if(typeof current[key]!=='string')throw Error();params[key]=current[key];}
  params.UsePolicy_bool=current.UsePolicy_bool===true;
  if(params.UsePolicy_bool){const fields=Object.entries(current).filter(([k])=>/^policy:[A-Za-z0-9]+_(bool|u32)$/.test(k));if(!fields.length)throw Error();for(const [k,v] of fields){if(k.endsWith('_bool')?typeof v!=='boolean':typeof v!=='number'||!Number.isInteger(v)||v<0)throw Error();params[k]=v;}}
  return params;
 }
 async edit(input:{hub:string;name:string;realName:string},actor:string){
  if(input.realName.length>255)throw new UserError(400,'Full name is too long.');
  return this.mutate('USER_EDIT',input.hub,input.name,actor,async()=>{
   const current=await this.rpc.call('GetUser',{HubName_str:input.hub,Name_str:input.name});
   const preserved=this.preserved(current);
   if(typeof current.HashedKey_bin!=='string'||!/^[A-Za-z0-9+/]{27}=$/.test(current.HashedKey_bin)||typeof current.NtLmSecureHash_bin!=='string'||!/^[A-Za-z0-9+/]{22}==$/.test(current.NtLmSecureHash_bin))throw new UserError(409,'Cannot safely preserve this account password. No change was made.');
   await this.rpc.call('SetUser',{...preserved,HubName_str:input.hub,Name_str:input.name,Realname_utf:input.realName,HashedKey_bin:current.HashedKey_bin,NtLmSecureHash_bin:current.NtLmSecureHash_bin});
  });
 }
 async remove(input:{hub:string;name:string;confirmName:string},actor:string){
  if(input.confirmName!==input.name)throw new UserError(400,'Type the exact username to confirm.');
  return this.mutate('USER_DELETE',input.hub,input.name,actor,async()=>{await this.rpc.call('DeleteUser',{HubName_str:input.hub,Name_str:input.name});});
 }
}
