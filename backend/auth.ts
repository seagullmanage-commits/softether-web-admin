import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const derive=promisify(scrypt);
export interface PasswordHash {salt:string; hash:string}
export function parseHash(text:string):PasswordHash {
  const data=JSON.parse(text) as PasswordHash;
  if(!/^[a-f0-9]{32}$/.test(data.salt)||!/^[a-f0-9]{128}$/.test(data.hash)) throw new Error('Invalid admin password hash file');
  return {salt:data.salt,hash:data.hash};
}
export async function verify(password:string, stored:PasswordHash) {
  const candidate=await derive(password,Buffer.from(stored.salt,'hex'),64) as Buffer;
  return timingSafeEqual(candidate,Buffer.from(stored.hash,'hex'));
}
export const token=()=>randomBytes(32).toString('hex');
export interface Session {csrf:string; created:number; seen:number}
export class Sessions {
  private entries=new Map<string,Session>();
  constructor(private now=()=>Date.now()) {}
  get(id:string|undefined) {
    if(!id) return undefined;
    const s=this.entries.get(id);
    if(!s) return undefined;
    if(this.now()-s.seen>=30*60_000||this.now()-s.created>=8*60*60_000) {this.entries.delete(id);return undefined;}
    s.seen=this.now();return s;
  }
  create() {
    for(const [id,s] of this.entries) if(this.now()-s.seen>=30*60_000||this.now()-s.created>=8*60*60_000) this.entries.delete(id);
    if(this.entries.size>=32) this.entries.delete(this.entries.keys().next().value!);
    const id=token(), session={csrf:token(),created:this.now(),seen:this.now()};this.entries.set(id,session);return {id,session};
  }
  delete(id:string|undefined) {if(id)this.entries.delete(id);}
}
export class LoginLimit {
  private attempts=new Map<string,{count:number;until:number}>();
  private global={count:0,until:0};
  constructor(private now=()=>Date.now()) {}
  allow(ip:string) {
    const now=this.now();
    for(const [key,value] of this.attempts) if(value.until<=now) this.attempts.delete(key);
    if(this.global.until<=now)this.global={count:0,until:now+15*60_000};
    if(this.global.count>=30||this.attempts.size>=1000&&!this.attempts.has(ip))return false;
    const value=this.attempts.get(ip)??{count:0,until:now+15*60_000};
    if(value.count>=5)return false;
    value.count++;this.global.count++;this.attempts.set(ip,value);return true;
  }
}
