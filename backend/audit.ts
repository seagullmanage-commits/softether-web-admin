import {openSync,writeSync,fsyncSync,closeSync,statSync,renameSync,existsSync,unlinkSync} from 'node:fs';
export interface AuditEntry {id:string;actor:string;action:string;hub:string;user:string;outcome:'requested'|'success'|'not_confirmed'}
export interface Audit {write(entry:AuditEntry):void}
export class FileAudit implements Audit {
 constructor(private path:string){}
 write(entry:AuditEntry){
  if(existsSync(this.path)&&statSync(this.path).size>5_000_000){
   if(existsSync(this.path+'.5'))unlinkSync(this.path+'.5');
   for(let i=4;i>=1;i--)if(existsSync(this.path+'.'+i))renameSync(this.path+'.'+i,this.path+'.'+(i+1));
   renameSync(this.path,this.path+'.1');
  }
  const fd=openSync(this.path,'a',0o600);
  try{writeSync(fd,JSON.stringify({time:new Date().toISOString(),...entry})+'\n');fsyncSync(fd);}finally{closeSync(fd);}
 }
}
