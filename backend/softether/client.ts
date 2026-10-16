import https from 'node:https';
import { randomUUID } from 'node:crypto';

export const METHODS = ['GetServerInfo','GetServerStatus','EnumHub','EnumListener','EnumSession','GetHubStatus','GetIPsecServices','GetOpenVpnSstpConfig','EnumUser','GetUser','CreateUser','SetUser','DeleteUser'] as const;
export type Method = typeof METHODS[number];
export type RecordValue = Record<string, unknown>;
export interface Reader { call(method: Method, params?: RecordValue): Promise<RecordValue> }
export class RpcError extends Error {
  constructor(public readonly kind: 'authentication'|'tls'|'timeout'|'unavailable'|'invalid_response'|'unsupported', public readonly rpcCode?: number) { super(kind); }
}
export function object(value: unknown): RecordValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RpcError('invalid_response');
  return value as RecordValue;
}
export class SoftEtherClient implements Reader {
  private agent: https.Agent;
  constructor(private config: {host: string; port: number; servername: string; ca: string; password: string; timeoutMs?: number}) {
    this.agent = new https.Agent({keepAlive: true, maxSockets: 2, ca: config.ca, rejectUnauthorized: true});
  }
  close() { this.agent.destroy(); }
  async call(method: Method, params: RecordValue = {}): Promise<RecordValue> {
    if (!(METHODS as readonly string[]).includes(method)) throw new RpcError('unsupported');
    const validName=(v:unknown)=>typeof v==='string' && v.length>0 && v.length<=255 && !/[\x00-\x1f\x7f]/.test(v);
    const keys=Object.keys(params);
    if (['EnumSession','GetHubStatus','EnumUser'].includes(method)) {
      if(keys.length!==1 || !validName(params.HubName_str))throw new RpcError('unsupported');
    } else if (['GetUser','DeleteUser'].includes(method)) {
      if(keys.length!==2 || !validName(params.HubName_str)||!validName(params.Name_str)||params.Name_str==='*')throw new RpcError('unsupported');
    } else if (method==='CreateUser'||method==='SetUser') {
      const fields=['HubName_str','Name_str','GroupName_str','Realname_utf','Note_utf','ExpireTime_dt','AuthType_u32','Auth_Password_str','UsePolicy_bool'];
      if(!validName(params.HubName_str)||!validName(params.Name_str)||params.Name_str==='*'||params.AuthType_u32!==1||typeof params.Auth_Password_str!=='string'||params.Auth_Password_str.length<10||params.Auth_Password_str.length>255||keys.some(k=>!fields.includes(k)&&!/^policy:[A-Za-z0-9]+_(bool|u32)$/.test(k)))throw new RpcError('unsupported');
    } else if(keys.length!==0)throw new RpcError('unsupported');
    const id = randomUUID();
    const payload = JSON.stringify({jsonrpc: '2.0', id, method, params});
    return new Promise((resolve, reject) => {
      const request = https.request({host: this.config.host, port: this.config.port, servername: this.config.servername,
        method: 'POST', path: '/api/', agent: this.agent, rejectUnauthorized: true,
        headers: {'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(payload), 'X-VPNADMIN-HUBNAME':'', 'X-VPNADMIN-PASSWORD':this.config.password}}, response => {
        let size = 0; const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 2_000_000) request.destroy(new RpcError('invalid_response')); else chunks.push(chunk); });
        response.on('error', () => reject(new RpcError('unavailable')));
        response.on('end', () => {
          if (response.statusCode === 401 || response.statusCode === 403) return reject(new RpcError('authentication'));
          if (response.statusCode !== 200) return reject(new RpcError('unavailable'));
          try {
            const data = object(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            if (data.jsonrpc !== '2.0' || data.id !== id) throw new RpcError('invalid_response');
            if (data.error) { const err = object(data.error); throw new RpcError('unsupported', typeof err.code === 'number' ? err.code : undefined); }
            resolve(object(data.result));
          } catch (error) { reject(error instanceof RpcError ? error : new RpcError('invalid_response')); }
        });
      });
      const timer = setTimeout(() => request.destroy(new RpcError('timeout')), this.config.timeoutMs ?? 5000);
      request.on('close', () => clearTimeout(timer));
      request.on('error', error => {
        const code = (error as NodeJS.ErrnoException).code ?? '';
        reject(error instanceof RpcError ? error : new RpcError(/CERT|TLS|SSL/.test(code) ? 'tls' : 'unavailable'));
      });
      request.end(payload);
    });
  }
}
