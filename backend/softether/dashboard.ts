import { RpcError, object, type Method, type Reader, type RecordValue as R } from './client.js';
const str = (r:R,k:string):string|null => typeof r[k] === 'string' ? (r[k] as string).slice(0,512) : null;
const num = (r:R,k:string):number|null => typeof r[k] === 'number' && Number.isSafeInteger(r[k]) && (r[k] as number)>=0 ? r[k] as number : null;
const bool = (r:R,k:string):boolean|null => typeof r[k] === 'boolean' ? r[k] as boolean : null;
const rows = (r:R,k:string):R[] => { if (!Array.isArray(r[k])) throw new RpcError('invalid_response'); return (r[k] as unknown[]).slice(0,200).map(object); };
const total = (r:R,p:string):number|null => { const a=num(r,p+'.BroadcastBytes_u64'),b=num(r,p+'.UnicastBytes_u64');return a!==null && b!==null && Number.isSafeInteger(a+b) ? a+b:null; };
export class Dashboard {
  private cached?: {time:number; value:Awaited<ReturnType<Dashboard['collect']>>};
  private pending?: ReturnType<Dashboard['collect']>;
  constructor(private rpc: Reader, private audit:(event:string,detail?:string)=>void = ()=>{}) {}
  async get() {
    if (this.cached && Date.now()-this.cached.time < 15000) return this.cached.value;
    if (!this.pending) this.pending=this.collect().then(value => {this.cached={time:Date.now(),value};return value;}).finally(()=>{this.pending=undefined;});
    return this.pending;
  }
  private async collect() {
    const warnings:string[]=[];
    const deadline=Date.now()+15000;
    const fetch = async (method:Method,params?:R):Promise<R> => {
      try { if(Date.now()>=deadline)throw new RpcError('timeout'); return await this.rpc.call(method,params); }
      catch(error) { const kind=error instanceof RpcError ? error.kind:'unavailable';this.audit('rpc_failure',`${method}:${kind}`); warnings.push(`${method}: ${kind}`);return {}; }
    };
    const info=await fetch('GetServerInfo');
    if (!str(info,'ServerVersionString_str')) {
      this.audit('connectivity','unavailable');
      return {observedAt:new Date().toISOString(),online:false,warnings,server:null,stats:null,hubs:[],sessions:[],leases:[],listeners:[],protocols:null};
    }
    const status=await fetch('GetServerStatus');
    const hubData=await fetch('EnumHub');
    const listenerData=await fetch('EnumListener');
    const ipsec=await fetch('GetIPsecServices');
    const openvpn=await fetch('GetOpenVpnSstpConfig');
    const safeRows=(r:R,k:string) => {try{if(Array.isArray(r[k])&&(r[k] as unknown[]).length>200)warnings.push(`${k}: showing the first 200 entries.`);return rows(r,k);}catch{warnings.push(`${k}: unavailable or invalid response`);return [];}};
    const hubs=safeRows(hubData,'HubList').map(h=>({name:str(h,'HubName_str'),online:bool(h,'Online_bool'),users:num(h,'NumUsers_u32'),sessions:num(h,'NumSessions_u32'),received:bool(h,'IsTrafficFilled_bool') ? total(h,'Ex.Recv'):null,sent:bool(h,'IsTrafficFilled_bool') ? total(h,'Ex.Send'):null,secureNat:null as boolean|null}));
    const sessions:Array<{hub:string;name:string|null;username:string|null;sourceIp:string|null;vpnIps:string[]|null;createdAt:string|null;bytes:number|null}>=[];
    const leases:Array<{hub:string;ip:string|null;hostname:string|null;expiresAt:string|null}>=[];
    // Bounded work: do not let a large installation create unlimited RPC fan-out.
    if(hubs.length>20) warnings.push('Hub details limited to the first 20 hubs.');
    for(const hub of hubs.slice(0,20)) {
      if (!hub.name || hub.online!==true) continue;
      const details=await fetch('GetHubStatus',{HubName_str:hub.name});
      hub.secureNat=bool(details,'SecureNATEnabled_bool');
      const ipData=await fetch('EnumIPTable',{HubName_str:hub.name});
      const ipRows=safeRows(ipData,'IpTable');
      const addresses=new Map<string,Set<string>>();
      for(const row of ipRows){const session=str(row,'SessionName_str'),ip=str(row,'IpAddress_ip');if(session&&ip){const set=addresses.get(session)??new Set<string>();set.add(ip);addresses.set(session,set);}}
      if(hub.secureNat===true){
        for(const row of safeRows(await fetch('EnumDHCP',{HubName_str:hub.name}),'DhcpTable'))leases.push({hub:hub.name,ip:str(row,'IpAddress_ip'),hostname:str(row,'Hostname_str'),expiresAt:str(row,'ExpireTime_dt')});
      }
      for (const row of safeRows(await fetch('EnumSession',{HubName_str:hub.name}),'SessionList')) sessions.push({hub:hub.name,name:str(row,'Name_str'),username:str(row,'Username_str'),sourceIp:str(row,'ClientIP_ip'),vpnIps:Array.isArray(ipData.IpTable)?[...(addresses.get(str(row,'Name_str')??'')??[])]:null,createdAt:str(row,'CreatedTime_dt'),bytes:num(row,'PacketSize_u64')});
    }
    const current=Date.parse(str(status,'CurrentTime_dt')??''),start=Date.parse(str(status,'StartTime_dt')??'');
    this.audit('connectivity',warnings.length?'partial':'online');
    return {observedAt:new Date().toISOString(),online:true,warnings,
      server:{product:str(info,'ServerProductName_str'),version:str(info,'ServerVersionString_str'),host:str(info,'ServerHostName_str'),type:num(info,'ServerType_u32'),uptimeSeconds:Number.isFinite(current)&&Number.isFinite(start)&&current>=start?Math.floor((current-start)/1000):null},
      stats:{hubs:num(status,'NumHubTotal_u32'),users:num(status,'NumUsers_u32'),sessions:num(status,'NumSessionsTotal_u32'),connections:num(status,'NumTcpConnections_u32'),received:total(status,'Recv'),sent:total(status,'Send')},hubs,sessions,leases,
      listeners:safeRows(listenerData,'ListenerList').map(l=>({port:num(l,'Ports_u32'),enabled:bool(l,'Enables_bool'),error:bool(l,'Errors_bool')})),
      protocols:{l2tpIpsec:bool(ipsec,'L2TP_IPsec_bool'),rawL2tp:bool(ipsec,'L2TP_Raw_bool'),openvpn:bool(openvpn,'EnableOpenVPN_bool'),openvpnPorts:str(openvpn,'OpenVPNPortList_str'),sstp:bool(openvpn,'EnableSSTP_bool')}};
  }
}
