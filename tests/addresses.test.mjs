import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Dashboard} from '../dist/backend/softether/dashboard.js';
function rpc(fail=false){return {call:async(method,p)=>{
 switch(method){
 case 'GetServerInfo':return{ServerVersionString_str:'fixture'};
 case 'EnumHub':return{HubList:['A','B'].map(HubName_str=>({HubName_str,Online_bool:true}))};
 case 'EnumListener':return{ListenerList:[]};
 case 'GetHubStatus':return{SecureNATEnabled_bool:p.HubName_str==='A'};
 case 'EnumSession':return{SessionList:[{Name_str:'same-session-name',Username_str:'fixture-user',ClientIP_ip:'192.0.2.10'}]};
 case 'EnumIPTable':if(fail)throw Error('private error');return{IpTable:[{SessionName_str:'same-session-name',IpAddress_ip:p.HubName_str==='A'?'192.0.2.20':'192.0.2.30',Secret:'must-not-leak'}]};
 case 'EnumDHCP':assert.equal(p.HubName_str,'A');return{DhcpTable:[{IpAddress_ip:'192.0.2.20',Hostname_str:'fixture-device',ExpireTime_dt:'2030-01-01T00:00:00Z',Secret:'must-not-leak'}]};
 default:return{};
 }
}};}
test('VPN addresses are matched by hub and session, separate from source IP; lease fields are projected',async()=>{const d=await new Dashboard(rpc()).get();assert.deepEqual(d.sessions.map(s=>s.vpnIps),[['192.0.2.20'],['192.0.2.30']]);assert.equal(d.sessions[0].sourceIp,'192.0.2.10');assert.deepEqual(d.leases,[{hub:'A',ip:'192.0.2.20',hostname:'fixture-device',expiresAt:'2030-01-01T00:00:00Z'}]);assert.ok(!JSON.stringify(d).includes('must-not-leak'));});
test('unavailable IP table is not shown as an empty successful lookup',async()=>{const d=await new Dashboard(rpc(true)).get();assert.equal(d.sessions[0].vpnIps,null);assert.ok(d.warnings.some(w=>w.includes('EnumIPTable')));assert.equal(d.leases.length,1);assert.ok(!JSON.stringify(d).includes('private error'));});
