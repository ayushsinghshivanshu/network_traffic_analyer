"""Builds a single self-contained HTML dashboard (no internet, no libraries needed)."""
import json

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Analysis Report</title>
<style>
:root{--bg:#0b1220;--panel:#121b30;--line:#22304d;--ink:#e6ecf8;--muted:#92a0bd;--accent:#4f8cff;
--critical:#ff5c5c;--high:#ff8a3d;--medium:#f5b83d;--low:#5aa2ff;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f3f6fb;--panel:#fff;--line:#d9e1ef;--ink:#13203b;--muted:#5a6b86;--accent:#2850e8;
--critical:#d92d2d;--high:#d9631a;--medium:#b8860b;--low:#2b6fd6;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:center;padding:24px clamp(16px,4vw,40px);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:1.5rem}h2{margin:0 0 14px;font-size:1rem}p{margin:4px 0 0;color:var(--muted)}
main{padding:24px clamp(16px,4vw,40px);max-width:1280px;margin:0 auto}
.risk{text-align:right}.risk b{display:block;font-size:2.4rem;line-height:1}.risk span{color:var(--muted);font-size:.85rem}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi,.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.kpi b{display:block;font-size:1.5rem}.kpi span{color:var(--muted);font-size:.82rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-top:16px}.wide{grid-column:1/-1}
.head{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:center;margin-bottom:6px}.head h2{margin:0}
button{font:inherit;font-size:.82rem;padding:4px 12px;border-radius:999px;border:1px solid var(--line);background:none;color:var(--ink);cursor:pointer}
button[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:9px 10px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;border-top:0}td:last-child{white-space:nowrap}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.75rem;font-weight:600;color:#fff;text-transform:uppercase}
.fix{color:var(--muted);font-size:.82rem;margin-top:2px}a{color:var(--accent)}.empty{color:var(--muted);padding:12px 0}
svg{width:100%;height:auto;display:block}.grid line.g{stroke:var(--line)}text{fill:var(--muted);font-size:10px}
.bar{display:grid;grid-template-columns:130px 1fr 70px;gap:8px;align-items:center;margin:7px 0;font-size:.85rem}
.bar i{display:block;height:10px;border-radius:5px;background:var(--accent)}.bar span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hist{display:flex;align-items:flex-end;gap:4px;height:150px}.hist div{flex:1;background:var(--accent);border-radius:3px 3px 0 0;min-height:2px}
.lab{display:flex;gap:4px}.lab span{flex:1;text-align:center;font-size:.68rem;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:8px;font-size:.82rem}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
footer{padding:20px clamp(16px,4vw,40px);color:var(--muted);font-size:.82rem;text-align:center}
</style></head><body>
<header><div><h1>Network Traffic Analysis</h1><p id="meta"></p></div><div class="risk" id="risk"></div></header>
<main>
<section class="kpis" id="kpis"></section>
<section class="card"><div class="head"><h2>Security findings</h2><div id="filters"></div></div><div class="scroll" id="alerts"></div></section>
<section class="grid">
<div class="card wide"><h2>Packets per second <span style="font-weight:400;color:var(--muted)">(dashed lines mark findings)</span></h2><div id="tl"></div></div>
<div class="card"><h2>Application share</h2><div id="pie"></div></div>
<div class="card"><h2>Top talkers (bytes sent)</h2><div id="talk"></div></div>
<div class="card"><h2>Packet size distribution</h2><div id="hist"></div></div>
<div class="card wide"><h2>Top conversations</h2><div class="scroll" id="conv"></div></div>
</section></main>
<footer>Passive analysis of a saved capture. Only analyze traffic you own or are authorized to inspect.</footer>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtB=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB';
const COL=['#4f8cff','#22c3a6','#f5b83d','#ff5c5c','#a78bfa','#f472b6','#94a3b8','#84cc16','#fb923c','#38bdf8'];
const SEV=['critical','high','medium','low'];
// Capture data (DNS names, IPs) is untrusted: every value goes through esc() before it reaches innerHTML.
$('#meta').textContent=D.file+' | generated '+D.generated;
$('#risk').innerHTML='<b style="color:var(--'+(D.risk.label==='Critical'?'critical':D.risk.label==='Elevated'?'medium':'low')+')">'+D.risk.score+'/100</b><span>Risk: '+esc(D.risk.label)+'</span>';
$('#kpis').innerHTML=[[D.packets.toLocaleString(),'Packets'],[fmtB(D.bytes),'Total data'],[D.duration+' s','Duration'],
 [D.pps.toFixed(1),'Packets / s'],[D.kbps.toFixed(1),'kbps'],[D.alerts.length,'Findings']].map(k=>'<div class="kpi"><b>'+esc(k[0])+'</b><span>'+k[1]+'</span></div>').join('');

let sel='all';
function techUrl(t){return 'https://attack.mitre.org/techniques/'+t.replace('.','/')+'/'}
function alerts(){
  const rows=D.alerts.filter(a=>sel==='all'||a.sev===sel);
  $('#alerts').innerHTML=rows.length?'<table><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Details</th><th>ATT&amp;CK</th><th>At</th></tr>'+
   rows.map(a=>'<tr><td><span class="pill" style="background:var(--'+a.sev+')">'+a.sev+'</span></td><td>'+esc(a.type)+'</td><td>'+esc(a.src)+
   '</td><td>'+esc(a.detail)+'<div class="fix">Fix: '+esc(a.fix)+'</div></td><td><a href="'+techUrl(esc(a.mitre))+'" target="_blank" rel="noopener">'+esc(a.mitre)+
   '</a></td><td>'+(a.t==null?'-':a.t+' s')+'</td></tr>').join('')+'</table>':'<div class="empty">No findings in this category.</div>';
}
function filters(){
  const counts={all:D.alerts.length};SEV.forEach(s=>counts[s]=D.alerts.filter(a=>a.sev===s).length);
  $('#filters').innerHTML=['all',...SEV].map(s=>'<button data-s="'+s+'" aria-pressed="'+(s===sel)+'">'+s+' ('+counts[s]+')</button>').join(' ');
  document.querySelectorAll('#filters button').forEach(b=>b.onclick=()=>{sel=b.dataset.s;filters();alerts()});
}
function timeline(){
  const W=700,H=230,L=42,R=10,T=10,B=26,v=D.timeline.map(x=>x[0]),n=v.length,mx=Math.max(1,...v);
  const x=i=>L+(n<2?0:Math.min(i,n-1)*(W-L-R)/(n-1)),y=a=>T+(H-T-B)*(1-a/mx);
  let s='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="Packets per second over time">';
  for(let g=0;g<=4;g++){const a=mx*g/4;s+='<line class="g" x1="'+L+'" x2="'+(W-R)+'" y1="'+y(a)+'" y2="'+y(a)+'"/><text x="'+(L-6)+'" y="'+(y(a)+3)+'" text-anchor="end">'+Math.round(a)+'</text>'}
  s+='<polyline fill="none" stroke="var(--accent)" stroke-width="2" points="'+v.map((a,i)=>x(i).toFixed(1)+','+y(a).toFixed(1)).join(' ')+'"/>';
  D.alerts.forEach(a=>{if(a.t!=null){const p=x(a.t).toFixed(1);s+='<line x1="'+p+'" x2="'+p+'" y1="'+T+'" y2="'+(H-B)+'" stroke="var(--'+a.sev+')" stroke-dasharray="4 3"><title>'+esc(a.type)+'</title></line>'}});
  [0,.5,1].forEach(f=>{s+='<text x="'+(L+f*(W-L-R))+'" y="'+(H-8)+'" text-anchor="'+(f===0?'start':f===1?'end':'middle')+'">'+Math.round(f*(n-1))+' s</text>'});
  $('#tl').innerHTML=s+'</svg>';
}
function pie(){
  const e=Object.entries(D.apps),tot=e.reduce((a,b)=>a+b[1],0);let a0=-Math.PI/2,s='<svg viewBox="0 0 200 200" style="max-width:240px;margin:auto" role="img" aria-label="Application share">';
  const p=(r,a)=>(100+r*Math.cos(a)).toFixed(2)+' '+(100+r*Math.sin(a)).toFixed(2);
  e.forEach((kv,i)=>{const a1=a0+kv[1]/tot*2*Math.PI-1e-4,lg=a1-a0>Math.PI?1:0;
    s+='<path fill="'+COL[i%COL.length]+'" d="M'+p(85,a0)+' A85 85 0 '+lg+' 1 '+p(85,a1)+' L'+p(52,a1)+' A52 52 0 '+lg+' 0 '+p(52,a0)+'Z"><title>'+esc(kv[0])+'</title></path>';a0=a1+1e-4});
  $('#pie').innerHTML=s+'</svg><div class="legend">'+e.map((kv,i)=>'<span><i style="background:'+COL[i%COL.length]+'"></i>'+esc(kv[0])+' '+(kv[1]/tot<.005?'<1':(kv[1]/tot*100).toFixed(0))+'%</span>').join('')+'</div>';
}
function bars(){
  const mx=Math.max(1,...D.talkers.map(t=>t[1]));
  $('#talk').innerHTML=D.talkers.map(t=>'<div class="bar"><span>'+esc(t[0])+'</span><i style="width:'+(t[1]/mx*100).toFixed(1)+'%"></i><span>'+fmtB(t[1])+'</span></div>').join('');
  const hm=Math.max(1,...D.hist.map(h=>h[1]));
  $('#hist').innerHTML='<div class="hist">'+D.hist.map(h=>'<div title="'+esc(h[0])+' B: '+h[1]+' packets" style="height:'+(h[1]/hm*100).toFixed(1)+'%"></div>').join('')+'</div><div class="lab">'+D.hist.map((h,i)=>'<span>'+(i%3===0?esc(h[0]):'')+'</span>').join('')+'</div>';
  $('#conv').innerHTML='<table><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th></tr>'+D.convs.map(c=>'<tr><td>'+esc(c[0])+'</td><td>'+esc(c[1])+'</td><td>'+esc(c[2])+'</td><td>'+fmtB(c[3])+'</td></tr>').join('')+'</table>';
}
filters();alerts();timeline();pie();bars();
</script></body></html>
"""


def build_dashboard(stats, path):
    data = json.dumps(stats).replace("</", "<\\/")   # keep capture data from closing the script tag
    with open(path, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.replace("__DATA__", data))
