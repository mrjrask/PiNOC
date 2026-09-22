const PiNOC=(()=>{const csrf=()=>document.body.dataset.csrf||'',mutate=(url,options={})=>fetch(url,{...options,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf(),...(options.headers||{})}});const esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct=v=>v==null?'—':`${Number(v).toFixed(1)}%`;const temperature=(value,unit='c')=>{let n=Number(value);if(!Number.isFinite(n))return '—';let c=unit==='f'?(n-32)*5/9:n,f=c*9/5+32;return `${f.toFixed(1)} °F / ${c.toFixed(1)} °C`};const temp=d=>temperature(d.cpu?.temperature_c);const bytes=v=>{if(v==null||v==='')return '—';let n=Number(v);if(!Number.isFinite(n))return '—';let sign=n<0?'-':'',size=Math.abs(n),units=['B','KiB','MiB','GiB','TiB','PiB'],i=0;while(size>=1024&&i<units.length-1){size/=1024;i++}let digits=i===0?0:size>=100?0:size>=10?1:2;return `${sign}${size.toFixed(digits)} ${units[i]}`};const duration=s=>{if(s==null)return '—';let d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return `${d?d+'d ':''}${h}h ${m}m`};const disk=d=>d.storage?.length?Math.max(...d.storage.map(x=>Number(x.percent)||0)):null;
const setConnection=(status,label)=>{let indicator=document.querySelector('#connection');if(!indicator)return;indicator.classList.toggle('online',status==='online');indicator.classList.toggle('offline',status==='offline');let text=indicator.querySelector('span');if(text)text.textContent=label};
// Periodically re-invoke an existing page render function (dashboard(),
// alerts(), events(), device()) as-is, so live fleet telemetry, alerts, and
// job status appear without a manual refresh. Paused while the tab is
// hidden (Page Visibility API) so a backgrounded tab doesn't keep polling.
function startAutoRefresh(fn,intervalMs=45000){
  let timer=null;
  const tick=()=>{if(document.hidden)return;Promise.resolve().then(fn).catch(()=>{})};
  const stop=()=>{if(timer){clearInterval(timer);timer=null}};
  const restart=()=>{stop();if(!document.hidden)timer=setInterval(tick,intervalMs)};
  document.addEventListener('visibilitychange',restart);
  restart();
  return stop;
}
async function connection(){try{let response=await fetch('/api/status');if(!response.ok)throw new Error('status unavailable');setConnection('online','Live')}catch(error){setConnection('offline','Offline')}}
const humanValue=(key,value)=>{if(value==null||value==='')return '—';let name=String(key).toLowerCase();if(Array.isArray(value))return value.join(', ');if(typeof value==='object')return JSON.stringify(value);if(name==='celsius'||name.endsWith('_c')||name.includes('temperature_c')||name.includes('temp_c'))return temperature(value);if(name==='fahrenheit'||name.endsWith('_f')||name.includes('temperature_f')||name.includes('temp_f'))return temperature(value,'f');if(name.includes('bytes')||name.endsWith('_size')||name==='ram'||['rx_rate','tx_rate'].includes(name))return `${bytes(value)}${name.includes('rate')||name.endsWith('_bps')?' / s':''}`;if(name.includes('percent')||name.endsWith('_pct'))return pct(value);if(name.includes('uptime')&&name.includes('seconds'))return duration(value);return value};
function card(d){let services=(d.services||[]).map(x=>x.name).join(' '),search=[d.friendly_name,d.hostname,d.ip,...d.roles,...d.tags,services].join(' ').toLowerCase();return `<a class="device-card" href="/devices/${encodeURIComponent(d.id)}" data-temperature="${d.cpu?.temperature_c??-1}" data-cpu="${d.cpu?.utilization_percent??-1}" data-memory="${d.memory?.percent??-1}" data-disk="${disk(d)??-1}" data-uptime="${d.uptime_seconds??-1}" data-name="${esc(d.friendly_name.toLowerCase())}" data-health="${esc(d.health)}" data-roles="${esc(d.roles.join(' '))}" data-search="${esc(search)}"><div class="device-head"><span class="dot ${esc(d.health)}"></span><div><h3>${esc(d.friendly_name)}</h3><small>${esc(d.hostname)}</small></div><strong>${esc(d.stale?'stale':d.health)}</strong></div><dl><dt>Roles</dt><dd>${esc(d.roles.join(', '))}</dd><dt>IP</dt><dd>${esc(d.network?.ip||d.ip)}</dd><dt>Temperature</dt><dd>${temp(d)}</dd><dt>CPU</dt><dd>${pct(d.cpu?.utilization_percent)}</dd><dt>Memory</dt><dd>${pct(d.memory?.percent)}</dd><dt>Disk</dt><dd>${pct(disk(d))}</dd><dt>Uptime</dt><dd>${duration(d.uptime_seconds)}</dd><dt>Services</dt><dd>${(d.services||[]).filter(x=>!['running','activating'].includes(x.state)).length} failed</dd><dt>Last seen</dt><dd>${esc(d.last_seen)}</dd></dl></a>`}
async function dashboard(){
  const updated=document.querySelector('#dashboard-updated');
  try{
    let [or,dr]=await Promise.all([fetch('/api/overview'),fetch('/api/devices')]);
    if(!or.ok||!dr.ok)throw new Error('Unable to load fleet data');
    let overview=await or.json(),data=await dr.json(),s=overview.summary,devices=data.devices||[];
    setConnection('online','Live');
    let names=['devices','online','healthy','warning','degraded','critical','offline','failed_services'];
    document.querySelector('#summary').innerHTML=names.map(n=>`<article data-kind="${esc(n)}"><strong>${esc(s[n]??0)}</strong><span>${esc(n.replaceAll('_',' '))}</span></article>`).join('');
    if(updated)updated.textContent=`Updated ${localTime(overview.generated_at)}`;
    let f=overview.aggregates||{},bps=v=>v==null?'—':v>=1e6?`${(v/1e6).toFixed(1)} MB/s`:v>=1e3?`${Math.round(v/1e3)} KB/s`:`${Math.round(v)} B/s`;
    let items=[
      [f.storage_used_bytes!=null&&f.storage_total_bytes?`${bytes(f.storage_used_bytes)} of ${bytes(f.storage_total_bytes)}`:null,'storage used',f.storage_forecast&&f.storage_forecast.estimated_days_remaining!=null?`≈${Math.round(f.storage_forecast.estimated_days_remaining)} days to full`:(f.storage_forecast&&f.storage_forecast.status!=='growing'?`trend ${f.storage_forecast.status}`:'')],
      [f.rx_rate_bps!=null||f.tx_rate_bps!=null?`${bps(f.rx_rate_bps)} ↓ · ${bps(f.tx_rate_bps)} ↑`:null,'network',''],
      [f.cpu_average_percent!=null?pct(f.cpu_average_percent):null,'avg cpu',''],
      [f.memory_average_percent!=null?pct(f.memory_average_percent):null,'avg memory',''],
      [f.cpu_max_temperature_c!=null?temperature(f.cpu_max_temperature_c):null,'max temperature',''],
      [f.uptime_min_seconds!=null?`${duration(f.uptime_min_seconds)} – ${duration(f.uptime_max_seconds)}`:null,'uptime min – max','']
    ].filter(x=>x[0]!=null);
    let aggRoot=document.querySelector('#fleet-aggregates');
    aggRoot.hidden=!items.length;
    aggRoot.innerHTML=items.map(([v,label,sub])=>`<article><strong>${esc(v)}</strong><span>${esc(label)}</span>${sub?`<small>${esc(sub)}</small>`:''}</article>`).join('');
    let spark=f.sparkline||[],trend=document.querySelector('#fleet-trend');
    trend.hidden=spark.length<2;
    if(!trend.hidden&&spark.length)plot(document.querySelector('#fleet-spark'),spark,['avg_cpu','avg_temp','avg_memory'],['#62d3ff','#edc84b','#ff9850']);
    let active=overview.active_alerts||[],alertRoot=document.querySelector('#alert-summary');
    alertRoot.innerHTML=`<div class="panel-heading"><div><p class="eyebrow">Attention</p><h2>Active alerts</h2></div><a href="/alerts">View all</a></div>${active.length?active.slice(0,3).map(a=>`<p><strong class="severity-${esc(a.severity)}">${esc(a.severity)}</strong> · ${esc(a.device_id)} — ${esc(a.message)}</p>`).join(''):'<p class="muted">No unresolved conditions. Your fleet is clear.</p>'}`;
    let valid=(key,fn,format)=>{let x=devices.filter(d=>Number.isFinite(fn(d))).sort((a,b)=>fn(b)-fn(a))[0];return x?`<article><span>${key}</span><strong>${esc(x.friendly_name)}</strong><small>${esc(format(fn(x)))}</small></article>`:''};
    document.querySelector('#highlights').innerHTML=valid('Hottest',d=>d.cpu?.temperature_c??-Infinity,temperature)+valid('Highest CPU',d=>d.cpu?.utilization_percent??-Infinity,pct)+valid('Highest memory',d=>d.memory?.percent??-Infinity,pct)+valid('Highest disk',d=>disk(d)??-Infinity,pct)+valid('Longest uptime',d=>d.uptime_seconds??-Infinity,duration)||'<p class="muted">Highlights appear after telemetry arrives.</p>';
    let root=document.querySelector('#devices');root.innerHTML=devices.map(card).join('')||'<p class="muted">No devices collected yet. Check configuration and collector status.</p>';
    let priorities={critical:0,offline:1,degraded:2,warning:3,healthy:4},sort=document.querySelector('#sort');
    const sortCards=()=>{let key=sort.value,cards=[...root.querySelectorAll('.device-card')];cards.sort((a,b)=>key==='health'?(priorities[a.dataset.health]??9)-(priorities[b.dataset.health]??9):['temperature','cpu','memory','disk','uptime'].includes(key)?Number(b.dataset[key])-Number(a.dataset[key]):String(a.dataset[key]).localeCompare(String(b.dataset[key]))).forEach(x=>root.appendChild(x))};sort.onchange=sortCards;sortCards();
    let roles=[...new Set(devices.flatMap(d=>d.roles||[]))].sort(),filters=['all','healthy','warning','degraded','critical','offline',...roles];document.querySelector('#filters').innerHTML=filters.map((f,i)=>`<button class="filter ${i?'':'selected'}" data-filter="${esc(f)}" aria-pressed="${i?'false':'true'}">${esc(f.replaceAll('_',' '))}</button>`).join('');
    let filter='all',search='';const apply=()=>{let visible=0;root.querySelectorAll('.device-card').forEach(x=>{x.hidden=!(x.dataset.search.includes(search)&&(filter==='all'||x.dataset.health===filter||x.dataset.roles.split(' ').includes(filter)));if(!x.hidden)visible++});let count=document.querySelector('#visible-count');if(count)count.textContent=`${visible} of ${devices.length}`};
    document.querySelector('#search').oninput=e=>{search=e.target.value.trim().toLowerCase();apply()};document.querySelector('#filters').onclick=e=>{if(!e.target.dataset.filter)return;filter=e.target.dataset.filter;document.querySelectorAll('.filter').forEach(x=>{let selected=x===e.target;x.classList.toggle('selected',selected);x.setAttribute('aria-pressed',selected)});apply()};apply();
  }catch(error){setConnection('offline','Offline');document.querySelector('#devices').innerHTML=`<p class="severity-critical">${esc(error.message)}. Retry or check <a href="/health">service health</a>.</p>`;if(updated)updated.textContent='Update failed'}
  let refresh=document.querySelector('#refresh-dashboard');if(refresh)refresh.onclick=()=>dashboard();
}
const section=(title,obj)=>`<section class="panel"><h2>${title}</h2><dl class="details">${Object.entries(obj||{}).map(([k,v])=>`<dt>${esc(k.replaceAll('_',' '))}</dt><dd>${esc(humanValue(k,v))}</dd>`).join('')}</dl></section>`;const media=d=>{if(!d.media?.length)return '';let rows=d.media.map(x=>{let unknown=x.io_error_status==='unknown',status=unknown?'unknown — kernel logs unavailable':x.media_errors?`⚠ ${x.io_errors} I/O error${x.io_errors===1?'':'s'} logged`:'none';return `<tr class="${x.media_errors?'critical-row':''}"><td>${esc(x.device)}</td><td>${esc((x.mount_points||[]).join(', '))}</td><td>${bytes(x.written_bytes)}</td><td>${bytes(x.read_bytes)}</td><td>${status}</td>${x.media_errors?`<td>${esc(x.last_error||'')}</td>`:'<td>—</td>'}</tr>`}).join('');return `<section class="panel"><h2>Storage media</h2><p class="muted">Wear and I/O-error status for block-backed storage (SD cards, eMMC, disks). Absent when the collector cannot read /proc/diskstats.</p><div class="table-wrap"><table><thead><tr><th>Device</th><th>Mounts</th><th>Written since boot</th><th>Read since boot</th><th>I/O errors</th><th>Last kernel error</th></tr></thead><tbody>${rows||'<tr><td colspan="6">No media telemetry</td></tr>'}</tbody></table></div></section>`};const services=d=>`<section class="panel"><h2>Services</h2><div class="table-wrap"><table><thead><tr><th>Service</th><th>State</th><th>PID</th><th>Restarts</th><th>Memory</th></tr></thead><tbody>${(d.services||[]).map(x=>`<tr class="${x.critical?'critical-row':''}"><td>${esc(x.name)}${x.critical?' ⚠':''}</td><td>${esc(x.state)}</td><td>${esc(x.main_pid)}</td><td>${esc(x.restart_count)}</td><td>${esc(bytes(x.memory_bytes))}</td></tr>`).join('')||'<tr><td colspan="5">No monitored services</td></tr>'}</tbody></table></div></section>`;
async function device(id){let r=await fetch(`/api/devices/${encodeURIComponent(id)}`),d=await r.json(),root=document.querySelector('#device');if(!r.ok){root.innerHTML='<h1>Device not found</h1>';return}let cockpit=d.cockpit_url?`<a class="action" href="${esc(d.cockpit_url)}" target="_blank" rel="noopener">Open Cockpit</a>`:'';root.innerHTML=`<div class="title-row"><span class="dot ${esc(d.health)}"></span><div><h1>${esc(d.friendly_name)}</h1><p>${esc(d.hostname)} · ${esc(d.stale?'stale':d.health)}</p></div>${cockpit}</div><div class="detail-grid">${section('Overview',{address:d.address,ip:d.network?.ip||d.ip,uptime:duration(d.uptime_seconds),last_seen:d.last_seen,last_attempt:d.last_collection_attempt,health_reasons:d.health_reasons})}${section('Hardware',{model:d.model,architecture:d.architecture,os:d.os,os_version:d.os_version,kernel:d.kernel,...d.hardware})}${section('CPU & Temperature',d.cpu)}${section('Memory',Object.fromEntries(Object.entries(d.memory||{}).map(([k,v])=>[k,['total','used','available','swap_total','swap_used'].includes(k)?bytes(v):v])))}${section('Network',d.network)}</div>${section('Storage',Object.fromEntries((d.storage||[]).map(x=>[x.mount_point||x.path,`${pct(x.percent)} used · ${bytes(x.used)} of ${bytes(x.total)} · ${bytes(x.available)} free · ${x.filesystem||'unknown filesystem'}${x.read_only?' · read-only':''}`])))}${media(d)}${services(d)}${Object.entries(d.integrations||{}).map(([name,value])=>section(`Integration · ${name}`,{health:value.health,available:value.available,last_success:value.last_success,last_attempt:value.last_attempt,data_source:value.data_source,error:value.error,...(value.data||{})})).join('')}<div class="detail-grid">${section('Collector Status',d.collector_status)}${section('Roles & Tags',{roles:d.roles,tags:d.tags,collection_method:d.collection_method})}</div>${d.notes?section('Notes',{notes:d.notes}):''}`}
const localTime=v=>v?new Date(v).toLocaleString():'—';
const table=(headers,rows)=>`<div class="table-wrap"><table><thead><tr>${headers.map(x=>`<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.join('')||`<tr><td colspan="${headers.length}">No data</td></tr>`}</tbody></table></div>`;
// Escape-first mini markdown for runbook bodies (## h4, - li, **bold**, [t](http|relative)).
  const runbookMd=md=>esc(md).split(/\n{2,}/).map(block=>{let html='',list=null;for(const line of block.split('\n')){if(/^##\s/.test(line)){if(list){html+='</ul>';list=null}html+=`<h4>${line.replace(/^##\s*/,'')}</h4>`}else if(/^[-*]\s/.test(line)){if(!list){html+='<ul>';list=true}html+=`<li>${line.replace(/^[-*]\s*/,'')}</li>`}else{if(list){html+='</ul>';list=null}if(line)html+=`<p>${line}</p>`}}if(list)html+='</ul>';return html.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/\[([^\]]+)\]\(((?:https?:\/\/|\/(?!\/))[^\s)]+)\)/g,(_,t,u)=>`<a href="${u}" target="_blank" rel="noopener">${t}</a>`)}).join('');
// Mirrors the safe-action registry confirmation levels: simple actions queue on click,
// strong actions (reboot, shutdown, service stop, disk rescues) require confirmation first.
const runbookGate=(action,deviceId,resource)=>action==='device.reboot'?{type:'confirm',text:`Reboot ${deviceId}?`}:action==='device.shutdown'?{type:'prompt',match:deviceId,text:`Type ${deviceId} to confirm shutdown`}:action==='service.stop'?{type:'prompt',match:resource,text:`Type ${resource} to confirm stopping it on ${deviceId}`}:action==='apt.clean'?{type:'confirm',text:`Clean the apt cache on ${deviceId}?`}:action==='apt.autoremove'?{type:'confirm',text:`Preview package autoremove on ${deviceId}? (no changes are made)`}:action==='logs.truncate'?{type:'prompt',match:'truncate',text:`Type \u0022truncate\u0022 to confirm truncating logs on ${deviceId}`}:action==='journal.vacuum'?{type:'prompt',match:'vacuum',text:`Type \u0022vacuum\u0022 to confirm a journal vacuum on ${deviceId}`}:action==='cache.drop'?{type:'prompt',match:'drop',text:`Type \u0022drop\u0022 to confirm dropping page caches on ${deviceId}`}:null;
// One card per shared-cause cluster (same trigger class + Wi-Fi SSID, gateway,
// or IP subnet) instead of a row per member -- see pinoc/correlation.py.
async function loadClusters(){
  let root=document.querySelector('#alert-clusters');if(!root)return;
  let response=await fetch('/api/alert-clusters');if(!response.ok){root.innerHTML='';return}
  let [cd,dd]=await Promise.all([response.json(),fetch('/api/devices').then(r=>r.json()).catch(()=>({}))]);
  let names=Object.fromEntries((dd.devices||[]).map(d=>[d.id,d.friendly_name||d.hostname||d.id]));
  let clusters=cd.clusters||[];
  if(!clusters.length){root.innerHTML='';return}
  root.innerHTML=clusters.map(c=>{
    let members=c.members||[];
    let rows=members.map(m=>`<tr class="severity-${esc(m.severity)}"><td><a href="/devices/${encodeURIComponent(m.device_id)}">${esc(names[m.device_id]||m.device_id)}</a></td><td>${esc(m.alert_type)}</td><td>${esc(m.message)}</td><td>${m.resolved_at?'resolved':'active'}</td></tr>`);
    return `<section class="panel cluster-card sev-${esc(c.severity)}"><div class="cluster-head"><span class="dot ${esc(c.severity)}"></span><div><h3>${esc(c.context_label)}</h3><p class="muted">${c.open_member_count} of ${c.member_count} device${c.member_count===1?'':'s'} affected · ${esc(c.trigger_class)} correlation · opened ${localTime(c.opened_at)}${c.resolved_at?` · resolved ${localTime(c.resolved_at)}`:''}</p></div></div><details><summary>${members.length} member device${members.length===1?'':'s'} (expand)</summary>${table(['Device','Type','Message','State'],rows)}</details></section>`;
  }).join('');
}
async function alerts(){
  let state='active',filters=['active','acknowledged','muted','resolved','all'],root=document.querySelector('#alerts-table'),runbookPanel=document.querySelector('#alert-runbook'),lastAlerts=[];
  document.querySelector('#alert-filters').innerHTML=filters.map(x=>`<button class="filter ${x==='active'?'selected':''}" data-state="${x}">${x}</button>`).join('');
  loadClusters();
  const actionUrl=(a,action,target)=>{const id=encodeURIComponent(a.device_id||'');if(action==='device.refresh')return `/api/devices/${id}/refresh`;if(action==='device.reboot')return `/api/devices/${id}/reboot`;if(action==='device.shutdown')return `/api/devices/${id}/shutdown`;if(action.startsWith('service.'))return target?`/api/devices/${id}/services/${encodeURIComponent(target)}/${action.split('.')[1]}`:null;return `/api/devices/${id}/actions/${action.replace('.','-')}`};
  // Playbook self-healing status: last attempt, cooldown, attempts used, and
  // (for an "approve"-policy or otherwise non-auto action) a pending
  // Approve/Deny decision, reusing the same action queue and audit trail as
  // a manual runbook click -- see pinoc/remediation.py.
  const remediationStatus=r=>{
    if(!r)return '';
    const bits=[`${esc(r.policy)} policy`,`${esc(r.action)}${r.target?' '+esc(r.target):''}`,`attempt ${r.attempts}/${r.max_attempts}`];
    if(r.last_attempt_at)bits.push(`last run ${localTime(r.last_attempt_at)} (${esc(r.last_status||'unknown')})`);
    if(r.cooldown_until&&new Date(r.cooldown_until)>new Date())bits.push(`cooling down until ${localTime(r.cooldown_until)}`);
    if(r.approval_status==='denied')bits.push('denied');
    const decision=r.approval_status==='pending'?`<div class="actions"><button data-remediation-approve>Approve run</button> <button data-remediation-deny>Deny</button></div>`:'';
    return `<div class="remediation-status"><h3>Self-healing</h3><p class="muted">${bits.join(' · ')}</p>${decision}</div>`;
  };
  function showRunbook(a){
    const pb=a.playbook,panel=runbookPanel;
    if(!pb){panel.hidden=true;panel.innerHTML='';return}
    let resource='';try{resource=JSON.parse(a.metadata_json||'{}').resource||''}catch(_){}
    const buttons=(pb.actions||[]).map(action=>{if(action.startsWith('service.')&&!resource)return `<button disabled title="No service target recorded for this alert">${esc(action)}</button>`;return `<button data-runbook-action="${esc(action)}">${esc(action.split('.').join(' '))}</button>`}).join(' ');
    const links=(pb.links||[]).map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join(' ');
    panel.innerHTML=`<h2>Runbook · ${esc(pb.title)}</h2><p class="muted">${esc(a.message)}${resource?` · ${esc(resource)}`:''}</p><div class="runbook-body">${runbookMd(pb.markdown)}</div>${links?`<p>${links}</p>`:''}<p class="action-result"></p><div class="actions">${buttons}</div>${remediationStatus(a.remediation)}`;
    panel.hidden=false;panel.scrollIntoView({block:'nearest'});
    const actionBar=panel.querySelector('.actions');
    if(actionBar)actionBar.onclick=async e=>{
      const action=e.target?.dataset?.runbookAction;if(!action)return;
      const url=actionUrl(a,action,resource);if(!url)return;
      const gate=runbookGate(action,a.device_id,resource);
      if(gate){const answer=gate.type==='confirm'?confirm(gate.text):prompt(gate.text);if(gate.type==='confirm'?!answer:answer!==gate.match)return}
      const response=await mutate(url,{method:'POST',body:'{}'});
      const result=await response.json().catch(()=>({error:'unknown error'}));
      panel.querySelector('.action-result').textContent=response.ok?`Queued ${action}`:`${action} failed: ${result.error||response.status}`;
    };
    const remediationBar=panel.querySelector('.remediation-status .actions');
    if(remediationBar)remediationBar.onclick=async e=>{
      const decision=e.target?.dataset?.remediationApprove!==undefined?'approve':e.target?.dataset?.remediationDeny!==undefined?'deny':null;
      if(!decision)return;
      const response=await mutate(`/api/alerts/${a.alert_id}/remediation/${decision}`,{method:'POST',body:'{}'});
      const result=await response.json().catch(()=>({error:'unknown error'}));
      panel.querySelector('.action-result').textContent=response.ok?`Remediation ${decision}d`:`Remediation ${decision} failed: ${result.error||response.status}`;
      if(response.ok){a.remediation=result.remediation;showRunbook(a)}
    };
  }
  async function load(){let q=state==='all'?'':`?state=${state}`,d=await(await fetch('/api/alerts'+q)).json();lastAlerts=d.alerts;root.innerHTML=table(['Severity','Device','Type','Message','Opened','Last seen','State','Actions'],lastAlerts.map((a,i)=>`<tr><td class="severity-${esc(a.severity)}">${esc(a.severity)}</td><td>${esc(a.device_id)}</td><td>${esc(a.alert_type)}</td><td>${esc(a.message)}</td><td>${localTime(a.opened_at)}</td><td>${localTime(a.last_seen_at)}</td><td>${esc(a.state)}</td><td>${a.playbook?`<button data-runbook="${i}">Runbook</button> `:''}${a.resolved_at?'':`<button data-ack="${a.alert_id}">Acknowledge</button> <button data-mute="${a.alert_id}">Mute 1h</button>`}</td></tr>`))}
  document.querySelector('#alert-filters').onclick=e=>{if(e.target.dataset.state){state=e.target.dataset.state;document.querySelectorAll('.filter').forEach(x=>x.classList.toggle('selected',x===e.target));load()}};
  root.onclick=async e=>{
    if(e.target.dataset.runbook!==undefined){showRunbook(lastAlerts[+e.target.dataset.runbook]);return}
    let id=e.target.dataset.ack||e.target.dataset.mute;if(!id)return;
    await mutate(`/api/alerts/${id}/${e.target.dataset.ack?'acknowledge':'mute'}`,{method:'POST',body:JSON.stringify({seconds:3600})});load()};
  load()
}
async function events(){let d=await(await fetch('/api/events')).json();document.querySelector('#events-table').innerHTML=table(['Time','Device','Type','Severity','Message'],d.events.map(x=>`<tr><td>${localTime(x.timestamp)}</td><td>${esc(x.device_id)}</td><td>${esc(x.event_type)}</td><td class="severity-${esc(x.severity)}">${esc(x.severity)}</td><td>${esc(x.message)}</td></tr>`))}
async function databaseStatus(){let d=await(await fetch('/api/database/status')).json();document.querySelector('#database-status').innerHTML=Object.entries(d).map(([k,v])=>`<dt>${esc(k.replaceAll('_',' '))}</dt><dd>${esc(v)}</dd>`).join('')}
function plot(canvas,points,keys,colors){let ctx=canvas.getContext('2d'),w=canvas.width=canvas.clientWidth*devicePixelRatio,h=canvas.height=canvas.clientHeight*devicePixelRatio;ctx.clearRect(0,0,w,h);let values=points.flatMap(x=>keys.map(k=>Number(x[k])).filter(Number.isFinite));if(!values.length){ctx.fillStyle='#8fa4b5';ctx.fillText('No historical data',15,30);return}let lo=Math.min(...values),hi=Math.max(...values);if(lo===hi){lo--;hi++}keys.forEach((key,j)=>{ctx.strokeStyle=colors[j];ctx.beginPath();let begun=false;points.forEach((x,i)=>{let v=Number(x[key]);if(!Number.isFinite(v)){begun=false;return}let px=10+i*(w-20)/Math.max(1,points.length-1),py=h-10-(v-lo)*(h-20)/(hi-lo);begun?ctx.lineTo(px,py):ctx.moveTo(px,py);begun=true});ctx.stroke()})}
async function loadHistory(id,range){let r=await fetch(`/api/devices/${encodeURIComponent(id)}/metrics?range=${range}`),d=await r.json(),charts=document.querySelector('#charts');if(!r.ok){charts.innerHTML=`<p>${esc(d.error)}</p>`;return}let defs=[['CPU %',['cpu_percent'],d.core],['Temperature °C',['cpu_temp_c','soc_temp_c'],d.core],['Memory %',['memory_percent'],d.core],['Storage %',['percent_used'],d.storage],['Network B/s',['rx_rate_bps','tx_rate_bps'],d.network],['Wi-Fi dBm',['wifi_signal_dbm'],d.network]];charts.innerHTML=defs.map((x,i)=>`<div class="chart"><strong>${x[0]}</strong><canvas id="chart-${i}"></canvas></div>`).join('');defs.forEach((x,i)=>plot(document.querySelector(`#chart-${i}`),x[2],x[1],['#62d3ff','#edc84b']));document.querySelector('#history-stats').innerHTML=Object.entries(d.statistics).map(([k,v])=>`<article><strong>${v==null?'—':esc(k.startsWith('temperature_')?temperature(v):Number(v).toFixed(1)+'%')}</strong><span>${esc(k.replaceAll('_',' '))}</span></article>`).join('')}
async function deviceHistory(id){let ranges=['1h','6h','24h','7d','30d'],root=document.querySelector('#ranges');root.innerHTML=ranges.map(x=>`<button class="filter ${x==='24h'?'selected':''}" data-range="${x}">${x}</button>`).join('');root.onclick=e=>{if(e.target.dataset.range){root.querySelectorAll('button').forEach(x=>x.classList.toggle('selected',x===e.target));loadHistory(id,e.target.dataset.range)}};loadHistory(id,'24h');let [fr,er]=await Promise.all([fetch(`/api/devices/${encodeURIComponent(id)}/storage/forecast`),fetch(`/api/devices/${encodeURIComponent(id)}/events?limit=10`)]),f=await fr.json(),ev=await er.json();document.querySelector('#forecasts').innerHTML=table(['Mount','Trend','Growth/day','Days remaining','Confidence'],(f.forecasts||[]).map(x=>`<tr><td>${esc(x.mount_point)}</td><td>${esc(x.status)}</td><td>${x.daily_growth_bytes==null?'—':(x.daily_growth_bytes/1073741824).toFixed(2)+' GiB'}</td><td>${x.estimated_days_remaining==null?'—':Math.round(x.estimated_days_remaining)}</td><td>${esc(x.forecast_confidence)}</td></tr>`));document.querySelector('#device-events').innerHTML=table(['Time','Type','Message'],(ev.events||[]).map(x=>`<tr><td>${localTime(x.timestamp)}</td><td>${esc(x.event_type)}</td><td>${esc(x.message)}</td></tr>`))}
async function deviceLogs(id){let panel=document.querySelector('#logs');if(!panel)return;let out=document.querySelector('#log-output'),note=document.querySelector('#log-note'),select=document.querySelector('#log-unit');if(!out||!note||!select)return;let currentUnit=null,text='';
  const setNote=msg=>{note.textContent=msg||'';};
  async function loadUnits(){
    let r=await fetch(`/api/devices/${encodeURIComponent(id)}/logs`);
    if(!r.ok){panel.hidden=true;return}
    let data=await r.json(),units=data.units||[];
    if(!units.length){panel.hidden=true;return}
    panel.hidden=false;
    if(!units.some(u=>u.unit===currentUnit))currentUnit=units[0].unit;
    select.innerHTML=units.map(u=>`<option value="${esc(u.unit)}" ${u.unit===currentUnit?'selected':''}>${esc(u.unit)}</option>`).join('');
    select.value=currentUnit;
    let latest=units.find(u=>u.unit===currentUnit);
    setNote(`Bounded tail of the journal, refreshed every few minutes · last collected ${localTime(latest.last_timestamp)}`);
    await loadUnit();
  }
  async function loadUnit(){
    let r=await fetch(`/api/devices/${encodeURIComponent(id)}/logs?unit=${encodeURIComponent(currentUnit)}`);
    if(!r.ok){let e=await r.json().catch(()=>({}));out.textContent=`${e.error||'unable to load logs'}`;text='';return}
    let data=await r.json(),sample=(data.samples||[])[0];
    if(!sample){out.textContent='No recent log lines captured.';text='';return}
    text=sample.lines.join('\n');
    out.textContent=`# ${currentUnit} — ${localTime(sample.timestamp)} (${sample.lines.length} lines, newest tail)\n\n`+text;
  }
  select.onchange=()=>{currentUnit=select.value;loadUnit()};
  let refresh=panel.querySelector('#log-refresh');if(refresh)refresh.onclick=()=>{loadUnits()};
  let copy=panel.querySelector('#log-copy');if(copy)copy.onclick=async()=>{try{await navigator.clipboard.writeText(text);setNote('Copied to clipboard');}catch(_){setNote('Copy failed')}};
  let download=panel.querySelector('#log-download');if(download)download.onclick=()=>{if(!text)return;let name=`logs-${currentUnit.replace(/[^A-Za-z0-9@:_.\-]/g,'_')}-${new Date().toISOString().replace(/[:.]/g,'-')}.txt`;let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:'text/plain'}));a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(a.href)};
  await loadUnits();
}
// Self-healing status for this device (attempts, cooldown, last run, any
// pending approval) across every alert with a remediation-carrying
// playbook; deciding a pending one happens on the alert's own Runbook
// panel (see PiNOC.alerts), this is read-only visibility.
async function deviceRemediation(id){
  let existing=document.querySelector('#device-remediation');if(existing)existing.remove();
  let r=await fetch(`/api/devices/${encodeURIComponent(id)}/remediations`);if(!r.ok)return;
  let rows=(await r.json()).remediations||[];if(!rows.length)return;
  let panel=document.createElement('section');panel.className='panel';panel.id='device-remediation';
  panel.innerHTML=`<h2>Self-healing</h2>${table(['Alert type','Action','Policy','Attempts','Last run','Status'],rows.map(x=>`<tr><td>${esc(x.alert_type)}</td><td>${esc(x.action)}${x.target?' '+esc(x.target):''}</td><td>${esc(x.policy)}</td><td>${x.attempts}/${x.max_attempts}</td><td>${localTime(x.last_attempt_at)}</td><td>${esc(x.approval_status==='pending'?'awaiting approval':x.last_status||'—')}</td></tr>`))}`;
  document.querySelector('#device').after(panel);
}
const originalDevice=device;device=async id=>{await originalDevice(id);deviceHistory(id);deviceLogs(id);deviceRemediation(id);let [dr,sr]=await Promise.all([fetch(`/api/devices/${encodeURIComponent(id)}`),fetch('/api/session')]),d=await dr.json(),who=await sr.json();if(!['operator','administrator'].includes(who.user?.role))return;let root=document.querySelector('#device'),panel=document.createElement('section');panel.className='panel actions';const rescueLabels={'apt.clean':'Clean apt cache','apt.autoremove':'Preview autoremove','logs.truncate':'Truncate log…','journal.vacuum':'Vacuum journal…','cache.drop':'Drop caches'};panel.innerHTML=`<h2>Safe actions</h2><button data-refresh>Refresh now</button> ${(d.manageable_services||[]).map(x=>`<button data-service="${esc(x)}">Restart ${esc(x)}</button>`).join(' ')} <button data-maintenance>Maintenance 1 hour</button>${who.user.role==='administrator'?' <button data-reboot>Reboot</button> <button data-shutdown>Shutdown</button>':''}${(d.allowed_actions||[]).filter(a=>rescueLabels[a]).map(a=>` <button data-rescue="${esc(a)}">${rescueLabels[a]}</button>`).join(' ')}<p class="action-result"></p>`;root.querySelector('.title-row').after(panel);panel.onclick=async e=>{let url,body={};if(e.target.dataset.refresh!==undefined)url=`/api/devices/${encodeURIComponent(id)}/refresh`;if(e.target.dataset.service&&confirm(`Restart ${e.target.dataset.service} on ${d.friendly_name}?`))url=`/api/devices/${encodeURIComponent(id)}/services/${encodeURIComponent(e.target.dataset.service)}/restart`;if(e.target.dataset.maintenance!==undefined){url=`/api/devices/${encodeURIComponent(id)}/maintenance`;body={seconds:3600,reason:prompt('Maintenance reason (optional)')||''}}if(e.target.dataset.reboot!==undefined&&confirm(`Reboot ${d.friendly_name}?`))url=`/api/devices/${encodeURIComponent(id)}/reboot`;if(e.target.dataset.shutdown!==undefined&&prompt(`Type ${d.friendly_name} to confirm shutdown`)===d.friendly_name)url=`/api/devices/${encodeURIComponent(id)}/shutdown`;if(e.target.dataset.rescue!==undefined){const action=e.target.dataset.rescue;if(action==='apt.clean'&&!confirm(`Clean the apt cache on ${d.friendly_name}?`))return;if(action==='apt.autoremove'&&!confirm(`Preview package autoremove on ${d.friendly_name}? (no changes are made)`))return;if(action==='logs.truncate'){const path=prompt(`Log path to truncate on ${d.friendly_name} (empty for the largest under /var/log)`,'');if(path===null)return;if(path.trim())body.target=path.trim()}if(action==='journal.vacuum'){const spec=prompt('Journal vacuum limit, e.g. size:100M or time:7d','time:7d');if(spec===null)return;if(spec.trim())body.target=spec.trim()}if(action==='cache.drop'&&prompt(`Type ${d.friendly_name} to confirm dropping page caches`)!==d.friendly_name)return;url=`/api/devices/${encodeURIComponent(id)}/actions/${action.replace('.','-')}`}if(!url)return;let response=await mutate(url,{method:'POST',body:JSON.stringify(body)}),result=await response.json();panel.querySelector('.action-result').textContent=response.ok?`Queued ${result.job_id||'maintenance update'}`:result.error}};
async function integrations(path){let endpoint=path==='/adsb'?'/api/adsb':path==='/displays'?'/api/displays':path==='/software'?'/api/software':path==='/network-inventory'?'/api/network-inventory':'/api/integrations',data=await(await fetch(endpoint)).json(),rows=data.integrations||data.receivers||data.displays||data.devices||[];document.querySelector('#integration-list').innerHTML=table(['Device','Integration / status','Health','Data'],rows.map(x=>`<tr><td>${esc(x.friendly_name||x.device_id||x.hostname)}</td><td>${esc(x.name||x.os||'inventory')}</td><td>${esc(x.health||x.status||'available')}</td><td><code>${esc(JSON.stringify(x.data||x.packages||x))}</code></td></tr>`))}
async function audit(){let d=await(await fetch('/api/audit')).json();document.querySelector('#audit-table').innerHTML=table(['Time','User','Device','Action','Result'],(d.audit||[]).map(x=>`<tr><td>${localTime(x.timestamp)}</td><td>${esc(x.user)}</td><td>${esc(x.device_id)}</td><td>${esc(x.action)} ${esc(x.target||'')}</td><td>${esc(x.execution_result||x.authorization_result)}</td></tr>`))}
async function settings(){
  const statusRoot=document.querySelector('#notifications-status');
  const editor=document.querySelector('#notifications-editor');
  if(!statusRoot&&!editor&&!document.querySelector('#notifications-save'))return;
  const statusMessage=()=>document.querySelector('#notifications-message');
  const renderStatus=async()=>{
    if(!statusRoot)return;
    try{
      let d=await(await fetch('/api/notifications')).json();
      if(!d.channels.length){statusRoot.innerHTML=`<p class="muted">${d.enabled?'No channels configured.':'Notifications are disabled.'} Add enabled channels in the editor below.</p>`;return}
      statusRoot.innerHTML=d.channels.map(c=>`<article class="notification-channel"><div><h3>${esc(c.id||'channel')}${c.enabled?'':' <span class="maintenance">disabled</span>'}</h3><small>${esc(c.kind||'')}${c.sent||c.failed?` · sent ${c.sent||0}, failed ${c.failed||0}`:''}${c.last_success?` · last success ${localTime(c.last_success)}`:''}</small>${c.last_error?`<small class="critical-row">last error: ${esc(c.last_error)}</small>`:''}</div><button data-channel="${esc(c.id||'')}">Send test</button></article>`).join('');
      statusRoot.querySelectorAll('button[data-channel]').forEach(button=>{button.onclick=async()=>{
        button.disabled=true;
        try{
          let response=await mutate('/api/notifications/test',{method:'POST',body:JSON.stringify({channel:button.dataset.channel})});
          let result=await response.json().catch(()=>({ok:false,error:`HTTP ${response.status}`}));
          let note=statusMessage();
          if(note){note.textContent=result.ok?'Test message delivered.':`Test failed: ${result.error||response.status}`;note.className=result.ok?'muted':'critical-row'}
          await renderStatus();
        }catch(error){}
        button.disabled=false;
      }});
    }catch(error){statusRoot.innerHTML='<p class="muted">Notification status unavailable.</p>'}
  };
  await renderStatus();
  let refresh=document.querySelector('#notifications-status-refresh');
  if(refresh)refresh.onclick=()=>{renderStatus()};
  if(editor){
    let fallback={enabled:false,open_severities:[],resolve_severities:[],channels:[]};
    let current=fallback;
    try{let config=await(await fetch('/api/settings')).json();current=config.notifications||fallback}catch(error){}
    editor.value=JSON.stringify(current,null,2);
    let save=document.querySelector('#notifications-save');
    if(save)save.onclick=async()=>{
      let value;
      try{value=JSON.parse(editor.value)}catch(err){let note=statusMessage();if(note){note.textContent=`Invalid JSON: ${err.message}`;note.className='critical-row'}return}
      let note=statusMessage();
      if(note){note.textContent='Saving…';note.className='muted'}
      try{
        let config=await(await fetch('/api/settings')).json();
        config.notifications=value;
        let response=await mutate('/api/settings',{method:'PUT',body:JSON.stringify(config)});
        let saved=await response.json().catch(()=>({}));
        if(!response.ok)throw new Error(saved.error||`HTTP ${response.status}`);
        if(note){note.textContent='Saved. Restart PiNOC to apply.';note.className='muted'}
        await renderStatus();
      }catch(err){if(note){note.textContent=err.message;note.className='critical-row'}}
    };
  }
  const backupStatus=document.querySelector('#backup-status');
  const backupMessage=()=>document.querySelector('#backup-message');
  if(backupStatus){
    const renderBackup=async()=>{
      try{
        let d=await(await fetch('/api/backup')).json();
        if(!d.enabled){backupStatus.innerHTML='<p class="muted">Scheduled backups are disabled. Set <code>backups.enabled</code> and a destination in config.json (applies after restart).</p>';return}
        const dest=d.destination?(d.destination.type==='ssh'?`${d.destination.host}:${d.destination.path}`:d.destination.path):'';
        backupStatus.innerHTML=`<p>Scheduled every ${d.interval_hours}h, keeping ${d.keep}. Destination: <code>${esc(dest)}</code>${d.last_run?` — last run ${localTime(d.last_run)}`:''}${d.last_size_bytes?`, ${formatBytes(d.last_size_bytes)}`:''}.</p>${d.last_error?`<small class="critical-row">last run failed: ${esc(d.last_error)}</small>`:''}`;
      }catch(error){backupStatus.innerHTML='<p class="muted">Backup status unavailable.</p>'}
    };
    await renderBackup();
    let download=document.querySelector('#backup-download');
    if(download)download.onclick=()=>{let note=backupMessage();if(note){note.textContent='Preparing download…';note.className='muted'}window.location.href='/api/backup/export'};
    let runNow=document.querySelector('#backup-run-now');
    if(runNow)runNow.onclick=async()=>{
      let note=backupMessage();
      if(note){note.textContent='Running backup…';note.className='muted'}
      runNow.disabled=true;
      try{
        let before=await(await fetch('/api/backup')).json();
        let response=await mutate('/api/backup/run',{method:'POST'});
        let queued=await response.json().catch(()=>({}));
        if(!response.ok)throw new Error(queued.error||`HTTP ${response.status}`);
        // The backup now runs on the server's own background thread (it can
        // take minutes over a slow link), so poll status for the result
        // instead of waiting on the request itself.
        let settled=false;
        for(let attempt=0;attempt<40 && !settled;attempt++){
          await new Promise(r=>setTimeout(r,3000));
          let d=await(await fetch('/api/backup')).json();
          if(d.last_run && d.last_run!==before.last_run){
            if(note){note.textContent=d.last_error?`Backup failed: ${d.last_error}`:`Backup complete: ${d.last_bundle||''}`;note.className=d.last_error?'critical-row':'muted'}
            settled=true;
          }
        }
        if(!settled && note){note.textContent='Backup still running in the background — refresh to check.';note.className='muted'}
        await renderBackup();
      }catch(err){if(note){note.textContent=err.message;note.className='critical-row'}}
      runNow.disabled=false;
    };
  }
}
const SCHEDULE_ACTIONS=["device.reboot","service.restart","service.start","service.stop","package.check","apt.clean","apt.autoremove","logs.truncate","journal.vacuum","cache.drop","wireguard.restart","desk_display.restart","magicmirror.restart","pi_hotspot.restart"];
async function schedules(){
  const statusRoot=document.querySelector('#schedules-status');
  const listRoot=document.querySelector('#schedules-list');
  if(!statusRoot&&!listRoot)return;
  const message=()=>document.querySelector('#schedule-message');
  const deviceSelect=document.querySelector('#schedule-device');
  const actionSelect=document.querySelector('#schedule-action');
  const note=(text,ok=true)=>{let m=message();if(m){m.textContent=text;m.className=ok?'muted':'critical-row'}};
  const renderStatus=d=>{if(!statusRoot)return;const s=d.status||{};statusRoot.innerHTML=`Scheduler ${s.running?'running':'stopped'} · ${s.active||0} active, ${s.paused||0} paused, ${s.schedules||0} total.`;};
  const renderList=async()=>{
    if(!listRoot)return;
    let data;
    try{data=await(await fetch('/api/schedules')).json()}catch(error){listRoot.innerHTML='<p class="muted">Schedules unavailable.</p>';return}
    renderStatus(data);
    const rows=(data.schedules||[]).map(x=>`<tr><td>${esc(x.device_id)}</td><td>${esc(x.action)}${x.target?` <small>${esc(x.target)}</small>`:''}</td><td><code>${esc(x.spec)}</code>${x.timezone&&x.timezone!=='UTC'?` <small>${esc(x.timezone)}</small>`:''}</td><td>${x.paused?'<span class="maintenance">paused</span>':esc(x.last_status||'—')}</td><td>${x.next_run?localTime(x.next_run):'—'}</td><td>${x.last_run?localTime(x.last_run):'—'}</td><td>${Number(x.consecutive_failures)||0}</td><td class="row-actions">
<button data-act="toggle" data-id="${esc(x.schedule_id)}" data-paused="${x.paused?1:0}">${x.paused?'Resume':'Pause'}</button>
<button data-act="run" data-id="${esc(x.schedule_id)}">Run now</button>
<button data-act="del" data-id="${esc(x.schedule_id)}" class="danger">Delete</button></td></tr>`).join('');
    listRoot.innerHTML=rows.length?table(['Device','Action','Schedule','State','Next run','Last run','Fails'],rows):'<p class="muted">No schedules yet. Add one below.</p>';
    listRoot.querySelectorAll('button[data-act]').forEach(btn=>{btn.onclick=async()=>{const id=btn.dataset.id;
      if(btn.dataset.act==='del'){if(!confirm('Delete this schedule?'))return;let response=await mutate(`/api/schedules/${encodeURIComponent(id)}`,{method:'DELETE'});let result=await response.json().catch(()=>({}));if(!response.ok)note(result.error||'delete failed',false);}
      else if(btn.dataset.act==='toggle'){let response=await mutate(`/api/schedules/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({paused:btn.dataset.paused==='1'?false:true})});let result=await response.json().catch(()=>({}));if(!response.ok)note(result.error||'update failed',false);}
      else{let response=await mutate(`/api/schedules/${encodeURIComponent(id)}/run`,{method:'POST'});let result=await response.json().catch(()=>({}));if(!response.ok)note(result.error||'run failed',false);}
      await renderList();note('');}});
  };
  if(actionSelect)actionSelect.innerHTML=SCHEDULE_ACTIONS.map(a=>`<option value="${a}">${a.replaceAll('.',' ')}</option>`).join('');
  if(deviceSelect){try{let d=await(await fetch('/api/devices')).json();const devices=d.devices||[];deviceSelect.innerHTML=devices.map(x=>`<option value="${esc(x.id)}">${esc(x.friendly_name||x.hostname||x.id)}</option>`).join('')||'<option value="">no devices</option>'}catch(error){deviceSelect.innerHTML='<option value="">unavailable</option>'}}
  let form=document.querySelector('#schedule-create');
  if(form)form.onsubmit=async e=>{
    e.preventDefault();
    const body={device_id:deviceSelect?.value,action:actionSelect?.value,spec:document.querySelector('#schedule-spec')?.value.trim(),target:document.querySelector('#schedule-target')?.value.trim()||null,timezone:document.querySelector('#schedule-tz')?.value.trim()||'UTC'};
    if(!body.device_id||!body.action||!body.spec)return note('Device, action and spec are required.',false);
    let response=await mutate('/api/schedules',{method:'POST',body:JSON.stringify(body)});
    let result=await response.json().catch(()=>({}));
    if(!response.ok){note(result.error||'could not add schedule',false);return}
    document.querySelector('#schedule-spec').value='';document.querySelector('#schedule-target')?.removeAttribute('value');
    note('Schedule added.');
    await renderList();
  };
  await renderList();
}
// Staged fleet update rollouts: a canary wave then the remainder, with a
// health gate between waves -- see pinoc/rollout.py. Each run's per-device
// wave table (status, before/after kernel, errors) is shown inline via
// <details> so the panel stays compact with many runs.
async function rollouts(){
  const listRoot=document.querySelector('#rollouts-list');
  if(!listRoot)return;
  const message=()=>document.querySelector('#rollout-message');
  const note=(text,ok=true)=>{let m=message();if(m){m.textContent=text;m.className=ok?'muted':'critical-row'}};
  const deviceRows=d=>`<tr class="${d.status==='failed'?'critical-row':''}"><td>${esc(d.device_id)}</td><td>${d.wave}</td><td>${esc(d.status)}</td><td>${esc(d.before_kernel)} → ${esc(d.after_kernel)}</td><td>${d.before_updates_available??'—'} → ${d.after_updates_available??'—'}</td><td>${d.reboot_required?'yes':'no'}</td><td>${esc(d.error||'')}</td></tr>`;
  const renderList=async()=>{
    let data;
    try{data=await(await fetch('/api/rollouts')).json()}catch(error){listRoot.innerHTML='<p class="muted">Rollouts unavailable.</p>';return}
    const runs=data.rollouts||[];
    if(!runs.length){listRoot.innerHTML='<p class="muted">No rollouts yet. Start one below.</p>';return}
    const sections=await Promise.all(runs.map(async r=>{
      let detail={};
      try{detail=await(await fetch(`/api/rollouts/${encodeURIComponent(r.run_id)}`)).json()}catch(error){}
      const devices=detail.devices||[],summary=detail.summary||{by_status:{}};
      const counts=Object.entries(summary.by_status||{}).map(([k,v])=>`${v} ${k}`).join(', ')||'no devices';
      const cancel=r.status==='running'?`<button data-cancel="${esc(r.run_id)}">Cancel</button>`:'';
      return `<section class="panel"><div class="panel-heading"><div><p class="eyebrow">${esc(r.scope)} · wave ${r.current_wave+1} of ${r.wave_count}</p><h3>${esc(r.name||r.run_id)}</h3></div>${cancel}</div><p class="muted">${esc(r.status)}${r.halted_reason?` — ${esc(r.halted_reason)}`:''} · started ${localTime(r.started_at)}${r.completed_at?` · finished ${localTime(r.completed_at)}`:''} · ${counts}</p><details><summary>${devices.length} device${devices.length===1?'':'s'} (expand)</summary>${table(['Device','Wave','Status','Kernel before → after','Updates before → after','Rebooted','Error'],devices.map(deviceRows))}</details></section>`;
    }));
    listRoot.innerHTML=sections.join('');
    listRoot.querySelectorAll('button[data-cancel]').forEach(btn=>{btn.onclick=async()=>{
      if(!confirm('Cancel this rollout? Devices already updating will finish, but no further wave will start.'))return;
      let response=await mutate(`/api/rollouts/${encodeURIComponent(btn.dataset.cancel)}/cancel`,{method:'POST',body:'{}'});
      let result=await response.json().catch(()=>({}));
      if(!response.ok)note(result.error||'cancel failed',false);
      await renderList();
    }});
  };
  let form=document.querySelector('#rollout-create');
  if(form)form.onsubmit=async e=>{
    e.preventDefault();
    const split=v=>v.split(',').map(x=>x.trim()).filter(Boolean);
    const waveSize=document.querySelector('#rollout-wave-size')?.value.trim();
    const body={scope:document.querySelector('#rollout-scope')?.value,
      roles:split(document.querySelector('#rollout-roles')?.value||''),
      tags:split(document.querySelector('#rollout-tags')?.value||''),
      canary_count:Number(document.querySelector('#rollout-canary')?.value||0),
      wave_size:waveSize?Number(waveSize):null,
      respect_maintenance:!!document.querySelector('#rollout-maintenance')?.checked};
    if(!body.roles.length&&!body.tags.length)return note('Select devices by role and/or tag.',false);
    let response=await mutate('/api/rollouts',{method:'POST',body:JSON.stringify(body)});
    let result=await response.json().catch(()=>({}));
    if(!response.ok){note(result.error||'could not start rollout',false);return}
    note('Rollout started.');
    await renderList();
  };
  await renderList();
}
async function anomalies(){
  const statusRoot=document.querySelector('#anomalies-status');
  const previewsRoot=document.querySelector('#anomalies-previews');
  if(!statusRoot&&!previewsRoot)return;
  let data={};
  try{data=await(await fetch('/api/anomalies?limit=100')).json()}catch(error){}
  const s=data.status||{};
  if(statusRoot){
    if(!s.enabled){statusRoot.innerHTML='Anomaly detection is <strong>off</strong>. Add the <code>anomaly_detection</code> section to config.json (restart required); preview mode records deviations here without opening alerts.';
      if(previewsRoot)previewsRoot.innerHTML='';return}
    const enabled=(Object.values(s.metrics||{}).filter(m=>m.enabled).map(m=>m.label));
    statusRoot.innerHTML=`Mode: <strong>${esc(s.mode)}</strong> · opens at ≥&thinsp;${s.z_open}σ, holds open ≥&thinsp;${s.z_hysteresis}σ · needs ${s.min_samples} baseline samples · tracking: ${enabled.length?enabled.map(esc).join(', '):'no metrics enabled'}`;
  }
  if(previewsRoot){
    const rows=(data.previews||[]).map(p=>`<tr><td>${localTime(p.timestamp)}</td><td>${esc(p.device_id)}</td><td>${esc(p.metric)}</td><td>${Number(p.value).toFixed(2)}${p.metric&&p.metric.endsWith('_bps')?' B/s':''}</td><td>${Number(p.baseline_mean||0).toFixed(2)}</td><td>${Number(p.z_score).toFixed(1)}σ</td></tr>`);
    const empty=s.mode==='preview'?'No deviations recorded yet — when a sample leaves its baseline it will appear here.':'No recent previewed deviations.';
    previewsRoot.innerHTML=rows.length?table(['Time','Device','Metric','Value','Baseline mean','Z-score'],rows):`<p class="muted">${empty}</p>`;
  }
}
async function correlationStatus(){
  const root=document.querySelector('#correlation-status');if(!root)return;
  let data={};
  try{data=await(await fetch('/api/alert-clusters')).json()}catch(error){}
  const s=data.status||{};
  if(!s.enabled){root.innerHTML='Alert correlation is <strong>off</strong> (<code>alert_correlation.enabled: false</code>).';return}
  const open=(data.clusters||[]).length;
  root.innerHTML=`<strong>On</strong> · groups within ${s.window_seconds}s of each other · needs ${s.min_members}+ devices to form a cluster · ${open} open cluster${open===1?'':'s'} right now`;
}
// Device-to-device network quality matrix and topology view: gateway +
// segments derived from the fleet/LAN inventory config, each pair's latest
// ping latency/loss, and which segments are persistently degraded -- see
// pinoc/topology.py and pinoc/collectors/network_matrix.py. The same
// degraded-segment signal is fed into alert correlation as shared-cause
// context (pinoc/correlation.py), visible there as a "segment" cluster.
async function topology(){
  const summary=document.querySelector('#topology-summary'),segRoot=document.querySelector('#topology-segments'),matrixRoot=document.querySelector('#topology-matrix');
  if(!summary&&!segRoot&&!matrixRoot)return;
  let data={};
  try{data=await(await fetch('/api/network-topology')).json()}catch(error){}
  if(!data.enabled){
    if(summary)summary.innerHTML=`<p class="muted">${data.error?`Configuration error: ${esc(data.error)}`:'Network topology sampling is <strong>off</strong>. Configure <code>network_topology</code> (gateway, segments, pairs) in config.json to enable a bounded device-to-device ping matrix.'}</p>`;
    if(segRoot)segRoot.innerHTML='';if(matrixRoot)matrixRoot.innerHTML='';
    return;
  }
  const segments=data.segments||[],pairs=data.pairs||[],degradedCount=segments.filter(s=>s.status!=='ok').length;
  const statusClass=s=>s==='critical'?'critical':s==='degraded'?'warning':'healthy';
  if(summary)summary.innerHTML=`Gateway <strong>${esc(data.gateway||'—')}</strong> · ${segments.length} segment${segments.length===1?'':'s'} · ${pairs.length} sampled pair${pairs.length===1?'':'s'} · ${degradedCount?`<span class="severity-critical">${degradedCount} segment${degradedCount===1?'':'s'} degraded</span>`:'<span class="muted">all clear</span>'}`;
  const pairLine=p=>{const latest=p.latest||{},lat=latest.latency_ms==null?'—':`${Number(latest.latency_ms).toFixed(1)} ms`,loss=latest.loss_percent==null?'—':`${Number(latest.loss_percent).toFixed(0)}% loss`;return `<li><span class="dot ${statusClass(p.severity)}"></span>${esc(p.source_id)} ↔ ${esc(p.target_id)} — ${lat} · ${loss}${latest&&latest.error?` · ${esc(latest.error)}`:''}</li>`};
  if(segRoot)segRoot.innerHTML=segments.map(s=>`<section class="panel cluster-card ${s.status==='critical'?'sev-critical':s.status==='degraded'?'sev-warning':''}"><div class="cluster-head"><span class="dot ${statusClass(s.status)}"></span><div><h3>${esc(s.name)}</h3><p class="muted">${(s.devices||[]).length} device${(s.devices||[]).length===1?'':'s'}${s.gateway?` · gateway ${esc(s.gateway)}`:''} · ${esc(s.status)}</p></div></div><ul>${(s.pairs||[]).map(pairLine).join('')||'<li class="muted">No sampled pairs yet</li>'}</ul></section>`).join('')||'<p class="muted">No segments configured.</p>';
  if(matrixRoot)matrixRoot.innerHTML=table(['Source','Target','Status','Latency','Loss','Error'],pairs.map(p=>{const latest=p.latest||{};return `<tr class="${p.severity==='critical'?'severity-critical':p.severity==='warning'?'severity-warning':''}"><td>${esc(p.source_id)}</td><td>${esc(p.target_id)}</td><td>${esc(p.severity)}</td><td>${latest.latency_ms==null?'—':Number(latest.latency_ms).toFixed(1)+' ms'}</td><td>${latest.loss_percent==null?'—':Number(latest.loss_percent).toFixed(0)+'%'}</td><td>${esc(latest.error||'')}</td></tr>`}));
}
return{connection,dashboard,device,alerts,events,databaseStatus,integrations,audit,settings,schedules,rollouts,anomalies,correlationStatus,topology,startAutoRefresh,formatBytes:bytes,formatTemperature:temperature,formatPercent:pct,humanValue,runbookMarkdown:runbookMd,runbookGate}})();
