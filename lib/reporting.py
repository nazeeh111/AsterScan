"""Self-contained, offline HTML reports for AsterScan scan events."""

import base64
import datetime
import json
import os
from pathlib import Path


def source_revisions(application_path):
    sources = []
    for manifest_path in sorted(Path(application_path).glob('*.cache.manifest.json')):
        try:
            with manifest_path.open(encoding='utf-8') as source:
                manifest = json.load(source)
            sources.append({
                'name': manifest_path.name[:-len('.cache.manifest.json')].lstrip('_').replace('_', '/'),
                'revision': str(manifest['sha']),
                'files': len(manifest['files']),
            })
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sources


def report_payload(logger, target, intense, scanned, application_path, coverage):
    if not scanned or logger.errors:
        status = 'incomplete'
    elif logger.alerts:
        status = 'alert'
    elif logger.warnings:
        status = 'warning'
    else:
        status = 'clear'
    return {
        'schema': 1,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'host': logger.hostname,
        'target': target,
        'mode': 'Deep' if intense else 'Fast',
        'status': status,
        'counts': {'alerts': logger.alerts, 'warnings': logger.warnings,
                   'notices': logger.notices, 'errors': logger.errors},
        'coverage': coverage,
        'events': logger.report_events,
        'events_dropped': logger.report_dropped,
        'sources': source_revisions(application_path),
    }


def write_report(path, payload, application_path):
    logo_path = Path(application_path) / '.github' / 'assets' / 'mark.png'
    logo = ''
    try:
        logo = 'data:image/png;base64,' + base64.b64encode(logo_path.read_bytes()).decode('ascii')
    except OSError:
        pass
    serialized = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)
    serialized = (serialized.replace('<', '\\u003c').replace('>', '\\u003e')
                  .replace('&', '\\u0026').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))
    html = TEMPLATE.replace('__ASTER_LOGO__', logo).replace('__ASTER_DATA__', serialized)
    with open(path, 'x', encoding='utf-8') as output:
        output.write(html)


TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>AsterScan report</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#f2f5f1;background:#111715;--bg:#111715;--panel:#19211e;--line:#334039;--muted:#aab7ae;--lime:#d8f47d;--orange:#ffad70;--red:#ff776d;--blue:#85c9d3}
*{box-sizing:border-box}body{margin:0}button,input,select{font:inherit}button{cursor:pointer}button:disabled{cursor:default;opacity:.4}button:focus-visible,input:focus-visible,select:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--lime);outline-offset:3px}a{color:var(--lime)}
.shell{max-width:1560px;margin:auto;padding:0 36px 56px}.top{height:72px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);gap:16px}.brand{display:flex;align-items:center;gap:12px;font-size:18px;font-weight:730}.brand img{width:29px;height:29px;object-fit:contain}.brandFallback{width:29px;height:29px;display:grid;place-items:center;background:var(--lime);color:var(--bg);font-weight:900;transform:rotate(45deg)}.brandFallback span{transform:rotate(-45deg)}.topRight{display:flex;align-items:center;gap:16px;color:var(--muted);font-size:12px}.topRight .mono{white-space:nowrap}.top button,.toolbar button,.detail button,.export button{border:1px solid var(--line);background:transparent;color:#f2f5f1;border-radius:6px;padding:8px 12px}.top button:hover,.toolbar button:hover,.detail button:hover,.export button:hover{border-color:#8ca098;background:#26332c}
.eyebrow{color:var(--lime);text-transform:uppercase;font-size:11px;font-weight:780;letter-spacing:.12em}.intro{display:flex;justify-content:space-between;align-items:end;gap:32px;padding:38px 0 32px}.intro h1{font-size:40px;line-height:1.08;margin:8px 0 13px;font-weight:730;letter-spacing:0}.target{color:#d6ded7;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}.introMeta{text-align:right;min-width:210px}.status{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:3px;padding:8px 11px;font-size:12px;text-transform:uppercase;font-weight:800;letter-spacing:.05em}.status:before,.severity:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}.status.alert,.severity.alert{color:var(--red)}.status.warning,.severity.warning{color:var(--orange)}.status.incomplete,.severity.error{color:var(--red)}.status.clear,.severity.notice{color:var(--lime)}.metaLine{color:var(--muted);font-size:12px;margin-top:12px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-bottom:30px}.metric{padding:19px 22px 18px;border-right:1px solid var(--line)}.metric:first-child{padding-left:0}.metric:last-child{border-right:0}.metric label{display:block;font-size:11px;font-weight:760;text-transform:uppercase;color:var(--muted);letter-spacing:.09em}.metric strong{display:block;font-size:32px;font-weight:690;margin-top:4px;line-height:1.1}.metric.alert strong{color:var(--red)}.metric.warning strong{color:var(--orange)}.metric.error strong{color:var(--red)}
.noticeBar{border-left:3px solid var(--red);background:#332723;padding:13px 17px;margin:-8px 0 28px;color:#ffe4df;font-size:13px;line-height:1.5}.noticeBar[hidden]{display:none}.tabs{display:flex;gap:22px;border-bottom:1px solid var(--line)}.tab{background:transparent;border:0;color:var(--muted);font-size:13px;font-weight:690;padding:0 0 14px}.tab.active{color:#f3f7f1;border-bottom:2px solid var(--lime)}.view{padding-top:22px}.view[hidden]{display:none}.toolbar{display:flex;align-items:center;gap:12px;justify-content:space-between;margin-bottom:18px}.search{flex:1;max-width:420px;background:#1d2822;border:1px solid var(--line);border-radius:6px;color:#fff;padding:10px 13px;min-width:120px}.search::placeholder{color:#8e9f94}.filter{display:flex;gap:4px;padding:3px;border:1px solid var(--line);border-radius:6px}.filter button{border:0;padding:7px 11px;border-radius:4px;color:var(--muted);font-size:12px}.filter button.active{background:#344138;color:#f4f8f2}.sort{background:#1d2822;border:1px solid var(--line);border-radius:6px;color:#fff;padding:9px 10px;font-size:12px}
.workspace{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(310px,1fr);gap:28px;min-height:450px}.listHeader{display:grid;grid-template-columns:88px minmax(0,1fr) 72px;gap:16px;color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:750;letter-spacing:.08em;padding:0 15px 10px;border-bottom:1px solid var(--line)}.listHeader span:last-child{text-align:right}.finding{display:grid;grid-template-columns:88px minmax(0,1fr) 72px;align-items:center;gap:16px;width:100%;border:0;border-bottom:1px solid #29352e;background:transparent;color:#eff3ed;text-align:left;padding:14px 15px;min-height:68px}.finding:hover{background:#1c2921}.finding.active{background:#243329;box-shadow:inset 3px 0 var(--lime)}.finding .name{font-weight:680;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.finding .sub{color:var(--muted);font-size:11px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.finding .score{text-align:right;font-size:16px;font-weight:700}.severity{display:inline-flex;align-items:center;gap:6px;font-size:10px;text-transform:uppercase;font-weight:830;letter-spacing:.03em}.severity:before{width:6px;height:6px}
.detail{border-left:1px solid var(--line);padding-left:28px;min-width:0}.detail h2{font-size:19px;margin:5px 0 8px;line-height:1.3;overflow-wrap:anywhere}.detailPath{font-size:12px;color:#c0d3c4;overflow-wrap:anywhere;line-height:1.55}.detailTop{display:flex;align-items:center;justify-content:space-between;gap:8px}.detail dl{display:grid;grid-template-columns:95px 1fr;gap:9px 14px;margin:24px 0;border-top:1px solid var(--line);padding-top:18px;font-size:12px}.detail dt{color:var(--muted)}.detail dd{margin:0;overflow-wrap:anywhere}.sectionLabel{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:780;margin:26px 0 10px}.reason{padding:12px 0;border-top:1px solid #29352e;font-size:12px;line-height:1.55;color:#e0e8df;overflow-wrap:anywhere}.empty{color:var(--muted);padding:44px 15px;line-height:1.6}.empty strong{display:block;color:#f4f7f2;font-size:16px;margin-bottom:5px}.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:18px 0;color:var(--muted);font-size:12px}.pager .actions{display:flex;gap:7px}.pager button{background:transparent;color:#f2f5f1;border:1px solid var(--line);padding:6px 10px;border-radius:5px}
.activityItem{display:grid;grid-template-columns:90px 140px minmax(0,1fr) 80px;gap:16px;border-bottom:1px solid #29352e;padding:13px 8px;font-size:12px;line-height:1.5}.activityItem .message{overflow-wrap:anywhere}.activityItem .dim{color:var(--muted)}.sourceList{display:grid;grid-template-columns:1fr 140px 70px;gap:0}.sourceList>div{padding:15px 10px;border-bottom:1px solid var(--line);font-size:12px;overflow-wrap:anywhere}.sourceList .head{color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:750;letter-spacing:.08em}.export{display:flex;gap:8px;justify-content:flex-end;margin-top:28px}.footer{border-top:1px solid var(--line);margin-top:38px;padding-top:16px;color:var(--muted);font-size:11px;line-height:1.6}
@media(max-width:900px){.shell{padding:0 20px 36px}.intro{align-items:start;flex-direction:column;gap:14px}.introMeta{text-align:left}.workspace{grid-template-columns:1fr}.detail{border-left:0;border-top:1px solid var(--line);padding:22px 0 0}.toolbar{flex-wrap:wrap}.search{max-width:none;width:100%;flex-basis:100%}.activityItem{grid-template-columns:76px 1fr 70px}.activityItem .module{display:none}}
@media(max-width:560px){.shell{padding:0 14px 30px}.top{height:61px}.topRight .mono{display:none}.intro h1{font-size:30px}.metrics{grid-template-columns:repeat(2,1fr)}.metric:nth-child(2){border-right:0}.metric:nth-child(-n+2){border-bottom:1px solid var(--line)}.metric:nth-child(3){padding-left:0}.filter{overflow-x:auto;width:100%}.filter button{flex:1}.sort{width:100%}.listHeader,.finding{grid-template-columns:75px minmax(0,1fr) 48px;gap:8px;padding-left:7px;padding-right:7px}.sourceList{grid-template-columns:minmax(0,1fr) 85px 42px}}
@media print{body{background:white;color:black}.shell{max-width:none}.top button,.toolbar,.tabs,.pager,.export,.footer{display:none}.view[hidden]{display:none}.view{display:block}.workspace{display:block}.detail{break-before:page}.finding{color:black}.metrics,.detail{border-color:#888}}
</style>
</head>
<body>
<div class="shell">
  <header class="top"><div class="brand"><img id="logo" src="__ASTER_LOGO__" alt=""><span id="logoFallback" class="brandFallback" hidden><span>A</span></span><span>AsterScan</span></div><div class="topRight"><span class="mono" id="generated"></span><button type="button" id="print">Print report</button></div></header>
  <main>
    <section class="intro"><div><div class="eyebrow">Investigation / Local report</div><h1>Scan report</h1><div class="target" id="target"></div></div><div class="introMeta"><span id="status" class="status"></span><div id="scanMeta" class="metaLine"></div></div></section>
    <section class="metrics" aria-label="Scan totals"><div class="metric alert"><label>Alerts</label><strong id="alerts">0</strong></div><div class="metric warning"><label>Warnings</label><strong id="warnings">0</strong></div><div class="metric"><label>Notices</label><strong id="notices">0</strong></div><div class="metric error"><label>Errors</label><strong id="errors">0</strong></div></section>
    <div class="noticeBar" id="noticeBar" hidden></div>
    <nav class="tabs" aria-label="Report views"><button type="button" class="tab active" data-tab="findings">Findings</button><button type="button" class="tab" data-tab="activity">Activity</button><button type="button" class="tab" data-tab="sources">Rule sources</button></nav>
    <section class="view" id="findingsView"><div class="toolbar"><input id="search" class="search" type="search" aria-label="Search findings" placeholder="Search findings"><div class="filter" role="group" aria-label="Severity filter"><button type="button" class="active" data-filter="all">All</button><button type="button" data-filter="ALERT">Alerts</button><button type="button" data-filter="WARNING">Warnings</button><button type="button" data-filter="NOTICE">Notices</button></div><select id="sort" class="sort" aria-label="Sort findings"><option value="score">Highest score</option><option value="time">Latest first</option><option value="name">Name A-Z</option></select></div><div class="workspace"><div><div class="listHeader"><span>Severity</span><span>Object</span><span>Score</span></div><div id="findings"></div><div class="pager"><span id="count"></span><div class="actions"><button type="button" id="prev">Previous</button><button type="button" id="next">Next</button></div></div></div><aside class="detail" id="detail" aria-label="Finding details"></aside></div></section>
    <section class="view" id="activityView" hidden><div id="activity"></div></section>
    <section class="view" id="sourcesView" hidden><div id="sources"></div></section>
    <div class="export"><button type="button" id="download">Download JSON</button></div>
  </main>
  <footer class="footer">AsterScan | GPL-3.0-or-later | Original scanner: Florian Roth and LOKI contributors. Matches are leads for investigation, not proof of compromise. This report stays on your device unless you share it; paths and findings may be sensitive.</footer>
</div>
<script>
const report=__ASTER_DATA__;
const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node};
const basename=path=>String(path||'').split(/[\\/]/).pop()||path;
const formatTime=value=>{const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString()};
const findings=report.events.filter(e=>['ALERT','WARNING'].includes(e.level)||(e.level==='NOTICE'&&e.data&&e.data.kind==='file'));
let filter='all',query='',sort='score',page=0,selected=null;const pageSize=40;
function setText(id,value){$(id).textContent=String(value)}
function severity(level){return el('span','severity '+String(level).toLowerCase(),level)}
function filtered(){let list=findings.filter(e=>(filter==='all'||e.level===filter)&&[e.message,e.data&&e.data.path,...((e.data&&e.data.reasons)||[])].join(' ').toLowerCase().includes(query));list=[...list];if(sort==='score')list.sort((a,b)=>(b.data?.score||0)-(a.data?.score||0));else if(sort==='time')list.sort((a,b)=>b.time.localeCompare(a.time));else list.sort((a,b)=>basename(a.data?.path||a.message).localeCompare(basename(b.data?.path||b.message)));return list}
function showDetail(event){selected=event;const pane=$('detail');pane.replaceChildren();if(!event){const empty=el('div','empty');empty.append(el('strong','',findings.length?'Select a finding':'No findings'),document.createTextNode(findings.length?'Choose a row to inspect its indicators and file details.':'No alert or warning was recorded in this report.'));pane.append(empty);return}const top=el('div','detailTop');top.append(severity(event.level));const copy=el('button','','Copy details');copy.type='button';copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(event.message);copy.textContent='Copied'}catch{copy.textContent='Copy unavailable'}});top.append(copy);pane.append(top);pane.append(el('h2','',event.data?.path?basename(event.data.path):event.module));pane.append(el('div','detailPath',event.data?.path||event.message));const dl=el('dl');const add=(name,value)=>{if(value===undefined||value===null||value==='')return;dl.append(el('dt','',name),el('dd','mono',value))};add('Time',formatTime(event.time));add('Module',event.module);if(event.data){add('Score',event.data.score);add('Type',event.data.file_type);add('Size',event.data.size===undefined?'':Number(event.data.size).toLocaleString()+' bytes');for(const [key,value] of Object.entries(event.data.hashes||{}))add(key.toUpperCase(),value)}pane.append(dl);pane.append(el('div','sectionLabel','Reasons'));const reasons=event.data?.reasons?.length?event.data.reasons:[event.message];for(const reason of reasons)pane.append(el('div','reason',reason))}
function renderFindings(){const list=filtered(),start=page*pageSize,shown=list.slice(start,start+pageSize),parent=$('findings');parent.replaceChildren();if(!list.length){const empty=el('div','empty');empty.append(el('strong','',findings.length?'No matching findings':'No findings recorded'),document.createTextNode(findings.length?'Try another filter or search.':'The activity view still contains scan notices and errors.'));parent.append(empty)}for(const event of shown){const row=el('button','finding'+(selected===event?' active':''));row.type='button';row.append(severity(event.level));const title=el('div');title.append(el('div','name',event.data?.path?basename(event.data.path):event.module),el('div','sub',event.data?.path||event.message));row.append(title,el('span','score mono',event.data?.score??'—'));row.addEventListener('click',()=>{showDetail(event);renderFindings()});parent.append(row)}setText('count',list.length?`${start+1}–${Math.min(start+pageSize,list.length)} of ${list.length} findings`:'0 findings');$('prev').disabled=page===0;$('next').disabled=start+pageSize>=list.length;if(selected&&!list.includes(selected))showDetail(null);if(!selected&&shown.length)showDetail(shown[0])}
function renderActivity(){const parent=$('activity');parent.replaceChildren();const events=report.events.filter(e=>['ALERT','WARNING','NOTICE','ERROR','RESULT'].includes(e.level));for(const event of events.slice(0,500)){const row=el('div','activityItem');row.append(severity(event.level),el('span','module dim',event.module),el('span','message',event.message),el('span','mono dim',event.time.slice(11,19)));parent.append(row)}if(!events.length)parent.append(el('div','empty','No activity recorded.'));if(events.length>500)parent.append(el('div','empty',`Showing 500 of ${events.length} events. Download JSON for the full captured set.`))}
function renderSources(){const parent=$('sources');parent.replaceChildren();if(!report.sources.length){const empty=el('div','empty');empty.append(el('strong','','No source revisions recorded'),document.createTextNode('Rules may have been installed manually or before per-source manifests were introduced.'));parent.append(empty);return}const grid=el('div','sourceList');grid.append(el('div','head','Source'),el('div','head','Revision'),el('div','head','Files'));for(const source of report.sources)grid.append(el('div','',source.name),el('div','mono',source.revision.slice(0,12)),el('div','mono',source.files));parent.append(grid)}
if(!$('logo').getAttribute('src')){$('logo').hidden=true;$('logoFallback').hidden=false}
setText('target',report.target);setText('generated',formatTime(report.generated_at));setText('scanMeta',`${report.host} · ${report.mode} · ${report.coverage?.files_seen??0} seen / ${report.coverage?.contents_inspected??0} inspected`);for(const key of ['alerts','warnings','notices','errors'])setText(key,report.counts[key]);$('status').classList.add(report.status);setText('status',report.status==='clear'?'No indicators':report.status==='incomplete'?'Scan incomplete':report.status==='alert'?'Alerts detected':'Review findings');
if(report.status==='incomplete'||report.events_dropped){$('noticeBar').hidden=false;setText('noticeBar',report.status==='incomplete'?`Scan incomplete: ${report.counts.errors} error(s). Review Activity before interpreting findings.`:`Report display limit reached: ${report.events_dropped} event(s) not captured.`)}
for(const button of document.querySelectorAll('[data-tab]'))button.addEventListener('click',()=>{for(const item of document.querySelectorAll('[data-tab]'))item.classList.toggle('active',item===button);for(const name of ['findings','activity','sources'])$(name+'View').hidden=name!==button.dataset.tab});
for(const button of document.querySelectorAll('[data-filter]'))button.addEventListener('click',()=>{filter=button.dataset.filter;page=0;for(const item of document.querySelectorAll('[data-filter]'))item.classList.toggle('active',item===button);renderFindings()});
$('search').addEventListener('input',event=>{query=event.target.value.toLowerCase();page=0;renderFindings()});$('sort').addEventListener('change',event=>{sort=event.target.value;page=0;renderFindings()});$('prev').addEventListener('click',()=>{page=Math.max(0,page-1);renderFindings()});$('next').addEventListener('click',()=>{page++;renderFindings()});$('print').addEventListener('click',()=>window.print());$('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='asterscan-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});renderFindings();renderActivity();renderSources();
</script>
</body>
</html>
'''
