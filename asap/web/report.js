'use strict';
(() => {
  const categories = ['SQL_Injection','WebView','DeepLink','HardCoded','Permission','Insecure_DataStorage','Insecure_Logging'];
  const $ = id => document.getElementById(id);
  const el = (tag, text, cls) => { const n=document.createElement(tag); if(text!==undefined)n.textContent=String(text); if(cls)n.className=cls; return n; };
  let data, category='', selected=null, firebaseRows=[];
  const ranks={critical:4,high:3,medium:2,low:1,info:0};
  const triageNames={unreviewed:'미검토',reviewing:'검토 중',needs_fix:'수정 필요',false_positive:'오탐 판단',accepted_risk:'위험 수용'};
  let reviews=Object.create(null);
  const storageKey=()=>data.scan.apk_sha256?`asap-v3-review:apk:${data.scan.apk_sha256}:${data.scan.source_set_sha256}`:`asap-v3-review:${data.scan.source_set_sha256}`;
  let guides=[];
  try{guides=JSON.parse($('asap-guides').textContent);}catch(_){}
  const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
  const knownStatus=status=>Object.hasOwn(triageNames,status);
  function feedback(message,error=false){
    const banner=$(error?'error-banner':'review-feedback');
    banner.textContent=message;banner.hidden=false;
    $(error?'review-feedback':'error-banner').hidden=true;
  }
  function validateReviews(value,requireCurrent=true){
    if(!isObject(value)||Object.keys(value).length>100000)throw Error('검토 기록은 항목별 JSON 객체여야 합니다.');
    const fingerprints=new Set(data.findings.map(f=>f.fingerprint)),clean=Object.create(null);
    for(const [fingerprint,review] of Object.entries(value)){
      if(!/^[a-f0-9]{64}$/.test(fingerprint)||(requireCurrent&&!fingerprints.has(fingerprint)))throw Error('현재 리포트에 없는 항목의 검토 기록이 포함되어 있습니다.');
      if(!isObject(review)||!knownStatus(review.status)||typeof review.note!=='string'||review.note.length>10000||typeof review.updated_at!=='string'||!Number.isFinite(Date.parse(review.updated_at)))throw Error('검토 상태, 메모 또는 저장 날짜가 올바르지 않습니다.');
      if(['false_positive','accepted_risk'].includes(review.status)&&!review.note.trim())throw Error('오탐 판단·위험 수용에는 근거가 필요합니다.');
      clean[fingerprint]={status:review.status,note:review.note,updated_at:review.updated_at};
    }
    return clean;
  }
  function mergeStoredReviews(){
    const raw=localStorage.getItem(storageKey());
    let stored;
    try{stored=validateReviews(JSON.parse(raw||'{}'),false);}catch(_){return;}
    for(const [fingerprint,review] of Object.entries(stored)){
      if(!reviews[fingerprint]||Date.parse(review.updated_at)>Date.parse(reviews[fingerprint].updated_at))reviews[fingerprint]=review;
    }
  }
  function persistReviews(){
    try{mergeStoredReviews();localStorage.setItem(storageKey(),JSON.stringify(reviews));return true;}catch(_){return false;}
  }
  function valid(d){
    const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
    return isObject(d)&&d.schema_version==='3.0.0'&&isObject(d.tool)&&isObject(d.scan)&&hash(d.scan.source_set_sha256)
      &&(d.scan.apk_sha256===undefined||hash(d.scan.apk_sha256))
      &&(d.scan.workspace_id===undefined||(typeof d.scan.workspace_id==='string'&&/^[a-f0-9]{32}$/.test(d.scan.workspace_id)))
      &&isObject(d.coverage)&&isObject(d.inventory)&&isObject(d.summary)
      &&(d.inventory.manifests===undefined||(Array.isArray(d.inventory.manifests)&&d.inventory.manifests.every(isObject)))
      &&(d.diagnostics===undefined||(Array.isArray(d.diagnostics)&&d.diagnostics.every(isObject)))
      &&Array.isArray(d.findings)&&d.findings.length<=100000&&d.findings.every(f=>isObject(f)
        &&categories.includes(f.category)&&Object.hasOwn(ranks,f.severity)&&['high','medium','low'].includes(f.confidence)
        &&typeof f.rule_id==='string'&&hash(f.fingerprint)&&Array.isArray(f.evidence)&&f.evidence.length>0
        &&f.evidence.every(e=>isObject(e)&&typeof e.path==='string'&&Number.isInteger(e.line)&&e.line>=1)
        &&(f.references===undefined||(Array.isArray(f.references)&&f.references.every(ref=>typeof ref==='string'))));
  }
  function load(d){
    if(!valid(d))throw Error('ASAP 3.0 JSON 형식이 아닙니다.');
    data=d; selected=null; reviews=Object.create(null);
    $('error-banner').hidden=true;$('review-feedback').hidden=true;
    try{reviews=validateReviews(JSON.parse(localStorage.getItem(storageKey())||'{}'),false);}
    catch(_){feedback('브라우저의 기존 검토 기록을 읽지 못했습니다. 기록 JSON을 가져오거나 새 기록을 내보내 보관하세요.');}
    resetFilters(false);
  }
  function badge(text,cls){return el('span',text,'badge '+(cls||''));}
  function render(){
    const workspaceId=data.scan.workspace_id;
    $('workspace-return').hidden=!workspaceId||!['http:','https:'].includes(location.protocol);
    if(workspaceId)$('workspace-return').href=`/workspaces/${workspaceId}`;
    const active=data.findings.filter(f=>!f.suppressed);
    const manifests=data.inventory.manifests||[];
    $('app-name').textContent=manifests[0]?.package || data.scan.input_name || 'Android 정적 보안 검토';
    $('scan-subtitle').textContent=`${data.scan.input_name} · ${String(data.scan.started_at||'').slice(0,19).replace('T',' ')} UTC · ${data.scan.duration_seconds ?? '?'}s`;
    $('version-pill').textContent=`ASAP ${data.tool.version}`;
    $('metric-active').textContent=active.length;
    $('metric-high').textContent=active.filter(f=>ranks[f.severity]>=3).length;
    $('metric-new').textContent=active.filter(f=>f.baseline_state==='new').length;
    $('metric-files').textContent=data.coverage.selected_files??data.inventory.files?.length??0;
    $('metric-coverage').textContent=data.coverage.status==='partial'?'일부 범위 미분석 · 진단 확인':'문서화된 한계 내 분석';
    $('total-nav').textContent=active.length;
    $('category-nav').replaceChildren(); $('category-bars').replaceChildren();
    const counts=Object.fromEntries(categories.map(c=>[c,active.filter(f=>f.category===c).length]));
    const maximum=Math.max(1,...Object.values(counts));
    for(const c of categories){
      const b=el('button',c,'nav-item'+(category===c?' selected':'')); b.append(el('span',counts[c]));
      b.setAttribute('aria-pressed',String(category===c));
      b.onclick=()=>{category=c;history.replaceState(null,'','#module='+encodeURIComponent(c));render();}; $('category-nav').append(b);
      const row=el('div',undefined,'bar-row'), track=el('div',undefined,'bar-track'),fill=el('div',undefined,'bar-fill');
      fill.style.width=`${counts[c]/maximum*100}%`;track.append(fill);row.append(el('span',c),track,el('span',counts[c],'bar-value'));$('category-bars').append(row);
    }
    $('all-findings').classList.toggle('selected',!category);
    $('all-findings').setAttribute('aria-pressed',String(!category));
    $('coverage-badge').textContent=data.coverage.status==='partial'?'PARTIAL':'STATIC ONLY';
    const targets=[...new Set(manifests.map(m=>m.target_sdk).filter(x=>x!=null))];
    const rows=[['대상 SDK',targets.length?targets.join(', '):'미확인'],['언어 / 파일',Object.entries(data.coverage.languages||{}).map(([k,v])=>`${k} ${v}`).join(' · ')||'없음'],['활성 규칙',`${data.coverage.enabled_rule_count??43}개 / 7개 카테고리`],['기기 실행','수행하지 않음'],['외부 서비스 요청','엔진에서 수행하지 않음']];
    $('scope-list').replaceChildren(...rows.flatMap(([k,v])=>[el('dt',k),el('dd',v)]));
    const diagnostics=data.diagnostics||[];$('diagnostics-count').textContent=`검사 진단 ${diagnostics.length}건`;
    $('diagnostics-list').replaceChildren();
    for(const d of diagnostics){const n=el('div',undefined,'diag-item');n.append(el('code',d.code),el('span',`${d.message}${d.path?' · '+d.path:''}`));$('diagnostics-list').append(n);}
    if(!diagnostics.length)$('diagnostics-list').append(el('p','추가 진단 없음. 분석 한계는 위 범위 설명을 참고하세요.','muted'));
    $('manifest-count').textContent=`${manifests.length}개 Manifest`;$('inventory-content').replaceChildren();
    for(const m of manifests){$('inventory-content').append(el('h3',`${m.package||'미확인 패키지'} · ${m.path}`));
      $('inventory-content').append(el('pre',JSON.stringify({target_sdk:m.target_sdk,min_sdk:m.min_sdk,permissions:m.permissions,components:m.components},null,2)));}
    renderGuide();renderQueue();
  }
  function renderGuide(){
    const guide=guides.find(item=>item.category===category);
    $('module-guide').hidden=!guide;if(!guide)return;
    $('module-guide-title').textContent=`${category} · 검토 안내`;
    const content=$('module-guide-content');content.replaceChildren(el('p',guide.summary));
    const columns=el('div',undefined,'guide-columns');
    for(const [title,items] of [['확인할 사항',guide.review_questions],['권장 구현',guide.safe_patterns],['검사 항목',guide.implemented_changes],['분석 한계',guide.limitations]]){
      const section=el('div'),list=el('ul');list.append(...(items||[]).map(item=>el('li',item)));section.append(el('h3',title),list);columns.append(section);
    }
    content.append(columns);
    for(const ref of guide.references||[]){try{const url=new URL(ref.url);if(url.protocol!=='https:')continue;const link=el('a',`${ref.publisher} · ${ref.title}`,'reference-link');link.href=url.href;link.target='_blank';link.rel='noopener noreferrer';content.append(link);}catch(_){}}
  }
  function renderQueue(){
    const query=$('search').value.trim().toLowerCase(),severity=$('severity').value,confidence=$('confidence').value,reviewStatus=$('review-status').value;
    const active=data.findings.filter(f=>!f.suppressed),recorded=active.filter(f=>reviews[f.fingerprint]&&reviews[f.fingerprint].status!=='unreviewed').length;
    $('review-progress-text').textContent=`${recorded} / ${active.length}개 활성 항목에 검토 기록`;
    $('review-progress').max=Math.max(1,active.length);$('review-progress').value=recorded;
    const results=data.findings.filter(f=>(!category||f.category===category)&&(!f.suppressed||$('show-suppressed').checked)&&(!severity||f.severity===severity)&&(!confidence||f.confidence===confidence)&&(!reviewStatus||(reviews[f.fingerprint]?.status||'unreviewed')===reviewStatus)&&(!$('only-new').checked||f.baseline_state==='new')&&(!query||[f.title,f.rule_id,f.message,...f.evidence.map(e=>e.path)].join(' ').toLowerCase().includes(query))).sort((a,b)=>ranks[b.severity]-ranks[a.severity]||a.rule_id.localeCompare(b.rule_id));
    $('visible-count').textContent=results.length;$('findings-body').replaceChildren();$('empty-state').hidden=results.length>0;
    for(const f of results.slice(0,2000)){
      const e=f.evidence.at(-1),tr=el('tr',undefined,'finding-row');tr.tabIndex=0;tr.setAttribute('role','button');tr.setAttribute('aria-label',`${f.rule_id} ${f.title}`);
      const sev=el('td');sev.append(badge(f.severity.toUpperCase(),f.severity),el('small',`신뢰도 ${f.confidence}`));
      const title=el('td');title.append(el('span',`${f.rule_id} · ${f.title}`,'row-title'),el('small',`${f.category} · ${f.kind}`));
      const file=el('td');file.append(el('span',e.path,'filename'),el('small',`L${e.line}${e.end_line>e.line?'–'+e.end_line:''}`));
      const state=el('td');state.append(badge(f.suppressed?'제외됨':f.baseline_state==='new'?'NEW':'기존',f.baseline_state==='new'&&!f.suppressed?'new':''),el('small',triageNames[reviews[f.fingerprint]?.status]||'미검토'));
      tr.append(sev,title,file,state,el('td','›'));tr.onclick=()=>detail(f);tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();detail(f);}};$('findings-body').append(tr);
    }
    if(results.length>2000){const tr=el('tr'),td=el('td','최대 2,000개 행을 표시합니다. 검색·카테고리 필터로 범위를 좁히세요.');td.colSpan=5;tr.append(td);$('findings-body').append(tr);}
  }
  function renderFirebasePaths(){
    const query=$('firebase-path-search').value.trim().toLowerCase();
    const rows=firebaseRows.filter(row=>row.path.toLowerCase().includes(query));
    $('firebase-path-rows').replaceChildren();
    for(const row of rows.slice(0,200)){
      const tr=el('tr');tr.append(el('td',row.path),el('td',row.info));$('firebase-path-rows').append(tr);
    }
    $('firebase-path-count').textContent=`${rows.length} / ${firebaseRows.length}개 경로${rows.length>200?' · 처음 200개 표시, 검색으로 범위를 좁히세요.':''}`;
  }
  function showFirebasePaths(f){
    const p=isObject(f.properties)?f.properties:{};
    firebaseRows=[];$('firebase-path-search').value='';
    const add=(path,info)=>{if(typeof path==='string'&&firebaseRows.length<4096)firebaseRows.push({path,info});};
    if(f.rule_id==='DS009'&&Array.isArray(p.firebase_paths)){
      for(const path of p.firebase_paths.slice(0,4096))add(path,'소스 참조');
    }else if(f.rule_id==='DS012'&&Array.isArray(p.paths)){
      for(const node of p.paths.slice(0,4096))if(isObject(node))add(node.path,`${node.type||'unknown'} · child ${Number.isInteger(node.child_count)?node.child_count:0}`);
    }else if(['DS010','DS011'].includes(f.rule_id)){
      add(p.firebase_path,`${p.operation==='write'?'쓰기':'읽기'} 허용 선언`);
      const overridden=new Set(Array.isArray(p.child_denies_overridden)?p.child_denies_overridden:[]);
      for(const path of (Array.isArray(p.affected_child_paths)?p.affected_child_paths:[]).slice(0,4096)){
        add(path,overridden.has(path)?'자식 false · 부모 허용 상속':'부모 허용 상속');
      }
    }
    $('firebase-path-panel').hidden=firebaseRows.length===0;
    const hosts=Array.isArray(p.database_hosts)?p.database_hosts.filter(host=>typeof host==='string').slice(0,16):[];
    $('firebase-path-summary').textContent=(hosts.length?`호스트: ${hosts.join(', ')} · `:'')+
      (f.rule_id==='DS012'?'제공된 JSON의 경로와 자료형입니다.':f.rule_id==='DS009'?'소스에서 확인한 경로입니다. {dynamic}은 실행 시 결정되는 값입니다.':'제공된 Rules에 선언된 하위 경로입니다. 실제 데이터 목록과는 다를 수 있습니다.')+
      (p.truncated?' 처리 한도에 도달했습니다. 검사 진단에서 누락 범위를 확인하세요.':'');
    renderFirebasePaths();
  }
  $('firebase-path-search').addEventListener('input',renderFirebasePaths);
  function detail(f){
    selected=f;$('detail-rule').textContent=`${f.rule_id} / ${f.category}`;$('detail-title').textContent=f.title;
    $('detail-badges').replaceChildren(badge(f.severity.toUpperCase(),f.severity),badge(`Confidence: ${f.confidence}`),badge(f.cwe),badge(f.masvs));
    $('detail-message').textContent=f.message;$('detail-remediation').textContent=f.remediation;
    showFirebasePaths(f);
    $('detail-properties').textContent=JSON.stringify({...f.properties,suppressed:f.suppressed,suppression_reason:f.suppression_reason,baseline_state:f.baseline_state,fingerprint:f.fingerprint},null,2);
    $('evidence-list').replaceChildren();for(const e of f.evidence){const n=el('article',undefined,'evidence');n.append(el('header',`${e.role} · ${e.path}:${e.line}`),el('pre',e.snippet));$('evidence-list').append(n);}
    $('detail-references').replaceChildren();for(const ref of f.references||[]){try{const u=new URL(ref);if(u.protocol!=='https:')continue;const a=el('a',u.href,'reference-link');a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';$('detail-references').append(a);}catch(_){}}
    const review=reviews[f.fingerprint]||{};$('triage-status').value=knownStatus(review.status)?review.status:'unreviewed';$('triage-note').value=review.note||'';$('triage-feedback').textContent='';$('detail-dialog').showModal();
  }
  $('save-triage').onclick=()=>{
    if(!selected)return;const status=$('triage-status').value,note=$('triage-note').value.trim();
    if(!knownStatus(status)||note.length>10000){$('triage-feedback').textContent='유효한 상태와 10,000자 이하의 메모를 입력하세요.';return;}
    if(['false_positive','accepted_risk'].includes(status)&&!note){$('triage-feedback').textContent='오탐 판단·위험 수용에는 근거가 필요합니다.';return;}
    reviews[selected.fingerprint]={status,note,updated_at:new Date().toISOString()};
    $('triage-feedback').textContent=persistReviews()?'이 브라우저에 저장했습니다. 공유하려면 검토 기록을 내보내세요.':'브라우저 저장소 접근이 제한됐습니다. 화면을 닫기 전에 검토 기록을 내보내세요.';
    renderQueue();
  };
  function resetFilters(updateLocation=true){
    category='';for(const id of ['search','severity','confidence','review-status'])$(id).value='';
    $('only-new').checked=false;$('show-suppressed').checked=false;if(updateLocation)history.replaceState(null,'',location.pathname+location.search);render();
  }
  $('reset-filters').onclick=()=>resetFilters();
  $('open-report').onclick=()=>$('import-file').click();
  $('import-review-button').onclick=()=>$('import-review-file').click();
  $('import-review-file').onchange=async e=>{
    const file=e.target.files[0],reportAtStart=data;e.target.value='';if(!file)return;
    try{
      if(file.size>10*1024*1024)throw Error('10 MiB 이하의 검토 기록 JSON을 선택하세요.');
      const payload=JSON.parse(await file.text());
      if(data!==reportAtStart)throw Error('리포트가 변경되었습니다. 현재 리포트에서 다시 가져오세요.');
      if(!isObject(payload)||payload.schema_version!=='3.0.0')throw Error('ASAP 3.0 검토 기록 JSON 형식이 아닙니다.');
      if(payload.source_set_sha256!==data.scan.source_set_sha256)throw Error('다른 소스의 검토 기록입니다. 동일한 소스의 리포트에서 가져오세요.');
      if((payload.apk_sha256||null)!==(data.scan.apk_sha256||null))throw Error('다른 APK의 검토 기록입니다. 같은 APK의 리포트에서 가져오세요.');
      const incoming=validateReviews(payload.reviews);
      try{mergeStoredReviews();}catch(_){}
      let merged=0,kept=0;
      for(const [fingerprint,review] of Object.entries(incoming)){
        const existing=reviews[fingerprint];
        if(existing&&Date.parse(existing.updated_at)>=Date.parse(review.updated_at)){kept++;continue;}
        reviews[fingerprint]=review;merged++;
      }
      const saved=persistReviews();renderQueue();
      feedback(`${merged}개 검토 기록을 가져왔습니다. 기존 기록 ${kept}개 유지.${saved?' 이 브라우저에 저장했습니다.':' 브라우저 저장이 제한됐습니다. 화면을 닫기 전에 검토 기록을 내보내세요.'}`);
    }catch(err){feedback(err.message,true);}
  };
  $('export-review').onclick=()=>{
    try{mergeStoredReviews();}catch(_){}
    const current=Object.fromEntries(data.findings.filter(f=>reviews[f.fingerprint]).map(f=>[f.fingerprint,reviews[f.fingerprint]]));
    const payload={schema_version:'3.0.0',source_set_sha256:data.scan.source_set_sha256,reviews:current};
    if(data.scan.apk_sha256)payload.apk_sha256=data.scan.apk_sha256;
    const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});const a=el('a');const url=URL.createObjectURL(blob);a.href=url;a.download='asap-review-decisions.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  if(location.protocol==='file:'){
    $('report-home').href='#main-content';
    $('report-home').setAttribute('aria-label','ASAP 리포트 맨 위로 이동');
  }
  $('all-findings').onclick=()=>{category='';history.replaceState(null,'',location.pathname+location.search);render();};
  for(const id of ['search','severity','confidence','review-status','only-new','show-suppressed'])$(id).addEventListener('input',renderQueue);
  $('close-dialog').onclick=()=>$('detail-dialog').close();
  $('import-file').onchange=async e=>{const f=e.target.files[0];e.target.value='';try{if(!f)return;if(f.size>100*1024*1024)throw Error('100 MiB 이하의 JSON을 선택하세요.');load(JSON.parse(await f.text()));$('download-sarif').hidden=true;}catch(err){feedback(err.message,true);}};
  function applyLocation(){
    if(!data)return;
    const params=new URLSearchParams(location.hash.slice(1)),requested=params.get('module');
    if(categories.includes(requested)){category=requested;render();}
    const finding=data.findings.find(item=>item.fingerprint===params.get('finding'));
    if(finding){if($('detail-dialog').open)$('detail-dialog').close();detail(finding);}
  }
  window.addEventListener('hashchange',applyLocation);
  try{load(JSON.parse($('asap-data').textContent));applyLocation();}catch(err){$('error-banner').textContent=`리포트를 읽지 못했습니다: ${err.message}`;$('error-banner').hidden=false;}
})();
