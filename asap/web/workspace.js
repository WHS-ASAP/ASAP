'use strict';
(() => {
  const $=id=>document.getElementById(id);
  const el=(tag,text,cls)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(cls)node.className=cls;return node;};
  const id=document.querySelector('meta[name="asap-workspace"]').content;
  const token=document.querySelector('meta[name="asap-token"]').content;
  const states={uploading:'업로드 중',queued:'대기 중',analyzing:'분석 중',completed:'완료',failed:'실패',interrupted:'중단됨'};
  const ranks={critical:4,high:3,medium:2,low:1,info:0};
  let workspace,jobs=[],modules=[],report=null,reportJob=null,selected='',dirty=false,busy=false,refreshing=false,snapshot='';
  const stamp=value=>String(value||'').slice(0,19).replace('T',' ')+' UTC';
  const size=value=>value==null?'—':value<1024*1024?`${(value/1024).toFixed(1)} KiB`:`${(value/1024/1024).toFixed(1)} MiB`;
  function feedback(message,error=false){$('workspace-feedback').textContent=message;$('workspace-feedback').classList.toggle('warning',error);$('workspace-feedback').hidden=false;}
  async function request(path,options={}){
    const response=await fetch(path,{cache:'no-store',...options});
    const data=await response.json();
    if(!response.ok)throw Error(data.error||'요청을 처리하지 못했습니다.');
    return data;
  }
  function controls(){
    const pending=jobs.some(job=>['uploading','queued','analyzing'].includes(job.state));
    $('rescan').disabled=busy||!workspace?.scan_available||workspace.archived||pending;
    $('rescan').textContent=pending?'분석 진행 중':'다시 분석';
    $('rescan').title=workspace?.archived?'보관을 해제한 뒤 다시 분석할 수 있습니다.':!workspace?.scan_available?'보관된 원본 APK가 없습니다. 같은 APK를 다시 업로드하세요.':'';
    $('archive-workspace').disabled=busy||!workspace;
    $('archive-workspace').textContent=workspace?.archived?'보관 해제':'보관';
    $('save-workspace').disabled=busy||!workspace;
  }
  function renderWorkspace(){
    $('workspace-title').textContent=workspace.display_name;
    document.title=`${workspace.display_name} · ASAP`;
    $('workspace-subtitle').textContent=`${workspace.original_filename} · ${workspace.sha256?workspace.sha256.slice(0,16)+'…':'이전 버전의 기록'}`;
    $('workspace-state').textContent=workspace.archived?'보관됨':states[workspace.latest_job?.state]||'분석 전';
    $('workspace-runs').textContent=workspace.job_count;
    $('workspace-size').textContent=size(workspace.size_bytes);
    $('workspace-package').textContent=workspace.package_name||((workspace.packages||[]).length>1?'여러 패키지 · 정보 확인':'패키지 확인 전');
    $('workspace-active').textContent=report?report.findings.filter(f=>!f.suppressed).length:'—';
    $('workspace-high').textContent=report?report.findings.filter(f=>!f.suppressed&&ranks[f.severity]>=3).length:'—';
    $('workspace-coverage').textContent=report?(report.coverage.status==='partial'?'최근 완료 · 일부 범위 미분석':'최근 완료 · 정적 분석'):'완료된 분석 없음';
    const packages=workspace.packages||[];
    const rows=[['원본 파일',workspace.original_filename],['SHA-256',workspace.sha256||'이전 기록에 원본 해시 없음'],['패키지',packages.map(p=>`${p.name} · min ${p.min_sdk??'?'} / target ${p.target_sdk??'?'}`).join('\n')||'분석 결과에서 확인되지 않음'],['등록 시각',stamp(workspace.created_at)],['원본 보관',workspace.scan_available?'재분석 가능':'원본 없음 · 기록만 보관']];
    $('artifact-info').replaceChildren(...rows.flatMap(([key,value])=>[el('dt',key),el('dd',value)]));
    if(!dirty){$('workspace-name').value=workspace.display_name;$('workspace-note').value=workspace.note||'';}
    $('history-count').textContent=`${workspace.job_count}회`;
    $('workspace-jobs').replaceChildren();
    for(const job of jobs){
      const row=el('article',undefined,'job-card'),text=el('div'),actions=el('div',undefined,'actions');
      text.append(el('h3',job.name),el('p',`${stamp(job.created_at)}${job.active==null?'':` · ${job.active}개 관찰`}${job.coverage==='partial'?' · 일부 범위 미분석':''}`));
      if(job.message)text.append(el('p',job.message));
      actions.append(el('span',states[job.state]||job.state,'badge '+(job.state==='completed'?'new':job.state==='failed'?'high':'')));
      if(job.state==='completed'){const link=el('a','리포트 열기','button secondary');link.href=`/reports/${job.id}/report.html`;actions.append(link);}
      row.append(text,actions);$('workspace-jobs').append(row);
    }
    if(!jobs.length)$('workspace-jobs').append(el('p','아직 분석 이력이 없습니다.','empty-state'));
    controls();renderModules();
  }
  function renderModules(){
    const focused=document.activeElement?.dataset?.category;
    const enabled=report?.coverage.enabled_categories||[];
    $('modules-status').textContent=report?`최근 완료 ${stamp(reportJob.created_at)} 기준`:'완료된 결과 없이 검토 안내 보기';
    $('module-grid').replaceChildren();
    for(const module of modules){
      const findings=report?.findings.filter(f=>f.category===module.category&&!f.suppressed)||[];
      const available=report&&enabled.includes(module.category);
      const button=el('button',undefined,'module-card'+(selected===module.category?' selected':''));
      button.type='button';button.setAttribute('aria-pressed',String(selected===module.category));button.dataset.category=module.category;
      button.append(el('span',module.category,'module-name'),el('strong',available?findings.length:'—'),el('small',`${module.rule_count}개 규칙 · ${available?'관찰 항목':report?'이 분석에서 미선택':'분석 전'}`));
      button.onclick=()=>{selected=module.category;history.replaceState(null,'','#module='+encodeURIComponent(selected));renderModules();};
      $('module-grid').append(button);
    }
    renderModule();
    if(focused)Array.from($('module-grid').children).find(button=>button.dataset.category===focused)?.focus({preventScroll:true});
  }
  function fillList(target,values){$(target).replaceChildren(...(values||[]).map(value=>el('li',value)));}
  function renderModule(){
    const module=modules.find(value=>value.category===selected);
    $('module-detail').hidden=!module;if(!module)return;
    $('module-title').textContent=module.category;$('module-summary').textContent=module.summary;
    fillList('module-questions',module.review_questions);fillList('module-safe',module.safe_patterns);fillList('module-changes',module.implemented_changes);fillList('module-limitations',module.limitations);
    const enabled=report?.coverage.enabled_categories?.includes(module.category);
    $('module-report').hidden=!reportJob;
    if(reportJob)$('module-report').href=`/reports/${reportJob.id}/report.html#module=${encodeURIComponent(module.category)}`;
    const findings=(report?.findings||[]).filter(f=>f.category===selected&&!f.suppressed).sort((a,b)=>ranks[b.severity]-ranks[a.severity]);
    $('module-finding-list').replaceChildren();
    if(!enabled)$('module-finding-list').append(el('p',report?'이 분석에서 선택하지 않은 모듈입니다.':'분석 완료 후 이 APK의 관찰 결과가 표시됩니다.','empty-state'));
    else if(!findings.length)$('module-finding-list').append(el('p','관찰된 항목이 없습니다. 분석 범위와 아래 한계를 함께 확인하세요.','empty-state'));
    else{
      for(const finding of findings.slice(0,8)){
        const link=el('a',undefined,'module-finding');link.href=`/reports/${reportJob.id}/report.html#module=${encodeURIComponent(selected)}&finding=${finding.fingerprint}`;
        link.append(el('span',finding.severity.toUpperCase(),'badge '+finding.severity),el('span',`${finding.rule_id} · ${finding.title}`),el('small',`${finding.evidence.at(-1).path}:${finding.evidence.at(-1).line}`));$('module-finding-list').append(link);
      }
      if(findings.length>8)$('module-finding-list').append(el('p',`전체 ${findings.length}개 중 8개 표시 · 리포트에서 모두 검토할 수 있습니다.`,'section-description'));
    }
    $('module-rules').replaceChildren(...module.rules.map(rule=>{const row=el('p');row.append(el('strong',`${rule.id} · ${rule.title}`),el('br'),el('span',rule.description));return row;}));
    $('module-references').replaceChildren();
    for(const ref of module.references||[]){try{const url=new URL(ref.url);if(url.protocol!=='https:')continue;const link=el('a',`${ref.publisher} · ${ref.title}`,'reference-link');link.href=url.href;link.target='_blank';link.rel='noopener noreferrer';$('module-references').append(link);}catch(_){}}
  }
  async function refresh(force=false){
    if(refreshing)return;refreshing=true;
    try{
      const data=await request(`/api/workspaces/${id}`);
      const serialized=JSON.stringify(data);if(serialized===snapshot&&!force)return;
      workspace=data.workspace;jobs=data.jobs;
      const completed=jobs.find(job=>job.state==='completed');
      if(completed?.id!==reportJob?.id){
        report=null;reportJob=null;
        if(completed){try{report=await request(`/reports/${completed.id}/report.json`);reportJob=completed;}catch(_){feedback('최근 완료 리포트를 읽지 못했습니다. 분석 이력에서 상태를 확인하세요.',true);}}
      }
      snapshot=serialized;renderWorkspace();
    }catch(error){feedback(error.message,true);}finally{refreshing=false;}
  }
  async function mutate(suffix,payload,message){
    if(busy)return;busy=true;controls();
    try{
      await request(`/api/workspaces/${id}${suffix}`,{method:'POST',headers:{'X-ASAP-Token':token,'Content-Type':'application/json'},body:JSON.stringify(payload)});
      if(!suffix&&Object.hasOwn(payload,'display_name'))dirty=false;
      feedback(message);await refresh(true);
    }catch(error){feedback(error.message,true);}finally{busy=false;controls();}
  }
  $('workspace-settings').onsubmit=event=>{event.preventDefault();mutate('',{display_name:$('workspace-name').value.trim(),note:$('workspace-note').value},'워크스페이스 이름과 메모를 저장했습니다.');};
  for(const key of ['workspace-name','workspace-note'])$(key).addEventListener('input',()=>{dirty=true;});
  $('archive-workspace').onclick=()=>mutate('',{archived:!workspace.archived},workspace.archived?'워크스페이스 보관을 해제했습니다.':'워크스페이스를 보관했습니다. 목록의 보관됨 필터에서 다시 볼 수 있습니다.');
  $('rescan').onclick=()=>mutate('/scan',{},'동일 APK의 새 분석을 시작했습니다. 결과는 이 워크스페이스에 추가됩니다.');
  async function start(){
    try{modules=await request('/api/modules');const requested=new URLSearchParams(location.hash.slice(1)).get('module');selected=modules.some(m=>m.category===requested)?requested:modules[0]?.category||'';await refresh(true);}
    catch(error){feedback(error.message,true);}
  }
  window.addEventListener('hashchange',()=>{const value=new URLSearchParams(location.hash.slice(1)).get('module');if(modules.some(m=>m.category===value)){selected=value;renderModules();}});
  start();setInterval(()=>{if(!document.hidden)refresh();},2500);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
})();
