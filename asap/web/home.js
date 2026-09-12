'use strict';
(() => {
 const $=id=>document.getElementById(id),el=(tag,text,cls)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(cls)node.className=cls;return node;};
 const token=document.querySelector('meta[name="asap-token"]').content;
 const names={uploading:'업로드 중',queued:'대기 중',analyzing:'분석 중',completed:'완료',failed:'실패',interrupted:'중단됨'};
 let uploading=false,workspaces=[],snapshot='',refreshing=false;
 function render(){
  const query=$('workspace-search').value.trim().toLowerCase(),state=$('workspace-filter').value;
  const shown=workspaces.filter(item=>(state==='all'||item.archived===(state==='archived'))&&(!query||[item.display_name,item.original_filename,item.package_name,item.sha256,...(item.packages||[]).map(p=>p.name)].join(' ').toLowerCase().includes(query)));
  $('job-count').textContent=`${shown.length} / ${workspaces.length}개 APK`;$('jobs').replaceChildren();
  if(!shown.length)$('jobs').append(el('div',workspaces.length?'검색·보관 필터에 맞는 APK가 없습니다.':'아직 APK 워크스페이스가 없습니다. 첫 APK를 업로드하세요.','empty-state'));
  for(const item of shown){
   const card=el('article',undefined,'workspace-card'),header=el('div',undefined,'panel-title'),title=el('a',item.display_name,'workspace-card-title');
   title.href=`/workspaces/${item.id}`;header.append(title,el('span',item.archived?'보관됨':names[item.latest_job?.state]||'분석 전','badge '+(item.latest_job?.state==='completed'&&!item.archived?'new':'')));
   const info=el('p',item.package_name||((item.packages||[]).length>1?'여러 패키지':item.original_filename),'workspace-card-package');
   const identity=el('p',item.sha256?`SHA-256 ${item.sha256.slice(0,20)}…`:'원본 해시 없는 이전 기록','workspace-card-hash');
   const footer=el('div',undefined,'workspace-card-footer');footer.append(el('span',`분석 ${item.job_count}회${item.latest_job?.active==null?'':` · 최근 ${item.latest_job.active}개 관찰`}`));
   const open=el('a','워크스페이스 열기','button secondary');open.href=title.href;footer.append(open);card.append(header,info,identity,footer);$('jobs').append(card);
  }
 }
 async function refresh(){
  if(refreshing)return;refreshing=true;
  try{const response=await fetch('/api/workspaces',{cache:'no-store'});if(!response.ok)throw Error();const data=await response.json(),serialized=JSON.stringify(data);if(serialized!==snapshot){workspaces=data;snapshot=serialized;render();}}
  catch(_){if(!uploading)$('upload-status').textContent='로컬 서버 연결을 확인하세요.';}finally{refreshing=false;}
 }
 function upload(file){
  if(!file||uploading)return;
  if(!/\.(apk|apks|xapk)$/i.test(file.name)||file.size<1||file.size>512*1024*1024){$('upload-status').textContent='내용이 있는 512 MiB 이하의 APK/APKS/XAPK 파일을 선택하세요.';return;}
  uploading=true;$('apk-input').disabled=true;$('upload-progress').hidden=false;$('upload-progress').value=0;$('upload-status').textContent='APK 워크스페이스를 준비하고 있습니다.';
  const xhr=new XMLHttpRequest();xhr.open('POST',`/api/upload?name=${encodeURIComponent(file.name)}`);xhr.setRequestHeader('X-ASAP-Token',token);xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.timeout=180000;
  xhr.upload.onprogress=event=>{if(event.lengthComputable)$('upload-progress').value=Math.round(event.loaded/event.total*100);};
  const finish=message=>{uploading=false;$('apk-input').disabled=false;$('upload-progress').hidden=true;$('upload-status').textContent=message;refresh();};
  xhr.onload=()=>{let data={};try{data=JSON.parse(xhr.responseText);}catch(_){}if(xhr.status===202&&/^[a-f0-9]{32}$/.test(data.workspace_id)){location.assign(`/workspaces/${data.workspace_id}`);return;}finish(data.error||'업로드를 완료하지 못했습니다.');};
  xhr.onerror=()=>finish('네트워크 오류: 로컬 서버를 확인하세요.');xhr.ontimeout=()=>finish('업로드 시간이 초과됐습니다.');xhr.send(file);
 }
 $('apk-input').onchange=event=>{const file=event.target.files[0];event.target.value='';upload(file);};
 const zone=$('drop-zone');zone.ondragover=event=>{event.preventDefault();zone.classList.add('drag');};zone.ondragleave=()=>zone.classList.remove('drag');zone.ondrop=event=>{event.preventDefault();zone.classList.remove('drag');upload(event.dataTransfer.files[0]);};
 for(const name of ['workspace-search','workspace-filter'])$(name).addEventListener('input',render);
 refresh();setInterval(()=>{if(!document.hidden)refresh();},2500);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
})();
