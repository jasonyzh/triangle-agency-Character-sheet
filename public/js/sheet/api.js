import { S, ATTRS } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast } from './ui.js';
import { initDropdowns } from './dropdowns.js';
import { setHybridInputState } from './dropdowns.js';
import { renderTriangles } from './track.js';

export async function loadConfigData() {
    try {
        const res = await fetch('/api/options');
        if (res.ok) {
            S.CONFIG_DATA = await res.json();
            console.log("配置数据加载成功:", S.CONFIG_DATA);
            initDropdowns();
        } else { console.error("无法加载配置数据"); }
    } catch (e) { console.error("配置数据请求出错:", e); }
}

export function triggerAutoSave() {
    if (S.isReadOnly) return;
    if (S.autoSaveTimer) clearTimeout(S.autoSaveTimer);
    S.autoSaveTimer = setTimeout(() => {
        saveData(true);
    }, 1000);
}

export function gatherData() {
    const d = { pName: document.getElementById('pName').value, pAnom: document.getElementById('pAnom').value, pReal: document.getElementById('pReal').value, pFunc: document.getElementById('pFunc').value, pTrig1: document.getElementById('pTrig1').innerHTML, pTrig2: document.getElementById('pTrig2').innerHTML, pTrig3: document.getElementById('pTrig3').innerHTML, perm1: document.getElementById('perm1').value, perm2: document.getElementById('perm2').value, perm3: document.getElementById('perm3').value, pComm: document.getElementById('pComm').value, pRep: document.getElementById('pRep').value, mvpCount: document.getElementById('mvpCount').value, watchCount: document.getElementById('watchCount').value, noteTitle: document.getElementById('noteTitle').value, noteBody: document.getElementById('noteBody').innerHTML, qs: [], attrs: {}, anoms: [], reals: [], items: [], pf: [], pr: [], pa: [], pf_ign: [], pr_ign: [], pa_ign: [], derivativeProgress: [], anomSlots: S.SLOT_LIMITS.anomSlots, realSlots: S.SLOT_LIMITS.realSlots };
    for (let i = 1; i <= 7; i++) d.qs.push(document.getElementById(`q${i}`).innerHTML);
    ATTRS.forEach(a => { const container = document.querySelector(`.attr-dots[data-attr="${a}"]`), m = []; if (container) { container.querySelectorAll('.tri-btn.marked').forEach(tri => m.push(parseInt(tri.dataset.i))); } const input = document.querySelector(`.attr-input[data-attr="${a}"]`); d.attrs[a] = { v: input ? input.value : '0', m: m }; });
    document.querySelectorAll('#list-anom .card').forEach(c => { d.anoms.push({ name: c.querySelector('.f-name').value, trig: c.querySelector('.f-qual').value, qual: c.querySelector('.f-trig').value, succ: c.querySelector('.f-succ').innerHTML, fail: c.querySelector('.f-fail').innerHTML, chk: c.querySelector('.f-chk').checked, tdesc: c.querySelector('.f-tdesc').value, t1: c.querySelector('.f-t1').value, t1v: c.querySelector('.f-t1-val').value, t2: c.querySelector('.f-t2').value, t2v: c.querySelector('.f-t2-val').value, p1: Array.from(c.querySelectorAll('.d1 .sq-dot')).map(e => e.classList.contains('active')), p2: Array.from(c.querySelectorAll('.d2 .sq-dot')).map(e => e.classList.contains('active')) }); });
    document.querySelectorAll('#list-real .card').forEach(c => { let l = 0; c.querySelectorAll('.r-dots-hidden .dot').forEach((e, i) => { if (e.classList.contains('active')) l = i + 1 }); d.reals.push({ name: c.querySelector('.f-name').value, actor: c.querySelector('.f-actor').value, desc: c.querySelector('.f-desc').innerHTML, act: c.querySelector('.f-act').checked, conn: c.querySelector('.f-conn').innerHTML, lvl: l }); });
    document.querySelectorAll('#list-item .card').forEach(c => { d.items.push({ item: c.querySelector('.f-item').value, pd: c.querySelector('.f-pd').value, eff: c.querySelector('.f-eff').innerHTML, once: c.querySelector('.f-once').value === '1' }); });
    document.querySelectorAll('.f-cell.active').forEach(e => d.pf.push(parseInt(e.dataset.idx)));
    document.querySelectorAll('.r-cell.active').forEach(e => d.pr.push(parseInt(e.dataset.idx)));
    document.querySelectorAll('.a-cell.active').forEach(e => d.pa.push(parseInt(e.dataset.idx)));
    document.querySelectorAll('.f-cell.ignored').forEach(e => d.pf_ign.push(parseInt(e.dataset.idx)));
    document.querySelectorAll('.r-cell.ignored').forEach(e => d.pr_ign.push(parseInt(e.dataset.idx)));
    document.querySelectorAll('.a-cell.ignored').forEach(e => d.pa_ign.push(parseInt(e.dataset.idx)));
    d.derivativeProgress = [];
    document.querySelectorAll('.progress-cell.active').forEach(e => d.derivativeProgress.push(parseInt(e.dataset.idx)));
    return d;
}

export function populateData(d) {
    S.lastAssessmentAttributes = [];

    S.SLOT_LIMITS.anomSlots = d.anomSlots || 10;
    S.SLOT_LIMITS.realSlots = d.realSlots || 10;
    ['pName', 'pTrig1', 'pTrig2', 'pTrig3', 'perm1', 'perm2', 'perm3', 'pComm', 'pRep', 'mvpCount', 'watchCount', 'noteTitle', 'noteBody'].forEach(id => { const e = document.getElementById(id); if (d[id] && e) { if (e.tagName === 'DIV') e.innerHTML = d[id]; else e.value = d[id]; } });
    document.getElementById('mvpCount').value = d.mvpCount || (d.rewards || []).reduce((sum, r) => sum + (r.count || 1), 0);
    document.getElementById('watchCount').value = d.watchCount || (d.reprimands || []).reduce((sum, r) => sum + (r.count || 1), 0);
    setHybridInputState('pAnom', d.pAnom); setHybridInputState('pReal', d.pReal); setHybridInputState('pFunc', d.pFunc); if (d.qs) d.qs.forEach((h, i) => { const q = document.getElementById(`q${i + 1}`); if (q) q.innerHTML = h; }); if (d.attrs) { for (let k in d.attrs) { const r = document.querySelector(`.attr-input[data-attr="${k}"]`); if (r) { r.value = d.attrs[k].v; renderTriangles(k, d.attrs[k].v); const container = document.querySelector(`.attr-dots[data-attr="${k}"]`); if (container && d.attrs[k].m) { d.attrs[k].m.forEach(idx => { const tri = container.querySelector(`.tri-btn[data-i="${idx}"]`); if (tri) { tri.classList.remove('active'); tri.classList.add('marked'); } }); } } } } document.getElementById('list-anom').innerHTML = ''; document.getElementById('list-real').innerHTML = ''; document.getElementById('list-item').innerHTML = '';
    (d.anoms || []).forEach(x => window.addAnom(x, false, true));
    (d.reals || []).forEach(x => { const card = window.addReal(x, true); if (card) document.getElementById('list-real').appendChild(card); });
    (d.items || []).forEach(x => window.addItem(x, false));
    if (!document.getElementById('list-anom').children.length) window.addAnom(null, false, true);
    if (!document.getElementById('list-real').children.length) { const card = window.addReal(null, true); if (card) document.getElementById('list-real').appendChild(card); }
    if (!document.getElementById('list-item').children.length) window.addItem(null, false);
    (d.pf || []).forEach(i => document.querySelector(`.f-cell[data-idx="${i}"]`)?.classList.add('active')); (d.pr || []).forEach(i => document.querySelector(`.r-cell[data-idx="${i}"]`)?.classList.add('active')); (d.pa || []).forEach(i => document.querySelector(`.a-cell[data-idx="${i}"]`)?.classList.add('active')); (d.pf_ign || []).forEach(i => document.querySelector(`.f-cell[data-idx="${i}"]`)?.classList.add('ignored')); (d.pr_ign || []).forEach(i => document.querySelector(`.r-cell[data-idx="${i}"]`)?.classList.add('ignored')); (d.pa_ign || []).forEach(i => document.querySelector(`.a-cell[data-idx="${i}"]`)?.classList.add('ignored'));
    if (d.derivativeProgress) { d.derivativeProgress.forEach(i => document.querySelector(`.progress-cell[data-idx="${i}"]`)?.classList.add('active')); }
    window.updateSlotButtons();
    window.syncCharDisplay();
}

export async function saveData(silent = false) {
    if (S.isReadOnly) return;
    const d = gatherData();
    const res = await fetch(`/api/character/${S.charId}`, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify(d) });
    if (res.ok) { if (!silent) { showToast('DATA_SAVED', 'success'); } } else if (res.status === 401 || res.status === 403) { window.location.href = 'login.html'; } else { if (!silent) { showToast('保存失败', 'error'); } }
}

export async function exportOffline() {
    const d = gatherData();
    const dataJson = JSON.stringify(d);
    let cssText = '', jsText = '';
    try { const r = await fetch('css/sheet.css'); if (r.ok) cssText = await r.text(); } catch (e) { }
    try { const r = await fetch('js/sheet.js'); if (r.ok) jsText = await r.text(); } catch (e) { }
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no,viewport-fit=cover"/>
<title>${(d.pName || '角色')}_离线备份 // TRIANGLE AGENCY</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>${cssText}</style>
</head>
<body class="offline-mode">
<div id="status-msg"><i class="fas fa-save"></i> DATA_SAVED</div>
<div class="container">
<div class="top-nav">
    <button class="btn-back" onclick="window.close()"><i class="fas fa-chevron-left"></i> 关闭</button>
    <div class="brand-logo-sm"><span>TRIANGLE</span><span>AGENCY</span></div>
    <div class="header-right">
        <h1>职员档案 <span class="sub"><span class="offline-tag">OFFLINE</span></span></h1>
    </div>
</div>
<div class="swiper-container" id="swiperContainer">
<div class="swiper-wrapper" id="swiperWrapper">
<div id="view-char" class="tab-view">
<div class="char-layout">
<div class="panel"><h2><i class="fas fa-shield-alt"></i> 资质保证<button class="btn-reset-all-attrs" onclick="resetAllAttrs()" title="重置所有标记">↻</button></h2><div id="attrs-list"></div></div>
<div class="panel">
<h2><i class="fas fa-id-card"></i> 基础信息</h2>
<label>玩家姓名</label><input type="text" id="pName" placeholder="输入姓名">
<div class="row-2">
<div><label>异常能力</label><div class="hybrid-input-wrapper" id="grp-pAnom"><select id="sel-pAnom" onchange="handlePresetChange('pAnom', this.value)"></select><input type="text" id="pAnom" placeholder="输入异常能力"><button class="btn-reset-list" onclick="resetToDropdown('pAnom')"><i class="fas fa-list"></i></button></div></div>
<div><label>现实身份</label><div class="hybrid-input-wrapper" id="grp-pReal"><select id="sel-pReal" onchange="handlePresetChange('pReal', this.value)"></select><input type="text" id="pReal" placeholder="输入现实身份"><button class="btn-reset-list" onclick="resetToDropdown('pReal')"><i class="fas fa-list"></i></button></div></div>
</div>
<label>机构职能</label><div class="hybrid-input-wrapper" id="grp-pFunc"><select id="sel-pFunc" onchange="handlePresetChange('pFunc', this.value)"></select><input type="text" id="pFunc" placeholder="输入机构职能"><button class="btn-reset-list" onclick="resetToDropdown('pFunc')"><i class="fas fa-list"></i></button></div>
<label>过载解除</label><div class="rich-editor" id="pTrig1" contenteditable="true" placeholder="如何解除过载"></div>
<label>现实触发器</label><div class="rich-editor" id="pTrig2" contenteditable="true" placeholder="GM可随时触发此项"></div>
<label>现实计数</label>
<div class="derivative-progress">
    <div class="progress-cell" data-idx="1"><span class="cell-number">1</span></div>
    <div class="progress-cell" data-idx="2"><span class="cell-number">2</span></div>
    <div class="progress-cell" data-idx="3"><span class="cell-number">3</span></div>
    <div class="progress-cell" data-idx="4"><span class="cell-number">4</span></div>
</div>
<label>首要指令</label><div class="rich-editor" id="pTrig3" contenteditable="true" placeholder="如果你……，则获得1点申诫"></div>
<label>许可行为</label><div class="perm-group"><input type="text" id="perm1" placeholder="许可行为 1"><input type="text" id="perm2" placeholder="许可行为 2"><input type="text" id="perm3" placeholder="许可行为 3"></div>
<div class="perm-note">如果你在单次任务中完成全部 3 项，将获得 3 点额外嘉奖。</div>
</div>
</div>
<div class="panel">
<h2><i class="fas fa-chart-bar"></i> 进度追踪</h2>
<div class="track-header">
<div class="track-stat"><label>MVP</label><input type="text" id="pComm" placeholder="0"></div>
<div class="track-stat"><label>嘉奖</label><input type="text" id="mvpCount" placeholder="0" readonly></div>
<div class="track-stat"><label>申诫</label><input type="text" id="watchCount" placeholder="0" readonly></div>
<div class="track-stat"><label>察看期</label><input type="text" id="pRep" placeholder="0"></div>
</div>
<div class="track-sec"><h3 class="c-func" style="font-size:12px; margin:5px 0;">职能</h3><div class="track-row-wrap"><svg class="track-svg" data-type="f"></svg><div class="track-snake" data-type="f"><div class="p-cell f-cell" data-idx="1"></div><div class="p-cell f-cell" data-idx="2"></div><div class="p-cell f-cell" data-idx="3"><span>A3</span></div><div class="p-cell f-cell" data-idx="4"></div><div class="p-cell f-cell" data-idx="5"></div><div class="p-cell f-cell" data-idx="6"><span>D4</span></div><div class="p-cell f-cell" data-idx="7"></div><div class="p-cell f-cell" data-idx="8"></div><div class="p-cell f-cell" data-idx="9"><span>G3</span></div><div class="p-cell f-cell" data-idx="10"></div><div class="p-cell f-cell" data-idx="11"></div><div class="p-cell f-cell" data-idx="12"><span>J3</span></div><div class="p-cell f-cell" data-idx="13"></div><div class="p-cell f-cell" data-idx="14"></div><div class="p-cell f-cell" data-idx="15"><span>N3</span></div><div class="p-cell f-cell" data-idx="30"></div><div class="p-cell f-cell" data-idx="29"></div><div class="p-cell f-cell" data-idx="28"></div><div class="p-cell f-cell" data-idx="27"><span>Y2</span></div><div class="p-cell f-cell" data-idx="26"></div><div class="p-cell f-cell" data-idx="25"></div><div class="p-cell f-cell" data-idx="24"><span>W8</span></div><div class="p-cell f-cell" data-idx="23"></div><div class="p-cell f-cell" data-idx="22"></div><div class="p-cell f-cell" data-idx="21"><span>T3</span></div><div class="p-cell f-cell" data-idx="20"></div><div class="p-cell f-cell" data-idx="19"></div><div class="p-cell f-cell" data-idx="18"><span>Q3</span></div><div class="p-cell f-cell" data-idx="17"></div><div class="p-cell f-cell" data-idx="16"></div></div></div><div class="track-rule">当你获得任务MVP时，在你的职能记录条上标记1格，且无需从其他记录条上移除一格。</div><div class="track-rule">每当你在职能记录条上标记一格时，将任意一项资质的"资质保证上限"提升1点，最高不超过9点。</div></div>
<div class="track-sec"><h3 class="c-real" style="font-size:12px; margin:5px 0;">现实</h3><div class="track-row-wrap"><svg class="track-svg" data-type="r"></svg><div class="track-snake" data-type="r"><div class="p-cell r-cell" data-idx="1"><span>C4</span></div><div class="p-cell r-cell" data-idx="2"></div><div class="p-cell r-cell" data-idx="3"></div><div class="p-cell r-cell" data-idx="4"><span>L11</span></div><div class="p-cell r-cell" data-idx="5"></div><div class="p-cell r-cell" data-idx="6"></div><div class="p-cell r-cell" data-idx="7"></div><div class="p-cell r-cell" data-idx="8"><span>E2</span></div><div class="p-cell r-cell" data-idx="9"></div><div class="p-cell r-cell" data-idx="10"><span>O4</span></div><div class="p-cell r-cell" data-idx="11"></div><div class="p-cell r-cell" data-idx="12"><span>J3</span></div><div class="p-cell r-cell" data-idx="13"></div><div class="p-cell r-cell" data-idx="14"><span>T6</span></div><div class="p-cell r-cell" data-idx="15"></div><div class="p-cell r-cell" data-idx="30"></div><div class="p-cell r-cell" data-idx="29"></div><div class="p-cell r-cell" data-idx="28"></div><div class="p-cell r-cell" data-idx="27"><span>E3</span></div><div class="p-cell r-cell" data-idx="26"></div><div class="p-cell r-cell" data-idx="25"></div><div class="p-cell r-cell" data-idx="24"></div><div class="p-cell r-cell" data-idx="23"></div><div class="p-cell r-cell" data-idx="22"><span>H5</span></div><div class="p-cell r-cell" data-idx="21"></div><div class="p-cell r-cell" data-idx="20"><span>X3</span></div><div class="p-cell r-cell" data-idx="19"></div><div class="p-cell r-cell" data-idx="18"></div><div class="p-cell r-cell" data-idx="17"></div><div class="p-cell r-cell" data-idx="16"><span>V2</span></div></div></div><div class="track-rule">当你既未获得任务MVP也未进入察看期时，你可以将你与任意一段关系的连结提升1点。</div><div class="track-rule">每当你在现实记录条上标记一格时，将你与任意一段"关系"的"连结"提升1点，然后对关系网内的每段关系重复此操作。</div></div>
<div class="track-sec"><h3 class="c-anom" style="font-size:12px; margin:5px 0;">异常</h3><div class="track-row-wrap"><svg class="track-svg" data-type="a"></svg><div class="track-snake" data-type="a"><div class="p-cell a-cell" data-idx="1"><span>H4</span></div><div class="p-cell a-cell" data-idx="2"><span>H3</span></div><div class="p-cell a-cell" data-idx="3"></div><div class="p-cell a-cell" data-idx="4"></div><div class="p-cell a-cell" data-idx="5"><span>U2</span></div><div class="p-cell a-cell" data-idx="6"></div><div class="p-cell a-cell" data-idx="7"><span>X2</span></div><div class="p-cell a-cell" data-idx="8"></div><div class="p-cell a-cell" data-idx="9"></div><div class="p-cell a-cell" data-idx="10"></div><div class="p-cell a-cell" data-idx="11"><span>N1</span></div><div class="p-cell a-cell" data-idx="12"></div><div class="p-cell a-cell" data-idx="13"><span>Q2</span></div><div class="p-cell a-cell" data-idx="14"></div><div class="p-cell a-cell" data-idx="15"></div><div class="p-cell a-cell" data-idx="30"></div><div class="p-cell a-cell" data-idx="29"></div><div class="p-cell a-cell" data-idx="28"></div><div class="p-cell a-cell" data-idx="27"></div><div class="p-cell a-cell" data-idx="26"></div><div class="p-cell a-cell" data-idx="25"></div><div class="p-cell a-cell" data-idx="24"></div><div class="p-cell a-cell" data-idx="23"><span>A7</span></div><div class="p-cell a-cell" data-idx="22"></div><div class="p-cell a-cell" data-idx="21"></div><div class="p-cell a-cell" data-idx="20"></div><div class="p-cell a-cell" data-idx="19"><span>G8</span></div><div class="p-cell a-cell" data-idx="18"></div><div class="p-cell a-cell" data-idx="17"><span>L10</span></div><div class="p-cell a-cell" data-idx="16"></div></div></div><div class="track-rule">当你进入察看期时，在你的异常记录条上标记1格，且无需从其他记录条上移除一格。</div><div class="track-rule">每当你在异常记录条上标记一格时，选择一项：<br>➤练习：在任意一项异常能力上标记"熟练"。 <br>➤广为人知：从一项异常能力中移除"熟练"标记，并向你的团队提出该能力的问题。在获得最多票数的答案轨道上做标记，然后获得所有已解锁的能力。</div></div>
</div>
<div class="panel"><h2><i class="fas fa-file-contract"></i> 欢迎你，特工！</h2><div style="margin-bottom:12px;"><label>1. 你是如何与你的异常接触的？</label><div class="rich-editor" id="q1" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>2. 机构是如何找到你的？</label><div class="rich-editor" id="q2" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>3. 你的能力有独特的外在视觉表现吗？</label><div class="rich-editor" id="q3" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>4. 你喝咖啡有什么偏好？</label><div class="rich-editor" id="q4" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>5. 请描述你过往的工作经历</label><div class="rich-editor" id="q5" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>6. 你对Adobe、Excel和Google套件的熟悉程度如何？</label><div class="rich-editor" id="q6" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>7. 在协作工作环境中，你能做出什么贡献？</label><div class="rich-editor" id="q7" contenteditable="true"></div></div></div>
<div class="panel"><h2><i class="fas fa-sticky-note"></i> 备注/笔记</h2><label>标题</label><input type="text" id="noteTitle" style="margin-bottom: 12px; font-weight: bold;"><label>内容</label><div class="rich-editor" id="noteBody" contenteditable="true" placeholder="摘要..."></div></div>
</div>
 <div id="view-anom" class="tab-view"><div class="mod-header"><h2>异常能力</h2><button class="btn-u2-unleash" id="btnU2Unleash" style="display:none" onclick="confirmU2Unleash()"><i class="fas fa-eye"></i></button><button class="btn-add" onclick="addAnom(null, false)"><i class="fas fa-plus"></i> 添加</button></div><div id="list-anom"></div></div>
<div id="view-real" class="tab-view"><div class="mod-header"><h2>关系网</h2><button class="btn-add" onclick="addRealSafe()"><i class="fas fa-plus"></i> 添加</button></div><div id="list-real"></div></div>
<div id="view-item" class="tab-view"><div class="mod-header"><h2>申领物/福利</h2><button class="btn-add" onclick="addItem(null, false)"><i class="fas fa-plus"></i> 添加</button></div><div id="list-item"></div></div>
</div>
</div>
</div>
<div class="nav-bar">
<div class="nav-btn active n-board" onclick="switchView('view-board', this)"><i class="fas fa-desktop"></i><span>画板</span></div>
<div class="nav-btn n-char" onclick="switchView('view-char', this)"><i class="fas fa-id-badge"></i><span>档案</span></div>
<div class="nav-btn n-anom" onclick="openAnomWindow()"><i class="fas fa-bolt"></i><span>异常</span></div>
<div class="nav-btn n-real" onclick="openRealPhone()"><i class="fas fa-heart"></i><span>关系</span></div>
<div class="nav-btn n-item" onclick="openBriefcase()"><i class="fas fa-box-open"></i><span>物品</span></div>
</div>
<div id="anomEditModal" class="anom-edit-modal" onclick="event.target===this&&closeAnomCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-bolt" style="color:var(--accent)"></i> 编辑异常能力</h3>
            <button class="anom-edit-close" onclick="closeAnomCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>能力名称</label><input type="text" class="anom-edit-name" placeholder="能力名称"></div>
                <div><label><i class="fas fa-bolt"></i> 触发器</label><input type="text" class="anom-edit-trig" placeholder="触发器"></div>
            </div>
            <label><i class="fas fa-star"></i> 资质</label><input type="text" class="anom-edit-qual" placeholder="资质">
            <div class="anom-edit-row-2">
                <div><label style="color:var(--accent)"><i class="fas fa-check-circle"></i> 成功时</label><div class="rich-editor anom-edit-succ" contenteditable="true"></div></div>
                <div><label style="color:#c0392b"><i class="fas fa-times-circle"></i> 失败时</label><div class="rich-editor anom-edit-fail" contenteditable="true"></div></div>
            </div>
            <div class="anom-edit-divider"></div>
            <label><i class="fas fa-question-circle"></i> 问题</label>
            <div class="anom-edit-q-row"><input type="text" class="anom-edit-tdesc" placeholder="问题"><label class="chk-btn chk-trained"><input type="checkbox" class="anom-edit-chk"><span></span></label></div>
            <div class="anom-edit-a-row"><input type="text" class="anom-edit-t1" placeholder="答案1"><input type="text" class="small-input anom-edit-t1v" placeholder="值"><div class="sq-dots anom-edit-d1"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div></div>
            <div class="anom-edit-a-row"><input type="text" class="anom-edit-t2" placeholder="答案2"><input type="text" class="small-input anom-edit-t2v" placeholder="值"><div class="sq-dots anom-edit-d2"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div></div>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" onclick="saveAnomCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<div id="realEditModal" class="anom-edit-modal" onclick="event.target===this&&closeRealCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-heart" style="color:var(--reality)"></i> 编辑关系</h3>
            <button class="anom-edit-close" onclick="closeRealCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>姓名</label><input type="text" class="real-edit-name" placeholder="姓名"></div>
                <div><label>扮演者</label><input type="text" class="real-edit-actor" placeholder="扮演者"></div>
            </div>
            <label><i class="fas fa-align-left"></i> 描述</label><div class="rich-editor real-edit-desc" contenteditable="true" placeholder="描述"></div>
            <div class="anom-edit-divider"></div>
            <label><i class="fas fa-link"></i> 连结进度</label>
            <div class="real-edit-lvl-row">
                <button class="real-lvl-btn" onclick="const v=document.querySelector('.real-edit-lvl');v.value=Math.max(0,parseInt(v.value||0)-1);updateRealLvlDots(v.value)">-</button>
                <div class="real-edit-lvl-dots"><div class="dot" data-i="1"></div><div class="dot" data-i="2"></div><div class="dot" data-i="3"></div><div class="dot" data-i="4"></div><div class="dot" data-i="5"></div><div class="dot" data-i="6"></div><div class="dot" data-i="7"></div><div class="dot" data-i="8"></div><div class="dot" data-i="9"></div></div>
                <button class="real-lvl-btn" onclick="const v=document.querySelector('.real-edit-lvl');v.value=Math.min(9,parseInt(v.value||0)+1);updateRealLvlDots(v.value)">+</button>
                <input type="hidden" class="real-edit-lvl" value="0">
                <label class="chk-btn"><input type="checkbox" class="real-edit-act"><span></span></label>
            </div>
            <label><i class="fas fa-gift"></i> 连结加成</label><div class="hybrid-input-wrapper has-editor"><select class="real-edit-conn-sel" onchange="handleRealBonusChange(this)"></select><div class="rich-editor real-edit-conn" contenteditable="true" placeholder="选择预设或输入加成效果..."></div><button class="btn-reset-list" onclick="resetRealBonus(this)"><i class="fas fa-list"></i></button></div>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" style="background:var(--reality)" onclick="saveRealCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<div id="itemEditModal" class="anom-edit-modal" onclick="event.target===this&&closeItemCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-box-open" style="color:var(--functional)"></i> 编辑申领物</h3>
            <button class="anom-edit-close" onclick="closeItemCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>物品名称</label><input type="text" class="item-edit-name" placeholder="物品名称"></div>
                <div><label>页面/PD码</label><input type="text" class="item-edit-pd" placeholder="页面/PD码"></div>
            </div>
            <label><i class="fas fa-magic"></i> 效果</label>
            <div class="rich-editor item-edit-eff" contenteditable="true" placeholder="效果描述..."></div>
            <div class="anom-edit-divider"></div>
            <label class="chk-btn chk-once" style="margin-top:10px"><input type="checkbox" class="item-edit-once"><span></span></label>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" style="background:var(--functional)" onclick="saveItemCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<script id="__SAVED_DATA__" type="application/json">${dataJson}<\/script>
<script>${jsText}<\/script>
<div class="nav-arrow arrow-left" onclick="moveTab(-1)"><i class="fas fa-caret-left"></i></div>
<div class="nav-arrow arrow-right" onclick="moveTab(1)"><i class="fas fa-caret-right"></i></div>
</body>
</html>`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    a.download = `${d.pName || '角色'}_离线备份.html`;
    a.click();
}
