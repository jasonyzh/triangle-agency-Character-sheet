import { S, navBtns } from './state.js';
import { setRandomVars } from './ui.js';
import { showToast } from './ui.js';

function createDelBtn(type) {
    return `<button class="btn-del" onclick="deleteCard(this, '${type}')">×</button>`;
}

export function deleteCard(btn, type) {
    if (!confirm('确定删除?')) return;
    btn.parentElement.remove();
    updateSlotButtons();
}

export function updateSlotButtons() {
    const anomCount = document.querySelectorAll('#list-anom .card').length;
    const realCount = document.querySelectorAll('#list-real .card').length;
    const btnAddAnom = document.querySelector('#view-anom .btn-add');
    const btnAddReal = document.querySelector('.phone-title');
    if (btnAddAnom) {
        if (anomCount >= S.SLOT_LIMITS.anomSlots) {
            btnAddAnom.disabled = true; btnAddAnom.innerHTML = `<i class="fas fa-lock"></i> 已满 (${anomCount}/${S.SLOT_LIMITS.anomSlots})`; btnAddAnom.style.opacity = '0.5'; btnAddAnom.style.cursor = 'not-allowed';
        } else {
            btnAddAnom.disabled = false; btnAddAnom.innerHTML = `<i class="fas fa-plus"></i> 添加 (${anomCount}/${S.SLOT_LIMITS.anomSlots})`; btnAddAnom.style.opacity = '1'; btnAddAnom.style.cursor = 'pointer';
        }
    }
    if (btnAddReal) {
        var pc = document.getElementById('phoneCount');
        if (realCount >= S.SLOT_LIMITS.realSlots) {
            btnAddReal.disabled = true; btnAddReal.style.opacity = '0.5'; btnAddReal.style.cursor = 'not-allowed';
            if (pc) pc.textContent = '(' + realCount + '/' + S.SLOT_LIMITS.realSlots + ')';
        } else {
            btnAddReal.disabled = false; btnAddReal.style.opacity = '1'; btnAddReal.style.cursor = 'pointer';
            if (pc) pc.textContent = '(' + realCount + '/' + S.SLOT_LIMITS.realSlots + ')';
        }
    }
}

export { createDelBtn };

export function addAnom(d = null, prepend = false, skipCheck = false) {
    if (S.isReadOnly && !d) return;
    if (!skipCheck && !d) {
        const currentCount = document.querySelectorAll('#list-anom .card').length;
        if (currentCount >= S.SLOT_LIMITS.anomSlots) {
            showToast('异常能力槽位已满，请联系经理解锁更多槽位', 'error');
            return;
        }
    }
    const div = document.createElement('div'); div.className = 'card bd-anom anom-card'; div.innerHTML = `<button class="anom-card-edit-btn" onclick="openAnomCardEdit(this.closest('.anom-card'))"><i class="fas fa-pen"></i></button>${createDelBtn('anom')}<input type="hidden" class="f-name"><input type="hidden" class="f-trig"><input type="hidden" class="f-qual"><input type="hidden" class="f-passive" value="0"><input type="hidden" class="f-tdesc"><input type="hidden" class="f-t1"><input type="hidden" class="f-t1-val"><input type="hidden" class="f-t2"><input type="hidden" class="f-t2-val"><input type="hidden" class="f-t3"><input type="hidden" class="f-t3-val"><input type="hidden" class="f-p1n" value="3"><input type="hidden" class="f-p2n" value="3"><input type="hidden" class="f-p3n" value="3"><input type="checkbox" class="f-chk" style="display:none"><div class="sq-dots d1" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="sq-dots d2" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="sq-dots d3" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="rich-editor f-succ" contenteditable="true" style="display:none"></div><div class="rich-editor f-fail" contenteditable="true" style="display:none"></div><div class="anom-title-bar"><div class="anom-title-row"><button class="anom-mode-toggle" onclick="toggleAnomPassive(this.closest('.anom-card'))" title="切换主动/被动"><i class="fas fa-bolt"></i></button><span class="anom-disp-name"></span><span class="anom-field-sep">|</span><span class="anom-disp-trig"></span></div><div class="anom-disp-qual-row"><span class="anom-disp-qual"></span></div></div><div class="anom-body"><div class="anom-result-row"><div class="anom-result succ-section"><div class="anom-result-label c-anom"><i class="fas fa-check-circle"></i> 成功时</div><div class="anom-disp-succ"></div></div><div class="anom-result fail-section"><div class="anom-result-label" style="color:#c0392b"><i class="fas fa-times-circle"></i> 失败时</div><div class="anom-disp-fail"></div></div></div></div><div class="anom-question-section"><div class="anom-disp-question"></div><div class="anom-disp-answers"><div class="anom-disp-a1"></div><div class="anom-disp-a2"></div><div class="anom-disp-a3"></div></div></div>`;
    setupSq(div); if (d) fillAnom(div, d); setRandomVars(div); syncAnomDisplay(div);
    const container = document.getElementById('list-anom');
    if (prepend) { container.prepend(div); } else { container.appendChild(div); }
    updateSlotButtons();
}

export function getBonusOptions() {
    let opts = '<option value="" disabled selected>-- 选择连结加成 --</option>';
    if (S.CONFIG_DATA.bonuses && Array.isArray(S.CONFIG_DATA.bonuses)) {
        S.CONFIG_DATA.bonuses.forEach(b => {
            const val = typeof b === 'string' ? b : (b.content || b.name);
            const name = typeof b === 'string' ? b : b.name;
            let displayName = name;
            if (displayName.length > 20) { displayName = displayName.substring(0, 20) + '...'; }
            const safeVal = val.replace(/"/g, '&quot;');
            opts += `<option value="${safeVal}">${displayName}</option>`;
        });
    }
    opts += '<option value="__CUSTOM__">➤ 自定义 / 手动输入...</option>';
    return opts;
}

export function handleBonusChange(select) {
    const wrapper = select.parentElement;
    const editor = wrapper.querySelector('.rich-editor');
    const val = select.value;
    wrapper.classList.add('show-input');
    if (val === '__CUSTOM__') { editor.focus(); }
    else { editor.innerHTML = val; }
}

export function resetBonus(btn) {
    const wrapper = btn.parentElement;
    const select = wrapper.querySelector('select');
    wrapper.classList.remove('show-input');
    select.value = '';
}

export function get3Sq() { return ` <div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div> `; }
export function get9Dots() { return Array(9).fill(0).map((_, i) => `<div class="dot" data-i="${i + 1}"></div>`).join(''); }

function bindSqDot(dot) {
    dot.onclick = () => { if (!S.isReadOnly) dot.classList.toggle('active'); };
    // 右键：涂抹计数器（当前点及右边全部变灰），卡片只显示未涂抹的
    dot.oncontextmenu = (e) => {
        e.preventDefault();
        if (S.isReadOnly) return;
        const container = dot.parentElement;
        const card = container.closest('.anom-card');
        if (!card) return;
        const cls = container.className.split(' ').find(c => /^d[123]$/.test(c));
        if (!cls) return;
        const pnInput = card.querySelector('.f-' + cls + 'n');
        const cur = pnInput ? (parseInt(pnInput.value) || 3) : 3;
        const idx = Array.from(container.querySelectorAll('.sq-dot')).indexOf(dot) + 1;
        // idx 在未涂区：涂抹 idx 及右边；在已涂区：恢复
        const next = idx <= cur ? Math.max(1, idx - 1) : Math.min(3, idx);
        if (pnInput) pnInput.value = next;
        const hadActive = Array.from(container.querySelectorAll('.sq-dot')).map(x => x.classList.contains('active'));
        applyDotsCount(card, cls, next);
        container.querySelectorAll('.sq-dot').forEach((d2, i) => {
            if (i < next && hadActive[i]) d2.classList.add('active');
            bindSqDot(d2);
        });
        window.triggerAutoSave();
    };
}

export function setupSq(div) {
    div.querySelectorAll('.sq-dot').forEach(bindSqDot);
}

// 涂抹数计算：右键第 idx 个点（1-based），返回新的可用点数
function smearNext(cur, idx) {
    if (idx <= cur) return Math.max(1, idx - 1); // 涂抹 idx 及右边
    return Math.min(3, idx);                      // 恢复（在已涂区）
}

export function setupRDots(div) {
    const d = div.querySelectorAll('.r-dots .dot');
    d.forEach(dot => {
        dot.onclick = () => {
            if (S.isReadOnly) return;
            const idx = parseInt(dot.dataset.i);
            d.forEach((dd, i) => { if (i < idx) dd.classList.add('active'); else dd.classList.remove('active'); });
        };
    });
}

// 标题栏一键切换主动/被动
export function toggleAnomPassive(card) {
    if (S.isReadOnly) return;
    const input = card.querySelector('.f-passive');
    input.value = input.value === '1' ? '0' : '1';
    syncAnomDisplay(card);
    window.triggerAutoSave();
}

export function fillAnom(div, d) {
    div.querySelector('.f-name').value = d.name || '';
    div.querySelector('.f-trig').value = d.qual || '';
    div.querySelector('.f-qual').value = d.trig || '';
    div.querySelector('.f-passive').value = d.passive ? '1' : '0';
    div.querySelector('.f-succ').innerHTML = d.succ || '';
    div.querySelector('.f-fail').innerHTML = d.fail || '';
    if (d.chk) div.querySelector('.f-chk').checked = d.chk;
    if (d.tdesc) div.querySelector('.f-tdesc').value = d.tdesc;
    if (d.t1) div.querySelector('.f-t1').value = d.t1;
    if (d.t1v) div.querySelector('.f-t1-val').value = d.t1v;
    if (d.t2) div.querySelector('.f-t2').value = d.t2;
    if (d.t2v) div.querySelector('.f-t2-val').value = d.t2v;
    if (d.t3) div.querySelector('.f-t3').value = d.t3;
    if (d.t3v) div.querySelector('.f-t3-val').value = d.t3v;
    // 计数器数量（右键隐藏后持久化）：3=3点，2=2点
    const p1n = d.p1 ? d.p1.length : 3, p2n = d.p2 ? d.p2.length : 3, p3n = d.p3 ? d.p3.length : 3;
    div.querySelector('.f-p1n').value = p1n;
    div.querySelector('.f-p2n').value = p2n;
    div.querySelector('.f-p3n').value = p3n;
    // 按数量重建 dots（右键隐藏=移除最后一个）
    applyDotsCount(div, 'd1', p1n);
    applyDotsCount(div, 'd2', p2n);
    applyDotsCount(div, 'd3', p3n);
    if (d.p1) div.querySelectorAll('.d1 .sq-dot').forEach((e, i) => { if (d.p1[i]) e.classList.add('active') });
    if (d.p2) div.querySelectorAll('.d2 .sq-dot').forEach((e, i) => { if (d.p2[i]) e.classList.add('active') });
    if (d.p3) div.querySelectorAll('.d3 .sq-dot').forEach((e, i) => { if (d.p3[i]) e.classList.add('active') });
}

// 按数量设置 dots 个数（涂抹后重建，重建后重新绑定事件）
function applyDotsCount(card, cls, count) {
    const container = card.querySelector('.' + cls);
    if (!container) return;
    const n = Math.max(1, Math.min(3, parseInt(count) || 3));
    container.innerHTML = '';
    for (let i = 0; i < n; i++) {
        const dot = document.createElement('div');
        dot.className = 'sq-dot';
        container.appendChild(dot);
        bindSqDot(dot);
    }
}

export function syncAnomDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
    const name = card.querySelector('.f-name').value;
    const trig = card.querySelector('.f-trig').value;
    const qual = card.querySelector('.f-qual').value;
    const passive = card.querySelector('.f-passive').value === '1';
    const succ = card.querySelector('.f-succ');
    const fail = card.querySelector('.f-fail');
    const tdesc = card.querySelector('.f-tdesc').value;
    const t1 = card.querySelector('.f-t1').value;
    const t1v = card.querySelector('.f-t1-val').value;
    const t2 = card.querySelector('.f-t2').value;
    const t2v = card.querySelector('.f-t2-val').value;
    const t3 = card.querySelector('.f-t3').value;
    const t3v = card.querySelector('.f-t3-val').value;

    // 主动/被动模式视觉切换（框体颜色不变，仅切换图标）
    const modeBtn = card.querySelector('.anom-mode-toggle');
    if (modeBtn) {
        modeBtn.innerHTML = passive ? '<i class="fas fa-shield-alt"></i>' : '<i class="fas fa-bolt"></i>';
        modeBtn.title = passive ? '被动（点击切换为主动）' : '主动（点击切换为被动）';
        modeBtn.classList.toggle('is-passive', passive);
    }
    // 被动模式：成功区变"描述"占满整行，隐藏失败区；主动模式恢复双栏
    const resultRow = card.querySelector('.anom-result-row');
    const failSection = card.querySelector('.anom-result.fail-section');
    const succLabel = card.querySelector('.anom-result.succ-section .anom-result-label');
    if (resultRow) resultRow.classList.toggle('passive-row', passive);
    if (succLabel) succLabel.innerHTML = passive ? '<i class="fas fa-shield-alt"></i> 描述' : '<i class="fas fa-check-circle"></i> 成功时';
    if (failSection) failSection.style.display = passive ? 'none' : '';

    const dn = card.querySelector('.anom-disp-name');
    if (dn) dn.innerHTML = esc(name) || '<span class="anom-empty">未命名</span>';
    const dt = card.querySelector('.anom-disp-trig');
    if (dt) dt.innerHTML = trig ? '<span class="anom-disp-tag c-anom"><i class="fas fa-bolt"></i></span> ' + esc(trig) : '<span class="anom-empty">无触发器</span>';
    const dq = card.querySelector('.anom-disp-qual');
    if (dq) dq.innerHTML = qual ? '<span class="anom-disp-tag c-anom"><i class="fas fa-star"></i> 资质</span> ' + esc(qual) : '';
    const dr = card.querySelector('.anom-disp-qual-row');
    if (dr) dr.style.display = qual ? '' : 'none';
    const ds = card.querySelector('.anom-disp-succ');
    if (ds) ds.innerHTML = succ?.textContent?.trim() ? succ.innerHTML : '<span class="anom-empty">无</span>';
    const df = card.querySelector('.anom-disp-fail');
    if (df) df.innerHTML = fail?.textContent?.trim() ? fail.innerHTML : '<span class="anom-empty">无</span>';
    const dqs = card.querySelector('.anom-disp-question');
    if (dqs) {
        let qhtml = '';
        if (card.querySelector('.f-chk').checked) qhtml += '<span class="anom-disp-trained"><i class="fas fa-graduation-cap"></i> 已训练</span> ';
        if (tdesc) qhtml += '<strong>' + esc(tdesc) + '</strong>';
        if (t1) qhtml += '<div class="anom-disp-a"><span class="anom-disp-tag"><i class="fas fa-angle-right"></i> ' + esc(t1) + '</span>' + (t1v ? ' <code>' + esc(t1v) + '</code>' : '') + renderDotsHtml(card, 'd1') + '</div>';
        if (t2) qhtml += '<div class="anom-disp-a"><span class="anom-disp-tag"><i class="fas fa-angle-right"></i> ' + esc(t2) + '</span>' + (t2v ? ' <code>' + esc(t2v) + '</code>' : '') + renderDotsHtml(card, 'd2') + '</div>';
        if (t3) qhtml += '<div class="anom-disp-a"><span class="anom-disp-tag"><i class="fas fa-angle-right"></i> ' + esc(t3) + '</span>' + (t3v ? ' <code>' + esc(t3v) + '</code>' : '') + renderDotsHtml(card, 'd3') + '</div>';
        if (!qhtml) qhtml = '<span class="anom-empty">无问题</span>';
        dqs.innerHTML = qhtml;
    }
}

export function renderDotsHtml(card, cls) {
    const dots = card.querySelectorAll('.' + cls + ' .sq-dot');
    if (!dots.length) return '';
    let h = '<span class="anom-disp-dots">';
    dots.forEach(d => { h += d.classList.contains('active') ? '<span class="sq-dot active"></span>' : '<span class="sq-dot"></span>'; });
    return h + '</span>';
}

// 编辑弹窗：被动时成功区变"描述"单栏，隐藏失败区；主动恢复双栏
export function updateAnomEditPassiveUI(isPassive) {
    const modal = document.getElementById('anomEditModal');
    if (!modal) return;
    const row = modal.querySelector('.anom-edit-row-succfail');
    const failCol = modal.querySelector('.anom-edit-row-succfail > div:last-child');
    const succLabel = modal.querySelector('.anom-edit-row-succfail > div:first-child > label');
    if (row) {
        row.style.gridTemplateColumns = isPassive ? '1fr' : '';
    }
    if (succLabel) succLabel.innerHTML = isPassive ? '<i class="fas fa-shield-alt"></i> 描述' : '<i class="fas fa-check-circle"></i> 成功时';
    if (failCol) failCol.style.display = isPassive ? 'none' : '';
}
export function handleAnomPassiveChange(cb) { updateAnomEditPassiveUI(cb.checked); }

export function openAnomCardEdit(cardEl) {
    if (S.isReadOnly) return;
    const modal = document.getElementById('anomEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    q('.anom-edit-name').value = cardEl.querySelector('.f-name').value;
    q('.anom-edit-trig').value = cardEl.querySelector('.f-trig').value;
    q('.anom-edit-qual').value = cardEl.querySelector('.f-qual').value;
    q('.anom-edit-passive').checked = cardEl.querySelector('.f-passive').value === '1';
    updateAnomEditPassiveUI(q('.anom-edit-passive').checked);
    q('.anom-edit-succ').innerHTML = cardEl.querySelector('.f-succ').innerHTML || '';
    q('.anom-edit-fail').innerHTML = cardEl.querySelector('.f-fail').innerHTML || '';
    q('.anom-edit-tdesc').value = cardEl.querySelector('.f-tdesc').value;
    q('.anom-edit-chk').checked = cardEl.querySelector('.f-chk').checked;
    q('.anom-edit-t1').value = cardEl.querySelector('.f-t1').value;
    q('.anom-edit-t1v').value = cardEl.querySelector('.f-t1-val').value;
    q('.anom-edit-t2').value = cardEl.querySelector('.f-t2').value;
    q('.anom-edit-t2v').value = cardEl.querySelector('.f-t2-val').value;
    q('.anom-edit-t3').value = cardEl.querySelector('.f-t3').value;
    q('.anom-edit-t3v').value = cardEl.querySelector('.f-t3-val').value;
    // 编辑弹窗 dots 按卡片数量重建（2点/3点）
    syncEditDots(cardEl, 'd1', 'anom-edit-d1');
    syncEditDots(cardEl, 'd2', 'anom-edit-d2');
    syncEditDots(cardEl, 'd3', 'anom-edit-d3');
    window._anomEditCard = cardEl;
    q('.anom-edit-name').focus();
}

// 把卡片 dots 状态同步到编辑弹窗（始终显示 3 个点，涂抹的显示灰色）
function syncEditDots(cardEl, cls, editCls) {
    const modal = document.getElementById('anomEditModal');
    const target = modal.querySelector('.' + editCls);
    const source = cardEl.querySelector('.' + cls);
    if (!target || !source) return;
    const pnInput = cardEl.querySelector('.f-' + cls + 'n');
    const n = pnInput ? (parseInt(pnInput.value) || 3) : 3;
    target.dataset.cls = cls; // 记录对应卡片 cls（d1/d2/d3）
    target.dataset.n = n;
    const hadActive = Array.from(source.querySelectorAll('.sq-dot')).map(x => x.classList.contains('active'));
    rebuildEditDots(target, n, hadActive);
}

// 重建编辑弹窗 dots：3 个点，>= n 的显示涂抹灰色
function rebuildEditDots(container, n, hadActive) {
    container.innerHTML = '';
    for (let i = 0; i < 3; i++) {
        const dot = document.createElement('div');
        dot.className = 'sq-dot' + (i >= n ? ' smeared' : '') + (hadActive[i] ? ' active' : '');
        container.appendChild(dot);
        dot.onclick = () => { if (!S.isReadOnly && !dot.classList.contains('smeared')) dot.classList.toggle('active'); };
        dot.oncontextmenu = (e) => {
            e.preventDefault();
            if (S.isReadOnly) return;
            const cur = parseInt(container.dataset.n) || 3;
            const next = smearNext(cur, i + 1);
            container.dataset.n = next;
            const had = Array.from(container.querySelectorAll('.sq-dot')).map(x => x.classList.contains('active'));
            rebuildEditDots(container, next, had);
        };
    }
}

// 编辑弹窗 dots → 卡片（按数量重建并同步 pn 记录）
function applyEditDots(card, cls, editCls) {
    const modal = document.getElementById('anomEditModal');
    const source = modal.querySelector('.' + editCls);
    const target = card.querySelector('.' + cls);
    if (!source || !target) return;
    // 可用点数 = 弹窗 dataset.n（默认3），未涂区 = 非 smeared
    const n = parseInt(source.dataset.n) || 3;
    const pnInput = card.querySelector('.f-' + cls + 'n');
    if (pnInput) pnInput.value = n;
    applyDotsCount(card, cls, n);
    source.querySelectorAll('.sq-dot').forEach((d, i) => {
        const t = target.querySelectorAll('.sq-dot')[i];
        if (t) { d.classList.contains('active') ? t.classList.add('active') : t.classList.remove('active'); }
    });
    // 重新绑定事件
    target.querySelectorAll('.sq-dot').forEach(bindSqDot);
}

export function closeAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._anomEditCard = null;
}

// === 导入异常能力（从 data/anoms.json，经 /api/options 加载到 S.CONFIG_DATA.anoms） ===
let _anomImportFlat = [];

function escHtml(s) {
    return s ? String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') : '';
}

export function openAnomImportModal() {
    const modal = document.getElementById('anomImportModal');
    if (!modal) return;
    modal.classList.add('active');
    const search = document.getElementById('anomImportSearch');
    if (search) search.value = '';
    renderAnomImportList('');
    setTimeout(() => { if (search) search.focus(); }, 60);
}

export function closeAnomImportModal() {
    const modal = document.getElementById('anomImportModal');
    if (modal) modal.classList.remove('active');
}

export function filterAnomImport(kw) { renderAnomImportList(kw); }

function renderAnomImportList(kw) {
    const list = document.getElementById('anomImportList');
    if (!list) return;
    const groups = (S.CONFIG_DATA.anoms && Array.isArray(S.CONFIG_DATA.anoms)) ? S.CONFIG_DATA.anoms : [];
    const key = (kw || '').trim().toLowerCase();
    _anomImportFlat = [];
    let html = '';
    groups.forEach(g => {
        const abis = (g.abilities || []).filter(a => !key || (a.name || '').toLowerCase().includes(key));
        if (!abis.length) return;
        html += `<div class="anom-import-group">${escHtml(g.name || '')}</div>`;
        abis.forEach(a => {
            const idx = _anomImportFlat.length;
            _anomImportFlat.push(a);
            html += `<div class="anom-import-item" data-i="${idx}"><span class="anom-import-name">${escHtml(a.name || '')}</span>${a.trig ? `<span class="anom-import-trig">${escHtml(a.trig)}</span>` : ''}</div>`;
        });
    });
    list.innerHTML = html || '<div class="anom-import-empty">未找到匹配的能力</div>';
    list.querySelectorAll('.anom-import-item').forEach(el => {
        el.onclick = () => applyAnomImport(parseInt(el.dataset.i));
    });
}

function applyAnomImport(idx) {
    const a = _anomImportFlat[idx];
    if (!a) return;
    const modal = document.getElementById('anomEditModal');
    const q = s => modal.querySelector(s);
    q('.anom-edit-name').value = a.name || '';
    q('.anom-edit-trig').value = a.trig || '';
    q('.anom-edit-qual').value = a.qual || '';
    q('.anom-edit-succ').innerHTML = a.succ || '';
    q('.anom-edit-fail').innerHTML = a.fail || '';
    q('.anom-edit-tdesc').value = a.tdesc || '';
    q('.anom-edit-t1').value = a.t1 || '';
    q('.anom-edit-t1v').value = a.t1v || '';
    q('.anom-edit-t2').value = a.t2 || '';
    q('.anom-edit-t2v').value = a.t2v || '';
    q('.anom-edit-t3').value = a.t3 || '';
    q('.anom-edit-t3v').value = a.t3v || '';
    closeAnomImportModal();
    showToast('已导入：' + (a.name || ''), 'success');
}

export function saveAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    const card = window._anomEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-name').value = q('.anom-edit-name').value;
    card.querySelector('.f-trig').value = q('.anom-edit-trig').value;
    card.querySelector('.f-qual').value = q('.anom-edit-qual').value;
    card.querySelector('.f-passive').value = q('.anom-edit-passive').checked ? '1' : '0';
    card.querySelector('.f-succ').innerHTML = q('.anom-edit-succ').innerHTML || '';
    card.querySelector('.f-fail').innerHTML = q('.anom-edit-fail').innerHTML || '';
    card.querySelector('.f-tdesc').value = q('.anom-edit-tdesc').value;
    card.querySelector('.f-chk').checked = q('.anom-edit-chk').checked;
    card.querySelector('.f-t1').value = q('.anom-edit-t1').value;
    card.querySelector('.f-t1-val').value = q('.anom-edit-t1v').value;
    card.querySelector('.f-t2').value = q('.anom-edit-t2').value;
    card.querySelector('.f-t2-val').value = q('.anom-edit-t2v').value;
    card.querySelector('.f-t3').value = q('.anom-edit-t3').value;
    card.querySelector('.f-t3-val').value = q('.anom-edit-t3v').value;
    // 弹窗 dots → 卡片（按数量重建 + 保留状态）
    applyEditDots(card, 'd1', 'anom-edit-d1');
    applyEditDots(card, 'd2', 'anom-edit-d2');
    applyEditDots(card, 'd3', 'anom-edit-d3');
    syncAnomDisplay(card);
    window.triggerAutoSave();
    closeAnomCardEdit();
}

export function openAnomWindow() {
    if (window.innerWidth < 1600) {
        var btn = document.querySelector('.nav-btn.n-anom');
        window.switchView('view-anom', btn);
        return;
    }
    var wf = document.getElementById('win98Float');
    var body = document.getElementById('win98Body');
    var listAnom = document.getElementById('list-anom');
    navBtns.forEach(function (b) { b.classList.remove('active'); });
    document.querySelector('.nav-btn.n-anom').classList.add('active');
    body.innerHTML = '';
    body.appendChild(listAnom);
    listAnom.style.display = '';
    if (!wf.dataset.pos) {
        wf.style.top = Math.max(20, (window.innerHeight - 620) / 2) + 'px';
        wf.style.left = Math.max(10, (window.innerWidth - 800) / 2) + 'px';
        wf.dataset.pos = '1';
    }
    wf.style.display = '';
    window._popupZ = (window._popupZ || 4000) + 1;
    wf.style.zIndex = window._popupZ;
    wf.classList.add('win98-opening');
    wf.addEventListener('animationend', function done() {
        wf.classList.remove('win98-opening'); wf.style.display = 'block'; wf.removeEventListener('animationend', done);
    });
}

export function closeAnomWindow() {
    var wf = document.getElementById('win98Float');
    var listAnom = document.getElementById('list-anom');
    wf.style.display = 'none';
    if (listAnom) {
        var viewAnom = document.getElementById('view-anom');
        if (viewAnom) viewAnom.appendChild(listAnom);
        listAnom.style.display = '';
    }
}

export function initAnomDrag() {
    var wf = document.getElementById('win98Float');
    if (!wf) return;
    var svg = wf.querySelector('.win98-svg');
    var titleText = svg ? svg.querySelector('.win98-title-text') : null;
    var dragging = false, sx, sy, sl, st;
    if (titleText) { titleText.addEventListener('click', function () { if (S.isReadOnly) return; addAnom(null, false); }); }
    var closeBtn = svg ? svg.querySelector('.win98-btn-close') : null;
    if (closeBtn) closeBtn.addEventListener('click', closeAnomWindow);
    wf.addEventListener('pointerdown', function (e) {
        if (e.target.closest('.win98-body') || e.target.closest('.win98-title-text')) return;
        window._popupZ = (window._popupZ || 4000) + 1; wf.style.zIndex = window._popupZ;
        dragging = true; sx = e.clientX; sy = e.clientY; sl = wf.offsetLeft; st = wf.offsetTop;
    });
    document.addEventListener('pointermove', function (e) {
        if (!dragging) return;
        var nx = Math.max(0, Math.min(sl + e.clientX - sx, window.innerWidth - 800));
        var ny = Math.max(0, Math.min(st + e.clientY - sy, window.innerHeight - 60));
        wf.style.left = nx + 'px'; wf.style.top = ny + 'px';
    });
    document.addEventListener('pointerup', function () { dragging = false; });
    wf.addEventListener('pointerdown', function () {
        window._popupZ = (window._popupZ || 4000) + 1; wf.style.zIndex = window._popupZ;
    });
}
