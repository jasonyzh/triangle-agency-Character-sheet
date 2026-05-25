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
    if (!skipCheck && !d) {
        const currentCount = document.querySelectorAll('#list-anom .card').length;
        if (currentCount >= S.SLOT_LIMITS.anomSlots) {
            showToast('异常能力槽位已满，请联系经理解锁更多槽位', 'error');
            return;
        }
    }
    const div = document.createElement('div'); div.className = 'card bd-anom anom-card'; div.innerHTML = `<button class="anom-card-edit-btn" onclick="openAnomCardEdit(this.closest('.anom-card'))"><i class="fas fa-pen"></i></button>${createDelBtn('anom')}<input type="hidden" class="f-name"><input type="hidden" class="f-trig"><input type="hidden" class="f-qual"><input type="hidden" class="f-tdesc"><input type="hidden" class="f-t1"><input type="hidden" class="f-t1-val"><input type="hidden" class="f-t2"><input type="hidden" class="f-t2-val"><input type="checkbox" class="f-chk" style="display:none"><div class="sq-dots d1" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="sq-dots d2" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="rich-editor f-succ" contenteditable="true" style="display:none"></div><div class="rich-editor f-fail" contenteditable="true" style="display:none"></div><div class="anom-title-bar"><div class="anom-title-row"><span class="anom-disp-name"></span><span class="anom-field-sep">|</span><span class="anom-disp-trig"></span></div><div class="anom-disp-qual-row"><span class="anom-disp-qual"></span></div></div><div class="anom-body"><div class="anom-result-row"><div class="anom-result succ-section"><div class="anom-result-label c-anom"><i class="fas fa-check-circle"></i> 成功时</div><div class="anom-disp-succ"></div></div><div class="anom-result fail-section"><div class="anom-result-label" style="color:#c0392b"><i class="fas fa-times-circle"></i> 失败时</div><div class="anom-disp-fail"></div></div></div></div><div class="anom-question-section"><div class="anom-disp-question"></div><div class="anom-disp-answers"><div class="anom-disp-a1"></div><div class="anom-disp-a2"></div></div></div>`;
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

export function setupSq(div) {
    div.querySelectorAll('.sq-dot').forEach(d => { d.onclick = () => { if (!S.isReadOnly) d.classList.toggle('active'); }; });
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

export function fillAnom(div, d) {
    div.querySelector('.f-name').value = d.name || '';
    div.querySelector('.f-trig').value = d.qual || '';
    div.querySelector('.f-qual').value = d.trig || '';
    div.querySelector('.f-succ').innerHTML = d.succ || '';
    div.querySelector('.f-fail').innerHTML = d.fail || '';
    if (d.chk) div.querySelector('.f-chk').checked = d.chk;
    if (d.tdesc) div.querySelector('.f-tdesc').value = d.tdesc;
    if (d.t1) div.querySelector('.f-t1').value = d.t1;
    if (d.t1v) div.querySelector('.f-t1-val').value = d.t1v;
    if (d.t2) div.querySelector('.f-t2').value = d.t2;
    if (d.t2v) div.querySelector('.f-t2-val').value = d.t2v;
    if (d.p1) div.querySelectorAll('.d1 .sq-dot').forEach((e, i) => { if (d.p1[i]) e.classList.add('active') });
    if (d.p2) div.querySelectorAll('.d2 .sq-dot').forEach((e, i) => { if (d.p2[i]) e.classList.add('active') });
}

export function syncAnomDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
    const name = card.querySelector('.f-name').value;
    const trig = card.querySelector('.f-trig').value;
    const qual = card.querySelector('.f-qual').value;
    const succ = card.querySelector('.f-succ');
    const fail = card.querySelector('.f-fail');
    const tdesc = card.querySelector('.f-tdesc').value;
    const t1 = card.querySelector('.f-t1').value;
    const t1v = card.querySelector('.f-t1-val').value;
    const t2 = card.querySelector('.f-t2').value;
    const t2v = card.querySelector('.f-t2-val').value;

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
    q('.anom-edit-succ').innerHTML = cardEl.querySelector('.f-succ').innerHTML || '';
    q('.anom-edit-fail').innerHTML = cardEl.querySelector('.f-fail').innerHTML || '';
    q('.anom-edit-tdesc').value = cardEl.querySelector('.f-tdesc').value;
    q('.anom-edit-chk').checked = cardEl.querySelector('.f-chk').checked;
    q('.anom-edit-t1').value = cardEl.querySelector('.f-t1').value;
    q('.anom-edit-t1v').value = cardEl.querySelector('.f-t1-val').value;
    q('.anom-edit-t2').value = cardEl.querySelector('.f-t2').value;
    q('.anom-edit-t2v').value = cardEl.querySelector('.f-t2-val').value;
    cardEl.querySelectorAll('.d1 .sq-dot').forEach((d, i) => { const md = q('.anom-edit-d1 .sq-dot:nth-child(' + (i + 1) + ')'); if (md) { d.classList.contains('active') ? md.classList.add('active') : md.classList.remove('active'); } });
    cardEl.querySelectorAll('.d2 .sq-dot').forEach((d, i) => { const md = q('.anom-edit-d2 .sq-dot:nth-child(' + (i + 1) + ')'); if (md) { d.classList.contains('active') ? md.classList.add('active') : md.classList.remove('active'); } });
    window._anomEditCard = cardEl;
    q('.anom-edit-name').focus();
}

export function closeAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._anomEditCard = null;
}

export function saveAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    const card = window._anomEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-name').value = q('.anom-edit-name').value;
    card.querySelector('.f-trig').value = q('.anom-edit-trig').value;
    card.querySelector('.f-qual').value = q('.anom-edit-qual').value;
    card.querySelector('.f-succ').innerHTML = q('.anom-edit-succ').innerHTML || '';
    card.querySelector('.f-fail').innerHTML = q('.anom-edit-fail').innerHTML || '';
    card.querySelector('.f-tdesc').value = q('.anom-edit-tdesc').value;
    card.querySelector('.f-chk').checked = q('.anom-edit-chk').checked;
    card.querySelector('.f-t1').value = q('.anom-edit-t1').value;
    card.querySelector('.f-t1-val').value = q('.anom-edit-t1v').value;
    card.querySelector('.f-t2').value = q('.anom-edit-t2').value;
    card.querySelector('.f-t2-val').value = q('.anom-edit-t2v').value;
    card.querySelectorAll('.d1 .sq-dot').forEach((d, i) => { const md = q('.anom-edit-d1 .sq-dot:nth-child(' + (i + 1) + ')'); if (md) { md.classList.contains('active') ? d.classList.add('active') : d.classList.remove('active'); } });
    card.querySelectorAll('.d2 .sq-dot').forEach((d, i) => { const md = q('.anom-edit-d2 .sq-dot:nth-child(' + (i + 1) + ')'); if (md) { md.classList.contains('active') ? d.classList.add('active') : d.classList.remove('active'); } });
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
    if (titleText) { titleText.addEventListener('click', function () { addAnom(null, false); }); }
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
