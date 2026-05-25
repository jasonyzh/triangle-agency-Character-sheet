import { S, navBtns } from './state.js';
import { setRandomVars, showToast } from './ui.js';
import { createDelBtn, updateSlotButtons, getBonusOptions, get9Dots, setupRDots } from './anomaly.js';

export function addReal(d = null, skipCheck = false) {
    if (!skipCheck && !d) {
        const currentCount = document.querySelectorAll('#list-real .card').length;
        if (currentCount >= S.SLOT_LIMITS.realSlots) {
            showToast('关系网槽位已满，请联系经理解锁更多槽位', 'error');
            return null;
        }
    }
    const div = document.createElement('div');
    div.className = 'card bd-real real-card';
    div.innerHTML = `<button class="real-card-edit-btn" onclick="openRealCardEdit(this.closest('.real-card'))"><i class="fas fa-pen"></i></button>${createDelBtn('real')}<input type="hidden" class="f-name"><input type="hidden" class="f-actor"><div class="rich-editor f-desc" contenteditable="true" style="display:none"></div><input type="checkbox" class="f-act" style="display:none"><div class="rich-editor f-conn" contenteditable="true" style="display:none"></div><div class="r-dots-hidden" style="display:none"><div class="dot" data-i="1"></div><div class="dot" data-i="2"></div><div class="dot" data-i="3"></div><div class="dot" data-i="4"></div><div class="dot" data-i="5"></div><div class="dot" data-i="6"></div><div class="dot" data-i="7"></div><div class="dot" data-i="8"></div><div class="dot" data-i="9"></div></div><div class="real-title-bar"><div class="real-title-row"><span class="real-disp-name"></span><span class="real-field-sep">|</span><span class="real-disp-actor"></span></div><div class="real-disp-desc"></div></div><div class="real-body"><div class="real-conn-row"><span class="real-disp-lbl"><i class="fas fa-link"></i> 连结</span><span class="real-disp-lvl"></span><span class="real-disp-act"></span></div><div class="real-disp-conn"></div></div>`;
    if (d) fillReal(div, d);
    setRandomVars(div);
    syncRealDisplay(div);
    setTimeout(updateSlotButtons, 0);
    return div;
}

export function addRealSafe() {
    const card = addReal(null, false);
    if (card) {
        document.getElementById('list-real').appendChild(card);
    }
}

export function fillReal(div, d) {
    div.querySelector('.f-name').value = d.name || '';
    div.querySelector('.f-actor').value = d.actor || '';
    div.querySelector('.f-desc').innerHTML = d.desc || '';
    if (d.act) div.querySelector('.f-act').checked = d.act;
    div.querySelector('.f-conn').innerHTML = d.conn || '';
    div.querySelectorAll('.r-dots-hidden .dot').forEach((e, i) => {
        if (i < (d.lvl || 0)) e.classList.add('active');
    });
}

export function syncRealDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
    const name = card.querySelector('.f-name').value;
    const actor = card.querySelector('.f-actor').value;
    const desc = card.querySelector('.f-desc');
    const act = card.querySelector('.f-act').checked;
    const conn = card.querySelector('.f-conn');
    const lvl = card.querySelectorAll('.r-dots-hidden .dot.active').length;

    const dn = card.querySelector('.real-disp-name');
    if (dn) dn.innerHTML = name ? '<span class="real-disp-label">姓名：</span>' + esc(name) : '<span class="anom-empty">未命名</span>';
    const da = card.querySelector('.real-disp-actor');
    const sep = card.querySelector('.real-field-sep');
    if (da && sep) { if (actor) { da.innerHTML = '<span class="real-disp-label">扮演者：</span>' + esc(actor); da.style.display = ''; sep.style.display = ''; } else { da.style.display = 'none'; sep.style.display = 'none'; } }
    const dd = card.querySelector('.real-disp-desc');
    if (dd) dd.innerHTML = desc?.textContent?.trim() ? desc.innerHTML : '';
    const dl = card.querySelector('.real-disp-lvl');
    if (dl) {
        let dots = '';
        for (let i = 1; i <= 9; i++) dots += `<span class="real-lvl-dot${i <= lvl ? ' active' : ''}"></span>`;
        dl.innerHTML = dots;
    }
    const dact = card.querySelector('.real-disp-act');
    if (dact) dact.innerHTML = act ? '<span class="real-act-badge"><i class="fas fa-check"></i> 已激活</span>' : '';
    const dc = card.querySelector('.real-disp-conn');
    if (dc) dc.innerHTML = conn?.textContent?.trim() ? conn.innerHTML : '';
}

export function openRealCardEdit(cardEl) {
    if (S.isReadOnly) return;
    const modal = document.getElementById('realEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.real-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    const bonusSel = q('.real-edit-conn-sel');
    bonusSel.innerHTML = getBonusOptions();
    const connWrapper = bonusSel.closest('.hybrid-input-wrapper');
    connWrapper.classList.remove('show-input');
    bonusSel.value = '';

    q('.real-edit-name').value = cardEl.querySelector('.f-name').value;
    q('.real-edit-actor').value = cardEl.querySelector('.f-actor').value;
    q('.real-edit-desc').innerHTML = cardEl.querySelector('.f-desc').innerHTML || '';
    q('.real-edit-act').checked = cardEl.querySelector('.f-act').checked;

    const connVal = cardEl.querySelector('.f-conn').innerHTML || '';
    q('.real-edit-conn').innerHTML = connVal;
    if (connVal.trim()) { connWrapper.classList.add('show-input'); bonusSel.value = '__CUSTOM__'; }

    const lvl = cardEl.querySelectorAll('.r-dots-hidden .dot.active').length;
    q('.real-edit-lvl').value = lvl;
    updateRealLvlDots(lvl);
    window._realEditCard = cardEl;
    q('.real-edit-name').focus();
}

export function handleRealBonusChange(select) {
    const wrapper = select.parentElement;
    const editor = wrapper.querySelector('.rich-editor');
    const val = select.value;
    wrapper.classList.add('show-input');
    if (val === '__CUSTOM__') { editor.focus(); }
    else { editor.innerHTML = val; }
}

export function resetRealBonus(btn) {
    const wrapper = btn.parentElement;
    const select = wrapper.querySelector('select');
    wrapper.classList.remove('show-input');
    select.value = '';
}

export function updateRealLvlDots(val) {
    const v = parseInt(val) || 0;
    document.querySelectorAll('.real-edit-lvl-dots .dot').forEach((d, i) => {
        i < v ? d.classList.add('active') : d.classList.remove('active');
    });
}

export function closeRealCardEdit() {
    const modal = document.getElementById('realEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._realEditCard = null;
}

export function saveRealCardEdit() {
    const modal = document.getElementById('realEditModal');
    const card = window._realEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-name').value = q('.real-edit-name').value;
    card.querySelector('.f-actor').value = q('.real-edit-actor').value;
    card.querySelector('.f-desc').innerHTML = q('.real-edit-desc').innerHTML || '';
    card.querySelector('.f-act').checked = q('.real-edit-act').checked;
    card.querySelector('.f-conn').innerHTML = q('.real-edit-conn').innerHTML || '';
    const lvl = parseInt(q('.real-edit-lvl').value) || 0;
    card.querySelectorAll('.r-dots-hidden .dot').forEach((d, i) => {
        i < lvl ? d.classList.add('active') : d.classList.remove('active');
    });
    syncRealDisplay(card);
    window.triggerAutoSave();
    closeRealCardEdit();
}

export function openRealPhone() {
    if (window.innerWidth < 1600) {
        var btn = document.querySelector('.nav-btn.n-real');
        window.switchView('view-real', btn);
        return;
    }
    var pf = document.getElementById('phoneFloat');
    var phoneBody = document.getElementById('phoneBody');
    var listReal = document.getElementById('list-real');
    navBtns.forEach(function (b) { b.classList.remove('active'); });
    document.querySelector('.nav-btn.n-real').classList.add('active');
    phoneBody.innerHTML = '';
    phoneBody.appendChild(listReal);
    listReal.style.display = '';
    if (!pf.dataset.pos) {
        pf.style.top = Math.max(20, (window.innerHeight - 680) / 2) + 'px';
        pf.style.left = Math.max(10, (window.innerWidth - 360) / 2) + 'px';
        pf.dataset.pos = '1';
    }
    pf.style.display = '';
    window._popupZ = (window._popupZ || 4000) + 1;
    pf.style.zIndex = window._popupZ;
    pf.classList.add('phone-opening');
    pf.addEventListener('animationend', function done() {
        pf.classList.remove('phone-opening'); pf.style.display = 'block'; pf.removeEventListener('animationend', done);
    });
}

export function closePhoneOverlay() {
    var pf = document.getElementById('phoneFloat');
    var listReal = document.getElementById('list-real');
    pf.style.display = 'none';
    if (listReal) {
        var viewReal = document.getElementById('view-real');
        if (viewReal) viewReal.appendChild(listReal);
        listReal.style.display = '';
    }
}

export function initPhoneDrag() {
    var pf = document.getElementById('phoneFloat');
    if (!pf) return;
    var header = pf.querySelector('.phone-header');
    var dragging = false, sx, sy, sl, st;
    header.addEventListener('pointerdown', function (e) {
        if (e.target.closest('button')) return;
        window._popupZ = (window._popupZ || 4000) + 1; pf.style.zIndex = window._popupZ;
        dragging = true; sx = e.clientX; sy = e.clientY; sl = pf.offsetLeft; st = pf.offsetTop;
        header.setPointerCapture(e.pointerId);
    });
    header.addEventListener('pointermove', function (e) {
        if (!dragging) return;
        var nx = Math.max(0, Math.min(sl + e.clientX - sx, window.innerWidth - 360));
        var ny = Math.max(0, Math.min(st + e.clientY - sy, window.innerHeight - 60));
        pf.style.left = nx + 'px'; pf.style.top = ny + 'px';
    });
    header.addEventListener('pointerup', function () { dragging = false; });
    pf.addEventListener('pointerdown', function () {
        window._popupZ = (window._popupZ || 4000) + 1; pf.style.zIndex = window._popupZ;
    });
}
