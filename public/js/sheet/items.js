import { S, navBtns } from './state.js';
import { setRandomVars, showToast } from './ui.js';
import { createDelBtn, updateSlotButtons } from './anomaly.js';
import { getPaperScatterHTML } from './paper.js';

export function addItem(d = null, prepend = false) {
    const div = document.createElement('div');
    div.className = 'card bd-func item-card';
    div.innerHTML = `${createDelBtn('item')}<input type="hidden" class="f-item"><input type="hidden" class="f-pd"><input type="hidden" class="f-once" value="0"><div class="rich-editor f-eff" contenteditable="true" style="display:none"></div><div class="item-title-bar"><div class="item-title-row"><span class="item-disp-once"><i class="fas fa-fire"></i> 一次性</span><span class="item-disp-name"></span><span class="item-field-sep">|</span><span class="item-disp-pd"></span></div></div><div class="item-body"><div class="item-disp-eff"></div></div><div class="item-actions"><button class="item-card-edit-btn" onclick="openItemCardEdit(this.closest('.item-card'))"><i class="fas fa-pen"></i> 编辑</button><button class="item-use-btn" onclick="useItem(this.closest('.item-card'))"><i class="fas fa-hand-sparkles"></i> 使用</button></div>`;
    if (d) { div.querySelector('.f-item').value = d.item || ''; div.querySelector('.f-pd').value = d.pd || ''; div.querySelector('.f-eff').innerHTML = d.eff || ''; div.querySelector('.f-once').value = d.once ? '1' : '0'; }
    setRandomVars(div);
    syncItemDisplay(div);
    const container = document.getElementById('list-item');
    if (prepend) { container.prepend(div); } else { container.appendChild(div); }
}

export function syncItemDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
    const item = card.querySelector('.f-item').value;
    const pd = card.querySelector('.f-pd').value;
    const eff = card.querySelector('.f-eff');
    const once = card.querySelector('.f-once').value === '1';
    if (once) { card.classList.add('bd-once'); card.classList.remove('bd-func'); } else { card.classList.remove('bd-once'); card.classList.add('bd-func'); }
    const dn = card.querySelector('.item-disp-name');
    if (dn) dn.innerHTML = item ? '<span class="item-disp-label">物品：</span>' + esc(item) : '<span class="anom-empty">未命名</span>';
    const dp = card.querySelector('.item-disp-pd');
    const sep = card.querySelector('.item-field-sep');
    if (dp && sep) { if (pd) { dp.innerHTML = '<span class="item-disp-label">PD：</span>' + esc(pd); dp.style.display = ''; sep.style.display = ''; } else { dp.style.display = 'none'; sep.style.display = 'none'; } }
    const de = card.querySelector('.item-disp-eff');
    if (de) de.innerHTML = eff?.textContent?.trim() ? eff.innerHTML : '';
}

export function useItem(card) {
    if (S.isReadOnly) return;
    const name = card.querySelector('.f-item').value || '此物品';
    if (!confirm(`确定使用「${name}」？此物品将被消耗。`)) return;
    card.style.transition = 'all 0.3s'; card.style.opacity = '0'; card.style.transform = 'scale(0.9)';
    setTimeout(() => { card.remove(); window.triggerAutoSave(); }, 300);
}

export function openItemCardEdit(cardEl) {
    if (S.isReadOnly) return;
    const modal = document.getElementById('itemEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    q('.item-edit-name').value = cardEl.querySelector('.f-item').value;
    q('.item-edit-pd').value = cardEl.querySelector('.f-pd').value;
    q('.item-edit-eff').innerHTML = cardEl.querySelector('.f-eff').innerHTML || '';
    q('.item-edit-once').checked = cardEl.querySelector('.f-once').value === '1';
    window._itemEditCard = cardEl;
    q('.item-edit-name').focus();
}

export function closeItemCardEdit() {
    const modal = document.getElementById('itemEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._itemEditCard = null;
}

export function saveItemCardEdit() {
    const modal = document.getElementById('itemEditModal');
    const card = window._itemEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-item').value = q('.item-edit-name').value;
    card.querySelector('.f-pd').value = q('.item-edit-pd').value;
    card.querySelector('.f-eff').innerHTML = q('.item-edit-eff').innerHTML || '';
    card.querySelector('.f-once').value = q('.item-edit-once').checked ? '1' : '0';
    syncItemDisplay(card);
    window.triggerAutoSave();
    closeItemCardEdit();
}

export function openBriefcase() {
    if (window.innerWidth < 1600) {
        var btn = document.querySelector('.nav-btn.n-item');
        window.switchView('view-item', btn);
        return;
    }
    var bf = document.getElementById('briefcaseFloat');
    var body = document.getElementById('briefcaseBody');
    var listItem = document.getElementById('list-item');
    navBtns.forEach(function (b) { b.classList.remove('active'); });
    document.querySelector('.nav-btn.n-item').classList.add('active');
    body.innerHTML = '';
    body.appendChild(listItem);
    listItem.style.display = '';
    if (!bf.dataset.pos) {
        bf.style.top = Math.max(20, (window.innerHeight - 520) / 2) + 'px';
        bf.style.left = Math.max(10, (window.innerWidth - 480) / 2) + 'px';
        bf.dataset.pos = '1';
    }
    bf.style.display = '';
    window._popupZ = (window._popupZ || 4000) + 1;
    bf.style.zIndex = window._popupZ;
    bf.classList.add('briefcase-opening');
    bf.addEventListener('animationend', function done() {
        bf.classList.remove('briefcase-opening'); bf.style.display = 'block'; bf.removeEventListener('animationend', done);
    });

    var overlay = document.createElement('div');
    overlay.className = 'paper-scatter-overlay';
    var bl = parseInt(bf.style.left), bt = parseInt(bf.style.top);
    overlay.style.left = (bl - 60) + 'px';
    overlay.style.top = (bt + 140) + 'px';
    overlay.style.width = '600px';
    overlay.style.height = '320px';
    overlay.innerHTML = getPaperScatterHTML();
    document.body.appendChild(overlay);

    var lastPaper = overlay.querySelector('.p16');
    if (lastPaper) lastPaper.addEventListener('animationend', function () { overlay.remove(); });
    else setTimeout(function () { overlay.remove(); }, 900);
}

export function closeBriefcase() {
    var bf = document.getElementById('briefcaseFloat');
    var listItem = document.getElementById('list-item');
    bf.style.display = 'none';
    if (listItem) {
        var viewItem = document.getElementById('view-item');
        if (viewItem) viewItem.appendChild(listItem);
        listItem.style.display = '';
    }
}

export function initBriefcaseDrag() {
    var bf = document.getElementById('briefcaseFloat');
    if (!bf) return;
    var header = bf.querySelector('.briefcase-header');
    var dragging = false, sx, sy, sl, st;
    header.addEventListener('pointerdown', function (e) {
        if (e.target.closest('button')) return;
        window._popupZ = (window._popupZ || 4000) + 1; bf.style.zIndex = window._popupZ;
        dragging = true; sx = e.clientX; sy = e.clientY; sl = bf.offsetLeft; st = bf.offsetTop;
        header.setPointerCapture(e.pointerId);
    });
    header.addEventListener('pointermove', function (e) {
        if (!dragging) return;
        var nx = Math.max(0, Math.min(sl + e.clientX - sx, window.innerWidth - 480));
        var ny = Math.max(0, Math.min(st + e.clientY - sy, window.innerHeight - 60));
        bf.style.left = nx + 'px'; bf.style.top = ny + 'px';
    });
    header.addEventListener('pointerup', function () { dragging = false; });
    bf.addEventListener('pointerdown', function () {
        window._popupZ = (window._popupZ || 4000) + 1; bf.style.zIndex = window._popupZ;
    });
}
