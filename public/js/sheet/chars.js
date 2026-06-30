import { S, ATTRS } from './state.js';
import { showToast, escapeHtmlText } from './ui.js';
import { renderDots } from './track.js';

export function syncCharDisplay() {
    const body = document.getElementById('charInfoBody');
    if (!body) return;
    const esc = s => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const richVal = id => { const el = document.getElementById(id); return el ? el.innerHTML.trim() : ''; };
    const textVal = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };

    const pName = textVal('pName');
    const pAnom = textVal('pAnom');
    const pReal = textVal('pReal');
    const pFunc = textVal('pFunc');
    const trig1 = richVal('pTrig1');
    const trig2 = richVal('pTrig2');
    const trig3 = richVal('pTrig3');
    const perm1 = textVal('perm1');
    const perm2 = textVal('perm2');
    const perm3 = textVal('perm3');
    const derivCells = document.querySelectorAll('.derivative-progress .progress-cell');
    const derivActive = [];
    derivCells.forEach((c, i) => { if (c.classList.contains('active')) derivActive.push(i + 1); });

    let html = '';
    if (pName) html += `<div class="char-info-row"><span class="char-info-label">姓名</span><span class="char-info-value">${esc(pName)}</span></div>`;

    const typeItems = [];
    if (pAnom) typeItems.push(`<span class="char-info-type type-anom"><i class="fas fa-bolt"></i><span>${esc(pAnom)}</span></span>`);
    if (pReal) typeItems.push(`<span class="char-info-type type-real"><i class="fas fa-heart"></i><span>${esc(pReal)}</span></span>`);
    if (pFunc) typeItems.push(`<span class="char-info-type type-func"><i class="fas fa-briefcase"></i><span>${esc(pFunc)}</span></span>`);
    if (typeItems.length) html += `<div class="char-info-types">${typeItems.join('')}</div>`;

    if (trig1 || trig2) {
        html += `<div class="char-info-section">`;
        if (trig1) html += `<div class="char-info-row"><span class="char-info-label">过载解除</span><span class="char-info-value rich-content">${trig1}</span></div>`;
        if (trig2) html += `<div class="char-info-row"><span class="char-info-label">现实触发器</span><span class="char-info-value rich-content">${trig2}</span></div>`;
        html += `</div>`;
    }

    if (derivCells.length > 0) {
        html += `<div class="char-info-section inline-section"><div class="char-info-section-title">现实计数</div><div class="char-info-dots">`;
        derivCells.forEach((c, i) => {
            html += `<span class="char-info-dot${c.classList.contains('active') ? ' active' : ''}">${i + 1}</span>`;
        });
        html += `</div></div>`;
    }

    if (trig3) {
        html += `<div class="char-info-section"><div class="char-info-section-title" style="color:var(--functional)">首要指令</div><div class="char-info-value rich-content">${trig3}</div></div>`;
    }

    if (perm1 || perm2 || perm3) {
        html += `<div class="char-info-section"><div class="char-info-section-title">许可行为</div><div class="char-info-perms">`;
        if (perm1) html += `<div class="char-info-perm-item">${esc(perm1)}</div>`;
        if (perm2) html += `<div class="char-info-perm-item">${esc(perm2)}</div>`;
        if (perm3) html += `<div class="char-info-perm-item">${esc(perm3)}</div>`;
        html += `</div></div>`;
    }

    body.innerHTML = html || '<div style="color:var(--text-dim); font-size:11px; text-align:center; padding:20px;">点击"编辑"填写基础信息</div>';
}

export function openCharEdit() {
    if (S.isReadOnly) return;
    const modal = document.getElementById('charEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });

    const q = s => modal.querySelector(s);
    q('.char-edit-name').value = document.getElementById('pName').value;
    q('.char-edit-anom').value = document.getElementById('pAnom').value;
    q('.char-edit-real').value = document.getElementById('pReal').value;
    q('.char-edit-func').value = document.getElementById('pFunc').value;
    q('.char-edit-trig1').innerHTML = document.getElementById('pTrig1').innerHTML || '';
    q('.char-edit-trig2').innerHTML = document.getElementById('pTrig2').innerHTML || '';
    q('.char-edit-trig3').innerHTML = document.getElementById('pTrig3').innerHTML || '';
    q('.char-edit-perm1').value = document.getElementById('perm1').value;
    q('.char-edit-perm2').value = document.getElementById('perm2').value;
    q('.char-edit-perm3').value = document.getElementById('perm3').value;

    const anomSel = q('.char-edit-anom-sel');
    const realSel = q('.char-edit-real-sel');
    const funcSel = q('.char-edit-func-sel');
    const fillSel = (sel, items) => {
        sel.innerHTML = '<option value="" disabled selected>-- 请选择 --</option>';
        if (items && Array.isArray(items)) items.forEach(item => { const val = typeof item === 'string' ? item : item.name; const o = document.createElement('option'); o.value = val; o.textContent = val; sel.appendChild(o); });
        const co = document.createElement('option'); co.value = '__CUSTOM__'; co.textContent = '➤ 自定义 / 手动输入...'; sel.appendChild(co);
    };
    fillSel(anomSel, S.CONFIG_DATA.anoms);
    fillSel(realSel, S.CONFIG_DATA.realities);
    fillSel(funcSel, S.CONFIG_DATA.functions);

    const setModalHybrid = (selClass, inputClass, grpId, val) => {
        const sel = q(selClass);
        const wrapper = document.getElementById(grpId);
        let isPreset = false;
        Array.from(sel.options).forEach(opt => { if (opt.value === val) isPreset = true; });
        if (isPreset) { wrapper.classList.remove('show-input'); sel.value = val; }
        else if (val && val.trim()) { wrapper.classList.add('show-input'); sel.value = '__CUSTOM__'; }
        else { wrapper.classList.remove('show-input'); sel.value = ''; }
    };
    setModalHybrid('.char-edit-anom-sel', '.char-edit-anom', 'grp-char-pAnom', document.getElementById('pAnom').value);
    setModalHybrid('.char-edit-real-sel', '.char-edit-real', 'grp-char-pReal', document.getElementById('pReal').value);
    setModalHybrid('.char-edit-func-sel', '.char-edit-func', 'grp-char-pFunc', document.getElementById('pFunc').value);

    const hiddenDeriv = document.querySelectorAll('.derivative-progress .progress-cell');
    modal.querySelectorAll('.char-deriv-cell[data-idx]').forEach((c, i) => {
        if (hiddenDeriv[i] && hiddenDeriv[i].classList.contains('active')) c.classList.add('active');
        else c.classList.remove('active');
    });

    q('.char-edit-name').focus();
}

export function handleCharPresetChange(fieldId, value) {
    const map = { pAnom: ['.char-edit-anom-sel', '.char-edit-anom', 'grp-char-pAnom'], pReal: ['.char-edit-real-sel', '.char-edit-real', 'grp-char-pReal'], pFunc: ['.char-edit-func-sel', '.char-edit-func', 'grp-char-pFunc'] };
    const m = map[fieldId];
    if (!m) return;
    const modal = document.getElementById('charEditModal');
    const wrapper = document.getElementById(m[2]);
    const input = modal.querySelector(m[1]);
    if (value === '__CUSTOM__') {
        wrapper.classList.add('show-input'); input.value = ''; input.focus();
    } else {
        input.value = value; wrapper.classList.remove('show-input');
        document.getElementById(fieldId).value = value;
        if (fieldId === 'pReal') {
            const config = S.CONFIG_DATA.realities.find(r => r.name === value);
            if (config) {
                modal.querySelector('.char-edit-trig1').innerHTML = config.trigger || '';
                modal.querySelector('.char-edit-trig2').innerHTML = config.overload || '';
                document.getElementById('pTrig1').innerHTML = config.trigger || '';
                document.getElementById('pTrig2').innerHTML = config.overload || '';
            }
        } else if (fieldId === 'pFunc') {
            const config = S.CONFIG_DATA.functions.find(f => f.name === value);
            if (config) {
                modal.querySelector('.char-edit-trig3').innerHTML = config.directive || '';
                document.getElementById('pTrig3').innerHTML = config.directive || '';
                if (config.perms && config.perms.length === 3) {
                    modal.querySelector('.char-edit-perm1').value = config.perms[0];
                    modal.querySelector('.char-edit-perm2').value = config.perms[1];
                    modal.querySelector('.char-edit-perm3').value = config.perms[2];
                    document.getElementById('perm1').value = config.perms[0];
                    document.getElementById('perm2').value = config.perms[1];
                    document.getElementById('perm3').value = config.perms[2];
                }
                const itemListContainer = document.getElementById('list-item');
                const presetItems = (config.items || []).slice().reverse();
                const numToReplace = presetItems.length;
                for (let i = 0; i < numToReplace; i++) { if (itemListContainer.firstChild) itemListContainer.firstChild.remove(); }
                presetItems.forEach(itemData => window.addItem(itemData, true));
                if (config.Assessment && config.Assessment.length > 0) {
                    modal._pendingAssessment = config.Assessment;
                }
            }
        } else if (fieldId === 'pAnom') {
            const config = S.CONFIG_DATA.anoms.find(a => a.name === value);
            if (config) {
                const anomListContainer = document.getElementById('list-anom');
                const presetAbilities = (config.abilities || []).slice().reverse();
                const numToReplace = presetAbilities.length;
                for (let i = 0; i < numToReplace; i++) { if (anomListContainer.firstChild) anomListContainer.firstChild.remove(); }
                presetAbilities.forEach(abilityData => window.addAnom(abilityData, true));
            }
        }
    }
}

export function resetCharDropdown(fieldId) {
    const map = { pAnom: ['.char-edit-anom-sel', 'grp-char-pAnom'], pReal: ['.char-edit-real-sel', 'grp-char-pReal'], pFunc: ['.char-edit-func-sel', 'grp-char-pFunc'] };
    const m = map[fieldId];
    if (!m) return;
    const modal = document.getElementById('charEditModal');
    const wrapper = document.getElementById(m[1]);
    const sel = modal.querySelector(m[0]);
    wrapper.classList.remove('show-input'); sel.value = '';
}

export function closeCharEdit() {
    const modal = document.getElementById('charEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
}

export function saveCharEdit() {
    const modal = document.getElementById('charEditModal');
    const q = s => modal.querySelector(s);
    const assessment = modal._pendingAssessment;
    modal._pendingAssessment = null;

    document.getElementById('pName').value = q('.char-edit-name').value;
    document.getElementById('pAnom').value = q('.char-edit-anom').value;
    document.getElementById('pReal').value = q('.char-edit-real').value;
    document.getElementById('pFunc').value = q('.char-edit-func').value;
    document.getElementById('pTrig1').innerHTML = q('.char-edit-trig1').innerHTML || '';
    document.getElementById('pTrig2').innerHTML = q('.char-edit-trig2').innerHTML || '';
    document.getElementById('pTrig3').innerHTML = q('.char-edit-trig3').innerHTML || '';
    document.getElementById('perm1').value = q('.char-edit-perm1').value;
    document.getElementById('perm2').value = q('.char-edit-perm2').value;
    document.getElementById('perm3').value = q('.char-edit-perm3').value;

    modal.querySelectorAll('.char-deriv-cell[data-idx]').forEach((c, i) => {
        const hiddenCells = document.querySelectorAll('.derivative-progress .progress-cell');
        if (hiddenCells[i]) {
            if (c.classList.contains('active')) hiddenCells[i].classList.add('active');
            else hiddenCells[i].classList.remove('active');
        }
    });

    syncCharDisplay();
    window.triggerAutoSave();
    closeCharEdit();
    if (assessment) window.showAssessmentModal(assessment);
}
