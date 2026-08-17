import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadNpcTemplates() {
    if (!S.currentBranchId) return;
    try {
        const res = await fetch('/api/npc-templates?branchId=' + S.currentBranchId, { headers: getAuthHeaders() });
        S.npcTemplates.length = 0;
        const data = await res.json();
        data.forEach(t => S.npcTemplates.push(t));
        renderNpcTemplates();
    } catch(e) {
        showToast('加载NPC关系模板失败');
    }
}

function renderNpcTemplates() {
    const container = document.getElementById('npcTemplateList');
    if (!container) return;
    if (!S.npcTemplates.length) {
        container.innerHTML = '<div class="requisition-empty"><i class="fas fa-user-tag" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i><p>暂无NPC关系模板，点击右上角创建</p></div>';
        return;
    }
    container.innerHTML = S.npcTemplates.map(t => {
        const lvl = t.lvl || 0;
        let dots = '';
        for (let i = 1; i <= 9; i++) dots += '<span class="npc-lvl-dot' + (i <= lvl ? ' active' : '') + '"></span>';
        let html = '<div class="npc-tpl-card">';
        html += '<button class="anom-tpl-edit-btn" onclick="event.stopPropagation();openNpcTemplateModal(\'' + t.id + '\')"><i class="fas fa-pen"></i></button>';
        html += '<button class="anom-tpl-del-btn" onclick="event.stopPropagation();deleteNpcTemplate(\'' + t.id + '\')"><i class="fas fa-trash"></i></button>';
        html += '<div class="anomaly-tpl-title-bar">';
        html += '<div class="anomaly-tpl-title-row">';
        html += '<span class="anomaly-tpl-disp-name">' + escapeHtml(t.name || '') + '</span>';
        if (t.actor) {
            html += '<span class="anomaly-tpl-field-sep">|</span>';
            html += '<span class="anomaly-tpl-disp-trig">' + escapeHtml(t.actor) + '</span>';
        }
        if (t.act) html += '<span class="npc-act-badge"><i class="fas fa-check"></i> 已激活</span>';
        html += '</div>';
        html += '</div>';
        html += '<div class="anomaly-tpl-body">';
        if (t.description) html += '<div class="npc-tpl-desc">' + t.description + '</div>';
        if (t.conn || lvl > 0) {
            html += '<div class="npc-tpl-conn-row">';
            html += '<span class="npc-conn-lbl"><i class="fas fa-link"></i> 连结</span>';
            html += '<span class="npc-conn-dots">' + dots + '</span>';
            if (t.conn) html += '<div class="npc-tpl-conn">' + t.conn + '</div>';
            html += '</div>';
        }
        html += '</div>';
        html += '</div>';
        return html;
    }).join('');
}

async function loadBonusOptions() {
    if (S.npcBonusOptions.length) return;
    try {
        const res = await fetch('/api/options');
        const data = await res.json();
        S.npcBonusOptions = (data && data.bonuses) ? data.bonuses : [];
    } catch(e) {
        S.npcBonusOptions = [];
    }
}

async function openNpcTemplateModal(editId) {
    const modal = document.getElementById('npcTemplateModal');
    document.getElementById('npcEditId').value = editId || '';
    document.getElementById('npcModalTitle').textContent = editId ? '编辑NPC关系模板' : '创建NPC关系模板';

    document.getElementById('npcTplName').value = '';
    document.getElementById('npcTplActor').value = '';
    document.getElementById('npcTplDesc').innerHTML = '';
    document.getElementById('npcTplAct').checked = false;

    // 重置连结加成 hybrid input
    const bonusSel = document.getElementById('npcTplConnSel');
    await loadBonusOptions();
    bonusSel.innerHTML = '<option value="">-- 选择预设加成 --</option>' + S.npcBonusOptions.map(b => '<option value="' + b + '">' + b + '</option>').join('') + '<option value="__CUSTOM__">自定义...</option>';
    const connWrapper = bonusSel.closest('.hybrid-input-wrapper');
    connWrapper.classList.remove('show-input');
    bonusSel.value = '';
    document.getElementById('npcTplConn').innerHTML = '';

    setNpcLvlDots(0);

    if (editId) {
        const t = S.npcTemplates.find(x => x.id === editId);
        if (t) {
            document.getElementById('npcTplName').value = t.name || '';
            document.getElementById('npcTplActor').value = t.actor || '';
            document.getElementById('npcTplDesc').innerHTML = t.description || '';
            document.getElementById('npcTplAct').checked = !!t.act;
            const connVal = t.conn || '';
            document.getElementById('npcTplConn').innerHTML = connVal;
            if (connVal.trim()) { connWrapper.classList.add('show-input'); bonusSel.value = '__CUSTOM__'; }
            setNpcLvlDots(t.lvl || 0);
        }
    }

    modal.classList.add('show');
}

function closeNpcTemplateModal() {
    document.getElementById('npcTemplateModal').classList.remove('show');
}

function handleNpcBonusChange(select) {
    const wrapper = select.parentElement;
    const editor = wrapper.querySelector('.rich-editor');
    const val = select.value;
    wrapper.classList.add('show-input');
    if (val === '__CUSTOM__') { editor.focus(); }
    else { editor.innerHTML = val; }
}

function resetNpcBonus(btn) {
    const wrapper = btn.parentElement;
    const select = wrapper.querySelector('select');
    wrapper.classList.remove('show-input');
    select.value = '';
    wrapper.querySelector('.rich-editor').innerHTML = '';
}

function setNpcLvlDots(val) {
    const v = parseInt(val) || 0;
    document.getElementById('npcTplLvl').value = v;
    document.getElementById('npcTplLvlNum').textContent = v;
    document.querySelectorAll('#npcTplLvlDots .dot').forEach((d, i) => {
        i < v ? d.classList.add('active') : d.classList.remove('active');
    });
}

function clickNpcLvlDot(i) {
    const current = parseInt(document.getElementById('npcTplLvl').value) || 0;
    setNpcLvlDots(i === current ? i - 1 : i);
}

async function saveNpcTemplate() {
    const editId = document.getElementById('npcEditId').value;
    const name = document.getElementById('npcTplName').value.trim();
    if (!name) { showToast('请输入关系姓名'); return; }

    const body = {
        branchId: S.currentBranchId,
        name,
        actor: document.getElementById('npcTplActor').value,
        description: document.getElementById('npcTplDesc').innerHTML,
        conn: document.getElementById('npcTplConn').innerHTML,
        lvl: parseInt(document.getElementById('npcTplLvl').value) || 0,
        act: document.getElementById('npcTplAct').checked
    };

    try {
        const url = editId ? '/api/npc-templates/' + editId : '/api/npc-templates';
        const method = editId ? 'PUT' : 'POST';
        const res = await fetch(url, { method, headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await res.json();
        if (data.success) {
            showToast(editId ? '已更新' : '已创建', 'success');
            closeNpcTemplateModal();
            await loadNpcTemplates();
        } else {
            showToast(data.message || '保存失败');
        }
    } catch(e) {
        showToast('保存失败');
    }
}

async function deleteNpcTemplate(id) {
    if (!confirm('确定删除此NPC关系模板？')) return;
    try {
        const res = await fetch('/api/npc-templates/' + id, { method: 'DELETE', headers: getAuthHeaders() });
        const data = await res.json();
        if (data.success) {
            showToast('已删除', 'success');
            await loadNpcTemplates();
        } else {
            showToast(data.message || '删除失败');
        }
    } catch(e) {
        showToast('删除失败');
    }
}

async function openGrantNpcModal(charId, charName) {
    S.currentGrantNpcCharId = charId;
    document.getElementById('grantNpcCharName').textContent = charName;

    if (!S.npcTemplates.length) {
        await loadNpcTemplates();
    }

    let charRealNames = [];
    try {
        const res = await fetch('/api/character/' + charId, { headers: getAuthHeaders() });
        const data = await res.json();
        charRealNames = (data.reals || []).map(r => r.name);
    } catch(e) {}

    const list = document.getElementById('grantNpcList');
    if (!S.npcTemplates.length) {
        list.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">暂无可赋予的NPC关系模板，请先在 NPC tab 创建</div>';
    } else {
        list.innerHTML = S.npcTemplates.map(t => {
            const isGranted = charRealNames.includes(t.name);
            const actorLabel = t.actor ? ' (' + escapeHtml(t.actor) + ')' : '';
            return `
                <label class="doc-item">
                    <input type="checkbox" value="${t.id}" ${isGranted ? 'checked' : ''}>
                    <div class="doc-item-content">
                        <div class="doc-item-name">${escapeHtml(t.name)}</div>
                        <div class="doc-item-meta">${actorLabel}</div>
                    </div>
                </label>
            `;
        }).join('');
    }

    document.getElementById('grantNpcModal').classList.add('show');
    const searchInput = document.getElementById('grantNpcSearch');
    if (searchInput) { searchInput.value = ''; }
}

function closeGrantNpcModal() {
    document.getElementById('grantNpcModal').classList.remove('show');
}

async function saveGrantedNpcs() {
    if (!S.currentGrantNpcCharId) return;

    const allCheckboxes = Array.from(document.querySelectorAll('#grantNpcList input[type="checkbox"]'));
    const selectedIds = allCheckboxes.filter(cb => cb.checked).map(cb => cb.value);
    const unselectedIds = allCheckboxes.filter(cb => !cb.checked).map(cb => cb.value);
    const btn = document.querySelector('#grantNpcModal .btn-modal-confirm');
    btn.textContent = '保存中...';
    btn.disabled = true;

    try {
        const grantPromises = selectedIds.map(id =>
            fetch('/api/npc-templates/' + id + '/grant', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: S.currentGrantNpcCharId })
            }).then(r => r.json())
        );
        const revokePromises = unselectedIds.map(id =>
            fetch('/api/npc-templates/' + id + '/revoke', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: S.currentGrantNpcCharId })
            }).then(r => r.json())
        );

        const grantResults = await Promise.all(grantPromises);
        await Promise.all(revokePromises);

        const failures = grantResults.filter(r => r && r.success === false && r.message);
        if (failures.length) {
            showToast(failures[0].message, 'error');
        } else {
            showToast('关系已更新', 'success');
            closeGrantNpcModal();
        }
    } catch (e) {
        showToast('更新失败', 'error');
    } finally {
        btn.textContent = '保存';
        btn.disabled = false;
    }
}

function filterGrantNpc(keyword) {
    const kw = (keyword || '').toLowerCase();
    document.querySelectorAll('#grantNpcList .doc-item').forEach(item => {
        const name = item.querySelector('.doc-item-name').textContent.toLowerCase();
        item.style.display = name.includes(kw) ? '' : 'none';
    });
}

export {
    loadNpcTemplates,
    renderNpcTemplates,
    openNpcTemplateModal,
    closeNpcTemplateModal,
    handleNpcBonusChange,
    resetNpcBonus,
    setNpcLvlDots,
    clickNpcLvlDot,
    saveNpcTemplate,
    deleteNpcTemplate,
    openGrantNpcModal,
    closeGrantNpcModal,
    saveGrantedNpcs,
    filterGrantNpc
};
