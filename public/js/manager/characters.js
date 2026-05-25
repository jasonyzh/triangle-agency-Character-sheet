import { S } from './state.js';
import { getAuthHeaders, sanitizeObject, safeFetch } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadCharacters() {
    console.log('loadCharacters called');

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        var url = '/api/manager/characters';
        if (S.currentBranchId) url += '?branchId=' + S.currentBranchId;
        const res = await fetch(url, {
            headers: getAuthHeaders(),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!res.ok) {
            const container = document.getElementById('charList');
            if (container) {
                container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>加载失败</h3>
                    <p>状态码: ${res.status}</p>
                </div>`;
            }
            showToast('加载失败');
            return;
        }

        const data = await res.json();
        S.allCharacters.length = 0;
        data.forEach(c => S.allCharacters.push(c));
        renderCharacters(S.allCharacters);

    } catch (e) {
        console.error('loadCharacters error:', e);
        const container = document.getElementById('charList');
        if (container) {
            const errorMsg = e.name === 'AbortError' ? '请求超时，请检查网络连接' : (e.message || '未知错误');
            container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>加载失败</h3>
                <p>${errorMsg}</p>
                <button onclick="loadCharacters()" style="margin-top:10px;padding:8px 16px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;">重试</button>
            </div>`;
        }
        showToast('加载失败: ' + (e.message || '未知错误'));
    }
}

function handleSearch() {
    const query = document.getElementById('charSearchInput').value.trim().toLowerCase();
    if (!query) {
        renderCharacters(S.allCharacters);
        return;
    }

    const filtered = S.allCharacters.filter(c => {
        return (c.name && c.name.toLowerCase().includes(query)) ||
               (c.ownerName && c.ownerName.toLowerCase().includes(query)) ||
               (c.func && c.func.toLowerCase().includes(query)) ||
               (c.anom && c.anom.toLowerCase().includes(query)) ||
               (c.real && c.real.toLowerCase().includes(query));
    });

    renderCharacters(filtered);
}

function renderCharacters(chars) {
    const container = document.getElementById('charList');

    if (!container) return;

    if (!chars || chars.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1/-1;">
                <i class="fas fa-folder-open"></i>
                <h3>未找到匹配角色</h3>
                <p>尝试更换搜索关键词</p>
            </div>
        `;
        return;
    }

    container.innerHTML = chars.map(c => {
        const safeCharName = c.name.replace(/'/g, "\\'");
        const safeOwnerName = c.ownerName.replace(/'/g, "\\'");

        return `
        <div class="char-card">
            <div class="card-header" onclick="openSheet('${c.id}')">
                <div class="card-name">${c.name}</div>
                <div class="card-owner"><i class="fas fa-user"></i> ${c.ownerName}</div>
            </div>
            <div class="card-body" onclick="openSheet('${c.id}')">
                <div class="card-info">
                    <div class="info-row">
                        <span class="info-label">异常</span>
                        <span class="info-value">${c.anom || '---'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">职能</span>
                        <span class="info-value">${c.func || '---'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">现实</span>
                        <span class="info-value">${c.real || '---'}</span>
                    </div>
                </div>
            </div>
            <div class="card-footer">
                <button class="btn-card-action btn-records" onclick="event.stopPropagation(); openRecordModal('${c.id}', '${safeCharName}')" title="嘉奖/申诫">
                    <i class="fas fa-medal"></i>
                </button>
                ${S.role >= 2 ? `<button class="btn-card-action btn-requisition-perm" onclick="event.stopPropagation(); openRequisitionPermModal(${c.ownerId})" title="权限物品授权">
                    <i class="fas fa-gift"></i>
                </button>` : ''}
                <button class="btn-card-action btn-docs" onclick="event.stopPropagation(); openDocModal('${c.id}', '${safeCharName}')" title="高墙授权">
                    <i class="fas fa-file-shield"></i>
                </button>
                <button class="btn-card-action" onclick="event.stopPropagation(); openGrantAnomalyModal('${c.id}', '${safeCharName}')" title="赋予异常能力">
                    <i class="fas fa-bolt"></i>
                </button>
                <button class="btn-card-action btn-slots" onclick="event.stopPropagation(); openSlotModal('${c.id}', '${safeCharName}')" title="槽位管理">
                    <i class="fas fa-unlock-alt"></i>
                </button>
                <button class="btn-card-action btn-delete" onclick="event.stopPropagation(); deleteCharacter('${c.id}', '${safeCharName}')" title="彻底删除角色">
                    <i class="fas fa-trash-alt"></i>
                </button>
                <button class="btn-card-action btn-view" onclick="openSheet('${c.id}')" title="编辑">
                    <i class="fas fa-edit"></i>
                </button>
            </div>
        </div>
        `
    }).join('');
}

async function deleteCharacter(charId, charName) {
    if (!confirm(`【警告】确定要彻底删除角色 "${charName}" 吗？\n此操作不可逆，将删除该角色的所有数据和授权记录。`)) {
        return;
    }

    try {
        const res = await fetch(`/api/character/${charId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        const data = await res.json();

        if (data.success) {
            showToast('角色已彻底删除', true);
            loadCharacters();
        } else {
            showToast(data.message || '删除失败');
        }
    } catch (e) {
        console.error('Delete character error:', e);
        showToast('删除失败');
    }
}

function handleSwipe(startX, startY, endX, endY) {
    const xDiff = endX - startX;
    const yDiff = endY - startY;
    const menu = document.getElementById('sideMenu');
    const isOpen = menu.classList.contains('show');
    const screenWidth = window.innerWidth;

    if (Math.abs(yDiff) > Math.abs(xDiff)) return;

    if (!isOpen && xDiff < -S.swipeThreshold && startX > (screenWidth - S.edgeThreshold)) {
        toggleSideMenu();
    }

    if (isOpen && xDiff > S.swipeThreshold) {
        closeSideMenu();
    }
}

function openSheet(id) {
    window.location.href = `sheet.html?id=${id}&from=manager`;
}

async function openSlotModal(charId, charName) {
    S.currentSlotCharId = charId;
    document.getElementById('modalCharName').textContent = charName;

    try {
        const res = await fetch(`/api/character/${charId}/slots`, {
            headers: getAuthHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            Object.assign(S.currentSlotData, data);
        } else {
            Object.assign(S.currentSlotData, { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 });
        }
    } catch (e) {
        Object.assign(S.currentSlotData, { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 });
    }

    document.getElementById('anomSlotValue').textContent = S.currentSlotData.anomSlots;
    document.getElementById('realSlotValue').textContent = S.currentSlotData.realSlots;
    document.getElementById('anomUsed').textContent = S.currentSlotData.currentAnoms;
    document.getElementById('realUsed').textContent = S.currentSlotData.currentReals;

    document.getElementById('slotModal').classList.add('show');
}

function closeSlotModal() {
    document.getElementById('slotModal').classList.remove('show');
    S.currentSlotCharId = null;
}

function adjustSlot(type, delta) {
    const valueEl = document.getElementById(type + 'SlotValue');
    const usedEl = document.getElementById(type + 'Used');
    let current = parseInt(valueEl.textContent);
    const used = parseInt(usedEl.textContent);

    current += delta;

    const minValue = Math.max(3, used);
    if (current < minValue) current = minValue;

    valueEl.textContent = current;
}

async function saveSlots() {
    if (!S.currentSlotCharId) return;

    const anomSlots = parseInt(document.getElementById('anomSlotValue').textContent);
    const realSlots = parseInt(document.getElementById('realSlotValue').textContent);

    try {
        const res = await fetch(`/api/character/${S.currentSlotCharId}/slots`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ anomSlots, realSlots })
        });

        const data = await res.json();
        if (data.success) {
            showToast('槽位设置已保存', true);
            closeSlotModal();
        } else {
            showToast(data.message || '保存失败');
        }
    } catch (e) {
        showToast('保存失败');
    }
}

async function openRequisitionPermModal(userId) {
    S.currentPermUserId = userId;
    const modal = document.getElementById('requisitionPermModal');
    const listContainer = document.getElementById('requisitionPermList');

    listContainer.innerHTML = '<div style="padding:20px;text-align:center;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    modal.classList.add('show');
    document.getElementById('requisitionPermSearch').value = '';

    try {
        const res1 = await fetch('/api/manager/requisitions' + (S.currentBranchId ? '?branchId=' + S.currentBranchId : ''), {
            headers: getAuthHeaders()
        });

        if (!res1.ok) throw new Error('获取申领物失败');
        const data1 = await res1.json();
        const allItems = (data1.items || []).filter(item => item.type === 'permission');

        const res2 = await fetch(`/api/admin/user/${userId}/requisition-permissions`, {
            headers: getAuthHeaders()
        });

        let grantedIds = [];
        if (res2.ok) {
            const data2 = await res2.json();
            grantedIds = data2.permissions || [];
        }

        if (allItems.length === 0) {
            listContainer.innerHTML = '<div style="padding:20px;text-align:center;color:#999;">暂无权限申领物</div>';
        } else {
            listContainer.innerHTML = allItems.map(item => `
                <label class="doc-item" data-pd="${escapeHtml(item.pd || '')}">
                    <input type="checkbox" value="${item.id}" ${grantedIds.includes(item.id) ? 'checked' : ''}>
                    <span>
                        ${escapeHtml(item.name)}
                        ${item.pd ? `<span style="color: #95a5a6; font-size: 11px; margin-left: 8px;">[${escapeHtml(item.pd)}]</span>` : ''}
                        <span style="color: #f1c40f; margin-left: 8px;">
                            <i class="fas fa-award"></i> ${item.price || 0}
                        </span>
                    </span>
                </label>
            `).join('');
        }
    } catch (e) {
        console.error('加载权限物品失败:', e);
        listContainer.innerHTML = '<div style="padding:20px;text-align:center;color:#e74c3c;">加载失败</div>';
    }
}

function filterRequisitionPerms() {
    const term = document.getElementById('requisitionPermSearch').value.toLowerCase();
    document.querySelectorAll('#requisitionPermList .doc-item').forEach(item => {
        const text = item.querySelector('span').textContent.toLowerCase();
        const pd = item.getAttribute('data-pd').toLowerCase();
        const matches = text.includes(term) || pd.includes(term);
        item.style.display = matches ? 'flex' : 'none';
    });
}

function closeRequisitionPermModal() {
    document.getElementById('requisitionPermModal').classList.remove('show');
    S.currentPermUserId = null;
}

async function saveRequisitionPerms() {
    if (!S.currentPermUserId) return;

    const selectedIds = Array.from(document.querySelectorAll('#requisitionPermList input:checked')).map(cb => cb.value);
    const btn = document.querySelector('#requisitionPermModal .btn-modal-confirm');
    btn.textContent = '保存中...';
    btn.disabled = true;

    try {
        const res = await fetch(`/api/admin/user/${S.currentPermUserId}/requisition-permissions`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ requisitionIds: selectedIds })
        });

        if (!res.ok) throw new Error('保存失败');
        const data = await res.json();

        if (!data.success) throw new Error(data.message || '保存失败');

        showToast('权限物品授权已更新', 'success');
        closeRequisitionPermModal();
    } catch (e) {
        console.error('保存失败:', e);
        showToast('保存失败: ' + e.message, 'error');
    } finally {
        btn.textContent = '保存';
        btn.disabled = false;
    }
}

async function openDocModal(charId, charName) {
    S.currentDocCharId = charId;
    document.getElementById('docAuthCharName').textContent = charName;
    document.getElementById('docSearch').value = '';

    const listContainer = document.getElementById('docAuthList');
    listContainer.innerHTML = '<div style="padding:20px;text-align:center;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    document.getElementById('docAuthModal').classList.add('show');

    try {
        const res = await fetch(`/api/manager/character/${charId}/permissions`, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error('无法获取权限列表');
        const files = await res.json();
        renderDocList(files);
    } catch (e) {
        console.error(e);
        listContainer.innerHTML = `<div style="color:red;text-align:center;">${e.message}</div>`;
    }
}

function renderDocList(files) {
    const container = document.getElementById('docAuthList');
    if (!files || files.length === 0) {
        container.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">无高墙文件</div>';
        return;
    }

    container.innerHTML = files.map(f => `
        <label class="doc-item">
            <input type="checkbox" value="${f.filename}" ${f.hasPerm ? 'checked' : ''}>
            <span>${f.filename.replace('.md', '')}</span>
        </label>
    `).join('');
}

function filterDocs() {
    const term = document.getElementById('docSearch').value.toLowerCase();
    document.querySelectorAll('#docAuthList .doc-item').forEach(item => {
        const text = item.querySelector('span').textContent.toLowerCase();
        item.style.display = text.includes(term) ? 'flex' : 'none';
    });
}

function closeDocModal() {
    document.getElementById('docAuthModal').classList.remove('show');
    S.currentDocCharId = null;
}

async function saveDocPermissions() {
    if (!S.currentDocCharId) return;

    const selectedFiles = Array.from(document.querySelectorAll('#docAuthList input:checked')).map(cb => cb.value);

    const btn = document.querySelector('#docAuthModal .btn-modal-confirm');
    btn.textContent = '保存中...';
    btn.disabled = true;

    try {
        const res = await fetch(`/api/manager/character/${S.currentDocCharId}/permissions`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ permissions: selectedFiles })
        });

        const data = await res.json();
        if (data.success) {
            showToast('权限已更新', true);
            closeDocModal();
        } else {
            throw new Error(data.message || '更新失败');
        }
    } catch (e) {
        showToast(e.message, false);
    } finally {
        btn.textContent = '保存更改';
        btn.disabled = false;
    }
}

async function openRecordModal(charId, charName) {
    S.currentRecordCharId = charId;
    S.currentRecordTab = 'reward';
    document.getElementById('recordCharName').textContent = charName;
    document.getElementById('recordReasonInput').value = '';

    document.getElementById('tabReward').className = 'record-tab active-reward';
    document.getElementById('tabReprimand').className = 'record-tab';
    updateAddButton();

    document.getElementById('recordModal').classList.add('show');

    await loadRecords();
}

function closeRecordModal() {
    document.getElementById('recordModal').classList.remove('show');
    S.currentRecordCharId = null;
}

function switchRecordTab(tab) {
    S.currentRecordTab = tab;

    const tabReward = document.getElementById('tabReward');
    const tabReprimand = document.getElementById('tabReprimand');

    if (tab === 'reward') {
        tabReward.className = 'record-tab active-reward';
        tabReprimand.className = 'record-tab';
    } else {
        tabReward.className = 'record-tab';
        tabReprimand.className = 'record-tab active-reprimand';
    }

    updateAddButton();
    renderRecords();
}

function updateAddButton() {
    const btnAdd = document.getElementById('btnAddRecord');
    const btnDeduct = document.getElementById('btnDeductRecord');
    if (S.currentRecordTab === 'reward') {
        btnAdd.className = 'btn-add-record reward';
        btnAdd.innerHTML = '<i class="fas fa-plus"></i> 添加嘉奖';
        btnDeduct.innerHTML = '<i class="fas fa-minus"></i> 扣除嘉奖';
        btnDeduct.style.background = '#e67e22';
    } else {
        btnAdd.className = 'btn-add-record reprimand';
        btnAdd.innerHTML = '<i class="fas fa-plus"></i> 添加申诫';
        btnDeduct.innerHTML = '<i class="fas fa-minus"></i> 扣除申诫';
        btnDeduct.style.background = '#c0392b';
    }
}

async function loadRecords() {
    const listEl = document.getElementById('recordList');
    listEl.innerHTML = '<div style="text-align:center;padding:20px;"><i class="fas fa-circle-notch fa-spin"></i></div>';

    try {
        const res = await fetch(`/api/character/${S.currentRecordCharId}/records`, {
            headers: getAuthHeaders()
        });

        if (!res.ok) throw new Error('加载失败');

        const data = await res.json();
        S.currentRecords.rewards = data.rewards || [];
        S.currentRecords.reprimands = data.reprimands || [];
        renderRecords();
    } catch (e) {
        listEl.innerHTML = '<div class="record-empty" style="color:#e74c3c;">加载失败</div>';
    }
}

function renderRecords() {
    const listEl = document.getElementById('recordList');
    const records = S.currentRecordTab === 'reward' ? S.currentRecords.rewards : S.currentRecords.reprimands;

    if (!records || records.length === 0) {
        listEl.innerHTML = `<div class="record-empty">暂无${S.currentRecordTab === 'reward' ? '嘉奖' : '申诫'}记录</div>`;
        return;
    }

    const sorted = [...records].sort((a, b) => b.date - a.date);

    listEl.innerHTML = sorted.map(r => {
        const date = new Date(r.date).toLocaleString('zh-CN', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit'
        });
        const countBadge = (r.count && Math.abs(r.count) !== 1)
            ? `<span class="record-count-badge ${S.currentRecordTab === 'reprimand' ? 'reprimand' : ''}">x${r.count}</span>`
            : '';
        return `
            <div class="record-entry ${S.currentRecordTab === 'reprimand' ? 'reprimand' : ''}">
                <div class="record-reason">${escapeHtml(r.reason)}${countBadge}</div>
                <div class="record-meta">
                    <i class="fas fa-clock"></i> ${date}
                    ${r.addedByName ? `&nbsp;&nbsp;<i class="fas fa-user"></i> ${escapeHtml(r.addedByName)}` : ''}
                </div>
                <button class="btn-delete-record" onclick="deleteRecord('${r.id}')" title="删除">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
    }).join('');
}

async function addRecord(type = 'add') {
    const reason = document.getElementById('recordReasonInput').value.trim();
    let count = parseInt(document.getElementById('recordCountInput').value) || 1;

    if (!reason) {
        showToast('请输入原因');
        return;
    }

    if (count < 1 || count > 99) {
        showToast('数量必须在1-99之间');
        return;
    }

    if (type === 'deduct') {
        count = -count;
    }

    const endpoint = S.currentRecordTab === 'reward' ? 'reward' : 'reprimand';
    const btn = type === 'add' ? document.getElementById('btnAddRecord') : document.getElementById('btnDeductRecord');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> 处理中...';
    btn.disabled = true;

    try {
        const recordData = sanitizeObject({ reason, count });
        console.log('[添加记录] 发送数据:', recordData);

        const res = await safeFetch(`/api/character/${S.currentRecordCharId}/${endpoint}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(recordData)
        });

        const data = await res.json();
        if (data.success) {
            showToast(data.message || '操作成功', true);
            document.getElementById('recordReasonInput').value = '';
            document.getElementById('recordCountInput').value = '1';
            await loadRecords();
        } else {
            throw new Error(data.message || '操作失败');
        }
    } catch (e) {
        showToast(e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function deleteRecord(recordId) {
    if (!confirm('确定要删除这条记录吗？')) return;

    try {
        const res = await fetch(`/api/character/${S.currentRecordCharId}/record/${recordId}?type=${S.currentRecordTab}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('记录已删除', true);
            await loadRecords();
        } else {
            throw new Error(data.message || '删除失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

function openAgentDetail(charId) {
    const modal = document.getElementById('agentDetailModal');
    const iframe = document.getElementById('agentDetailIframe');
    iframe.src = `sheet.html?id=${charId}&readonly=true&embed=true`;
    modal.classList.add('show');
}

function closeAgentDetailModal() {
    const modal = document.getElementById('agentDetailModal');
    const iframe = document.getElementById('agentDetailIframe');
    modal.classList.remove('show');
    iframe.src = 'about:blank';
}

import { toggleSideMenu, closeSideMenu } from './ui.js';

export {
    loadCharacters,
    handleSearch,
    renderCharacters,
    deleteCharacter,
    handleSwipe,
    openSheet,
    openSlotModal,
    closeSlotModal,
    adjustSlot,
    saveSlots,
    openRequisitionPermModal,
    filterRequisitionPerms,
    closeRequisitionPermModal,
    saveRequisitionPerms,
    openDocModal,
    renderDocList,
    filterDocs,
    closeDocModal,
    saveDocPermissions,
    openRecordModal,
    closeRecordModal,
    switchRecordTab,
    updateAddButton,
    loadRecords,
    renderRecords,
    addRecord,
    deleteRecord,
    openAgentDetail,
    closeAgentDetailModal
};
