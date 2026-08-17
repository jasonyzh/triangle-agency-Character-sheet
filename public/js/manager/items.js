import { S } from './state.js';
import { getAuthHeaders, sanitizeObject, safeFetch } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadRequisitionItems() {
    try {
        var reqUrl = '/api/manager/requisitions';
        if (S.currentBranchId) reqUrl += '?branchId=' + S.currentBranchId;
        const res = await fetch(reqUrl, {
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error('加载失败');
        }

        const data = await res.json();
        if (data.success) {
            S.requisitionItems.length = 0;
            (data.items || []).forEach(i => S.requisitionItems.push(i));
            renderRequisitionItems();
        } else {
            throw new Error(data.message || '加载失败');
        }
    } catch (e) {
        console.error('加载申领物失败:', e);
        S.requisitionItems.length = 0;
        renderRequisitionItems();
        showToast('加载申领物失败: ' + e.message, 'error');
    }
}

function renderRequisitionItems() {
    const container = document.getElementById('requisitionList');

    if (!container) {
        console.error('找不到 requisitionList 容器！');
        return;
    }

    if (!S.requisitionItems || S.requisitionItems.length === 0) {
        container.innerHTML = `
            <div class="requisition-empty">
                <i class="fas fa-box-open" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i>
                <p>暂无申领物，点击右上角添加</p>
            </div>
        `;
        return;
    }

    const searchInput = document.getElementById('itemSearchInput');
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';

    const filteredItems = S.requisitionItems.filter(item => {
        if (!searchTerm) return true;
        return (item.name || '').toLowerCase().includes(searchTerm) ||
               (item.pd || '').toLowerCase().includes(searchTerm) ||
               (item.effect || '').toLowerCase().includes(searchTerm);
    });

    if (filteredItems.length === 0) {
        container.innerHTML = `
            <div class="requisition-empty">
                <i class="fas fa-search" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i>
                <p>未找到匹配的申领物</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filteredItems.map(item => `
        <div class="requisition-item-card" data-id="${item.id}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div class="requisition-item-name">${escapeHtml(item.name || '未命名物品')}</div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <span style="font-size: 10px; padding: 3px 8px; border-radius: 4px; font-weight: bold;
                        ${item.type === 'basic' ? 'background: #e8f5e9; color: #27ae60;' : 'background: #fff3e0; color: #e67e22;'}">
                        ${item.type === 'basic' ? '基础' : '权限'}
                    </span>
                    ${item.once ? '<span style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:bold;background:#ffeaea;color:#e74c3c;">一次性</span>' : ''}
                    <span style="font-size: 12px; color: #f1c40f; font-weight: bold; display: flex; align-items: center; gap: 4px;">
                        <i class="fas fa-award"></i> ${item.price || 0}
                    </span>
                </div>
            </div>
            <div class="requisition-item-pd">${escapeHtml(item.pd || '')}</div>
            <div class="requisition-item-effect">${item.effect || '暂无效果描述'}</div>
            <div class="requisition-item-actions">
                <button class="btn-requisition-action btn-edit-requisition" onclick="openRequisitionModal('${item.id}')">
                    <i class="fas fa-edit"></i> 编辑
                </button>
                <button class="btn-requisition-action btn-assign-requisition" onclick="openAssignRequisitionModal('${item.id}')">
                    <i class="fas fa-user-plus"></i> 分配给角色
                </button>
                <button class="btn-requisition-action btn-delete-requisition" onclick="deleteRequisitionItem('${item.id}')">
                    <i class="fas fa-trash"></i> 删除
                </button>
            </div>
        </div>
    `).join('');
}

function filterRequisitions() {
    renderRequisitionItems();
}

function openRequisitionModal(itemId = null) {
    S.currentEditingRequisitionId = itemId;
    const modal = document.getElementById('requisitionModal');
    const title = document.getElementById('requisitionModalTitle');
    const nameInput = document.getElementById('requisitionItemName');
    const pdInput = document.getElementById('requisitionItemPd');
    const typeInput = document.getElementById('requisitionItemType');
    const priceInput = document.getElementById('requisitionItemPrice');
    const effectInput = document.getElementById('requisitionItemEffect');
    const onceInput = document.getElementById('requisitionItemOnce');

    document.getElementById('priceOptionsList').innerHTML = '';

    if (itemId) {
        const item = S.requisitionItems.find(i => i.id === itemId);
        if (item) {
            title.textContent = '编辑申领物';
            nameInput.value = item.name || '';
            pdInput.value = item.pd || '';
            typeInput.value = item.type || 'basic';
            priceInput.value = item.price || 0;
            onceInput.checked = !!item.once;

            if (item.prices && Array.isArray(item.prices)) {
                item.prices.forEach(p => addPriceOption(p.description, p.price));
            }
            effectInput.innerHTML = item.effect || '';
        }
    } else {
        title.textContent = '新增申领物';
        nameInput.value = '';
        pdInput.value = '';
        typeInput.value = 'basic';
        priceInput.value = 0;
        onceInput.checked = false;
        effectInput.innerHTML = '';
    }

    modal.classList.add('active');
}

function closeRequisitionModal() {
    document.getElementById('requisitionModal').classList.remove('active');
    S.currentEditingRequisitionId = null;
}

function addPriceOption(description = '', price = 0) {
    const container = document.getElementById('priceOptionsList');
    const optionDiv = document.createElement('div');
    optionDiv.className = 'price-option-item';
    const optionIndex = container.children.length + 1;
    optionDiv.innerHTML = `
        <input type="text" class="price-desc-input" placeholder="例如：标准版、豪华版、限定版等..." value="${description}">
        <input type="number" class="price-value-input" placeholder="价格" min="0" value="${price}">
        <button type="button" class="btn-remove-price" onclick="removePriceOption(this)" title="删除此选项">×</button>
    `;
    container.appendChild(optionDiv);
}

function removePriceOption(btn) {
    btn.parentElement.remove();
}

function getPriceOptions() {
    const container = document.getElementById('priceOptionsList');
    const options = [];
    container.querySelectorAll('.price-option-item').forEach(item => {
        const desc = item.querySelector('.price-desc-input').value.trim();
        const price = parseInt(item.querySelector('.price-value-input').value) || 0;
        if (desc || price > 0) {
            options.push({ description: desc, price });
        }
    });
    return options.length > 0 ? options : null;
}

function generateId() {
    return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

async function saveRequisitionItem() {
    const name = document.getElementById('requisitionItemName').value.trim();
    const pd = document.getElementById('requisitionItemPd').value.trim();
    const type = document.getElementById('requisitionItemType').value;
    const price = parseInt(document.getElementById('requisitionItemPrice').value) || 0;
    const effect = document.getElementById('requisitionItemEffect').innerHTML.trim();
    const prices = getPriceOptions();
    const once = document.getElementById('requisitionItemOnce').checked;

    if (!name) {
        showToast('请输入物品名称', 'error');
        return;
    }

    let itemData = {
        id: S.currentEditingRequisitionId || generateId(),
        name,
        pd,
        type,
        price,
        prices,
        once,
        effect,
        branchId: S.currentBranchId,
        createdAt: S.currentEditingRequisitionId ?
            S.requisitionItems.find(i => i.id === S.currentEditingRequisitionId)?.createdAt :
            new Date().toISOString()
    };

    try {
        itemData = sanitizeObject(itemData);

        console.log('[保存申领物] 准备发送的数据:', itemData);

        let jsonBody;
        try {
            jsonBody = JSON.stringify(itemData);
            console.log('[保存申领物] JSON 字符串长度:', jsonBody.length);
            console.log('[保存申领物] JSON 前200字符:', jsonBody.substring(0, 200));
        } catch (stringifyError) {
            console.error('[保存申领物] JSON.stringify 失败:', stringifyError);
            showToast('数据格式化失败: ' + stringifyError.message, 'error');
            return;
        }

        const res = await safeFetch('/api/manager/requisitions', {
            method: S.currentEditingRequisitionId ? 'PUT' : 'POST',
            headers: getAuthHeaders(),
            body: jsonBody
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.message || '保存失败');
        }

        const data = await res.json();

        if (!data.success) {
            throw new Error(data.message || '保存失败');
        }

        await loadRequisitionItems();
        closeRequisitionModal();
        showToast(S.currentEditingRequisitionId ? '申领物已更新' : '申领物已创建', 'success');

    } catch (e) {
        console.error('保存申领物失败:', e);
        showToast('保存失败: ' + e.message, 'error');
    }
}

async function deleteRequisitionItem(itemId) {
    if (!confirm('确定要删除这个申领物吗？')) return;

    try {
        const res = await fetch(`/api/manager/requisitions/${itemId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.message || '删除失败');
        }

        const data = await res.json();
        if (!data.success) {
            throw new Error(data.message || '删除失败');
        }

        await loadRequisitionItems();
        showToast('申领物已删除', 'success');

    } catch (e) {
        console.error('删除申领物失败:', e);
        showToast('删除失败: ' + e.message, 'error');
    }
}

async function openAssignRequisitionModal(itemId) {
    S.currentAssignRequisitionId = itemId;
    const modal = document.getElementById('characterSelectModal');
    modal.classList.add('active');

    await loadCharactersForSelect();
    renderCharacterSelectList();
}

function closeCharacterSelectModal() {
    document.getElementById('characterSelectModal').classList.remove('active');
    S.currentAssignRequisitionId = null;
    document.getElementById('characterFilterInput').value = '';
}

async function loadCharactersForSelect() {
    try {
        var selUrl = '/api/manager/characters';
        if (S.currentBranchId) selUrl += '?branchId=' + S.currentBranchId;
        const res = await fetch(selUrl, {
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            if (res.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 1500);
            }
            throw new Error('加载失败');
        }

        const characters = await res.json();

        S.allCharactersForSelect.length = 0;
        (characters || []).map(char => {
            let charData = {};
            try {
                charData = typeof char.data === 'string' ? JSON.parse(char.data) : (char.data || {});
            } catch(e) {
                charData = {};
            }

            return {
                id: char.id,
                name: charData.pName || char.name || '未命名角色',
                playerName: char.ownerName || '未知玩家',
                data: charData
            };
        }).forEach(c => S.allCharactersForSelect.push(c));
    } catch (e) {
        console.error('加载角色列表失败:', e);
        S.allCharactersForSelect.length = 0;
        showToast('加载角色列表失败: ' + e.message, 'error');
    }
}

function renderCharacterSelectList() {
    const container = document.getElementById('characterSelectList');
    const filterTerm = document.getElementById('characterFilterInput').value.toLowerCase();

    let filteredChars = S.allCharactersForSelect;
    if (filterTerm) {
        filteredChars = S.allCharactersForSelect.filter(char => {
            const charName = (char.name || '').toLowerCase();
            const playerName = (char.playerName || '').toLowerCase();
            return charName.includes(filterTerm) || playerName.includes(filterTerm);
        });
    }

    if (filteredChars.length === 0) {
        container.innerHTML = `
            <div style="text-align:center;padding:20px;color:#999;">
                <i class="fas fa-user-slash" style="font-size:36px;margin-bottom:10px;"></i>
                <p>未找到匹配的角色</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filteredChars.map(char => {
        const charId = char.id;
        return `
            <div class="character-select-item" data-char-id="${charId}" onclick="toggleCharacterSelection('${charId}')">
                <input type="checkbox" class="character-select-checkbox" id="char-check-${charId}">
                <div class="character-select-info">
                    <div class="character-select-name">${escapeHtml(char.name)}</div>
                    <div class="character-select-player">玩家: ${escapeHtml(char.playerName)}</div>
                </div>
            </div>
        `;
    }).join('');
}

function filterCharacterList() {
    renderCharacterSelectList();
}

function toggleCharacterSelection(charId) {
    const item = document.querySelector(`.character-select-item[data-char-id="${charId}"]`);
    const checkbox = document.getElementById(`char-check-${charId}`);
    if (item && checkbox) {
        checkbox.checked = !checkbox.checked;
        if (checkbox.checked) {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    }
}

async function confirmAssignRequisitions() {
    const selectedCharIds = [];
    document.querySelectorAll('.character-select-checkbox:checked').forEach(checkbox => {
        const charId = checkbox.id.replace('char-check-', '');
        selectedCharIds.push(charId);
    });

    if (selectedCharIds.length === 0) {
        showToast('请至少选择一个角色', 'error');
        return;
    }

    const item = S.requisitionItems.find(i => i.id === S.currentAssignRequisitionId);
    if (!item) {
        showToast('申领物不存在', 'error');
        return;
    }

    try {
        const assignData = sanitizeObject({
            requisitionId: S.currentAssignRequisitionId,
            characterIds: selectedCharIds,
            itemData: {
                item: item.name || '',
                pd: item.pd || '',
                eff: item.effect || '',
                once: !!item.once
            },
            branchId: S.currentBranchId
        });

        console.log('[分配申领物] 发送数据:', assignData);

        const res = await safeFetch('/api/manager/assign-requisition', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(assignData)
        });
        const data = await res.json();
        if (data.success) {
            showToast(`已成功分配给 ${selectedCharIds.length} 个角色`, 'success');
            closeCharacterSelectModal();
            return;
        } else {
            throw new Error(data.message || '分配失败');
        }
    } catch (e) {
        console.error('分配申领物失败:', e);
        showToast('分配失败: ' + e.message, 'error');
    }
}

export {
    loadRequisitionItems,
    renderRequisitionItems,
    filterRequisitions,
    openRequisitionModal,
    closeRequisitionModal,
    saveRequisitionItem,
    deleteRequisitionItem,
    addPriceOption,
    removePriceOption,
    getPriceOptions,
    generateId,
    openAssignRequisitionModal,
    closeCharacterSelectModal,
    renderCharacterSelectList,
    filterCharacterList,
    toggleCharacterSelection,
    confirmAssignRequisitions
};
