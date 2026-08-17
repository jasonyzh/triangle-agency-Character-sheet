import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadSiphonProducts() {
    try {
        var siphonUrl = '/api/manager/siphon-products';
        if (S.currentBranchId) siphonUrl += '?branchId=' + S.currentBranchId;
        const res = await fetch(siphonUrl, { headers: getAuthHeaders() });
        if (!res.ok) throw new Error('加载失败');
        const data = await res.json();
        if (data.success) {
            S.siphonProducts.length = 0;
            (data.products || []).forEach(p => S.siphonProducts.push(p));
            renderSiphonProducts();
        }
    } catch (e) {
        console.error('加载Siphon商品失败:', e);
        S.siphonProducts.length = 0;
        renderSiphonProducts();
    }
}

function renderSiphonProducts() {
    const container = document.getElementById('siphonProductList');
    if (!container) return;
    container.innerHTML = '';

    const searchTerm = (document.getElementById('siphonSearchInput')?.value || '').toLowerCase();
    const filtered = S.siphonProducts.filter(p => !searchTerm || p.name.toLowerCase().includes(searchTerm));

    if (filtered.length === 0) {
        container.innerHTML = `<div class="requisition-empty"><i class="fas fa-eye" style="font-size:48px;margin-bottom:15px;opacity:0.3;color:#2980b9"></i><p>${S.siphonProducts.length === 0 ? '暂无Siphon商品，点击"新增商品"创建' : '没有匹配的商品'}</p></div>`;
        return;
    }

    container.innerHTML = filtered.map(product => `
        <div class="requisition-item-card" data-id="${product.id}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div class="requisition-item-name">${escapeHtml(product.name || '未命名商品')}</div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <span style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:bold;background:rgba(41,128,185,0.1);color:#2980b9;">
                        <i class="fas fa-eye"></i> Siphon
                    </span>
                    <span style="font-size:12px;color:#e74c3c;font-weight:bold;display:flex;align-items:center;gap:4px;">
                        <i class="fas fa-exclamation-circle"></i> ${product.price}申诫
                    </span>
                </div>
            </div>
            <div class="requisition-item-effect">${product.description || '暂无描述'}</div>
            <div class="requisition-item-actions">
                <button class="btn-requisition-action btn-edit-requisition" onclick="openSiphonModal('${product.id}')">
                    <i class="fas fa-edit"></i> 编辑
                </button>
                <button class="btn-requisition-action btn-delete-requisition" onclick="deleteSiphonProduct('${product.id}')">
                    <i class="fas fa-trash"></i> 删除
                </button>
            </div>
        </div>
    `).join('');
}

function filterSiphonProducts() { renderSiphonProducts(); }

function openSiphonModal(productId = null) {
    S.currentEditingSiphonId = productId;
    const modal = document.getElementById('siphonModal');
    const title = document.getElementById('siphonModalTitle');
    const nameInput = document.getElementById('siphonProductName');
    const priceInput = document.getElementById('siphonProductPrice');
    const descInput = document.getElementById('siphonProductDesc');

    if (productId) {
        const product = S.siphonProducts.find(p => p.id === productId);
        if (product) {
            title.textContent = '编辑商品';
            nameInput.value = product.name || '';
            priceInput.value = product.price || 1;
            descInput.innerHTML = product.description || '';
        }
    } else {
        title.textContent = '新增商品';
        nameInput.value = '';
        priceInput.value = 1;
        descInput.innerHTML = '';
    }
    modal.classList.add('active');
}

function closeSiphonModal() {
    document.getElementById('siphonModal').classList.remove('active');
    S.currentEditingSiphonId = null;
}

async function saveSiphonProduct() {
    const name = document.getElementById('siphonProductName').value.trim();
    const price = parseInt(document.getElementById('siphonProductPrice').value) || 1;
    const description = document.getElementById('siphonProductDesc').innerHTML.trim();

    if (!name) { showToast('请输入商品名称', 'error'); return; }

    const body = { id: S.currentEditingSiphonId, name, price, description, branchId: S.currentBranchId };

    try {
        const res = await fetch('/api/manager/siphon-products', {
            method: S.currentEditingSiphonId ? 'PUT' : 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message, 'success');
            closeSiphonModal();
            await loadSiphonProducts();
        } else {
            showToast(data.message || '保存失败', 'error');
        }
    } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
    }
}

async function deleteSiphonProduct(productId) {
    if (!confirm('确定要删除此商品吗？')) return;
    try {
        const res = await fetch(`/api/manager/siphon-products/${productId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        const data = await res.json();
        if (data.success) {
            showToast('商品已删除', 'success');
            await loadSiphonProducts();
        } else {
            showToast(data.message || '删除失败', 'error');
        }
    } catch (e) {
        showToast('删除失败', 'error');
    }
}

export {
    loadSiphonProducts,
    renderSiphonProducts,
    filterSiphonProducts,
    openSiphonModal,
    closeSiphonModal,
    saveSiphonProduct,
    deleteSiphonProduct
};
