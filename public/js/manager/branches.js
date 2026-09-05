import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadBranchApplications() {
    try {
        const res = await fetch('/api/manager/branch-applications', { headers: getAuthHeaders() });
        const data = await res.json();
        if (data.success) {
            S.branchApplications.length = 0;
            (data.applications || []).forEach(a => S.branchApplications.push(a));
            renderBranchApplications();
        }
    } catch (e) {
        console.error('加载申请失败:', e);
        S.branchApplications.length = 0;
        renderBranchApplications();
    }
}

function renderBranchApplications() {
    const container = document.getElementById('applicationList');
    if (!container) return;

    if (S.branchApplications.length === 0) {
        container.innerHTML = `<div class="requisition-empty"><i class="fas fa-door-open" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i><p>暂无待审批的入职申请</p></div>`;
        return;
    }

    container.innerHTML = S.branchApplications.map(app => {
        const date = new Date(app.created_at).toLocaleString('zh-CN');
        return `
            <div class="requisition-item-card">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                    <div>
                        <div class="requisition-item-name">${escapeHtml(app.user_name || app.username)}</div>
                        <div style="font-size:12px;color:#aaa;margin-top:4px;">账号: ${escapeHtml(app.username || '')} | 申请加入: ${escapeHtml(app.branch_name || '')}</div>
                        <div style="font-size:11px;color:#999;margin-top:2px;"><i class="fas fa-clock"></i> ${date}</div>
                    </div>
                </div>
                <div class="requisition-item-actions">
                    <button class="btn-requisition-action" style="background:#27ae60;color:white;" onclick="reviewApplication(${app.id}, 'approved')">
                        <i class="fas fa-check"></i> 批准
                    </button>
                    <button class="btn-requisition-action" style="background:#e74c3c;color:white;" onclick="reviewApplication(${app.id}, 'rejected')">
                        <i class="fas fa-times"></i> 拒绝
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

async function reviewApplication(appId, status) {
    const action = status === 'approved' ? '批准' : '拒绝';
    if (!confirm(`确定${action}此申请吗？`)) return;
    try {
        const res = await fetch(`/api/manager/branch-application/${appId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ status })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`已${action}`, 'success');
            await loadBranchApplications();
        } else {
            showToast(data.message || '操作失败', 'error');
        }
    } catch (e) {
        showToast('操作失败', 'error');
    }
}

export {
    loadBranchApplications,
    renderBranchApplications,
    reviewApplication
};
