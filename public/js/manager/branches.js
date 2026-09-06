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
            showToast(`已${action}，结果已实时通知该职员`, 'success');
            await loadBranchApplications();
        } else {
            showToast(data.message || '操作失败', 'error');
        }
    } catch (e) {
        showToast('操作失败', 'error');
    }
}

/* ================= 分部管理面板（特工档案窗口 · 侧边「分部管理」） ================= */
let bpCropper = null;
let bpCurrentBranchId = null;

/* 侧边功能切换：特工管理 / 分部管理 */
function initMCharSideSwitch() {
    const side = document.querySelector('#winMChar .mchar-side');
    if (!side || side.dataset.bound) return;
    side.dataset.bound = '1';
    side.addEventListener('click', (e) => {
        const btn = e.target.closest('.mchar-side-btn');
        if (!btn) return;
        side.querySelectorAll('.mchar-side-btn').forEach(b => b.classList.toggle('active', b === btn));
        const chars = document.getElementById('tabCharacters');
        const branch = document.getElementById('tabBranchProfile');
        if (chars) chars.classList.toggle('active', btn.dataset.pane === 'chars');
        if (branch) branch.classList.toggle('active', btn.dataset.pane === 'branch');
        if (btn.dataset.pane === 'branch') loadBranchProfilePane();
    });
    bindBranchProfilePane();
}

/* 分部管理面板事件绑定（一次即可） */
function bindBranchProfilePane() {
    const box = document.getElementById('bpIconBox');
    if (!box || box.dataset.bound) return;
    box.dataset.bound = '1';
    box.addEventListener('click', () => document.getElementById('bpIconFile').click());
    document.getElementById('bpIconFile').addEventListener('change', onBpIconFile);
    document.getElementById('bpIntroInput').addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/\s+/g, ' ');
        updateBpIntroCount();
    });
    document.getElementById('bpSave').addEventListener('click', saveBpIntro);
    document.getElementById('bpCropCancel').addEventListener('click', closeBpCrop);
    document.getElementById('bpCropClose').addEventListener('click', closeBpCrop);
    document.getElementById('bpCropConfirm').addEventListener('click', confirmBpCrop);
}

/* 可管理的分部下拉：超管=全部分部，经理=自己所属分部 */
async function loadBranchProfilePane() {
    const sel = document.getElementById('bpBranchSel');
    if (!sel) return;
    try {
        let branches = [];
        if (S.role >= 2) {
            const res = await fetch('/api/admin/branches', { headers: getAuthHeaders() });
            const data = await res.json();
            branches = (data.branches || []).map(b => ({ id: b.id, name: b.name }));
        } else {
            branches = (S.myBranches || []).map(b => ({ id: b.id, name: b.name }));
        }
        if (!branches.length) {
            sel.innerHTML = '<option value="">暂无可管理的分部</option>';
            return;
        }
        sel.innerHTML = branches.map(b => `<option value="${escapeHtml(b.id)}">${escapeHtml(b.name)}</option>`).join('');
        const want = S.currentBranchId && branches.some(b => b.id === S.currentBranchId) ? S.currentBranchId : branches[0].id;
        sel.value = want;
        if (!sel.dataset.bound) {
            sel.dataset.bound = '1';
            sel.addEventListener('change', () => loadBranchProfileInto(sel.value));
        }
        await loadBranchProfileInto(sel.value);
    } catch (e) {
        showToast('加载分部信息失败', 'error');
    }
}

/* 拉取分部资料并填充面板 */
async function loadBranchProfileInto(branchId) {
    if (!branchId) return;
    bpCurrentBranchId = branchId;
    try {
        const res = await fetch(`/api/manager/branch/${encodeURIComponent(branchId)}/profile`, { headers: getAuthHeaders() });
        const data = await res.json();
        if (!data.success) { showToast(data.message || '加载失败', 'error'); return; }
        const input = document.getElementById('bpIntroInput');
        input.value = data.branch.intro || '';
        updateBpIntroCount();
        renderBpIcon(data.branch.icon || '');
    } catch (e) {
        showToast('加载失败', 'error');
    }
}

function renderBpIcon(url) {
    const img = document.getElementById('bpIconImg');
    const holder = document.getElementById('bpIconHolder');
    if (!url) { img.style.display = 'none'; img.removeAttribute('src'); holder.style.display = ''; return; }
    img.onload = () => { img.style.display = ''; holder.style.display = 'none'; };
    img.onerror = () => { img.style.display = 'none'; holder.style.display = ''; };
    img.src = window.DA && window.DA.avaSrc ? window.DA.avaSrc(url) : url;
}

function updateBpIntroCount() {
    const input = document.getElementById('bpIntroInput');
    const n = [...input.value].length;
    const counter = document.getElementById('bpIntroCount');
    counter.textContent = n + '/50';
    counter.style.color = n > 50 ? '#e74c3c' : '';
}

async function saveBpIntro() {
    if (!bpCurrentBranchId) { showToast('请先选择分部', 'error'); return; }
    const chars = [...document.getElementById('bpIntroInput').value.trim()];
    if (chars.length > 50) { showToast('介绍短语不能超过 50 字', 'error'); return; }
    try {
        const res = await fetch(`/api/manager/branch/${encodeURIComponent(bpCurrentBranchId)}/profile`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ intro: chars.join('') })
        });
        const data = await res.json();
        if (data.success) showToast('分部介绍已保存', 'success');
        else showToast(data.message || '保存失败', 'error');
    } catch (e) {
        showToast('保存失败', 'error');
    }
}

/* ---------- 分部图标：选择 → 裁剪 → 上传（同头像链路） ---------- */
function onBpIconFile(e) {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (!/^image\/(png|jpe?g)$/.test(file.type)) { showToast('仅支持 jpg / png', 'error'); return; }
    const reader = new FileReader();
    reader.onload = () => openBpCrop(reader.result);
    reader.readAsDataURL(file);
}

function openBpCrop(dataUrl) {
    const mask = document.getElementById('bpCropMask');
    const img = document.getElementById('bpCropImg');
    mask.classList.add('show');
    img.onload = () => {
        if (bpCropper) { bpCropper.destroy(); bpCropper = null; }
        bpCropper = new Cropper(img, {
            aspectRatio: 1,
            viewMode: 1,
            dragMode: 'move',
            autoCropArea: 0.9,
            background: false
        });
    };
    img.src = dataUrl;
}

function closeBpCrop() {
    if (bpCropper) { bpCropper.destroy(); bpCropper = null; }
    document.getElementById('bpCropMask').classList.remove('show');
}

async function confirmBpCrop() {
    if (!bpCropper || !bpCurrentBranchId) return;
    const canvas = bpCropper.getCroppedCanvas({ width: 256, height: 256, imageSmoothingQuality: 'high' });
    if (!canvas) { showToast('裁剪失败', 'error'); return; }
    canvas.toBlob(async (blob) => {
        if (!blob) { showToast('裁剪失败', 'error'); return; }
        const fd = new FormData();
        fd.append('icon', blob, 'icon.jpg');
        try {
            const res = await fetch(`/api/manager/branch/${encodeURIComponent(bpCurrentBranchId)}/icon`, {
                method: 'POST',
                /* FormData 上传不能带 application/json 头（会破坏 multipart 边界），只带鉴权 */
                headers: { Authorization: 'Bearer ' + (S.token || '') },
                body: fd
            });
            const data = await res.json();
            if (data.success) {
                if (window.DA && window.DA.bumpAvaVer) window.DA.bumpAvaVer(data.icon);
                renderBpIcon(data.icon);
                showToast('分部图标已更新', 'success');
                closeBpCrop();
            } else {
                showToast(data.message || '上传失败', 'error');
            }
        } catch (e) {
            showToast('上传失败', 'error');
        }
    }, 'image/jpeg', 0.9);
}

export {
    loadBranchApplications,
    renderBranchApplications,
    reviewApplication,
    initMCharSideSwitch,
    loadBranchProfilePane
};
