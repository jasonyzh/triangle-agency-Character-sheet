import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadInbox() {
    try {
        const res = await fetch('/api/manager/inbox', {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error('加载收件箱失败');
        S.inboxMessages.length = 0;
        const data = await res.json();
        data.forEach(m => S.inboxMessages.push(m));
        updateInboxBadge();
    } catch (e) {
        console.error('加载收件箱失败:', e);
    }
}

function updateInboxBadge() {
    const unread = S.inboxMessages.filter(m => !m.read).length;
    const badge = document.getElementById('inboxBadge');
    if (!badge) return;
    badge.textContent = unread;
    badge.style.display = unread > 0 ? 'flex' : 'none';
}

function openInboxModal() {
    renderInboxList();
    document.getElementById('inboxModal').classList.add('show');
}

function closeInboxModal() {
    document.getElementById('inboxModal').classList.remove('show');
}

function renderInboxList() {
    const container = document.getElementById('inboxList');

    if (S.inboxMessages.length === 0) {
        container.innerHTML = '<div class="inbox-empty"><i class="fas fa-envelope-open" style="font-size:32px;margin-bottom:10px;"></i><br>收件箱为空</div>';
        return;
    }

    container.innerHTML = S.inboxMessages.map(msg => {
        const typeLabel = getMessageTypeLabel(msg.message_type);
        const timeStr = new Date(msg.created_at).toLocaleString('zh-CN');

        return `
            <div class="inbox-item ${msg.read ? '' : 'unread'}" onclick="openMailDetail(${msg.id})">
                <div class="inbox-item-icon">
                    <i class="fas ${getMessageTypeIcon(msg.message_type)}"></i>
                </div>
                <div class="inbox-item-content">
                    <div class="inbox-item-subject">${escapeHtml(msg.subject || '(无主题)')}</div>
                    <div class="inbox-item-meta">
                        <span class="inbox-item-sender">${escapeHtml(msg.sender_name || '未知')}</span>
                        <span class="inbox-item-type">${typeLabel}</span>
                        <span class="inbox-item-time">${timeStr}</span>
                    </div>
                </div>
                ${msg.read ? '' : '<div class="inbox-unread-dot"></div>'}
            </div>
        `;
    }).join('');
}

function getMessageTypeLabel(type) {
    switch (type) {
        case 'mail': return '信件';
        case 'report': return '任务报告';
        case 'containment': return '收容物';
        default: return '邮件';
    }
}

function getMessageTypeIcon(type) {
    switch (type) {
        case 'mail': return 'fa-envelope';
        case 'report': return 'fa-file-alt';
        case 'containment': return 'fa-box';
        default: return 'fa-envelope';
    }
}

async function openMailDetail(msgId) {
    const msg = S.inboxMessages.find(m => m.id === msgId);
    if (!msg) return;

    if (!msg.read) {
        await markInboxRead(msgId);
    }

    document.getElementById('mailDetailSubject').textContent = msg.subject || '(无主题)';
    document.getElementById('mailDetailSender').textContent = msg.sender_name || '未知';
    document.getElementById('mailDetailTime').textContent = new Date(msg.created_at).toLocaleString('zh-CN');
    document.getElementById('mailDetailType').textContent = getMessageTypeLabel(msg.message_type);

    const contentEl = document.getElementById('mailDetailContent');
    const reportEl = document.getElementById('mailReportData');

    contentEl.innerHTML = escapeHtml(msg.content || '').replace(/\n/g, '<br>');

    if (msg.message_type === 'report' && msg.report_data) {
        try {
            const reportData = typeof msg.report_data === 'string' ? JSON.parse(msg.report_data) : msg.report_data;
            reportEl.style.display = 'block';
            reportEl.innerHTML = renderReportData(reportData);
        } catch (e) {
            reportEl.style.display = 'none';
        }
    } else {
        reportEl.style.display = 'none';
    }

    closeInboxModal();
    document.getElementById('mailDetailModal').classList.add('show');
}

function renderReportData(data) {
    return `
        <div class="report-section">
            <h4>异常状态</h4>
            <div class="report-status">
                ${data.status?.neutralized ? '✓ 已中和' : ''}
                ${data.status?.captured ? '✓ 已捕获' : ''}
                ${data.status?.escaped ? '✓ 已逃脱' : ''}
                ${data.status?.other ? `✓ 其他: ${escapeHtml(data.status.otherText || '')}` : ''}
            </div>
        </div>
        <div class="report-section">
            <h4>异常分析</h4>
            <table class="report-table">
                <tr><td>代号</td><td>${escapeHtml(data.analysis?.codename || '-')}</td></tr>
                <tr><td>行为</td><td>${escapeHtml(data.analysis?.behavior || '-')}</td></tr>
                <tr><td>焦点</td><td>${escapeHtml(data.analysis?.focus || '-')}</td></tr>
                <tr><td>领域</td><td>${escapeHtml(data.analysis?.domain || '-')}</td></tr>
            </table>
        </div>
        ${data.散逸端?.length > 0 ? `
        <div class="report-section">
            <h4>散逸端</h4>
            <table class="report-table">
                <tr><th>姓名</th><th>数量</th><th>备注</th></tr>
                ${data.散逸端.map(row => `<tr><td>${escapeHtml(row.name || '-')}</td><td>${escapeHtml(row.count || '-')}</td><td>${escapeHtml(row.note || '-')}</td></tr>`).join('')}
            </table>
        </div>
        ` : ''}
        <div class="report-section">
            <h4>评估</h4>
            <div class="report-rating">
                <span>最终评级: <strong>${escapeHtml(data.rating || '-')}</strong></span>
                <span>混沌池: <strong>${escapeHtml(data.chaosPool || '-')}</strong></span>
            </div>
        </div>
        ${data.mvp ? `<div class="report-section"><h4>MVP</h4><p>${escapeHtml(data.mvp)}</p></div>` : ''}
        ${data.probation ? `<div class="report-section"><h4>察看期</h4><p>${escapeHtml(data.probation)}</p></div>` : ''}
        ${data.participants ? `<div class="report-section"><h4>参与者</h4><p>${escapeHtml(data.participants)}</p></div>` : ''}
        ${data.可选目标?.length > 0 ? `
        <div class="report-section">
            <h4>可选目标</h4>
            <table class="report-table">
                <tr><th>目标</th><th>奖励</th><th>按特工</th></tr>
                ${data.可选目标.map(row => `<tr><td>${escapeHtml(row.target || '-')}</td><td>${escapeHtml(row.reward || '-')}</td><td>${escapeHtml(row.agent || '-')}</td></tr>`).join('')}
            </table>
        </div>
        ` : ''}
    `;
}

async function markInboxRead(msgId) {
    try {
        await fetch(`/api/manager/inbox/${msgId}/read`, {
            method: 'PUT',
            headers: getAuthHeaders()
        });
        const msg = S.inboxMessages.find(m => m.id === msgId);
        if (msg) msg.read = 1;
        updateInboxBadge();
        renderInboxList();
    } catch (e) {
        console.error('标记已读失败:', e);
    }
}

function closeMailDetailModal() {
    document.getElementById('mailDetailModal').classList.remove('show');
}

export {
    loadInbox,
    updateInboxBadge,
    openInboxModal,
    closeInboxModal,
    renderInboxList,
    getMessageTypeLabel,
    getMessageTypeIcon,
    openMailDetail,
    renderReportData,
    closeMailDetailModal
};
