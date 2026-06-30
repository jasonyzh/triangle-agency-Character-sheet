import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtmlText } from './ui.js';
import { preventScrollPropagation } from './ui.js';

function escapeHtmlMail(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export function openMailModal() {
    const modal = document.getElementById('mail-full-modal');
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    modal.addEventListener('wheel', preventScrollPropagation, { passive: false });
    loadMailbox();
}

export function closeMailModal() {
    const modal = document.getElementById('mail-full-modal');
    modal.classList.remove('active');
    document.body.style.overflow = '';
    modal.removeEventListener('wheel', preventScrollPropagation);
}

export function switchMailTab(tab) {
    S.currentMailTab = tab;
    document.querySelectorAll('.mail-tab').forEach(t => t.classList.remove('active'));
    const tabIndex = tab === 'inbox' ? 1 : tab === 'sent' ? 2 : tab === 'compose' ? 3 : 4;
    document.querySelector(`.mail-tab:nth-child(${tabIndex})`).classList.add('active');
    renderMailContent();
}

export async function loadMailbox() {
    if (!S.charId || !S.token) return;

    try {
        const a1Res = await fetch(`/api/character/${S.charId}/check-a1`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (a1Res.ok) {
            const a1Data = await a1Res.json();
            S.isA1Unlocked = a1Data.unlocked;
        }

        const inboxRes = await fetch(`/api/character/${S.charId}/messages`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (inboxRes.ok) {
            S.mailData.inbox = await inboxRes.json();
        }

        const sentRes = await fetch(`/api/character/${S.charId}/sent-messages`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (sentRes.ok) {
            S.mailData.sent = await sentRes.json();
        }

        const hwRes = await fetch(`/api/character/${S.charId}/highwall-files`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (hwRes.ok) {
            S.mailData.highwallFiles = await hwRes.json();
        }

        S.isU2Unlocked = (S.mailData.highwallFiles || []).some(f => f.filename && f.filename.toLowerCase() === 'u2.md');
        const btnU2 = document.getElementById('btnU2Unleash');
        if (btnU2) btnU2.style.display = S.isU2Unlocked ? '' : 'none';
        var u2Svg = document.querySelector('.win98-u2-text');
        if (u2Svg) {
            u2Svg.style.display = S.isU2Unlocked ? '' : 'none';
            u2Svg.addEventListener('click', function () { window.confirmU2Unleash(); });
        }

        const unreadCount = S.mailData.inbox.filter(m => !m.read).length;
        const mailBtn = document.querySelector('.top-mail-btn');
        const badge = document.getElementById('topMailBadge');

        if (unreadCount > 0) {
            mailBtn.classList.add('has-unread');
            badge.style.display = 'block';
            badge.textContent = unreadCount;
        } else {
            mailBtn.classList.remove('has-unread');
            badge.style.display = 'none';
        }

        const hwTab = document.getElementById('tab-highwall');
        if (hwTab) {
            if (S.isA1Unlocked) {
                hwTab.style.display = '';
            } else {
                hwTab.style.display = 'none';
                if (S.currentMailTab === 'highwall') {
                    switchMailTab('inbox');
                    return;
                }
            }
        }

        renderMailContent();
        window.initPlayerBoard();

    } catch (e) {
        console.error('加载邮箱失败:', e);
        document.getElementById('mailContent').innerHTML = '<div class="mail-empty"><i class="fas fa-exclamation-triangle"></i><p>加载失败</p></div>';
    }
}

export function renderMailContent() {
    const content = document.getElementById('mailContent');
    if (S.currentMailTab === 'inbox') renderInbox(content);
    else if (S.currentMailTab === 'sent') renderSentMail(content);
    else if (S.currentMailTab === 'compose') renderCompose(content);
    else if (S.currentMailTab === 'highwall') renderHighwallFiles(content);
}

export function renderInbox(container) {
    const messages = [];
    S.mailData.inbox.forEach(m => {
        messages.push({
            type: m.messageType || 'mail',
            id: m.id,
            sender: m.senderName,
            subject: m.subject,
            content: m.content,
            preview: m.content ? m.content.substring(0, 50) : '',
            time: m.createdAt,
            read: m.read,
            hwFilename: m.hwFilename
        });
    });
    messages.sort((a, b) => b.time - a.time);

    if (messages.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-inbox"></i><p>收件箱为空</p></div>';
        return;
    }

    container.innerHTML = '<div class="mail-list">' + messages.map(m => {
        const date = new Date(m.time).toLocaleDateString('zh-CN');
        const isHwAuth = m.type === 'hw_auth';
        const isOS = m.sender === 'OS' || isHwAuth;
        const clickHandler = `openMailReader(${JSON.stringify(m).replace(/"/g, '&quot;')})`;
        return `
            <div class="mail-item ${isHwAuth ? 'hw-auth' : ''} ${m.read === 0 || m.read === false ? 'unread' : ''}"
                 onclick="${clickHandler}">
                <button class="mail-delete-btn" onclick="event.stopPropagation();deleteMail(${m.id})" title="删除"><i class="fas fa-trash"></i></button>
                <div class="mail-sender">
                    ${isOS ? '<span class="os-badge">OS</span>' : `<i class="fas fa-user"></i> ${escapeHtmlMail(m.sender)}`}
                </div>
                <div class="mail-subject">${escapeHtmlMail(m.subject)}</div>
                <div class="mail-preview">${escapeHtmlMail(m.preview)}</div>
                <div class="mail-time"><i class="fas fa-clock"></i> ${date}</div>
            </div>
        `;
    }).join('') + '</div>';
}

export async function deleteMail(msgId) {
    if (!confirm('确定删除此邮件？')) return;
    try {
        await fetch('/api/character/' + S.charId + '/message/' + msgId, { method: 'DELETE', headers: getAuthHeaders() });
        showToast('已删除', 'success');
        loadMailbox();
    } catch (e) { showToast('删除失败'); }
}

export function renderSentMail(container) {
    const messages = S.mailData.sent || [];
    if (messages.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-paper-plane"></i><p>暂无已发记录</p></div>';
        return;
    }

    container.innerHTML = '<div class="mail-list">' + messages.map(m => {
        const date = new Date(m.createdAt);
        const timeStr = date.toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        let icon, iconColor, itemInfo, borderColor, statusBadge = '';
        if (m.type === 'containment') {
            icon = 'fa-cube'; iconColor = '#27ae60'; itemInfo = `任务: ${escapeHtmlText(m.missionName)}`; borderColor = '#27ae60';
        } else if (m.type === 'report') {
            icon = 'fa-file-alt'; iconColor = '#e67e22'; itemInfo = `任务: ${escapeHtmlText(m.missionName)}`; borderColor = '#e67e22';
            const statusMap = { 'submitted': '待评审', 'reviewed': '已评审', 'sent': '已完成' };
            const statusClass = m.status || 'submitted';
            statusBadge = `<span class="sent-status-badge ${statusClass}">${statusMap[statusClass] || '未知'}</span>`;
        }
        const preview = m.content ? m.content.substring(0, 50) + (m.content.length > 50 ? '...' : '') : '';
        return `
            <div class="mail-item sent-mail-item" style="border-left-color: ${borderColor};" onclick="openSentMailReader('${m.id}')">
                <div class="mail-icon sent-icon" style="color: ${iconColor};"><i class="fas ${icon}"></i></div>
                <div class="mail-info">
                    <div class="mail-header-row">
                        <span class="mail-recipient" style="color: ${iconColor};">${itemInfo}</span>
                        ${statusBadge}
                        <span class="mail-time">${timeStr}</span>
                    </div>
                    <div class="mail-subject">${escapeHtmlText(m.subject)}</div>
                    ${m.type === 'report' ? '' : `<div class="mail-preview">${escapeHtmlText(preview)}</div>`}
                </div>
            </div>
        `;
    }).join('') + '</div>';
}

export function renderCompose(container) {
    const reportOption = S.isA1Unlocked ? `
            <div class="outbox-option opt-report" onclick="selectOutboxOption('report')">
                <i class="fas fa-file-alt"></i>
                <h4>提交任务报告</h4>
                <p>填写并提交任务报告</p>
            </div>` : '';
    container.innerHTML = `
        <div class="outbox-options">
            <div class="outbox-option opt-containment" onclick="selectOutboxOption('containment')">
                <i class="fas fa-cube"></i>
                <h4>寄送收容物</h4>
                <p>向经理发送收容物品</p>
            </div>
            ${reportOption}
        </div>
        <div id="form-containment" class="outbox-form">
            <h4><i class="fas fa-cube" style="color:#27ae60;"></i> 寄送收容物</h4>
            <label>选择任务 *</label>
            <select id="containment-mission-select" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:6px; font-size:14px; margin-bottom:15px;">
                <option value="" disabled selected>-- 请选择要寄送收容物的任务 --</option>
            </select>
            <p style="font-size:12px; color:#7f8c8d; margin-top:-10px; margin-bottom:15px;">
                <i class="fas fa-info-circle"></i> 每个任务只能寄送一次收容物
            </p>
            <label>收容物名称 *</label>
            <input type="text" id="containment-name" placeholder="输入收容物名称">
            <label>收容物描述</label>
            <textarea id="containment-desc" placeholder="描述收容物的特征、来源等信息..."></textarea>
            <button class="btn-send" onclick="sendContainment()">
                <i class="fas fa-paper-plane"></i> 寄送
            </button>
        </div>
        <div id="form-report" class="outbox-form">
            <h4><i class="fas fa-file-alt" style="color:#e67e22;"></i> 任务报告</h4>
            <div class="report-section">
                <h5>选择任务 *</h5>
                <select id="rpt-mission-select" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:6px; font-size:14px;">
                    <option value="" disabled selected>-- 请选择要提交报告的任务 --</option>
                </select>
                <p style="font-size:12px; color:#7f8c8d; margin-top:8px;">
                    <i class="fas fa-info-circle"></i> 只能为进行中的任务提交报告，且每个任务只能提交一次
                </p>
            </div>
            <div class="report-section">
                <h5>异常状态</h5>
                <div class="report-status-grid">
                    <label class="report-status-item"><input type="checkbox" id="rpt-neutralized"><span class="status-icon">🔫</span><div class="status-info"><h6>已中和</h6><small>无影响</small></div></label>
                    <label class="report-status-item"><input type="checkbox" id="rpt-captured"><span class="status-icon">💼</span><div class="status-info"><h6>已捕获</h6><small>+3 嘉奖</small></div></label>
                    <label class="report-status-item"><input type="checkbox" id="rpt-escaped"><span class="status-icon">🚪</span><div class="status-info"><h6>已逃脱</h6><small>+3 申诫</small></div></label>
                    <label class="report-status-item"><input type="checkbox" id="rpt-other-check"><span class="status-icon">📝</span><div class="status-info"><h6>其他</h6><input type="text" id="rpt-other-text" placeholder="..." style="width:80px;padding:2px 5px;font-size:11px;" onclick="event.stopPropagation()"></div></label>
                </div>
            </div>
            <div class="report-section">
                <h5>异常分析</h5>
                <div class="report-row"><label>代号</label><input type="text" id="rpt-codename"></div>
                <div class="report-row"><label>行为</label><input type="text" id="rpt-behavior"></div>
                <div class="report-row"><label>焦点</label><input type="text" id="rpt-focus"></div>
                <div class="report-row"><label>领域</label><input type="text" id="rpt-domain"></div>
            </div>
            <div class="report-section">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <h5 style="margin:0;">散逸端</h5>
                    <button type="button" class="btn-add-row" onclick="addScatteringRow()" title="添加行"><i class="fas fa-plus-circle"></i></button>
                </div>
                <table class="report-table" id="table-scattering">
                    <thead><tr><th>姓名</th><th>数量</th><th>备注</th><th></th></tr></thead>
                    <tbody><tr><td><input type="text" class="scat-name"></td><td><input type="text" class="scat-qty"></td><td><input type="text" class="scat-note"></td><td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td></tr></tbody>
                </table>
            </div>
            <div class="report-section">
                <h5>评优信息</h5>
                <div class="report-row"><label>最终评级</label><input type="text" id="rpt-rating" placeholder="仅供GM使用"></div>
                <div class="report-row"><label>混沌池</label><input type="number" id="rpt-chaos"></div>
                <div class="report-row"><label>MVP</label><input type="text" id="rpt-mvp"></div>
                <div class="report-row"><label>察看期</label><input type="text" id="rpt-probation"></div>
                <label style="margin-top:10px;">参与者</label>
                <textarea id="rpt-participants" placeholder="填写参与任务的特工..."></textarea>
            </div>
            <div class="report-section">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <h5 style="margin:0;">可选目标</h5>
                    <button type="button" class="btn-add-row" onclick="addObjectiveRow()" title="添加行"><i class="fas fa-plus-circle"></i></button>
                </div>
                <table class="report-table" id="table-objectives">
                    <thead><tr><th>目标</th><th>奖励</th><th>按特工</th><th></th></tr></thead>
                    <tbody><tr><td><input type="text" class="obj-target"></td><td><input type="text" class="obj-reward"></td><td><input type="text" class="obj-agent"></td><td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td></tr></tbody>
                </table>
            </div>
            <button class="btn-send" onclick="sendReport()"><i class="fas fa-paper-plane"></i> 提交报告</button>
        </div>
    `;
}

export async function loadAvailableMissions() {
    if (!S.charId || !S.token) return;
    try {
        const res = await fetch(`/api/character/${S.charId}/available-missions`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (res.ok) {
            S.availableMissions.splice(0, S.availableMissions.length, ...(await res.json()));
            populateMissionSelect();
        }
    } catch (e) { console.error('加载任务列表失败:', e); }
}

export async function loadAvailableMissionsForContainment() {
    if (!S.charId || !S.token) return;
    try {
        const res = await fetch(`/api/character/${S.charId}/available-missions-containment`, {
            headers: { 'Authorization': `Bearer ${S.token}` }
        });
        if (res.ok) {
            S.availableMissions.splice(0, S.availableMissions.length, ...(await res.json()));
            populateContainmentMissionSelect();
        }
    } catch (e) { console.error('加载任务列表失败:', e); }
}

export function populateMissionSelect() {
    const select = document.getElementById('rpt-mission-select');
    if (!select) return;
    select.innerHTML = '<option value="" disabled selected>-- 请选择要提交报告的任务 --</option>';
    if (S.availableMissions.length === 0) {
        const opt = document.createElement('option');
        opt.value = ''; opt.disabled = true; opt.textContent = '暂无可提交报告的任务';
        select.appendChild(opt); return;
    }
    S.availableMissions.forEach(mission => {
        const opt = document.createElement('option');
        opt.value = mission.id;
        if (mission.hasSubmitted) { opt.textContent = `${mission.name} 【已提交】`; opt.disabled = true; opt.style.color = '#95a5a6'; }
        else { opt.textContent = mission.name; }
        select.appendChild(opt);
    });
}

export function populateContainmentMissionSelect() {
    const select = document.getElementById('containment-mission-select');
    if (!select) return;
    select.innerHTML = '<option value="" disabled selected>-- 请选择要寄送收容物的任务 --</option>';
    if (S.availableMissions.length === 0) {
        const opt = document.createElement('option');
        opt.value = ''; opt.disabled = true; opt.textContent = '暂无可寄送收容物的任务';
        select.appendChild(opt); return;
    }
    S.availableMissions.forEach(mission => {
        const opt = document.createElement('option');
        opt.value = mission.id;
        if (mission.hasSentContainment) { opt.textContent = `${mission.name} 【已寄送】`; opt.disabled = true; opt.style.color = '#95a5a6'; }
        else { opt.textContent = mission.name; }
        select.appendChild(opt);
    });
}

export function selectOutboxOption(type) {
    document.querySelectorAll('.outbox-option').forEach(opt => opt.classList.remove('active'));
    document.querySelector(`.opt-${type}`).classList.add('active');
    document.querySelectorAll('.outbox-form').forEach(form => form.classList.remove('active'));
    document.getElementById(`form-${type}`).classList.add('active');
    S.currentOutboxForm = type;
    if (type === 'report') loadAvailableMissions();
    else if (type === 'containment') loadAvailableMissionsForContainment();
}

export async function sendContainment() {
    const missionId = document.getElementById('containment-mission-select').value;
    if (!missionId) { showToast('请先选择要寄送收容物的任务', 'error'); return; }
    const name = document.getElementById('containment-name').value.trim();
    const desc = document.getElementById('containment-desc').value.trim();
    if (!name) { showToast('请输入收容物名称', 'error'); return; }
    const btn = document.querySelector('#form-containment .btn-send');
    btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 发送中...';
    try {
        const res = await fetch(`/api/character/${S.charId}/send-containment`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${S.token}` },
            body: JSON.stringify({ missionId, name, description: desc })
        });
        const data = await res.json();
        if (!res.ok) {
            if (res.status === 409) showToast(data.message || '您已为该任务寄送过收容物', 'error');
            else if (res.status === 404) showToast('任务不存在或您不在该任务成员中', 'error');
            else throw new Error(data.message || '发送失败');
        } else {
            showToast('收容物已寄送', 'success');
            document.getElementById('containment-name').value = '';
            document.getElementById('containment-desc').value = '';
            loadAvailableMissionsForContainment();
        }
    } catch (e) { showToast('发送失败: ' + e.message, 'error'); }
    finally { btn.disabled = false; btn.innerHTML = '<i class="fas fa-paper-plane"></i> 寄送'; }
}

export function closeSuccessModal() {
    const modal = document.getElementById('reportSuccessModal');
    if (modal) modal.classList.remove('show');
}

export async function sendReport() {
    const missionId = document.getElementById('rpt-mission-select').value;
    if (!missionId) { showToast('请先选择要提交报告的任务', 'error'); return; }
    const scattering = Array.from(document.querySelectorAll('#table-scattering tbody tr')).map(row => ({
        name: row.querySelector('.scat-name').value.trim(), qty: row.querySelector('.scat-qty').value.trim(), note: row.querySelector('.scat-note').value.trim()
    })).filter(s => s.name);
    const objectives = Array.from(document.querySelectorAll('#table-objectives tbody tr')).map(row => ({
        target: row.querySelector('.obj-target').value.trim(), reward: row.querySelector('.obj-reward').value.trim(), agent: row.querySelector('.obj-agent').value.trim()
    })).filter(o => o.target);
    const reportData = {
        missionId,
        status: { neutralized: document.getElementById('rpt-neutralized').checked, captured: document.getElementById('rpt-captured').checked, escaped: document.getElementById('rpt-escaped').checked, other: document.getElementById('rpt-other-check').checked ? document.getElementById('rpt-other-text').value : null },
        analysis: { codename: document.getElementById('rpt-codename').value, behavior: document.getElementById('rpt-behavior').value, focus: document.getElementById('rpt-focus').value, domain: document.getElementById('rpt-domain').value },
        scattering,
        evaluation: { rating: document.getElementById('rpt-rating').value, chaosPool: document.getElementById('rpt-chaos').value, mvp: document.getElementById('rpt-mvp').value, probation: document.getElementById('rpt-probation').value, participants: document.getElementById('rpt-participants').value },
        objectives
    };
    const btn = document.querySelector('#form-report .btn-send');
    btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 提交中...';
    try {
        const res = await fetch(`/api/character/${S.charId}/send-report`, { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ reportData }) });
        const data = await res.json();
        if (!res.ok) {
            if (res.status === 409) showToast(data.message || '您已为该任务提交过报告', 'error');
            else if (res.status === 404) showToast('任务不存在或您不在该任务成员中', 'error');
            else throw new Error(data.message || '提交失败，请稍后重试');
        } else {
            const modal = document.getElementById('reportSuccessModal');
            if (modal) { modal.classList.add('show'); setTimeout(() => closeSuccessModal(), 2500); }
            loadAvailableMissions();
        }
    } catch (e) { showToast(e.message, 'error'); }
    finally { btn.disabled = false; btn.innerHTML = '<i class="fas fa-paper-plane"></i> 提交报告'; }
}

export function renderHighwallFiles(container) {
    if (S.mailData.highwallFiles.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-file-shield"></i><p>暂无授权的高墙文件</p></div>';
        return;
    }
    container.innerHTML = '<div class="hw-folder">' + S.mailData.highwallFiles.map(f => `
        <div class="hw-file" onclick="openHighwallFile('${f.filename}')">
            <i class="fas fa-file-alt"></i>
            <div class="hw-name">${escapeHtmlMail(f.title)}</div>
        </div>
    `).join('') + '</div>';
}

export { escapeHtmlMail };

export function addScatteringRow() {
    const tbody = document.querySelector('#table-scattering tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><input type="text" class="scat-name"></td>
        <td><input type="text" class="scat-qty"></td>
        <td><input type="text" class="scat-note"></td>
        <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
    `;
    tbody.appendChild(tr);
}

export function addObjectiveRow() {
    const tbody = document.querySelector('#table-objectives tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><input type="text" class="obj-target"></td>
        <td><input type="text" class="obj-reward"></td>
        <td><input type="text" class="obj-agent"></td>
        <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
    `;
    tbody.appendChild(tr);
}

export function openHighwallFile(filename) {
    const overlay = document.getElementById('hw-overlay');
    const icon = document.getElementById('hw-icon');
    const text = document.getElementById('hw-text');
    const scanlines = document.getElementById('hw-scanlines');
    const eyeLayer = document.getElementById('hw-eye-layer');
    const eyeIcon = document.getElementById('hw-eye-icon');
    const tentaclesLayer = document.getElementById('hw-tentacles');
    const blackout = document.getElementById('hw-blackout');
    const content = document.getElementById('hw-content');

    overlay.classList.remove('active', 'glitch-mode');
    icon.className = 'fas fa-circle-notch fa-spin hw-loader-icon';
    icon.style.color = ''; icon.style.transform = '';
    text.style.color = ''; text.style.fontFamily = '';
    text.innerHTML = '访问高墙文件<span class="hw-dots"></span>';
    scanlines.style.display = 'none'; content.style.display = '';
    eyeLayer.style.opacity = '0';
    eyeIcon.classList.remove('eye-open', 'scared');
    tentaclesLayer.innerHTML = '';
    blackout.classList.remove('active');

    overlay.classList.add('active');

    setTimeout(() => {
        icon.classList.remove('fa-spin'); icon.style.transform = 'rotate(160deg)';
        setTimeout(() => {
            icon.className = 'fas fa-exclamation-triangle hw-loader-icon';
            icon.style.color = '#ff0000'; text.style.color = '#ff0000'; text.style.fontFamily = 'monospace';
            text.innerHTML = 'SYSTEM FAILURE /// 0xFF';
            overlay.classList.add('glitch-mode'); scanlines.style.display = 'block';
        }, 100);
    }, 1000);

    setTimeout(() => {
        overlay.classList.remove('glitch-mode'); scanlines.style.display = 'none'; content.style.display = 'none';
        eyeLayer.style.opacity = '1';
        setTimeout(() => { eyeIcon.classList.add('eye-open'); }, 100);
    }, 1500);

    setTimeout(() => {
        eyeIcon.classList.add('scared'); tentaclesLayer.innerHTML = '';
        for (let i = 0; i < 20; i++) {
            const div = document.createElement('div'); div.className = 'tendril';
            div.style.setProperty('--r', `${i * (360 / 20)}deg`);
            div.style.animationDelay = `${Math.random() * 0.4}s`;
            tentaclesLayer.appendChild(div);
            requestAnimationFrame(() => div.classList.add('creeping'));
        }
    }, 1900);

    setTimeout(() => {
        blackout.classList.add('active');
        setTimeout(() => { window.location.href = `documents.html?file=${encodeURIComponent(filename)}&S.charId=${encodeURIComponent(S.charId)}&from=sheet`; }, 500);
    }, 2500);
}

export function openMailReader(md) {
    S.currentOpenMail = md;
    const overlay = document.getElementById('mail-reader-overlay');
    const subjectEl = document.getElementById('mail-reader-subject');
    const senderEl = document.getElementById('mail-reader-sender');
    const timeEl = document.getElementById('mail-reader-time');
    const bodyEl = document.getElementById('mail-reader-body');
    const actionsEl = document.getElementById('mail-reader-actions');
    const eyeContainer = document.querySelector('.mail-eye-container');

    subjectEl.textContent = md.subject || '无主题';
    const isOS = md.sender === 'OS' || md.type === 'hw_auth';
    senderEl.innerHTML = isOS ? '<span class="os-badge">OS</span> 系统通知' : `<i class="fas fa-user"></i> ${escapeHtmlMail(md.sender)}`;
    const date = new Date(md.time);
    timeEl.innerHTML = `<i class="fas fa-clock"></i> ${date.toLocaleDateString('zh-CN')} ${date.toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit'})}`;
    bodyEl.textContent = md.content || '';

    if (md.type === 'hw_auth' && md.hwFilename) {
        actionsEl.innerHTML = `<button class="mail-reader-btn secondary" onclick="closeMailReader()"><i class="fas fa-times"></i> 关闭</button><button class="mail-reader-btn danger" onclick="openHighwallFromMail('${escapeHtmlMail(md.hwFilename)}')"><i class="fas fa-file-shield"></i> 查看高墙文件</button>`;
    } else {
        actionsEl.innerHTML = `<button class="mail-reader-btn secondary" onclick="closeMailReader()"><i class="fas fa-check"></i> 关闭</button>`;
    }

    if (md.id && (md.read === 0 || md.read === false)) markMessageRead(md.id);
    eyeContainer.classList.add('mail-eye-blink');
    setTimeout(() => eyeContainer.classList.remove('mail-eye-blink'), 300);
    overlay.classList.add('active');
}

export function closeMailReader() {
    const overlay = document.getElementById('mail-reader-overlay');
    const eyeContainer = document.querySelector('.mail-eye-container');
    eyeContainer.classList.add('mail-eye-blink');
    setTimeout(() => { overlay.classList.remove('active'); eyeContainer.classList.remove('mail-eye-blink'); S.currentOpenMail = null; }, 200);
}

export function openHighwallFromMail(filename) {
    closeMailReader();
    setTimeout(() => openHighwallFile(filename), 300);
}

export function openSentMailReader(msgId) {
    const msg = S.mailData.sent.find(m => m.id == msgId);
    if (!msg) return;
    const overlay = document.getElementById('mail-reader-overlay');
    const subjectEl = document.getElementById('mail-reader-subject');
    const senderEl = document.getElementById('mail-reader-sender');
    const timeEl = document.getElementById('mail-reader-time');
    const bodyEl = document.getElementById('mail-reader-body');
    const actionsEl = document.getElementById('mail-reader-actions');
    const eyeContainer = document.querySelector('.mail-eye-container');

    subjectEl.textContent = msg.subject || '无主题';
    let icon, iconColor, recipientInfo;
    if (msg.type === 'containment') { icon = 'fa-cube'; iconColor = '#27ae60'; recipientInfo = `任务: ${escapeHtmlMail(msg.missionName)}`; }
    else if (msg.type === 'report') { icon = 'fa-file-alt'; iconColor = '#e67e22'; recipientInfo = `任务: ${escapeHtmlMail(msg.missionName)}`; }
    senderEl.innerHTML = `<i class="fas ${icon}" style="color:${iconColor};"></i> ${recipientInfo}`;

    const date = new Date(msg.createdAt);
    timeEl.innerHTML = `<i class="fas fa-clock"></i> ${date.toLocaleDateString('zh-CN')} ${date.toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit'})}`;

    if (msg.type === 'report') {
        const reportData = msg.reportData || {};
        const statusMap = { 'submitted': '待评审', 'reviewed': '已评审', 'sent': '已完成' };
        const statusName = statusMap[msg.status] || '未知';
        let reportHTML = '';
        reportHTML += `<div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #34495e;">`;
        reportHTML += `<div style="margin-bottom: 8px;"><strong style="color: #ffffff; font-size: 14px;">状态：</strong><span style="color: ${msg.status === 'sent' ? '#2ecc71' : '#f39c12'}; font-weight: bold;">${statusName}</span></div>`;
        if (msg.rating) {
            reportHTML += `<div style="display: flex; gap: 20px;">`;
            reportHTML += `<div><strong style="color: #ffffff; font-size: 14px;">评级：</strong><span style="font-size: 18px; font-weight: bold; color: #9b59b6;">${msg.rating}</span></div>`;
            reportHTML += `<div><strong style="color: #ffffff; font-size: 14px;">逸散端：</strong><span style="font-size: 18px; font-weight: bold; color: #e67e22;">${msg.scatterValue || 0}</span></div>`;
            reportHTML += `</div>`;
        }
        reportHTML += `</div>`;
        if (msg.annotations && msg.annotations.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px; padding: 12px; background: rgba(243, 156, 18, 0.15); border-left: 4px solid #f39c12; border-radius: 4px;">`;
            reportHTML += `<div style="font-weight: bold; color: #f39c12; margin-bottom: 8px; font-size: 14px;">📝 经理批注</div>`;
            msg.annotations.forEach(a => { reportHTML += `<div style="color: #ecf0f1; margin: 5px 0; font-size: 13px;">• ${escapeHtmlMail(a)}</div>`; });
            reportHTML += `</div>`;
        }
        if (reportData.status) {
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<strong style="color: #ffffff; font-size: 14px;">任务状态：</strong>`;
            const statusLabels = [];
            if (reportData.status.neutralized) statusLabels.push('✓ 已中和');
            if (reportData.status.captured) statusLabels.push('✓ 已捕获');
            if (reportData.status.escaped) statusLabels.push('✓ 已逃脱');
            if (reportData.status.other) statusLabels.push('✓ 其他');
            reportHTML += `<span style="color: #2ecc71; font-weight: bold;">${statusLabels.join(' / ') || '未设置'}</span></div>`;
        }
        if (reportData.analysis) {
            const analysis = reportData.analysis;
            reportHTML += `<div style="margin-bottom: 15px;"><div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">🔍 威胁分析</div>`;
            if (analysis.codename) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">代号：${escapeHtmlMail(analysis.codename)}</div>`;
            if (analysis.behavior) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">行为：${escapeHtmlMail(analysis.behavior)}</div>`;
            if (analysis.focus) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">专注：${escapeHtmlMail(analysis.focus)}</div>`;
            if (analysis.domain) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">区域：${escapeHtmlMail(analysis.domain)}</div>`;
            reportHTML += `</div>`;
        }
        if (reportData.scattering && reportData.scattering.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px;"><div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">⚠️ 散逸端记录</div>`;
            reportData.scattering.forEach(s => {
                if (typeof s === 'string') { reportHTML += `<div style="margin: 5px 0; color: #e67e22; font-weight: bold; font-size: 13px;">• ${escapeHtmlMail(s)}</div>`; }
                else {
                    const name = s.name || '', qty = s.qty || '', note = s.note || '';
                    reportHTML += `<div style="margin: 5px 0; color: #e67e22; font-size: 13px;">• <strong>${escapeHtmlMail(name)}</strong>`;
                    if (qty) reportHTML += ` × ${escapeHtmlMail(qty)}`;
                    if (note) reportHTML += ` <span style="color: #95a5a6;">(${escapeHtmlMail(note)})</span>`;
                    reportHTML += `</div>`;
                }
            });
            reportHTML += `</div>`;
        }
        if (reportData.evaluation) {
            const eval_data = reportData.evaluation;
            reportHTML += `<div style="margin-bottom: 15px;"><div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">📊 评估</div>`;
            if (eval_data.rating) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">威胁等级：${escapeHtmlMail(eval_data.rating)}</div>`;
            if (eval_data.chaosPool) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">混沌池：${escapeHtmlMail(eval_data.chaosPool)}</div>`;
            if (eval_data.mvp) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">MVP：${escapeHtmlMail(eval_data.mvp)}</div>`;
            if (eval_data.probation) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">察看期：${escapeHtmlMail(eval_data.probation)}</div>`;
            if (eval_data.participants) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">参与者：${escapeHtmlMail(eval_data.participants)}</div>`;
            reportHTML += `</div>`;
        }
        if (reportData.objectives && reportData.objectives.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px;"><div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">🎯 任务目标</div>`;
            reportData.objectives.forEach(o => {
                if (typeof o === 'string') { reportHTML += `<div style="margin: 5px 0; color: #3498db; font-size: 13px;">• ${escapeHtmlMail(o)}</div>`; }
                else {
                    const target = o.target || '', reward = o.reward || '', agent = o.agent || '';
                    reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">• <strong style="color: #3498db;">${escapeHtmlMail(target)}</strong>`;
                    if (reward) reportHTML += ` → <span style="color: #2ecc71;">奖励: ${escapeHtmlMail(reward)}</span>`;
                    if (agent) reportHTML += ` <span style="color: #95a5a6;">[${escapeHtmlMail(agent)}]</span>`;
                    reportHTML += `</div>`;
                }
            });
            reportHTML += `</div>`;
        }
        bodyEl.innerHTML = reportHTML || '<div style="color: #95a5a6;">暂无报告内容</div>';
    } else {
        bodyEl.textContent = msg.content || '';
    }

    actionsEl.innerHTML = `<button class="mail-reader-btn secondary" onclick="closeMailReader()"><i class="fas fa-check"></i> 关闭</button>`;
    eyeContainer.classList.add('mail-eye-blink');
    setTimeout(() => eyeContainer.classList.remove('mail-eye-blink'), 300);
    overlay.classList.add('active');
}

async function markMessageRead(msgId) {
    try {
        await fetch(`/api/character/${S.charId}/message/${msgId}/read`, { method: 'PUT', headers: { 'Authorization': `Bearer ${S.token}` } });
        const msg = S.mailData.inbox.find(m => m.id === msgId);
        if (msg) msg.read = 1;
        const unreadCount = S.mailData.inbox.filter(m => !m.read).length;
        const mailBtn = document.querySelector('.top-mail-btn');
        const badge = document.getElementById('topMailBadge');
        if (unreadCount > 0) { mailBtn.classList.add('has-unread'); badge.style.display = 'block'; badge.textContent = unreadCount; }
        else { mailBtn.classList.remove('has-unread'); badge.style.display = 'none'; }
    } catch (e) { console.error('标记已读失败:', e); }
}

export function openMessage(msgId) {
    const msg = S.mailData.inbox.find(m => m.id === msgId);
    if (msg) {
        openMailReader({ type: msg.messageType || 'mail', id: msg.id, sender: msg.senderName, subject: msg.subject, content: msg.content, time: msg.createdAt, read: msg.read, hwFilename: msg.hwFilename });
    }
}
