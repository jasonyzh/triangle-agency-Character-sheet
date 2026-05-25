import { S } from './state.js';
import { getAuthHeaders, sanitizeObject, safeFetch } from './auth.js';
import { showToast, escapeHtml } from './ui.js';
import { loadCharacters } from './characters.js';

async function loadMissions() {
    try {
        var url = `/api/manager/missions?status=${S.currentMissionTab}`;
        if (S.currentBranchId) url += '&branchId=' + S.currentBranchId;
        const res = await fetch(url, {
            headers: getAuthHeaders()
        });

        if (!res.ok) throw new Error('加载任务失败');
        S.missionsList.length = 0;
        const data = await res.json();
        data.forEach(m => S.missionsList.push(m));
        renderMissions();
    } catch (e) {
        console.error('加载任务失败:', e);
        document.getElementById('missionList').innerHTML = `<div class="mission-empty">加载失败</div>`;
    }
}

function renderMissions() {
    const container = document.getElementById('missionList');
    const filtered = S.missionsList.filter(m => m.status === S.currentMissionTab);

    if (filtered.length === 0) {
        container.innerHTML = `<div class="mission-empty"><i class="fas fa-clipboard-list"></i><br>${S.currentMissionTab === 'active' ? '暂无进行中的任务' : '暂无已归档任务'}</div>`;
        return;
    }

    container.innerHTML = filtered.map(mission => {
        const memberCount = mission.members ? mission.members.length : 0;
        const memberPreview = mission.members && mission.members.length > 0
            ? mission.members.slice(0, 3).map(m => escapeHtml(m.name)).join('、') + (mission.members.length > 3 ? '...' : '')
            : '暂无成员';
        const missionTypeName = mission.mission_type === 'sweep' ? '清扫' : '收容';
        const missionTypeClass = mission.mission_type === 'sweep' ? 'sweep' : 'containment';

        return `
            <div class="mission-card clickable" data-id="${mission.id}" onclick="openMissionDetail('${mission.id}')">
                <div class="mission-card-header">
                    <div class="mission-info">
                        <h4>${escapeHtml(mission.name)} <span class="mission-type-badge ${missionTypeClass}">${missionTypeName}</span></h4>
                        ${mission.description ? `<p class="mission-desc">${escapeHtml(mission.description)}</p>` : ''}
                    </div>
                    <div class="mission-quick-actions" onclick="event.stopPropagation()">
                        ${mission.status === 'active' ? `
                            <button class="btn-mission-action" onclick="event.stopPropagation();archiveMission('${mission.id}')" title="归档">
                                <i class="fas fa-archive"></i>
                            </button>
                        ` : `
                            <button class="btn-mission-action" onclick="event.stopPropagation();restoreMission('${mission.id}')" title="恢复">
                                <i class="fas fa-undo"></i>
                            </button>
                            <button class="btn-mission-action delete" onclick="event.stopPropagation();deleteMission('${mission.id}')" title="删除">
                                <i class="fas fa-trash"></i>
                            </button>
                        `}
                    </div>
                </div>
                <div class="mission-card-footer">
                    <div class="mission-member-count">
                        <i class="fas fa-users"></i>
                        <span>${memberPreview}</span>
                    </div>
                    <div class="mission-enter-hint">
                        <i class="fas fa-chevron-right"></i>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function switchMissionTab(tab) {
    S.currentMissionTab = tab;
    document.querySelectorAll('.mission-tabs button').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    loadMissions();
}

function openMissionModal(editId = null) {
    S.currentMissionId = editId;
    document.getElementById('missionEditId').value = editId || '';
    document.getElementById('missionModalTitle').textContent = editId ? '编辑任务' : '创建任务';

    if (editId) {
        const mission = S.missionsList.find(m => m.id === editId);
        if (mission) {
            document.getElementById('missionName').value = mission.name;
            document.getElementById('missionType').value = mission.mission_type || 'containment';
            document.getElementById('missionDesc').value = mission.description || '';
        }
    } else {
        document.getElementById('missionName').value = '';
        document.getElementById('missionType').value = 'containment';
        document.getElementById('missionDesc').value = '';
    }

    document.getElementById('missionModal').classList.add('show');
}

function closeMissionModal() {
    document.getElementById('missionModal').classList.remove('show');
    S.currentMissionId = null;
}

function editMission(missionId) {
    openMissionModal(missionId);
}

async function saveMission() {
    const name = document.getElementById('missionName').value.trim();
    const missionType = document.getElementById('missionType').value;
    const description = document.getElementById('missionDesc').value.trim();
    const editId = document.getElementById('missionEditId').value;

    if (!name) {
        showToast('请输入任务名称');
        return;
    }

    try {
        const url = editId ? `/api/manager/mission/${editId}` : '/api/manager/mission';
        const method = editId ? 'PUT' : 'POST';

        const missionData = sanitizeObject({ name, description, missionType, branchId: S.currentBranchId });
        console.log('[保存任务] 发送数据:', missionData);

        const res = await safeFetch(url, {
            method,
            headers: getAuthHeaders(),
            body: JSON.stringify(missionData)
        });

        const data = await res.json();
        if (data.success) {
            showToast(editId ? '任务已更新' : '任务已创建', true);
            closeMissionModal();
            await loadMissions();
        } else {
            throw new Error(data.message || '保存失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function archiveMission(missionId) {
    if (!confirm('确定要归档此任务吗？')) return;

    try {
        const res = await fetch(`/api/manager/mission/${missionId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ status: 'archived' })
        });

        const data = await res.json();
        if (data.success) {
            showToast('任务已归档', true);
            await loadMissions();
        } else {
            throw new Error(data.message || '归档失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function restoreMission(missionId) {
    try {
        const res = await fetch(`/api/manager/mission/${missionId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ status: 'active' })
        });

        const data = await res.json();
        if (data.success) {
            showToast('任务已恢复', true);
            await loadMissions();
        } else {
            throw new Error(data.message || '恢复失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function deleteMission(missionId) {
    if (!confirm('确定要永久删除此任务吗？此操作不可撤销。')) return;

    try {
        const res = await fetch(`/api/manager/mission/${missionId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('任务已删除', true);
            await loadMissions();
        } else {
            throw new Error(data.message || '删除失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function openAddMemberModal(missionId) {
    S.addMemberMissionId = missionId;
    const container = document.getElementById('memberSelectList');
    const searchInput = document.getElementById('memberSearchInput');
    if (searchInput) searchInput.value = '';

    container.innerHTML = '<div style="text-align:center;padding:20px;color:#95a5a6;"><i class="fas fa-spinner fa-spin"></i> 加载中...</div>';
    document.getElementById('addMemberModal').classList.add('show');

    try {
        var charUrl = '/api/manager/characters';
        if (S.currentBranchId) charUrl += '?branchId=' + S.currentBranchId;
        const res = await fetch(charUrl, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error('加载角色失败');
        const characters = await res.json();

        const mission = S.missionsList.find(m => m.id === missionId);
        const existingIds = mission?.members?.map(m => m.character_id) || [];

        S.allAvailableCharacters.length = 0;
        characters.filter(c => !existingIds.includes(c.id)).forEach(c => S.allAvailableCharacters.push(c));
        renderAvailableMembers(S.allAvailableCharacters);

    } catch (e) {
        container.innerHTML = `<div style="text-align:center;padding:20px;color:#e74c3c;">加载失败: ${e.message}</div>`;
    }
}

function filterAvailableMembers() {
    const query = document.getElementById('memberSearchInput').value.toLowerCase().trim();
    const filtered = S.allAvailableCharacters.filter(c =>
        c.name.toLowerCase().includes(query)
    );
    renderAvailableMembers(filtered);
}

function renderAvailableMembers(characters) {
    const container = document.getElementById('memberSelectList');
    if (characters.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding:20px;color:#95a5a6;">没有匹配的角色</div>';
        return;
    }

    container.innerHTML = characters.map(char => `
        <div class="member-select-item" onclick="addMemberToMission('${char.id}', '${escapeHtml(char.name)}')">
            <i class="fas fa-user-circle" style="font-size:24px;color:#3498db;margin-right:10px;"></i>
            <span>${escapeHtml(char.name)}</span>
        </div>
    `).join('');
}

function closeAddMemberModal() {
    document.getElementById('addMemberModal').classList.remove('show');
    S.addMemberMissionId = null;
}

async function addMemberToMission(charId, charName) {
    if (!S.addMemberMissionId) return;
    try {
        const res = await fetch(`/api/manager/mission/${S.addMemberMissionId}/member`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ characterId: charId })
        });

        const data = await res.json();
        if (data.success) {
            showToast(`已添加 ${charName}`, true);

            const missionIdToRefresh = S.addMemberMissionId;
            closeAddMemberModal();

            await loadMissions();
            if (S.currentMissionDetailId && S.currentMissionDetailId === missionIdToRefresh) {
                const mission = S.missionsList.find(m => m.id === S.currentMissionDetailId);

                if (mission) {
                    renderMissionDetailMembers(mission.members || []);
                }
            }
        } else {
            throw new Error(data.message || '添加失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function removeMember(missionId, charId) {
    if (!confirm('确定要从任务中移除此成员吗？')) return;

    try {
        const res = await fetch(`/api/manager/mission/${missionId}/member/${charId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('成员已移除', true);
            await loadMissions();
        } else {
            throw new Error(data.message || '移除失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

function openMissionDetail(missionId) {
    S.currentMissionDetailId = missionId;
    const mission = S.missionsList.find(m => m.id === missionId);
    if (!mission) {
        showToast('任务不存在');
        return;
    }
    S.currentMissionDetailData = mission;

    document.getElementById('missionDetailName').textContent = mission.name;
    document.getElementById('missionDetailDesc').textContent = mission.description || '暂无描述';

    const statusEl = document.getElementById('missionDetailStatus');
    statusEl.textContent = mission.status === 'active' ? '进行中' : '已归档';
    statusEl.className = 'mission-detail-status' + (mission.status === 'archived' ? ' archived' : '');

    const archiveBtn = document.querySelector('.btn-mission-archive');
    if (mission.status === 'archived') {
        archiveBtn.innerHTML = '<i class="fas fa-undo"></i> 恢复';
        archiveBtn.onclick = restoreCurrentMission;
    } else {
        archiveBtn.innerHTML = '<i class="fas fa-archive"></i> 归档';
        archiveBtn.onclick = archiveCurrentMission;
    }

    renderMissionDetailMembers(mission.members || []);

    document.getElementById('missionChaosValue').value = mission.chaos_value || 0;
    document.getElementById('missionScatterValue').value = mission.scatter_value || 0;

    loadMissionReports(missionId);

    loadMissionInbox(missionId);

    document.getElementById('missionDetailOverlay').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeMissionDetail() {
    document.getElementById('missionDetailOverlay').classList.remove('active');
    document.body.style.overflow = '';
    S.currentMissionDetailId = null;
    S.currentMissionDetailData = null;
}

function renderMissionDetailMembers(members) {
    const container = document.getElementById('missionDetailMembers');

    if (!members || members.length === 0) {
        container.innerHTML = '<div class="no-members">暂无成员，点击上方"添加特工"按钮添加</div>';
        return;
    }
    container.innerHTML = members.map(member => {
        const safeName = escapeHtml(member.name).replace(/'/g, "\\'");
        return `
            <div class="agent-card clickable" data-char-id="${member.character_id}" onclick="openAgentDetail('${member.character_id}')">
                <div class="agent-name">${escapeHtml(member.name)}</div>
                <div class="agent-actions" onclick="event.stopPropagation()">
                    <button class="btn-agent-record" onclick="openRecordModal('${member.character_id}', '${safeName}')" title="嘉奖/申诫">
                        <i class="fas fa-medal"></i>
                    </button>
                    <button class="btn-agent-perm" onclick="openRequisitionPermModal(${member.user_id})" title="权限物品授权">
                        <i class="fas fa-gift"></i>
                    </button>
                    <button class="btn-agent-slots" onclick="openSlotModal('${member.character_id}', '${safeName}')" title="槽位管理">
                        <i class="fas fa-unlock-alt"></i>
                    </button>
                    <button class="btn-agent-docs" onclick="openDocModal('${member.character_id}', '${safeName}')" title="高墙授权">
                        <i class="fas fa-file-shield"></i>
                    </button>
                    <button class="btn-agent-anomaly" onclick="openGrantAnomalyModal('${member.character_id}', '${safeName}')" title="赋予异常能力">
                        <i class="fas fa-bolt"></i>
                    </button>
                    <button class="btn-remove-agent" onclick="removeMemberFromDetail('${member.character_id}')" title="移除">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

async function loadMissionReports(missionId) {
    if (!missionId) return;

    try {
        const res = await fetch(`/api/manager/mission/${missionId}/reports`, {
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            S.missionReports.length = 0;
            (data.reports || []).forEach(r => S.missionReports.push(r));
            renderMissionReports();
        }
    } catch (e) {
        console.error('加载任务报告失败', e);
    }
}

function renderMissionReports() {
    const container = document.getElementById('missionReportsList');
    const badge = document.getElementById('reportStatusBadge');

    if (S.missionReports.length === 0) {
        badge.className = 'report-status-badge none';
        badge.textContent = '';
    } else {
        const hasUnreviewed = S.missionReports.some(r => r.status === 'submitted');
        const hasUnsent = S.missionReports.some(r => r.status === 'reviewed');
        const allSent = S.missionReports.every(r => r.status === 'sent');

        if (hasUnreviewed) {
            badge.className = 'report-status-badge submitted';
            badge.textContent = '待评审';
        } else if (hasUnsent) {
            badge.className = 'report-status-badge reviewed';
            badge.textContent = '待发送';
        } else if (allSent) {
            badge.className = 'report-status-badge sent';
            badge.textContent = '已完成';
        }
    }

    if (S.missionReports.length === 0) {
        container.innerHTML = '<div class="report-empty"><i class="fas fa-file-alt"></i><br>等待特工提交报告...</div>';
        return;
    }

    container.innerHTML = S.missionReports.map(report => {
        const statusNames = { submitted: '待评审', reviewed: '已评审', sent: '已发送' };
        const statusName = statusNames[report.status] || '未知';
        const date = new Date(report.submittedAt);
        const timeStr = date.toLocaleString();
        const isSent = report.status === 'sent';

        return `
            <div class="report-item" data-report-id="${report.id}">
                <div class="report-item-header">
                    <div>
                        <span class="report-submitter">${escapeHtml(report.submitterName)}</span>
                        <span class="report-time">${timeStr}</span>
                    </div>
                    <span class="report-status ${report.status}">${statusName}</span>
                </div>
                <div class="report-rating-row">
                    <div class="report-rating-input">
                        <label>评级</label>
                        <select id="reportRating_${report.id}" ${isSent ? 'disabled' : ''}>
                            <option value="">选择评级</option>
                            <option value="S" ${report.rating === 'S' ? 'selected' : ''}>S</option>
                            <option value="A" ${report.rating === 'A' ? 'selected' : ''}>A</option>
                            <option value="B" ${report.rating === 'B' ? 'selected' : ''}>B</option>
                            <option value="C" ${report.rating === 'C' ? 'selected' : ''}>C</option>
                            <option value="D" ${report.rating === 'D' ? 'selected' : ''}>D</option>
                            <option value="F" ${report.rating === 'F' ? 'selected' : ''}>F</option>
                        </select>
                    </div>
                    <div class="report-rating-input">
                        <label>逸散端</label>
                        <input type="number" id="reportScatter_${report.id}" value="${report.scatterValue || 0}" ${isSent ? 'disabled' : ''}>
                    </div>
                </div>
                <div class="report-annotation">
                    <textarea id="reportAnnotation_${report.id}" placeholder="添加批注..." ${isSent ? 'disabled' : ''}>${escapeHtml((report.annotations || []).join('\n'))}</textarea>
                </div>
                <div class="report-actions">
                    ${!isSent ? `
                        <button class="btn-report save" onclick="saveReportReview(${report.id})">
                            <i class="fas fa-save"></i> 保存评审
                        </button>
                        <button class="btn-report send" onclick="sendReportRating(${report.id})" ${report.status === 'submitted' ? 'disabled title="请先保存评审"' : ''}>
                            <i class="fas fa-paper-plane"></i> 发送评级
                        </button>
                    ` : `
                        <span style="color:#27ae60;font-size:12px;"><i class="fas fa-check-circle"></i> 已发送给特工</span>
                    `}
                </div>
            </div>
        `;
    }).join('');
}

async function saveReportReview(reportId) {
    if (!S.currentMissionDetailId) return;

    const rating = document.getElementById(`reportRating_${reportId}`).value;
    const scatterValue = parseInt(document.getElementById(`reportScatter_${reportId}`).value) || 0;
    const annotationText = document.getElementById(`reportAnnotation_${reportId}`).value;
    const annotations = annotationText.trim() ? annotationText.split('\n').filter(a => a.trim()) : [];

    try {
        const reviewData = sanitizeObject({ rating, scatterValue, annotations });
        console.log('[保存报告评审] 发送数据:', reviewData);

        const res = await safeFetch(`/api/manager/mission/${S.currentMissionDetailId}/report/${reportId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify(reviewData)
        });

        const data = await res.json();
        if (data.success) {
            showToast('评审已保存', true);
            await loadMissionReports(S.currentMissionDetailId);
        } else {
            throw new Error(data.message || '保存失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function sendReportRating(reportId) {
    if (!S.currentMissionDetailId) return;
    if (!confirm('确定要发送评级给特工吗？发送后将无法修改。')) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/report/${reportId}/send`, {
            method: 'POST',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('评级已发送', true);
            await loadMissionReports(S.currentMissionDetailId);
        } else {
            throw new Error(data.message || '发送失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function loadMissionInbox(missionId) {
    if (!missionId) return;

    try {
        const res = await fetch(`/api/manager/mission/${missionId}/inbox`, {
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            S.missionInboxMessages.length = 0;
            (data.messages || []).forEach(m => S.missionInboxMessages.push(m));
            renderMissionInbox();
        }
    } catch (e) {
        console.error('加载任务收件箱失败', e);
    }
}

function renderMissionInbox() {
    const container = document.getElementById('missionInboxList');
    const badge = document.getElementById('missionInboxBadge');

    const unreadCount = S.missionInboxMessages.filter(m => !m.read).length;
    if (unreadCount > 0) {
        badge.textContent = unreadCount;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }

    if (S.missionInboxMessages.length === 0) {
        container.innerHTML = '<div class="inbox-empty"><i class="fas fa-envelope-open"></i><br>暂无邮件</div>';
        return;
    }

    container.innerHTML = S.missionInboxMessages.map(msg => {
        const initial = (msg.sender_name || '?').charAt(0).toUpperCase();
        const typeNames = { mail: '邮件', containment: '收容物', report: '报告' };
        const typeName = typeNames[msg.message_type] || '邮件';
        const date = new Date(msg.created_at);
        const timeStr = `${date.getMonth()+1}/${date.getDate()} ${date.getHours()}:${String(date.getMinutes()).padStart(2,'0')}`;

        return `
            <div class="mission-inbox-item ${msg.read ? '' : 'unread'}" onclick="openMissionMail(${msg.id})">
                <div class="mission-inbox-sender">${initial}</div>
                <div class="mission-inbox-content">
                    <div class="mission-inbox-subject">${escapeHtml(msg.subject || '无标题')}</div>
                    <div class="mission-inbox-preview">${escapeHtml(msg.sender_name || '未知')}: ${escapeHtml((msg.content || '').substring(0, 50))}</div>
                </div>
                <div class="mission-inbox-meta">
                    <span class="mission-inbox-time">${timeStr}</span>
                    <span class="mission-inbox-type ${msg.message_type}">${typeName}</span>
                </div>
            </div>
        `;
    }).join('');
}

async function openMissionMail(msgId) {
    const msg = S.missionInboxMessages.find(m => m.id === msgId);
    if (!msg) return;

    if (!msg.read && S.currentMissionDetailId) {
        try {
            await fetch(`/api/manager/mission/${S.currentMissionDetailId}/inbox/${msgId}/read`, {
                method: 'PUT',
                headers: getAuthHeaders()
            });

            msg.read = 1;
            renderMissionInbox();
        } catch (e) {}
    }

    document.getElementById('mailDetailSubject').textContent = msg.subject || '无标题';
    document.getElementById('mailDetailSender').textContent = msg.sender_name || '未知';
    document.getElementById('mailDetailTime').textContent = new Date(msg.created_at).toLocaleString();

    const typeNames = { mail: '普通邮件', containment: '收容物申领', report: '任务报告' };
    document.getElementById('mailDetailType').textContent = typeNames[msg.message_type] || '邮件';

    document.getElementById('mailDetailContent').textContent = msg.content || '';

    const reportDataEl = document.getElementById('mailReportData');
    if (msg.message_type === 'report' && msg.report_id) {
        try {
            const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/reports`, {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const data = await res.json();
                const reports = (data.reports || []);
                const report = reports.find(r => r.id === msg.report_id);
                if (report) {
                    const rd = report.originalData || {};
                    const status = rd.status || {};
                    const analysis = rd.analysis || {};
                    const evaluation = rd.evaluation || {};
                    const scattering = rd.scattering || [];
                    const objectives = rd.objectives || [];
                    let statusText = [];
                    if (status.neutralized) statusText.push('已中和');
                    if (status.captured) statusText.push('已捕获');
                    if (status.escaped) statusText.push('已逃脱');
                    if (status.other) statusText.push(status.other);
                    let scHtml = scattering.map(s => `<li>${escapeHtml(s.name)}: ${escapeHtml(s.qty)} (${escapeHtml(s.note || '-')})</li>`).join('');
                    let objHtml = objectives.map(o => `<li>${escapeHtml(o.target)} - ${escapeHtml(o.reward)} (${escapeHtml(o.agent || '-')})</li>`).join('');
                    reportDataEl.innerHTML = `<div style="margin-top:12px;padding:12px;background:#f8f9fa;border-radius:8px;border-left:3px solid #3498db;">
                        <strong style="color:#2c3e50;"><i class="fas fa-file-alt"></i> 任务报告</strong>
                        <p style="color:#7f8c8d;font-size:12px;margin:4px 0 10px;">提交者: ${escapeHtml(report.submitterName)} | ${new Date(report.submittedAt).toLocaleString('zh-CN')}</p>
                        <div style="margin-bottom:8px;"><strong>异常状态:</strong> ${statusText.join(', ') || '未填写'}</div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px;font-size:13px;">
                            <div><strong>代号:</strong> ${escapeHtml(analysis.codename || '-')}</div>
                            <div><strong>行为:</strong> ${escapeHtml(analysis.behavior || '-')}</div>
                            <div><strong>焦点:</strong> ${escapeHtml(analysis.focus || '-')}</div>
                            <div><strong>领域:</strong> ${escapeHtml(analysis.domain || '-')}</div>
                        </div>
                        <div style="margin-bottom:8px;"><strong>MVP推荐:</strong> ${escapeHtml(evaluation.mvp || '无')}</div>
                        <div style="margin-bottom:8px;"><strong>参与者:</strong><div style="background:#fff;padding:8px;border-radius:4px;margin-top:4px;white-space:pre-wrap;font-size:13px;">${escapeHtml(evaluation.participants || '无')}</div></div>
                        ${scHtml ? `<div style="margin-bottom:8px;"><strong>散逸端:</strong><ul style="margin:4px 0;padding-left:18px;font-size:13px;">${scHtml}</ul></div>` : ''}
                        ${objHtml ? `<div><strong>可选目标:</strong><ul style="margin:4px 0;padding-left:18px;font-size:13px;">${objHtml}</ul></div>` : ''}
                    </div>`;
                    reportDataEl.style.display = 'block';
                } else {
                    reportDataEl.innerHTML = '<div style="margin-top:10px;padding:10px;background:#f0f0f0;border-radius:8px;color:#999;">报告数据未找到</div>';
                    reportDataEl.style.display = 'block';
                }
            }
        } catch (e) {
            reportDataEl.style.display = 'none';
        }
    } else {
        reportDataEl.style.display = 'none';
    }

    document.getElementById('mailDetailModal').classList.add('show');
}

async function viewMissionReport(reportId) {
    if (!S.currentMissionDetailId) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/reports`, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error('加载失败');

        const data = await res.json();
        if (!data.success) throw new Error(data.message || '加载失败');
        const reports = data.reports || [];
        const report = reports.find(r => r.id === reportId);

        if (!report) {
            showToast('报告不存在');
            return;
        }

        const reportData = report.originalData || {};
        const status = reportData.status || {};
        const analysis = reportData.analysis || {};
        const evaluation = reportData.evaluation || {};
        const scattering = reportData.scattering || [];
        const objectives = reportData.objectives || [];

        let statusText = [];
        if (status.neutralized) statusText.push('已中和');
        if (status.captured) statusText.push('已捕获');
        if (status.escaped) statusText.push('已逃脱');
        if (status.other) statusText.push(status.other);

        let scatteringHtml = scattering.map(s => `<li>${escapeHtml(s.name)}: ${escapeHtml(s.qty)} (${escapeHtml(s.note || '-')})</li>`).join('');
        let objectivesHtml = objectives.map(o => `<li>${escapeHtml(o.target)} - ${escapeHtml(o.reward)} (${escapeHtml(o.agent || '-')})</li>`).join('');

        const reportHtml = `
            <div style="background:#fff;padding:20px;border-radius:8px;max-height:70vh;overflow-y:auto;">
                <h3 style="margin:0 0 15px;color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px;">
                    <i class="fas fa-file-alt"></i> 任务报告
                </h3>
                <p style="color:#7f8c8d;font-size:12px;margin-bottom:15px;">
                    提交者: ${escapeHtml(report.submitterName)} |
                    时间: ${new Date(report.submittedAt).toLocaleString('zh-CN')}
                </p>

                <div style="margin-bottom:15px;">
                    <strong>异常状态:</strong> ${statusText.join(', ') || '未填写'}
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px;">
                    <div><strong>代号:</strong> ${escapeHtml(analysis.codename || '-')}</div>
                    <div><strong>行为:</strong> ${escapeHtml(analysis.behavior || '-')}</div>
                    <div><strong>焦点:</strong> ${escapeHtml(analysis.focus || '-')}</div>
                    <div><strong>领域:</strong> ${escapeHtml(analysis.domain || '-')}</div>
                </div>

                <div style="margin-bottom:15px;">
                    <strong>MVP推荐:</strong> ${escapeHtml(evaluation.mvp || '无')}
                </div>

                <div style="margin-bottom:15px;">
                    <strong>参与者:</strong>
                    <div style="background:#f8f9fa;padding:10px;border-radius:4px;margin-top:5px;white-space:pre-wrap;">${escapeHtml(evaluation.participants || '无')}</div>
                </div>

                ${scatteringHtml ? `
                <div style="margin-bottom:15px;">
                    <strong>散逸端:</strong>
                    <ul style="margin:5px 0;padding-left:20px;font-size:13px;">${scatteringHtml}</ul>
                </div>
                ` : ''}

                ${objectivesHtml ? `
                <div style="margin-bottom:15px;">
                    <strong>可选目标:</strong>
                    <ul style="margin:5px 0;padding-left:20px;font-size:13px;">${objectivesHtml}</ul>
                </div>
                ` : ''}

                <button class="btn-modal btn-modal-cancel" onclick="this.closest('.report-view-overlay').remove()" style="width:100%;margin-top:10px;">关闭</button>
            </div>
        `;

        const overlay = document.createElement('div');
        overlay.className = 'report-view-overlay';
        overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10001;display:flex;align-items:center;justify-content:center;padding:20px;';
        overlay.innerHTML = `<div style="max-width:600px;width:100%;">${reportHtml}</div>`;
        overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
        document.body.appendChild(overlay);

    } catch (e) {
        console.error('加载报告失败:', e);
        showToast('加载报告失败');
    }
}

async function deleteMissionMail(msgId) {
    if (!S.currentMissionDetailId) return;
    if (!confirm('确定要删除这封邮件吗？')) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/inbox/${msgId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('邮件已删除', true);
            closeMailDetailModal();
            await loadMissionInbox(S.currentMissionDetailId);
        }
    } catch (e) {
        showToast('删除失败');
    }
}

function adjustMissionValue(type, delta) {
    const inputId = type === 'chaos' ? 'missionChaosValue' : 'missionScatterValue';
    const input = document.getElementById(inputId);
    let value = parseInt(input.value) || 0;
    value += delta;
    if (type === 'chaos' && value < 0) value = 0;
    input.value = value;
}

async function saveMissionValues() {
    if (!S.currentMissionDetailId) return;

    const chaosValue = parseInt(document.getElementById('missionChaosValue').value) || 0;
    const scatterValue = parseInt(document.getElementById('missionScatterValue').value) || 0;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ chaosValue, scatterValue })
        });

        const data = await res.json();
        if (data.success) {
            showToast('数值已保存', true);
            if (S.currentMissionDetailData) {
                S.currentMissionDetailData.chaos_value = chaosValue;
                S.currentMissionDetailData.scatter_value = scatterValue;
            }
            await loadMissions();
        } else {
            throw new Error(data.message || '保存失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function removeMemberFromDetail(charId) {
    if (!S.currentMissionDetailId) return;
    if (!confirm('确定要从任务中移除此特工吗？')) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/member/${charId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('特工已移除', true);
            await loadMissions();
            const mission = S.missionsList.find(m => m.id === S.currentMissionDetailId);
            if (mission) {
                renderMissionDetailMembers(mission.members || []);
            }
        } else {
            throw new Error(data.message || '移除失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

function editCurrentMission() {
    if (!S.currentMissionDetailId) return;
    closeMissionDetail();
    openMissionModal(S.currentMissionDetailId);
}

function openMissionPanel() {
    if (!S.currentMissionDetailId) return;
    window.open('mission-panel.html?missionId=' + S.currentMissionDetailId, '_blank');
}

async function archiveCurrentMission() {
    if (!S.currentMissionDetailId) return;
    if (!confirm('确定要归档此任务吗？\n\n注意：如果有未发送的报告评级，需先完成所有评审并发送给特工后才能归档。')) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}/archive`, {
            method: 'POST',
            headers: getAuthHeaders()
        });

        const data = await res.json();
        if (data.success) {
            showToast('任务已归档', true);
            closeMissionDetail();
            await loadMissions();
        } else {
            throw new Error(data.message || '归档失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

async function restoreCurrentMission() {
    if (!S.currentMissionDetailId) return;

    try {
        const res = await fetch(`/api/manager/mission/${S.currentMissionDetailId}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ status: 'active' })
        });

        const data = await res.json();
        if (data.success) {
            showToast('任务已恢复', true);
            closeMissionDetail();
            await loadMissions();
        } else {
            throw new Error(data.message || '恢复失败');
        }
    } catch (e) {
        showToast(e.message);
    }
}

import { closeMailDetailModal } from './mail.js';

S.currentMissionId = null;

export {
    loadMissions,
    renderMissions,
    switchMissionTab,
    openMissionModal,
    closeMissionModal,
    editMission,
    saveMission,
    archiveMission,
    restoreMission,
    deleteMission,
    openAddMemberModal,
    filterAvailableMembers,
    renderAvailableMembers,
    closeAddMemberModal,
    addMemberToMission,
    removeMember,
    openMissionDetail,
    closeMissionDetail,
    renderMissionDetailMembers,
    loadMissionReports,
    renderMissionReports,
    saveReportReview,
    sendReportRating,
    loadMissionInbox,
    renderMissionInbox,
    openMissionMail,
    viewMissionReport,
    deleteMissionMail,
    adjustMissionValue,
    saveMissionValues,
    removeMemberFromDetail,
    editCurrentMission,
    openMissionPanel,
    archiveCurrentMission,
    restoreCurrentMission
};
