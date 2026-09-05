import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { escapeHtmlText } from './ui.js';

export async function showRecordHistory(type) {
    const modal = document.getElementById('recordHistoryModal');
    const titleEl = document.getElementById('recordHistoryTitle');
    const contentEl = document.getElementById('recordHistoryContent');

    const titles = { reward: '嘉奖记录', reprimand: '申诫记录', mvp: 'MVP记录', watch: '察看期记录' };
    titleEl.textContent = titles[type] || '记录';
    contentEl.innerHTML = '<div style="text-align:center; padding:40px; color:#95a5a6;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    modal.style.display = 'flex';

    document.body.style.overflow = 'hidden';

    modal.addEventListener('wheel', function (e) { e.stopPropagation(); }, { passive: false });

    try {
        if (!S.cachedRecords && S.charId) {
            const res = await fetch(`/api/character/${S.charId}/records`, { headers: getAuthHeaders() });
            if (res.ok) { S.cachedRecords = await res.json(); }
        }

        const recordsMap = {
            reward: S.cachedRecords?.rewards || [],
            reprimand: S.cachedRecords?.reprimands || [],
            mvp: S.cachedRecords?.mvpRecords || [],
            watch: S.cachedRecords?.watchRecords || []
        };
        const records = recordsMap[type] || [];

        if (records.length === 0) {
            contentEl.innerHTML = `<div style="text-align:center; padding:40px; color:#95a5a6;">暂无${titles[type] || '记录'}</div>`;
            return;
        }

        const sorted = [...records].sort((a, b) => (b.date || 0) - (a.date || 0));

        const colors = {
            reward: { bg: '#fff5f5', border: '#e74c3c', badge: '#e74c3c' },
            reprimand: { bg: '#f0f8ff', border: '#3498db', badge: '#3498db' },
            mvp: { bg: '#fff8f0', border: '#ea580c', badge: '#ea580c' },
            watch: { bg: '#f0f0ff', border: '#7c3aed', badge: '#7c3aed' }
        };
        const c = colors[type] || colors.reward;

        contentEl.innerHTML = sorted.map(r => {
            const date = r.date ? new Date(r.date).toLocaleString('zh-CN', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            }) : '未知时间';
            const countBadge = (r.count && r.count > 1)
                ? `<span style="padding:2px 6px; border-radius:3px; font-size:11px; font-weight:bold; background:${c.badge}; color:white; margin-left:8px;">x${r.count}</span>`
                : '';
            return `
                <div style="background:${c.bg}; border-left:4px solid ${c.border}; border-radius:6px; padding:15px; margin-bottom:12px;">
                    <div style="font-size:14px; font-weight:bold; color:#2c3e50; margin-bottom:8px;">${escapeHtmlText(r.reason || '无原因')}${countBadge}</div>
                    <div style="font-size:12px; color:#7f8c8d;">
                        <i class="fas fa-clock"></i> ${date}
                        ${r.addedByName ? `&nbsp;&nbsp;<i class="fas fa-user-tie"></i> ${escapeHtmlText(r.addedByName)}` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        console.error('加载记录失败:', e);
        contentEl.innerHTML = '<div style="text-align:center; padding:40px; color:#e74c3c;">加载失败</div>';
    }
}

export function closeRecordHistory() {
    document.getElementById('recordHistoryModal').style.display = 'none';
    document.body.style.overflow = '';
}

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
