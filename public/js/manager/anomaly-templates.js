import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

async function loadAnomalyTemplates() {
    if (!S.currentBranchId) return;
    try {
        const res = await fetch('/api/anomaly-templates?branchId=' + S.currentBranchId, { headers: getAuthHeaders() });
        S.anomalyTemplates.length = 0;
        const data = await res.json();
        data.forEach(t => S.anomalyTemplates.push(t));
        renderAnomalyTemplates();
    } catch(e) {
        showToast('加载异常能力模板失败');
    }
}

async function loadAnomalyDocFiles() {
    try {
        const res = await fetch('/api/documents/list', { headers: getAuthHeaders() });
        const files = await res.json();
        S.anomalyDocFiles.length = 0;
        files.map(f => f.filename).forEach(f => S.anomalyDocFiles.push(f));
        const sel = document.getElementById('anomTplDocFile');
        if (sel) {
            sel.innerHTML = '<option value="">-- 不关联 --</option>';
            S.anomalyDocFiles.forEach(f => {
                sel.innerHTML += '<option value="' + f + '">' + f.replace(/\.md$/i, '') + '</option>';
            });
        }
    } catch(e) {}
}

function renderAnomalyTemplates() {
    const container = document.getElementById('anomalyTemplateList');
    if (!container) return;
    if (!S.anomalyTemplates.length) {
        container.innerHTML = '<div class="requisition-empty"><i class="fas fa-bolt" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i><p>暂无异常能力模板，点击右上角创建</p></div>';
        return;
    }
    container.innerHTML = S.anomalyTemplates.map(t => {
        const docLabel = t.doc_filename ? t.doc_filename.replace(/\.md$/i, '') : '';
        let html = '<div class="anomaly-tpl-card">';
        html += '<button class="anom-tpl-edit-btn" onclick="event.stopPropagation();openAnomalyTemplateModal(\'' + t.id + '\')"><i class="fas fa-pen"></i></button>';
        html += '<button class="anom-tpl-del-btn" onclick="event.stopPropagation();deleteAnomalyTemplate(\'' + t.id + '\')"><i class="fas fa-trash"></i></button>';
        html += '<div class="anomaly-tpl-title-bar">';
        html += '<div class="anomaly-tpl-title-row">';
        html += '<span class="anomaly-tpl-disp-name">' + (t.name || '') + '</span>';
        html += '<span class="anomaly-tpl-field-sep">|</span>';
        html += '<span class="anomaly-tpl-disp-trig">' + (t.trig || '') + '</span>';
        if (docLabel) html += '<span class="anomaly-tpl-doc-badge"><i class="fas fa-file-shield"></i> ' + docLabel + '</span>';
        html += '</div>';
        if (t.qual) html += '<div class="anomaly-tpl-disp-qual">' + t.qual + '</div>';
        html += '</div>';
        html += '<div class="anomaly-tpl-body">';
        html += '<div class="anomaly-tpl-result-row">';
        html += '<div class="anomaly-tpl-result succ"><div class="anomaly-tpl-result-label"><i class="fas fa-check-circle"></i> 成功时</div><div class="anomaly-tpl-disp-succ">' + (t.succ || '<span style="color:#555;">-</span>') + '</div></div>';
        html += '<div class="anomaly-tpl-result fail"><div class="anomaly-tpl-result-label"><i class="fas fa-times-circle"></i> 失败时</div><div class="anomaly-tpl-disp-fail">' + (t.fail || '<span style="color:#555;">-</span>') + '</div></div>';
        html += '</div>';
        html += '</div>';
        if (t.tdesc) {
            html += '<div class="anomaly-tpl-question">';
            html += '<div class="anomaly-tpl-question-text"><i class="fas fa-question-circle"></i> ' + t.tdesc + '</div>';
            if (t.t1 || t.t2) {
                html += '<div class="anomaly-tpl-answers">';
                if (t.t1) html += '<div class="anomaly-tpl-answer">A: ' + t.t1 + (t.t1v ? ' <code>' + t.t1v + '</code>' : '') + '</div>';
                if (t.t2) html += '<div class="anomaly-tpl-answer">B: ' + t.t2 + (t.t2v ? ' <code>' + t.t2v + '</code>' : '') + '</div>';
                html += '</div>';
            }
            html += '</div>';
        }
        html += '</div>';
        return html;
    }).join('');
}

async function openAnomalyTemplateModal(editId) {
    const modal = document.getElementById('anomalyTemplateModal');
    document.getElementById('anomalyEditId').value = editId || '';
    document.getElementById('anomalyModalTitle').textContent = editId ? '编辑异常能力模板' : '创建异常能力模板';

    document.getElementById('anomTplName').value = '';
    document.getElementById('anomTplTrig').value = '';
    document.getElementById('anomTplQual').value = '';
    document.getElementById('anomTplSucc').innerHTML = '';
    document.getElementById('anomTplFail').innerHTML = '';
    document.getElementById('anomTplTdesc').value = '';
    document.getElementById('anomTplT1').value = '';
    document.getElementById('anomTplT1v').value = '';
    document.getElementById('anomTplT2').value = '';
    document.getElementById('anomTplT2v').value = '';
    document.getElementById('anomTplDocFile').value = '';

    await loadAnomalyDocFiles();

    if (editId) {
        const t = S.anomalyTemplates.find(x => x.id === editId);
        if (t) {
            document.getElementById('anomTplName').value = t.name || '';
            document.getElementById('anomTplTrig').value = t.trig || '';
            document.getElementById('anomTplQual').value = t.qual || '';
            document.getElementById('anomTplSucc').innerHTML = t.succ || '';
            document.getElementById('anomTplFail').innerHTML = t.fail || '';
            document.getElementById('anomTplTdesc').value = t.tdesc || '';
            document.getElementById('anomTplT1').value = t.t1 || '';
            document.getElementById('anomTplT1v').value = t.t1v || '';
            document.getElementById('anomTplT2').value = t.t2 || '';
            document.getElementById('anomTplT2v').value = t.t2v || '';
            document.getElementById('anomTplDocFile').value = t.doc_filename || '';
        }
    }

    modal.classList.add('show');
}

function closeAnomalyTemplateModal() {
    document.getElementById('anomalyTemplateModal').classList.remove('show');
}

async function saveAnomalyTemplate() {
    const editId = document.getElementById('anomalyEditId').value;
    const name = document.getElementById('anomTplName').value.trim();
    if (!name) { showToast('请输入能力名称'); return; }

    const body = {
        branchId: S.currentBranchId,
        name,
        trig: document.getElementById('anomTplTrig').value,
        qual: document.getElementById('anomTplQual').value,
        succ: document.getElementById('anomTplSucc').innerHTML,
        fail: document.getElementById('anomTplFail').innerHTML,
        tdesc: document.getElementById('anomTplTdesc').value,
        t1: document.getElementById('anomTplT1').value,
        t1v: document.getElementById('anomTplT1v').value,
        t2: document.getElementById('anomTplT2').value,
        t2v: document.getElementById('anomTplT2v').value,
        docFilename: document.getElementById('anomTplDocFile').value
    };

    try {
        const url = editId ? '/api/anomaly-templates/' + editId : '/api/anomaly-templates';
        const method = editId ? 'PUT' : 'POST';
        const res = await fetch(url, { method, headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await res.json();
        if (data.success) {
            showToast(editId ? '已更新' : '已创建', 'success');
            closeAnomalyTemplateModal();
            await loadAnomalyTemplates();
        } else {
            showToast(data.message || '保存失败');
        }
    } catch(e) {
        showToast('保存失败');
    }
}

async function deleteAnomalyTemplate(id) {
    if (!confirm('确定删除此异常能力模板？')) return;
    try {
        const res = await fetch('/api/anomaly-templates/' + id, { method: 'DELETE', headers: getAuthHeaders() });
        const data = await res.json();
        if (data.success) {
            showToast('已删除', 'success');
            await loadAnomalyTemplates();
        } else {
            showToast(data.message || '删除失败');
        }
    } catch(e) {
        showToast('删除失败');
    }
}

async function openGrantAnomalyModal(charId, charName) {
    S.currentGrantAnomalyCharId = charId;
    document.getElementById('grantAnomalyCharName').textContent = charName;

    if (!S.anomalyTemplates.length) {
        await loadAnomalyTemplates();
    }

    const list = document.getElementById('grantAnomalyList');
    if (!S.anomalyTemplates.length) {
        list.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">暂无可赋予的异常能力模板</div>';
    } else {
        list.innerHTML = S.anomalyTemplates.map(t => {
            const docLabel = t.doc_filename ? ' (' + t.doc_filename.replace(/\.md$/i, '') + ')' : '';
            return `
                <label class="doc-item">
                    <input type="checkbox" value="${t.id}" ${t.granted ? 'checked' : ''}>
                    <div class="doc-item-content">
                        <div class="doc-item-name">${t.name}</div>
                        ${docLabel ? `<div class="doc-item-meta">${docLabel}</div>` : ''}
                    </div>
                </label>
            `;
        }).join('');
    }

    document.getElementById('grantAnomalyModal').classList.add('show');
}

function closeGrantAnomalyModal() {
    document.getElementById('grantAnomalyModal').classList.remove('show');
}

async function saveGrantedAnomalies() {
    if (!S.currentGrantAnomalyCharId) return;

    const selectedIds = Array.from(document.querySelectorAll('#grantAnomalyList input:checked')).map(cb => cb.value);
    const btn = document.querySelector('#grantAnomalyModal .btn-modal-confirm');
    btn.textContent = '保存中...';
    btn.disabled = true;

    try {
        const promises = selectedIds.map(id =>
            fetch('/api/anomaly-templates/' + id + '/grant', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: S.currentGrantAnomalyCharId })
            })
        );

        await Promise.all(promises);
        showToast('异常能力已赋予', 'success');
        closeGrantAnomalyModal();
    } catch (e) {
        showToast('赋予失败', 'error');
    } finally {
        btn.textContent = '保存';
        btn.disabled = false;
    }
}

async function grantAnomalyToChar(templateId) {
    const charId = document.getElementById('grantAnomalyCharId').value;
    try {
        const res = await fetch('/api/anomaly-templates/' + templateId + '/grant', {
            method: 'POST',
            headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
            body: JSON.stringify({ characterId: charId })
        });
        const data = await res.json();
        if (data.success) {
            showToast('异常能力已赋予', 'success');
        } else {
            showToast(data.message || '赋予失败');
        }
    } catch(e) {
        showToast('赋予失败');
    }
}

export {
    loadAnomalyTemplates,
    renderAnomalyTemplates,
    openAnomalyTemplateModal,
    closeAnomalyTemplateModal,
    saveAnomalyTemplate,
    deleteAnomalyTemplate,
    openGrantAnomalyModal,
    closeGrantAnomalyModal,
    saveGrantedAnomalies,
    grantAnomalyToChar
};
