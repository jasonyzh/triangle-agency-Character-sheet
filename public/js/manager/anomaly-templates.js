import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';
import { anomIcon, injectAnomIcons } from '../common-modules/anom-icons.js';

// 注入静态 HTML（模板弹窗等）中的模块图标
injectAnomIcons();

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
        const isPassive = !!t.passive;
        let html = '<div class="anomaly-tpl-card' + (isPassive ? ' passive' : '') + '">';
        html += '<button class="anom-tpl-edit-btn" onclick="event.stopPropagation();openAnomalyTemplateModal(\'' + t.id + '\')"><i class="fas fa-pen"></i></button>';
        html += '<button class="anom-tpl-del-btn" onclick="event.stopPropagation();deleteAnomalyTemplate(\'' + t.id + '\')"><i class="fas fa-trash"></i></button>';
        html += '<div class="anomaly-tpl-title-bar">';
        html += '<div class="anomaly-tpl-title-row">';
        html += '<span class="anomaly-tpl-disp-name">' + (t.name || '') + '</span>';
        html += '<span class="anomaly-tpl-field-sep">|</span>';
        html += '<span class="anomaly-tpl-disp-trig">' + (t.trig || '') + '</span>';
        if (isPassive) html += '<span class="anomaly-tpl-passive-badge"><i class="fas fa-shield-alt"></i> 被动</span>';
        if (docLabel) html += '<span class="anomaly-tpl-doc-badge"><i class="fas fa-file-shield"></i> ' + docLabel + '</span>';
        html += '</div>';
        if (t.qual) html += '<div class="anomaly-tpl-disp-qual">' + t.qual + '</div>';
        html += '</div>';
        html += '<div class="anomaly-tpl-body">';
        if (isPassive) {
            html += '<div class="anomaly-tpl-result-row" style="grid-template-columns:1fr;">';
            html += '<div class="anomaly-tpl-result succ"><div class="anomaly-tpl-result-label"><i class="fas fa-shield-alt"></i> 描述</div><div class="anomaly-tpl-disp-succ">' + (t.succ || '<span style="color:#555;">-</span>') + '</div></div>';
            html += '</div>';
        } else {
            html += '<div class="anomaly-tpl-result-row">';
            html += '<div class="anomaly-tpl-result succ"><div class="anomaly-tpl-result-label">' + anomIcon('check') + ' 成功时</div><div class="anomaly-tpl-disp-succ">' + (t.succ || '<span style="color:#555;">-</span>') + '</div></div>';
            html += '<div class="anomaly-tpl-result fail"><div class="anomaly-tpl-result-label">' + anomIcon('x') + ' 失败时</div><div class="anomaly-tpl-disp-fail">' + (t.fail || '<span style="color:#555;">-</span>') + '</div></div>';
            html += '</div>';
        }
        // 列表 / 三重升华（勾选启用才显示；列表允许无子项）
        let alist = [];
        try { alist = JSON.parse(t.alist || '[]'); } catch (e) {}
        if (t.list_on) {
            const tlHtml = alist.length === 1
                ? '<div class="anom-timeline single"><div class="tl-text">' + escapeHtml(alist[0]) + '</div></div>'
                : '<div class="anom-timeline">' + alist.map(r => '<div class="tl-row"><span class="tl-node"></span><span class="tl-text">' + escapeHtml(r) + '</span></div>').join('') + '</div>';
            html += '<div class="anomaly-tpl-extra list"><div class="anomaly-tpl-result-label">' + anomIcon('star') + '<span>' + (t.alist_name || '列表') + '</span></div>' + tlHtml + '</div>';
        }
        if (t.sub_on && t.sub) {
            html += '<div class="anomaly-tpl-extra sub"><div class="anomaly-tpl-sec-label anom-sec-sub">' + anomIcon('wave') + '<span>三重升华时</span></div><div class="anomaly-tpl-sub-body">' + t.sub + '</div></div>';
        }
        html += '</div>';
        if (t.tdesc) {
            html += '<div class="anomaly-tpl-question">';
            html += '<div class="anomaly-tpl-question-text"><i class="fas fa-question-circle"></i> ' + t.tdesc + '</div>';
            if (t.t1 || t.t2 || t.t3) {
                html += '<div class="anomaly-tpl-answers">';
                if (t.t1) html += '<div class="anomaly-tpl-answer">A: ' + t.t1 + (t.t1v ? ' <code>' + t.t1v + '</code>' : '') + '</div>';
                if (t.t2) html += '<div class="anomaly-tpl-answer">B: ' + t.t2 + (t.t2v ? ' <code>' + t.t2v + '</code>' : '') + '</div>';
                if (t.t3) html += '<div class="anomaly-tpl-answer">C: ' + t.t3 + (t.t3v ? ' <code>' + t.t3v + '</code>' : '') + '</div>';
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
    document.getElementById('anomTplPassive').checked = false;
    updateAnomTplPassiveUI(false);
    document.getElementById('anomTplSucc').innerHTML = '';
    document.getElementById('anomTplFail').innerHTML = '';
    // 三重升华 / 列表
    document.getElementById('anomTplSubOn').checked = false;
    document.getElementById('anomTplSub').innerHTML = '';
    document.getElementById('anomTplSubWrap').style.display = 'none';
    document.getElementById('anomTplListOn').checked = false;
    document.getElementById('anomTplListWrap').style.display = 'none';
    document.getElementById('anomTplListName').value = '';
    document.getElementById('anomTplListRows').innerHTML = '';
    tplAddListRow();
    document.getElementById('anomTplTdesc').value = '';
    document.getElementById('anomTplT1').value = '';
    document.getElementById('anomTplT1v').value = '';
    document.getElementById('anomTplT2').value = '';
    document.getElementById('anomTplT2v').value = '';
    document.getElementById('anomTplT3').value = '';
    document.getElementById('anomTplT3v').value = '';
    document.getElementById('anomTplDocFile').value = '';

    await loadAnomalyDocFiles();

    if (editId) {
        const t = S.anomalyTemplates.find(x => x.id === editId);
        if (t) {
            document.getElementById('anomTplName').value = t.name || '';
            document.getElementById('anomTplTrig').value = t.trig || '';
            document.getElementById('anomTplQual').value = t.qual || '';
            document.getElementById('anomTplPassive').checked = !!t.passive;
            updateAnomTplPassiveUI(!!t.passive);
            document.getElementById('anomTplSucc').innerHTML = t.succ || '';
            document.getElementById('anomTplFail').innerHTML = t.fail || '';
            // 三重升华 / 列表
            const subOn = !!t.sub_on;
            document.getElementById('anomTplSubOn').checked = subOn;
            document.getElementById('anomTplSub').innerHTML = t.sub || '';
            document.getElementById('anomTplSubWrap').style.display = subOn ? '' : 'none';
            const listOn = !!t.list_on;
            document.getElementById('anomTplListOn').checked = listOn;
            document.getElementById('anomTplListWrap').style.display = listOn ? '' : 'none';
            document.getElementById('anomTplListName').value = t.alist_name || '';
            const rowsWrap = document.getElementById('anomTplListRows');
            rowsWrap.innerHTML = '';
            let alist = [];
            try { alist = JSON.parse(t.alist || '[]'); } catch (e) {}
            if (!alist.length) alist = [''];
            alist.forEach(v => tplAddListRow(v));
            document.getElementById('anomTplTdesc').value = t.tdesc || '';
            document.getElementById('anomTplT1').value = t.t1 || '';
            document.getElementById('anomTplT1v').value = t.t1v || '';
            document.getElementById('anomTplT2').value = t.t2 || '';
            document.getElementById('anomTplT2v').value = t.t2v || '';
            document.getElementById('anomTplT3').value = t.t3 || '';
            document.getElementById('anomTplT3v').value = t.t3v || '';
            document.getElementById('anomTplDocFile').value = t.doc_filename || '';
        }
    }

    modal.classList.add('show');
}

// 模板弹窗：被动时成功区变"描述"单栏，隐藏失败区；主动恢复双栏
function handleAnomTplPassiveChange(cb) { updateAnomTplPassiveUI(cb.checked); }
function updateAnomTplPassiveUI(isPassive) {
    const succGroup = document.querySelector('#anomTplSuccFailGroup .requisition-form-group:first-child');
    const failGroup = document.querySelector('#anomTplSuccFailGroup .requisition-form-group:last-child');
    const succLabel = succGroup ? succGroup.querySelector('label') : null;
    if (succLabel) succLabel.innerHTML = isPassive ? '<i class="fas fa-shield-alt" style="color:#7f8c8d;"></i> 描述' : '<i class="fas fa-check-circle" style="color:#27ae60;"></i> 成功时';
    if (failGroup) failGroup.style.display = isPassive ? 'none' : '';
}

// 模板弹窗：添加一个列表行（时间线节点 + 输入框 + 删除）
function tplAddListRow(val) {
    const wrap = document.getElementById('anomTplListRows');
    if (!wrap) return;
    const row = document.createElement('div');
    row.className = 'anom-edit-list-row';
    row.innerHTML = '<span class="tl-node"></span><input type="text" placeholder="列表项内容..."><button type="button" class="anom-edit-list-del" onclick="this.parentElement.remove()" title="删除此行">×</button>';
    row.querySelector('input').value = val || '';
    wrap.appendChild(row);
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
        passive: document.getElementById('anomTplPassive').checked,
        succ: document.getElementById('anomTplSucc').innerHTML,
        fail: document.getElementById('anomTplFail').innerHTML,
        tdesc: document.getElementById('anomTplTdesc').value,
        t1: document.getElementById('anomTplT1').value,
        t1v: document.getElementById('anomTplT1v').value,
        t2: document.getElementById('anomTplT2').value,
        t2v: document.getElementById('anomTplT2v').value,
        t3: document.getElementById('anomTplT3').value,
        t3v: document.getElementById('anomTplT3v').value,
        subOn: document.getElementById('anomTplSubOn').checked,
        sub: document.getElementById('anomTplSub').innerHTML,
        listOn: document.getElementById('anomTplListOn').checked,
        listName: document.getElementById('anomTplListName').value.trim(),
        list: Array.from(document.querySelectorAll('#anomTplListRows input')).map(i => i.value.trim()).filter(v => v),
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

    let charAnomNames = [];
    try {
        const res = await fetch('/api/character/' + charId, { headers: getAuthHeaders() });
        const data = await res.json();
        charAnomNames = (data.anoms || []).map(a => a.name);
    } catch(e) {}

    const list = document.getElementById('grantAnomalyList');
    if (!S.anomalyTemplates.length) {
        list.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">暂无可赋予的异常能力模板</div>';
    } else {
        list.innerHTML = S.anomalyTemplates.map(t => {
            const docLabel = t.doc_filename ? ' (' + t.doc_filename.replace(/\.md$/i, '') + ')' : '';
            const passiveLabel = t.passive ? ' <i class="fas fa-shield-alt" title="被动" style="color:#7f8c8d;"></i>' : '';
            const isGranted = charAnomNames.includes(t.name);
            return `
                <label class="doc-item">
                    <input type="checkbox" value="${t.id}" ${isGranted ? 'checked' : ''}>
                    <div class="doc-item-content">
                        <div class="doc-item-name">${t.name}${passiveLabel}</div>
                        ${docLabel ? `<div class="doc-item-meta">${docLabel}</div>` : ''}
                    </div>
                </label>
            `;
        }).join('');
    }

    document.getElementById('grantAnomalyModal').classList.add('show');
    var searchInput = document.getElementById('grantAnomalySearch');
    if (searchInput) { searchInput.value = ''; }
}

function closeGrantAnomalyModal() {
    document.getElementById('grantAnomalyModal').classList.remove('show');
}

async function saveGrantedAnomalies() {
    if (!S.currentGrantAnomalyCharId) return;

    const allCheckboxes = Array.from(document.querySelectorAll('#grantAnomalyList input[type="checkbox"]'));
    const selectedIds = allCheckboxes.filter(cb => cb.checked).map(cb => cb.value);
    const unselectedIds = allCheckboxes.filter(cb => !cb.checked).map(cb => cb.value);
    const btn = document.querySelector('#grantAnomalyModal .btn-modal-confirm');
    btn.textContent = '保存中...';
    btn.disabled = true;

    try {
        const grantPromises = selectedIds.map(id =>
            fetch('/api/anomaly-templates/' + id + '/grant', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: S.currentGrantAnomalyCharId })
            })
        );
        const revokePromises = unselectedIds.map(id =>
            fetch('/api/anomaly-templates/' + id + '/revoke', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: S.currentGrantAnomalyCharId })
            })
        );

        await Promise.all([...grantPromises, ...revokePromises]);
        showToast('异常能力已更新', 'success');
        closeGrantAnomalyModal();
    } catch (e) {
        showToast('更新失败', 'error');
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

function filterGrantAnomaly(keyword) {
    const kw = (keyword || '').toLowerCase();
    document.querySelectorAll('#grantAnomalyList .doc-item').forEach(item => {
        const name = item.querySelector('.doc-item-name').textContent.toLowerCase();
        item.style.display = name.includes(kw) ? '' : 'none';
    });
}

// 导入 JSON 批量创建/更新异常能力模板（同名模板覆盖更新）
// 格式：[{name, trig, qual, succ, fail, passive, tdesc, t1, t1v, t2, t2v, t3, t3v, sub, subOn, list, listOn, docFilename}]
async function importAnomalyJson(e) {
    const file = e.target.files[0];
    if (!file) return;
    if (!S.currentBranchId) { showToast('请先选择分部'); e.target.value = ''; return; }
    let items;
    try {
        items = JSON.parse(await file.text());
        if (!Array.isArray(items)) throw new Error('JSON 应为数组');
    } catch (err) {
        showToast('JSON 解析失败: ' + err.message); e.target.value = ''; return;
    }
    if (!items.length) { showToast('JSON 为空'); e.target.value = ''; return; }
    if (!confirm('确定导入 ' + items.length + ' 条异常能力模板？同名模板将被覆盖更新。')) { e.target.value = ''; return; }

    const byName = new Map(S.anomalyTemplates.map(t => [t.name, t]));
    let created = 0, updated = 0, failed = 0;
    for (const it of items) {
        if (!it.name || typeof it.name !== 'string') { failed++; continue; }
        const body = {
            name: it.name,
            trig: it.trig || '',
            qual: it.qual || '',
            passive: !!it.passive,
            succ: it.succ || '',
            fail: it.fail || '',
            tdesc: it.tdesc || '',
            t1: it.t1 || '', t1v: it.t1v || '',
            t2: it.t2 || '', t2v: it.t2v || '',
            t3: it.t3 || '', t3v: it.t3v || '',
            subOn: it.subOn != null ? !!it.subOn : !!(it.sub && it.sub.trim()),
            sub: it.sub || '',
            listOn: it.listOn != null ? !!it.listOn : !!(it.list && it.list.length),
            listName: it.listName || '',
            list: it.list || [],
            docFilename: it.docFilename || ''
        };
        const existing = byName.get(it.name);
        try {
            const res = await fetch(existing ? `/api/anomaly-templates/${existing.id}` : '/api/anomaly-templates', {
                method: existing ? 'PUT' : 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify(existing ? body : { ...body, branchId: S.currentBranchId })
            });
            const data = await res.json();
            if (data.success) {
                if (existing) { updated++; byName.set(it.name, { ...existing, ...body }); }
                else { created++; byName.set(it.name, { id: data.id, name: it.name }); }
            } else { failed++; }
        } catch (err) { failed++; }
    }
    e.target.value = '';
    showToast('导入完成：新增 ' + created + '，更新 ' + updated + '，失败 ' + failed, created + updated > 0 ? 'success' : 'error');
    await loadAnomalyTemplates();
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
    grantAnomalyToChar,
    filterGrantAnomaly,
    handleAnomTplPassiveChange,
    importAnomalyJson,
    tplAddListRow
};
