const token = localStorage.getItem('ta_token');
const role = parseInt(localStorage.getItem('ta_role') || '0');
if (!token || role < 1) window.location.href = 'login.html';

const params = new URLSearchParams(window.location.search);
const missionId = params.get('missionId');
if (!missionId) { showToast('缺少任务ID'); setTimeout(() => window.location.href = 'manager.html', 1000); }

let missionData = null;
let charactersData = [];
let socket = null;
let gmBoard = null;
let currentPanelTab = 'overview';
let currentLibCategory = 'npc';
let currentLibFolder = '';
let imageLib = [];
let libFolders = [];
let boardData = null;
let connectMode = false;
let connectSourceId = null;
let tianqiList = [];
let weatherSelected = []; // 已勾选天气卡的 id 数组（弹窗内编辑态）

async function init() {
    try {
        const res = await fetch(`/api/manager/mission/${missionId}/characters-full`, { headers: getAuthHeaders() });
        if (res.status === 401) { window.location.href = 'login.html'; return; }
        const data = await res.json();
        if (!data.success) { showToast(data.message || '加载失败'); return; }

        missionData = data.mission;
        charactersData = data.characters;

        document.getElementById('mpMissionName').textContent = missionData.name;
        document.getElementById('mpMissionStatus').textContent = missionData.status === 'active' ? '进行中' : '已归档';
        document.getElementById('mpMissionStatus').className = 'mp-status' + (missionData.status === 'archived' ? ' archived' : '');
        document.getElementById('mpChaosValue').textContent = missionData.chaos_value;
        document.getElementById('mpScatterValue').textContent = missionData.scatter_value;

        await loadTianqiOptions();
        renderWeatherCount();

        renderAgents();
        initSocket();
        await loadImageLibrary();
    } catch(e) { showToast('加载失败'); console.error(e); }
}

function initSocket() {
    socket = io({ auth: { token } });
    socket.on('connect', () => {
        console.log('Board socket connected');
        // 重连后若当前在画板 tab，自动重新加入房间，保证广播正常
        if (currentPanelTab === 'board') joinBoardRoom('mgr');
    });
    // 始终监听骰子事件（不管在哪个tab）
    socket.on('dice:roll', function(d) {
        var detail = '(' + (d.results || []).map(function(r, i) {
            var isCheck3 = d.type === 'check' && r === 3;
            return '<span' + (isCheck3 ? ' style="color:#ff6b6b;font-weight:900;"' : '') + '>' + r + (i < d.results.length-1 ? ' ' : '') + '</span>';
        }).join('') + ')';
        var html = '<span class="dice-char">[' + d.charName + ']</span> <span class="dice-label">' + d.label + '</span> <span class="dice-total">' + d.total + '</span> <span class="dice-detail">' + detail + '</span>';
        // 存入历史
        var gmDiceHistory = JSON.parse(localStorage.getItem('ta_gm_dice_history') || '[]');
        gmDiceHistory.unshift({ time: new Date().toLocaleTimeString(), html: html });
        if (gmDiceHistory.length > 50) gmDiceHistory.pop();
        try { localStorage.setItem('ta_gm_dice_history', JSON.stringify(gmDiceHistory)); } catch(e) {}
        // 在当前页面显示
        var container = document.getElementById('gmDiceResults');
        if (container) {
            var el = document.createElement('div');
            el.className = 'dice-entry';
            el.innerHTML = html;
            el.style.cssText = 'background:rgba(26,37,47,0.85);color:white;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;animation:diceFadeIn 0.2s ease;opacity:1;transition:opacity 0.5s;';
            container.appendChild(el);
            setTimeout(function() { el.style.opacity = '0'; }, 4500);
            setTimeout(function() { if (el.parentNode) el.remove(); }, 5200);
            var entries = container.querySelectorAll('.dice-entry');
            if (entries.length > 20) entries[0].remove();
        }
    });
}

function joinBoardRoom(bRole) {
    if (socket && socket.connected) socket.emit('join-board', { missionId, role: bRole });
}

function leaveBoardRoom() {
    if (socket) socket.emit('leave-board');
}

function switchPanelTab(tab) {
    currentPanelTab = tab;
    document.querySelectorAll('.mp-tab').forEach(b => b.classList.remove('active'));
    document.querySelector(`.mp-tab[onclick*="${tab}"]`).classList.add('active');
    document.querySelectorAll('.mp-tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('mpTab' + (tab === 'overview' ? 'Overview' : 'Board')).classList.add('active');

    leaveBoardRoom();
    if (tab === 'board') {
        joinBoardRoom('mgr');
        initBoardView();
    }
}

function switchLibCategory(cat) {
    currentLibCategory = cat;
    document.querySelectorAll('.lib-cat-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.lib-cat-btn[data-cat="' + cat + '"]').classList.add('active');
    renderImageLibrary();
}

async function loadImageLibrary() {
    try {
        const folderParam = currentLibFolder ? '?folder=' + encodeURIComponent(currentLibFolder) : '';
        const res = await fetch('/api/image-library' + folderParam, { headers: getAuthHeaders() });
        imageLib = await res.json();
        await loadLibFolders();
        renderImageLibrary();
    } catch(e) {}
}

async function loadLibFolders() {
    try {
        const res = await fetch('/api/image-library/folders', { headers: getAuthHeaders() });
        libFolders = await res.json();
        var sel = document.getElementById('libFolderSelect');
        if (sel) { sel.innerHTML = '<option value="">全部</option>'; libFolders.forEach(function(f) { sel.innerHTML += '<option value="' + f + '"' + (f===currentLibFolder?' selected':'') + '>' + f + '</option>'; }); }
    } catch(e) {}
}

function switchLibFolder() { currentLibFolder = document.getElementById('libFolderSelect').value; loadImageLibrary(); }
function createLibFolder() {
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:20000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:white;border-radius:8px;padding:20px;min-width:260px;box-shadow:0 8px 32px rgba(0,0,0,0.2);">' +
        '<h3 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#333;"><i class="fas fa-folder-plus"></i> 新建文件夹</h3>' +
        '<input type="text" placeholder="文件夹名称" style="width:100%;padding:8px;border:1px solid #d0d5dd;border-radius:4px;font-size:13px;color:#333;box-sizing:border-box;">' +
        '<div style="display:flex;gap:8px;margin-top:12px;">' +
        '<button class="fld-cancel" style="flex:1;padding:6px;background:#eee;border:none;border-radius:4px;cursor:pointer;font-size:12px;color:#666;">取消</button>' +
        '<button class="fld-ok" style="flex:1;padding:6px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:700;">确定</button>' +
        '</div></div>';
    document.body.appendChild(overlay);
    var input = overlay.querySelector('input');
    overlay.querySelector('.fld-cancel').onclick = function() { overlay.remove(); };
    overlay.querySelector('.fld-ok').onclick = async function() {
        var name = input.value.trim();
        if (!name) return;
        try {
            const res = await fetch('/api/image-library/folders', {
                method: 'POST', headers: getAuthHeaders(),
                body: JSON.stringify({ name })
            });
            const d = await res.json();
            if (d.success) {
                currentLibFolder = d.name;
                overlay.remove();
                await loadImageLibrary();
                showToast('文件夹 "' + d.name + '" 已创建', 'success');
            } else {
                showToast(d.message || '创建失败', 'error');
            }
        } catch(e) { showToast('创建失败', 'error'); }
    };
    overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
    setTimeout(function() { input.focus(); }, 100);
}

function renderImageLibrary() {
    const list = document.getElementById('imageLibList');
    if (!list) return;
    const filtered = imageLib.filter(img => img.category === currentLibCategory);
    const html = !filtered.length
        ? '<div class="lib-empty">暂无' + (currentLibCategory === 'npc' ? 'NPC' : '地图') + '图片</div>'
        : filtered.map(img => '<div class="lib-item" draggable="true" ondragstart="onLibDrag(event,\'' + img.id + '\',\'' + img.filename + '\',\'' + (img.original_name||img.filename).replace(/'/g,"\\'") + '\',\'' + img.category + '\')" ondblclick="renameLibImage(\'' + img.id + '\',\'' + (img.original_name||img.filename).replace(/'/g,"\\'") + '\')" oncontextmenu="event.preventDefault();showLibItemMenu(event,\'' + img.id + '\',\'' + (img.original_name||img.filename).replace(/'/g,"\\'") + '\')"><img src="' + (img.filename && img.filename.indexOf('http') === 0 ? img.filename : '/' + img.filename) + '" title="双击改名｜右键删除"><span>' + (img.original_name||img.filename).substring(0, 10) + '</span></div>').join('');
    list.innerHTML = html;
}

function onLibDrag(e, id, filename, name, cat) {
    e.dataTransfer.setData('text/plain', JSON.stringify({ id, filename, name, category: cat }));
}

async function uploadImageToLib(e) {
    const file = e.target.files[0];
    if (!file) return;
    const form = new FormData();
    form.append('folder', currentLibFolder || '默认');
    form.append('category', currentLibCategory);
    form.append('image', file);
    try {
        const res = await fetch('/api/image-library/upload?folder=' + encodeURIComponent(currentLibFolder || '默认') + '&category=' + currentLibCategory, { method: 'POST', headers: { 'Authorization': 'Bearer ' + token }, body: form });
        const data = await res.json();
        if (data.success) { showToast('上传成功', 'success'); await loadImageLibrary(); }
        else showToast(data.message || '上传失败');
    } catch(e) { showToast('上传失败'); }
    e.target.value = '';
}

async function renameLibImage(imgId, oldName) {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:20000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:white;border-radius:8px;padding:20px;min-width:280px;box-shadow:0 8px 32px rgba(0,0,0,0.2);">' +
        '<h3 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#333;"><i class="fas fa-pen"></i> 重命名图库文件</h3>' +
        '<input type="text" value="' + (oldName || '') + '" placeholder="文件名称" style="width:100%;padding:8px;border:1px solid #d0d5dd;border-radius:4px;font-size:13px;color:#333;box-sizing:border-box;">' +
        '<div style="display:flex;gap:8px;margin-top:12px;">' +
        '<button class="rn-cancel" style="flex:1;padding:6px;background:#eee;border:none;border-radius:4px;cursor:pointer;font-size:12px;color:#666;">取消</button>' +
        '<button class="rn-ok" style="flex:1;padding:6px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:700;">确定</button>' +
        '</div></div>';
    document.body.appendChild(overlay);
    const input = overlay.querySelector('input');
    overlay.querySelector('.rn-cancel').onclick = function() { overlay.remove(); };
    overlay.querySelector('.rn-ok').onclick = async function() {
        const name = input.value.trim();
        overlay.remove();
        if (!name || name === oldName) return;
        try {
            await fetch('/api/image-library/' + imgId, {
                method: 'PUT', headers: getAuthHeaders(),
                body: JSON.stringify({ name })
            });
            const img = imageLib.find(i => i.id === imgId);
            if (img) { img.original_name = name; renderImageLibrary(); }
            showToast('已改名', 'success');
        } catch(e) { showToast('改名失败'); }
    };
    overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
    setTimeout(() => input.focus(), 100);
}

async function deleteLibImage(imgId) {
    if (!confirm('删除此图库文件？')) return;
    try {
        await fetch('/api/image-library/' + imgId, { method: 'DELETE', headers: getAuthHeaders() });
        await loadImageLibrary();
        showToast('已删除', 'success');
    } catch(e) { showToast('删除失败'); }
}

function showLibItemMenu(e, imgId, name) {
    var ex = document.querySelector('.lib-ctx-menu');
    if (ex) ex.remove();
    var m = document.createElement('div');
    m.className = 'lib-ctx-menu';
    m.style.cssText = 'position:fixed;left:' + e.clientX + 'px;top:' + e.clientY + 'px;z-index:99999;background:white;border:1px solid #e0e0e0;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,0.12);padding:4px 0;min-width:120px;';
    m.innerHTML = '<div style="position:absolute;top:-7px;left:12px;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:8px solid #c0392b;"></div>' +
        '<div class="ctx-item" onclick="var p=this.closest(\'.lib-ctx-menu\');if(p)p.remove();renameLibImage(\'' + imgId + '\',\'' + name.replace(/'/g,"\\'") + '\')"><i class="fas fa-pen" style="color:#666;"></i> 重命名</div>' +
        '<div class="ctx-item" onclick="var p=this.closest(\'.lib-ctx-menu\');if(p)p.remove();deleteLibImage(\'' + imgId + '\')"><i class="fas fa-trash" style="color:#c0392b;"></i> 删除</div>';
    m.addEventListener('pointerdown', function(ev) { ev.stopPropagation(); });
    document.body.appendChild(m);
    setTimeout(function() { document.addEventListener('mousedown', function close(ev) { if (!m.contains(ev.target)) { m.remove(); document.removeEventListener('mousedown', close); } }); }, 0);
}

// ===== 统一画板 =====

async function initBoardView() {
    const canvasEl = document.getElementById('boardCanvas');
    if (!canvasEl) return;
    try {
        const res = await fetch('/api/board/' + missionId, { headers: getAuthHeaders() });
        const data = await res.json();
        if (!data.success) return;
        boardData = data;

        canvasEl.innerHTML = '';

        gmBoard = new BoardCore(canvasEl, {
            editable: true, role: 'manager', imageBaseUrl: '/',
            onImageMove: function(id, x, y) { saveImagePos(id, x, y); },
            onImageResize: function(id, w, h) { saveImageSize(id, w, h); },
            onImageClick: function(id) {
                if (connectMode) {
                    if (!connectSourceId) {
                        connectSourceId = id;
                        gmBoard.clearHighlight();
                        gmBoard.highlightImage(id);
                        showToast('已选起点，点击目标图片完成连线');
                    } else if (connectSourceId !== id) {
                        createConnection(connectSourceId, id);
                        gmBoard.clearHighlight();
                        connectSourceId = null;
                    }
                }
            },
            onImageRightClick: function(id, x, y) {
                showBoardContextMenu(id, x, y);
            },
            onMapLineRightClick: function(connId, x, y) {
                showMapLineCtxMenu(connId, x, y);
            }
        });

        gmBoard.onRename = function(id) {
            promptRename(id);
        };

        // Single drop handler - no duplicate!
        canvasEl.ondragover = function(e) { e.preventDefault(); };
        canvasEl.ondrop = async function(e) {
            e.preventDefault();
            try {
                const info = JSON.parse(e.dataTransfer.getData('text/plain'));
                const rect = canvasEl.getBoundingClientRect();
                const x = Math.max(0, e.clientX - rect.left - 60);
                const y = Math.max(0, e.clientY - rect.top - 10);
                const isMapNode = info.category === 'map';
                const res2 = await fetch('/api/board/' + missionId + '/image', {
                    method: 'POST', headers: getAuthHeaders(),
                    body: JSON.stringify({ imageLibId: info.id, name: info.name, x, y, w: 120, h: 120, isMapNode })
                });
                const d2 = await res2.json();
                if (d2.success) {
                    gmBoard.addImage({ id: d2.id, imageFile: d2.imageFile, x: d2.m_x, y: d2.m_y, w: d2.m_w, h: d2.m_h, name: d2.name, isMapNode: d2.is_map_node });
                    socket.emit('board:image-add', d2);
                }
            } catch(e2) {}
        };

        gmBoard.loadImages(data.images);
        gmBoard.setConnections(boardData.board.show_connections ? data.connections : []);
        document.getElementById('btnToggleConn').innerHTML = data.board.show_connections
            ? '<i class="fas fa-link"></i> 隐藏连线' : '<i class="fas fa-unlink"></i> 显示连线';

        socket.off('board:image-move').on('board:image-move', function(d) { if (gmBoard) { gmBoard.moveImage(d.imageId, d.x, d.y); gmBoard.drawAll(); } });
        socket.off('board:image-resize').on('board:image-resize', function(d) { if (gmBoard) { gmBoard.resizeImage(d.imageId, d.w, d.h); gmBoard.drawAll(); } });
        socket.off('board:image-add').on('board:image-add', function(d) { if (gmBoard) gmBoard.addImage({ id: d.id, imageFile: d.imageFile, x: d.m_x, y: d.m_y, w: d.m_w, h: d.m_h, name: d.name, isMapNode: d.is_map_node }); });
        socket.off('board:image-remove').on('board:image-remove', function(d) {
            if (gmBoard) {
                if (boardData && boardData.connections) {
                    boardData.connections = boardData.connections.filter(function(c) { return c.node_a !== d.imageId && c.node_b !== d.imageId; });
                }
                gmBoard.removeImage(d.imageId); gmBoard.drawAll();
            }
        });
        socket.off('board:image-rename').on('board:image-rename', function(d) { if (gmBoard) gmBoard.renameImage(d.imageId, d.name); });

        // 骰子结果容器
        var diceDiv = document.createElement('div');
        diceDiv.id = 'gmDiceResults';
        diceDiv.style.cssText = 'position:absolute;top:8px;left:8px;z-index:100;pointer-events:none;display:flex;flex-direction:column;gap:3px;';
        canvasEl.appendChild(diceDiv);

        socket.off('board:image-rename').on('board:image-rename', function(d) { if (gmBoard) gmBoard.renameImage(d.imageId, d.name); });
    } catch(e) { console.error('Board init failed', e); }
}

function showGmDiceHistory() {
    var existing = document.querySelector('.dice-hist-modal');
    if (existing) { existing.remove(); return; }
    var history = JSON.parse(localStorage.getItem('ta_gm_dice_history') || '[]');
    var overlay = document.createElement('div');
    overlay.className = 'dice-hist-modal';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:30000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:#1a252f;border-radius:8px;max-width:400px;width:90%;max-height:80vh;display:flex;flex-direction:column;box-shadow:0 8px 32px rgba(0,0,0,0.4);">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.1);"><h3 style="margin:0;font-size:14px;color:white;"><i class="fas fa-history"></i> 骰子历史</h3><button onclick="this.closest(\'.dice-hist-modal\').remove()" style="background:none;border:none;color:#999;font-size:16px;cursor:pointer;">&times;</button></div>' +
        '<div style="flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:4px;">' +
        (history.length ? history.map(function(h) { return '<div style="background:rgba(255,255,255,0.05);color:white;padding:4px 8px;border-radius:4px;font-size:11px;font-family:monospace;"><span style="color:#888;font-size:10px;">' + h.time + '</span> ' + h.html + '</div>'; }).join('') : '<div style="color:#888;text-align:center;padding:20px;">暂无记录</div>') +
        '</div>' +
        '<div style="padding:8px;border-top:1px solid rgba(255,255,255,0.1);text-align:center;"><button onclick="clearGmDiceHistory()" style="background:#c0392b;color:white;border:none;border-radius:4px;padding:4px 12px;font-size:10px;cursor:pointer;">清除历史</button></div>' +
        '</div>';
    document.body.appendChild(overlay);
    overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
}

function clearGmDiceHistory() {
    localStorage.setItem('ta_gm_dice_history', '[]');
    var modal = document.querySelector('.dice-hist-modal');
    if (modal) modal.remove();
}

function openMailModal() {
    if (!charactersData.length) { showToast('暂无任务参与者'); return; }
    var list = document.getElementById('mailRecipientList');
    list.innerHTML = charactersData.map(function(c, i) {
        var d = c.data || {};
        var name = d.pName || '未命名';
        return '<div style="display:flex;align-items:center;gap:6px;padding:3px 0;font-size:12px;color:#333;">' +
            '<input type="checkbox" class="mail-recipient" data-id="' + c.characterId + '" ' + (d._canEdit !== false ? 'checked' : '') + '>' +
            '<span>' + name + (c.ownerName ? ' (' + c.ownerName + ')' : '') + '</span></div>';
    }).join('');
    document.getElementById('mailSelectAll').checked = true;
    document.getElementById('mailModal').style.display = 'flex';
}

function closeMailModal() {
    document.getElementById('mailModal').style.display = 'none';
}

function toggleSelectAllRecipients() {
    var checked = document.getElementById('mailSelectAll').checked;
    document.querySelectorAll('.mail-recipient').forEach(function(cb) { cb.checked = checked; });
}

async function sendMail() {
    var checkedIds = [];
    document.querySelectorAll('.mail-recipient:checked').forEach(function(cb) { checkedIds.push(cb.dataset.id); });
    if (!checkedIds.length) { showToast('请选择收件人'); return; }
    var subject = document.getElementById('mailSubject').value.trim();
    var content = document.getElementById('mailContent').value.trim();
    if (!subject || !content) { showToast('标题和内容不能为空'); return; }
    try {
        var res = await fetch('/api/manager/send-mail', {
            method: 'POST', headers: getAuthHeaders(),
            body: JSON.stringify({ characterIds: checkedIds, subject: subject, content: content })
        });
        var data = await res.json();
        if (data.success) {
            showToast('已发送给 ' + data.sentCount + ' 个角色', 'success');
            // 通知 socket 各收件人
            if (socket && data.recipientIds) {
                data.recipientIds.forEach(function(uid) {
                    socket.emit('mail:notify', { userId: uid });
                });
            }
            closeMailModal();
            document.getElementById('mailSubject').value = '';
            document.getElementById('mailContent').value = '';
        } else showToast(data.message || '发送失败');
    } catch(e) { showToast('发送失败'); }
}

async function saveImagePos(imageId, x, y) {
    await fetch('/api/board/' + missionId + '/image/' + imageId, {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ x, y, role: 'manager' })
    });
    socket.emit('board:image-move', { imageId, x, y });
}

async function saveImageSize(imageId, w, h) {
    await fetch('/api/board/' + missionId + '/image/' + imageId, {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ w, h, role: 'manager' })
    });
    socket.emit('board:image-resize', { imageId, w, h });
}

async function saveImageName(imageId, name) {
    await fetch('/api/board/' + missionId + '/image/' + imageId, {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ name })
    });
    socket.emit('board:image-rename', { imageId, name });
}

async function deleteBoardImage(imageId) {
    if (!confirm('删除此图片？')) return;
    await fetch('/api/board/' + missionId + '/image/' + imageId, { method: 'DELETE', headers: getAuthHeaders() });
    socket.emit('board:image-remove', { imageId });
    if (boardData && boardData.connections) {
        boardData.connections = boardData.connections.filter(function(c) { return c.node_a !== imageId && c.node_b !== imageId; });
    }
    if (gmBoard) { gmBoard.removeImage(imageId); gmBoard.drawAll(); }
}

async function toggleConnections() {
    const res = await fetch('/api/board/' + missionId + '/connections-toggle', { method: 'PUT', headers: getAuthHeaders() });
    const d = await res.json();
    document.getElementById('btnToggleConn').innerHTML = d.showConnections
        ? '<i class="fas fa-link"></i> 隐藏' : '<i class="fas fa-unlink"></i> 显示';
    if (gmBoard && boardData) {
        boardData.board.show_connections = d.showConnections ? 1 : 0;
        gmBoard.setConnections(d.showConnections ? boardData.connections : []);
    }
}

function toggleConnectMode() {
    connectMode = !connectMode;
    connectSourceId = null;
    gmBoard.clearHighlight();
    const btn = document.getElementById('btnConnectMode');
    if (connectMode) {
        btn.innerHTML = '<i class="fas fa-check-circle"></i> 连线中';
        btn.style.background = '#e74c3c';
        btn.style.color = 'white';
        btn.style.borderColor = '#c0392b';
    } else {
        btn.innerHTML = '<i class="fas fa-project-diagram"></i> 连线';
        btn.style.background = '';
        btn.style.color = '';
        btn.style.borderColor = '';
    }
    showToast(connectMode ? '连线模式：依次点击两个图片' : '连线模式已关闭');
}

async function createConnection(nodeA, nodeB) {
    try {
        const res = await fetch('/api/board/' + missionId + '/connection', {
            method: 'POST', headers: getAuthHeaders(),
            body: JSON.stringify({ nodeA, nodeB })
        });
        const d = await res.json();
        if (d.success) {
            if (!boardData.connections) boardData.connections = [];
            boardData.connections.push({ id: d.id, node_a: d.nodeA, node_b: d.nodeB, label: d.label || '' });
            gmBoard.setConnections(boardData.connections);
            socket.emit('board:connection-add', d);
            showToast('连线已创建', 'success');
        } else showToast(d.message || '连线失败');
    } catch(e) { showToast('连线失败'); }
}

let ctxMenuEl = null;
function showBoardContextMenu(imageId, x, y) {
    if (ctxMenuEl) ctxMenuEl.remove();
    ctxMenuEl = document.createElement('div');
    ctxMenuEl.style.cssText = 'position:fixed;left:' + x + 'px;top:' + y + 'px;z-index:99999;background:white;border:1px solid #e0e0e0;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,0.12);padding:4px 0;min-width:130px;';
    ctxMenuEl.innerHTML =
        '<div style="position:absolute;top:-7px;left:12px;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:8px solid #c0392b;"></div>' +
        '<div class="ctx-item" onclick="hideBoardContextMenu();promptRename(\'' + imageId + '\')"><i class="fas fa-pen" style="color:#666;"></i> 重命名</div>' +
        '<div class="ctx-item" onclick="hideBoardContextMenu();startConnectFrom(\'' + imageId + '\')"><i class="fas fa-link" style="color:#c0392b;"></i> 添加连线</div>' +
        '<div class="ctx-item" onclick="hideBoardContextMenu();deleteBoardImage(\'' + imageId + '\')"><i class="fas fa-trash" style="color:#c0392b;"></i> 删除</div>';
    ctxMenuEl.addEventListener('touchstart', function(e) { e.stopPropagation(); });
    ctxMenuEl.addEventListener('pointerdown', function(e) { e.stopPropagation(); });
    document.body.appendChild(ctxMenuEl);
    function close(e) { if (!ctxMenuEl || ctxMenuEl.contains(e.target)) return; hideBoardContextMenu(); document.removeEventListener('mousedown', close); }
    setTimeout(() => { document.addEventListener('mousedown', close); }, 0);
}

function hideBoardContextMenu() {
    if (ctxMenuEl) { ctxMenuEl.remove(); ctxMenuEl = null; }
}

let mapLineCtxEl = null;
function showMapLineCtxMenu(connId, x, y) {
    if (mapLineCtxEl) mapLineCtxEl.remove();
    mapLineCtxEl = document.createElement('div');
    mapLineCtxEl.style.cssText = 'position:fixed;left:' + x + 'px;top:' + y + 'px;z-index:99999;background:white;border:1px solid #e0e0e0;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,0.12);padding:4px 0;min-width:110px;';
    mapLineCtxEl.innerHTML =
        '<div style="position:absolute;top:-7px;left:12px;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:8px solid #c0392b;"></div>' +
        '<div class="ctx-item" onclick="deleteMapConnection(\'' + connId + '\')"><i class="fas fa-trash" style="color:#c0392b;"></i> 删除连线</div>';
    mapLineCtxEl.addEventListener('touchstart', function(e) { e.stopPropagation(); });
    mapLineCtxEl.addEventListener('pointerdown', function(e) { e.stopPropagation(); });
    document.body.appendChild(mapLineCtxEl);
    function close(e) { if (!mapLineCtxEl || mapLineCtxEl.contains(e.target)) return; mapLineCtxEl.remove(); mapLineCtxEl = null; document.removeEventListener('mousedown', close); }
    setTimeout(() => document.addEventListener('mousedown', close), 0);
}

async function deleteMapConnection(connId) {
    try {
        await fetch('/api/board/' + missionId + '/connection/' + connId, { method: 'DELETE', headers: getAuthHeaders() });
        boardData.connections = (boardData.connections || []).filter(c => c.id !== connId);
        gmBoard.setConnections(boardData.connections);
        socket.emit('board:connection-remove', { connId });
        showToast('连线已删除', 'success');
    } catch(e) { showToast('删除失败'); }
}

function startConnectFrom(imageId) {
    toggleConnectMode();
    connectSourceId = imageId;
    gmBoard.clearHighlight();
    gmBoard.highlightImage(imageId);
    showToast('已选起点，点击目标图片完成连线');
}

function promptRename(imageId) {
    const el = gmBoard.images[imageId];
    if (!el) return;
    const oldName = el.querySelector('.board-img-label').textContent;
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:20000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:white;border-radius:8px;padding:20px;min-width:280px;box-shadow:0 8px 32px rgba(0,0,0,0.2);">' +
        '<h3 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#333;"><i class="fas fa-pen"></i> 重命名</h3>' +
        '<input type="text" value="' + (oldName || '') + '" placeholder="图片名称" style="width:100%;padding:8px;border:1px solid #d0d5dd;border-radius:4px;font-size:13px;color:#333;box-sizing:border-box;">' +
        '<div style="display:flex;gap:8px;margin-top:12px;">' +
        '<button class="rn-cancel" style="flex:1;padding:6px;background:#eee;border:none;border-radius:4px;cursor:pointer;font-size:12px;color:#666;">取消</button>' +
        '<button class="rn-ok" style="flex:1;padding:6px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:700;">确定</button>' +
        '</div></div>';
    document.body.appendChild(overlay);
    const input = overlay.querySelector('input');
    overlay.querySelector('.rn-cancel').onclick = function() { overlay.remove(); };
    overlay.querySelector('.rn-ok').onclick = function() {
        const name = input.value.trim();
        overlay.remove();
        if (name !== oldName) { saveImageName(imageId, name); gmBoard.renameImage(imageId, name); }
    };
    overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
    setTimeout(() => input.focus(), 100);
}

// ===== 总览 Tab =====
function renderAgents() {
    const container = document.getElementById('mpAgents');
    if (!charactersData.length) { container.innerHTML = '<div class="mp-empty">暂无任务特工</div>'; return; }
    container.innerHTML = charactersData.map((c, idx) => renderAgentRow(c, idx)).join('');
}

function renderAgentRow(c, idx) {
    const d = c.data;
    const name = d.pName || '未命名', anom = d.pAnom || '', real = d.pReal || '', func = d.pFunc || '';
    const trig1 = d.pTrig1 ? stripHtmlText(d.pTrig1).trim() : '';
    const trig2 = d.pTrig2 ? stripHtmlText(d.pTrig2).trim() : '';
    const trig3 = d.pTrig3 ? stripHtmlText(d.pTrig3).trim() : '';
    const perm1 = d.perm1 || '', perm2 = d.perm2 || '', perm3 = d.perm3 || '';
    const anoms = d.anoms || [], reals = d.reals || [], items = d.items || [], mvp = d.mvpCount || 0, watch = d.watchCount || 0;

    let html = '<div class="mp-agent-row">';
    html += '<div class="mp-agent-name-col"><span class="mp-agent-idx">' + (idx + 1) + '</span><span class="mp-agent-name">' + esc(name) + '</span></div>';

    html += '<div class="mp-agent-qual-col">';
    const attrs = d.attrs || {}; let hasAttr = false;
    Object.keys(attrs).forEach(k => {
        const v = parseInt(attrs[k].v || '0'); if (v <= 0) return; hasAttr = true;
        const marks = attrs[k].m || [], markHtml = marks.length ? '<span class="mp-qual-marks">' + marks.map(() => '<i class="fas fa-exclamation"></i>').join('') + '</span>' : '';
        html += '<div class="mp-qual-item"><span class="mp-qual-num">' + esc(k) + '</span> <span class="mp-qual-text">' + v + '</span>' + markHtml + '</div>';
    });
    if (!hasAttr) html += '<div class="mp-qual-empty">-</div>';
    html += '</div>';

    html += '<div class="mp-agent-info-col">';
    if (anom) html += '<div class="mp-info-row"><span class="mp-info-label c-anom"><i class="fas fa-bolt"></i> 异常</span><span class="mp-info-value">' + esc(anom) + '</span></div>';
    if (real) html += '<div class="mp-info-row"><span class="mp-info-label c-real"><i class="fas fa-fingerprint"></i> 现实</span><span class="mp-info-value">' + esc(real) + '</span></div>';
    if (func) html += '<div class="mp-info-row"><span class="mp-info-label c-func"><i class="fas fa-briefcase"></i> 职能</span><span class="mp-info-value">' + esc(func) + '</span></div>';
    if (trig1) html += '<div class="mp-info-row"><span class="mp-info-label c-real"><i class="fas fa-shield-alt"></i> 过载</span><span class="mp-info-value">' + esc(trig1) + '</span></div>';
    if (trig2) html += '<div class="mp-info-row"><span class="mp-info-label c-real"><i class="fas fa-exclamation-circle"></i> 触发</span><span class="mp-info-value">' + esc(trig2) + '</span></div>';
    if (trig3) html += '<div class="mp-info-row"><span class="mp-info-label c-func"><i class="fas fa-flag"></i> 指令</span><span class="mp-info-value">' + esc(trig3) + '</span></div>';
    if (perm1) html += renderPermRow('perm1_' + c.characterId, '许可1', perm1);
    if (perm2) html += renderPermRow('perm2_' + c.characterId, '许可2', perm2);
    if (perm3) html += renderPermRow('perm3_' + c.characterId, '许可3', perm3);
    html += '<div class="mp-info-counters">';
    if (mvp) html += '<span class="mp-badge mp-badge-mvp"><i class="fas fa-medal"></i> ' + mvp + '</span>';
    if (watch) html += '<span class="mp-badge mp-badge-watch"><i class="fas fa-exclamation-triangle"></i> ' + watch + '</span>';
    html += '</div></div>';

    html += '<div class="mp-agent-anoms-col">';
    if (anoms.length) { html += '<div class="mp-card-list">'; anoms.forEach(a => {
        const s = a.succ ? stripHtmlText(a.succ).trim() : '', f = a.fail ? stripHtmlText(a.fail).trim() : '';
        html += '<div class="mp-card mp-card-anom"' + (s || f || a.tdesc ? ' onclick="this.classList.toggle(\'expanded\')"' : '') + '>';
        html += '<div class="mp-card-head"><span class="mp-card-name">' + esc(a.name) + '</span>' + (a.trig ? '<span class="mp-card-trig">' + esc(a.trig) + '</span>' : '') + '</div>';
        if (s || f || a.tdesc) { html += '<div class="mp-card-body">'; if (s) html += '<div class="mp-card-succ"><i class="fas fa-check-circle"></i> ' + esc(s) + '</div>'; if (f) html += '<div class="mp-card-fail"><i class="fas fa-times-circle"></i> ' + esc(f) + '</div>'; if (a.tdesc) html += '<div class="mp-card-question"><i class="fas fa-question-circle"></i> ' + esc(a.tdesc) + '</div>'; html += '</div>'; }
        html += '</div>'; }); html += '</div>';
    } else html += '<div class="mp-col-empty">-</div>';
    html += '</div>';

    html += '<div class="mp-agent-reals-col">';
    if (reals.length) { html += '<div class="mp-card-list">'; reals.forEach(r => {
        const lvl = r.lvl || 0, conn = r.conn ? stripHtmlText(r.conn).trim() : '';
        html += '<div class="mp-card mp-card-real">';
        html += '<div class="mp-card-head"><span class="mp-card-name">' + esc(r.name) + '</span>' + (r.actor ? '<span class="mp-card-trig">' + esc(r.actor) + '</span>' : '') + (r.act ? '<span class="mp-real-act">激活</span>' : '') + '</div>';
        html += '<div class="mp-real-dots">' + Array.from({length:9}, (_, i) => '<span class="mp-real-dot' + (i < lvl ? ' active' : '') + '"></span>').join('') + '</div>';
        if (conn) html += '<div class="mp-real-conn"><i class="fas fa-link"></i> ' + esc(conn) + '</div>';
        html += '</div>'; }); html += '</div>';
    } else html += '<div class="mp-col-empty">-</div>';
    html += '</div>';

    html += '<div class="mp-agent-items-col">';
    if (items.length) { html += '<div class="mp-card-list">'; items.forEach(it => {
        const eff = it.eff ? stripHtmlText(it.eff).trim() : '';
        html += '<div class="mp-card mp-card-item"' + (eff ? ' onclick="this.classList.toggle(\'expanded\')"' : '') + '>';
        html += '<div class="mp-card-head"><span class="mp-card-name">' + esc(it.name || it.item) + '</span>' + (it.once ? '<span class="mp-item-once">一次性</span>' : '') + '</div>';
        if (eff) html += '<div class="mp-card-body"><div class="mp-card-desc"><i class="fas fa-info-circle"></i> ' + esc(eff) + '</div></div>';
        html += '</div>'; }); html += '</div>';
    } else html += '<div class="mp-col-empty">-</div>';
    html += '</div></div>';
    return html;
}

function renderPermRow(id, label, text) {
    if (!window._pc) window._pc = {}; if (!window._pc[id]) window._pc[id] = 0;
    return '<div class="mp-info-row mp-perm-row"><span class="mp-info-label"><i class="fas fa-key"></i> ' + label + '</span><span class="mp-info-value">' + esc(text) + '</span><span class="mp-perm-counter" id="ctr_' + id + '">0</span><button class="mp-perm-btn" onclick="adjustPerm(\'' + id + '\',-1)">−</button><button class="mp-perm-btn" onclick="adjustPerm(\'' + id + '\',1)">+</button></div>';
}

function adjustPerm(id, delta) { if (!window._pc) window._pc = {}; if (!window._pc[id]) window._pc[id] = 0; window._pc[id] = Math.max(0, window._pc[id] + delta); const el = document.getElementById('ctr_' + id); if (el) el.textContent = window._pc[id]; }
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function stripHtmlText(html) { if (!html) return ''; const d = document.createElement('div'); d.innerHTML = html; return d.textContent || ''; }

// ===== 天气功能 =====
// 解析任务已保存的天气卡 id 数组
function getSavedWeatherIds() {
    if (!missionData || !missionData.weather) return [];
    try { const arr = JSON.parse(missionData.weather); return Array.isArray(arr) ? arr : []; } catch (e) { return []; }
}

async function loadTianqiOptions() {
    if (tianqiList.length) return;
    try {
        const res = await fetch('/api/options');
        const data = await res.json();
        tianqiList = Array.isArray(data.tianqi) ? data.tianqi : [];
    } catch (e) { tianqiList = []; }
}

// 递进展开：选了某 group 的 b，则补 a；选了 c，则补 a、b（同组低位自动生效）
function expandWeatherIds(ids) {
    const result = [];
    ids.forEach(id => {
        const card = tianqiList.find(c => c.id === id);
        if (!card) return;
        // 同 group 内，把所有比当前卡更低位（a<b<c）的也加进来
        const siblings = tianqiList.filter(c => c.group === card.group).sort((a, b) => a.id.localeCompare(b.id));
        const myIdx = siblings.findIndex(c => c.id === id);
        siblings.slice(0, myIdx + 1).forEach(c => { if (!result.includes(c.id)) result.push(c.id); });
    });
    // 按 group 排序，同 group 按 a/b/c 排序
    result.sort((a, b) => {
        const ca = tianqiList.find(c => c.id === a);
        const cb = tianqiList.find(c => c.id === b);
        if (ca.group !== cb.group) return ca.group - cb.group;
        return a.localeCompare(b);
    });
    return result;
}

function renderWeatherCount() {
    const ids = getSavedWeatherIds();
    const expanded = expandWeatherIds(ids);
    const namesEl = document.getElementById('mpWeatherNames');
    const tipEl = document.getElementById('mpWeatherTooltip');
    if (!namesEl) return;
    // bar 上显示天气名字（递进展开后，完整不省略）
    if (!expanded.length) {
        namesEl.textContent = '无';
    } else {
        const cards = expanded.map(id => tianqiList.find(c => c.id === id)).filter(Boolean);
        namesEl.textContent = cards.map(c => c.title).join('、');
    }
    // tooltip 显示每张卡的 id + 标题 + 详情（展开后全部）
    if (tipEl) {
        if (!expanded.length) {
            tipEl.innerHTML = '<div class="mp-weather-tip-empty">当前无生效天气</div>';
        } else {
            const cards = expanded.map(id => tianqiList.find(c => c.id === id)).filter(Boolean);
            tipEl.innerHTML = cards.map(c =>
                '<div class="mp-weather-tip-card">' +
                '<div class="mp-weather-tip-head"><span class="mp-weather-tip-id">' + esc(c.id) + '</span><span class="mp-weather-tip-title">' + esc(c.title) + '</span></div>' +
                '<div class="mp-weather-tip-text">' + esc(c.text) + '</div>' +
                '</div>'
            ).join('');
        }
    }
}

function openWeatherModal() {
    weatherSelected = getSavedWeatherIds().slice();
    renderWeatherCards();
    document.getElementById('weatherSearch').value = '';
    document.getElementById('weatherModal').style.display = 'flex';
}

function closeWeatherModal() {
    document.getElementById('weatherModal').style.display = 'none';
}

// 按 group 分组渲染全卡表，预勾选 weatherSelected
function renderWeatherCards() {
    const container = document.getElementById('weatherCardList');
    if (!tianqiList.length) { container.innerHTML = '<div style="text-align:center;color:#999;padding:20px;">天气卡数据加载中或为空</div>'; return; }
    // 按 group 聚合
    const groups = {};
    tianqiList.forEach(c => { (groups[c.group] = groups[c.group] || []).push(c); });
    const groupKeys = Object.keys(groups).map(Number).sort((a, b) => a - b);

    container.innerHTML = groupKeys.map(g => {
        const cards = groups[g];
        const cardHtml = cards.map(c => {
            const checked = weatherSelected.includes(c.id);
            return `<div class="weather-card${checked ? ' selected' : ''}" data-id="${c.id}" onclick="toggleWeatherCard('${c.id}', event)">
                <div class="weather-card-head">
                    <input type="checkbox" ${checked ? 'checked' : ''} onclick="event.stopPropagation()">
                    <span class="weather-card-id">${esc(c.id)}</span>
                    <span class="weather-card-title">${esc(c.title)}</span>
                </div>
                <div class="weather-card-text">${esc(c.text)}</div>
            </div>`;
        }).join('');
        return `<div class="weather-group"><div class="weather-group-label">第 ${g} 组</div><div class="weather-group-cards">${cardHtml}</div></div>`;
    }).join('');

    updateWeatherSelectedCount();
}

function updateWeatherSelectedCount() {
    const el = document.getElementById('weatherSelectedCount');
    if (el) el.textContent = weatherSelected.length ? '已选 ' + weatherSelected.length + ' 张' : '';
}

function toggleWeatherCard(id, ev) {
    // 点击整张卡切换勾选（复选框自身点击不重复处理）
    if (ev && ev.target && ev.target.tagName === 'INPUT') { ev.stopPropagation(); }
    const idx = weatherSelected.indexOf(id);
    if (idx >= 0) weatherSelected.splice(idx, 1);
    else weatherSelected.push(id);
    // 更新该卡片视觉态
    const cardEl = document.querySelector('.weather-card[data-id="' + id + '"]');
    if (cardEl) {
        cardEl.classList.toggle('selected', weatherSelected.includes(id));
        const cb = cardEl.querySelector('input[type="checkbox"]');
        if (cb) cb.checked = weatherSelected.includes(id);
    }
    updateWeatherSelectedCount();
}

function filterWeatherCards(keyword) {
    const kw = (keyword || '').toLowerCase().trim();
    document.querySelectorAll('.weather-card').forEach(card => {
        if (!kw) { card.style.display = ''; return; }
        const text = (card.textContent || '').toLowerCase();
        card.style.display = text.includes(kw) ? '' : 'none';
    });
}

async function saveWeather() {
    if (!missionData) return;
    const weatherJson = JSON.stringify(weatherSelected);
    try {
        await fetch('/api/manager/mission/' + missionId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ weather: weatherJson }) });
        missionData.weather = weatherJson;
        renderWeatherCount();
        broadcastWeather();
        showToast('天气已保存并广播', 'success');
        closeWeatherModal();
    } catch (e) { showToast('保存失败'); }
}

async function clearWeather() {
    weatherSelected = [];
    renderWeatherCards();
    await saveWeather();
}

// 广播完整天气卡对象数组给玩家端
function broadcastWeather() {
    if (!socket || !socket.connected) return;
    const cards = weatherSelected.length
        ? weatherSelected.map(id => tianqiList.find(c => c.id === id)).filter(Boolean)
        : getSavedWeatherIds().map(id => tianqiList.find(c => c.id === id)).filter(Boolean);
    socket.emit('weather:update', { missionId, weather: cards });
}

async function adjustCounter(type, delta) {
    if (!missionData) return;
    const isC = type === 'chaos';
    const current = missionData[isC ? 'chaos_value' : 'scatter_value'] || 0;
    const newVal = Math.max(0, current + delta);
    missionData[isC ? 'chaos_value' : 'scatter_value'] = newVal;
    document.getElementById(isC ? 'mpChaosValue' : 'mpScatterValue').textContent = newVal;
    try { await fetch('/api/manager/mission/' + missionId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ [isC ? 'chaosValue' : 'scatterValue']: newVal }) }); } catch(e) { showToast('保存失败'); }
}

function goBack() { window.close(); if (!window.closed) window.location.href = 'manager.html'; }
function goManagerEdit() { window.open('manager.html', '_blank'); }
init();
