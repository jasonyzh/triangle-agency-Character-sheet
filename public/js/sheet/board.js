import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast } from './ui.js';

// 确保玩家 socket 单例存在，并绑定 board 相关监听（幂等，可安全多次调用）
function ensurePlayerSocket() {
    if (!S.playerSocket) {
        S.playerSocket = io({ auth: { token: S.token } });
    }
    if (S.playerSocket.__boardBound) return S.playerSocket;
    S.playerSocket.__boardBound = true;

    S.playerSocket.on('connect', () => {
        // 重连后自动重新加入当前任务房间
        if (S.currentPlayerBoardMissionId) S.playerSocket.emit('join-board', { missionId: S.currentPlayerBoardMissionId, role: 'ply' });
    });
    S.playerSocket.on('board:image-add', function (d) {
        if (S.playerBoard) S.playerBoard.addImage({ id: d.id, imageFile: d.imageFile || d.image_lib_filename, x: d.p_x, y: d.p_y, w: d.p_w, h: d.p_h, name: d.name || '', isMapNode: d.is_map_node });
    });
    S.playerSocket.on('board:image-remove', function (d) {
        if (S.playerBoard) { S.playerBoard.removeImage(d.imageId); S.playerBoard.drawAll(); }
    });
    S.playerSocket.on('weather:update', function (d) {
        renderWeatherBar(d && d.weather ? d.weather : []);
    });
    return S.playerSocket;
}

export async function initPlayerBoard() {
    try {
        // 确保 socket 存在并绑定 board 相关监听（不重复创建，复用 init.js 创建的单例）
        ensurePlayerSocket();

        const res = await fetch(`/api/character/${S.charId}/mission-boards`, { headers: { 'Authorization': 'Bearer ' + S.token } });
        S.playerBoardMissions = await res.json();
        const sel = document.getElementById('boardMissionSelect');
        if (sel) {
            sel.innerHTML = '<option value="">-- 选择任务 --</option>';
            S.playerBoardMissions.forEach(m => {
                sel.innerHTML += '<option value="' + m.mission_id + '">' + m.mission_name + '</option>';
            });
            var savedMission = localStorage.getItem('ta_board_mission_' + S.charId);
            if (savedMission && S.playerBoardMissions.some(function (m) { return m.mission_id === savedMission; })) {
                sel.value = savedMission;
                switchBoardMission();
            }
        }
    } catch (e) { console.error('加载任务画板失败', e); }
}

export async function switchBoardMission() {
    const sel = document.getElementById('boardMissionSelect');
    const missionId = sel ? sel.value : null;
    const canvasEl = document.getElementById('playerBoardCanvas');
    if (!missionId || !canvasEl) return;
    localStorage.setItem('ta_board_mission_' + S.charId, missionId);

    if (S.playerSocket && S.currentPlayerBoardMissionId) S.playerSocket.emit('leave-board');
    if (S.playerBoard) {
        Object.values(S.playerBoard.images).forEach(el => el.remove());
        if (S.playerBoard.mapSvg) S.playerBoard.mapSvg.innerHTML = '';
        if (S.playerBoard.npcSvg) S.playerBoard.npcSvg.innerHTML = '';
    }

    try {
        const [boardRes, npcRes] = await Promise.all([
            fetch('/api/board/' + missionId, { headers: { 'Authorization': 'Bearer ' + S.token } }),
            fetch('/api/board/' + missionId + '/npc-connections', { headers: { 'Authorization': 'Bearer ' + S.token } })
        ]);
        const data = await boardRes.json();
        const npcConns = await npcRes.json();
        if (!data.success) return;
        S.currentPlayerBoardMissionId = missionId;

        canvasEl.innerHTML = '';
        ensureWeatherButton(canvasEl);

        S.playerBoard = new BoardCore(canvasEl, {
            editable: true, role: 'player', imageBaseUrl: '/',
            onImageMove: function (id, x, y) {
                fetch('/api/board/' + missionId + '/image/' + id, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + S.token },
                    body: JSON.stringify({ x, y, role: 'player' })
                });
                S.playerSocket.emit('board:image-move', { imageId: id, x, y });
            },
            onImageResize: function (id, w, h) {
                fetch('/api/board/' + missionId + '/image/' + id, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + S.token },
                    body: JSON.stringify({ w, h, role: 'player' })
                });
                S.playerSocket.emit('board:image-resize', { imageId: id, w, h });
            },
            onImageClick: function (imageId) {
                if (S.npcConnectSourceId && S.npcConnectSourceId !== imageId) finishNpcConnect(imageId);
            },
            onImageRightClick: function (imageId, x, y) {
                const el = S.playerBoard.images[imageId];
                if (!el) return;
                const isMap = el.dataset.isMapNode === '1';
                if (!isMap) showPlayerNpcContextMenu(imageId, x, y, missionId);
            },
            onNpcLineDblClick: function (connId) { promptNpcLabel(connId, missionId); },
            onNpcLineRightClick: function (connId, x, y) { showNpcLineMenu(connId, x, y, missionId); },
            onImageDblClick: function (imageId) { showImagePopup(imageId); }
        });

        S.playerBoard.loadImages(data.images);
        if (data.board.show_connections) S.playerBoard.setConnections(data.connections);
        S.playerBoard.setNpcConnections(npcConns);

        // 渲染任务初始天气（data.weather 是已选 id 的 JSON 字符串）
        renderWeatherBarByIds(data.weather);

        S.playerSocket.off('board:image-move').on('board:image-move', function (d) { if (S.playerBoard) { S.playerBoard.moveImage(d.imageId, d.x, d.y); S.playerBoard.drawAll(); } });
        S.playerSocket.off('board:image-resize').on('board:image-resize', function (d) { if (S.playerBoard) { S.playerBoard.resizeImage(d.imageId, d.w, d.h); S.playerBoard.drawAll(); } });
        S.playerSocket.off('board:connection-add').on('board:connection-add', function (d) {
            if (S.playerBoard) {
                if (!S.playerBoard.connections) S.playerBoard.connections = [];
                S.playerBoard.connections.push({ id: d.id, node_a: d.nodeA, node_b: d.nodeB, label: d.label || '' });
                S.playerBoard.setConnections(S.playerBoard.connections);
            }
        });
        S.playerSocket.off('board:connection-remove').on('board:connection-remove', function (d) {
            if (S.playerBoard) {
                S.playerBoard.connections = (S.playerBoard.connections || []).filter(function (c) { return c.id !== d.connId; });
                S.playerBoard.setConnections(S.playerBoard.connections);
            }
        });
        S.playerSocket.off('dice:roll').on('dice:roll', function (d) {
            var detail = '(' + (d.results || []).map(function (r, i) {
                var isCheck3 = d.type === 'check' && r === 3;
                return '<span' + (isCheck3 ? ' style="color:#ff6b6b;font-weight:900;"' : '') + '>' + r + (i < d.results.length - 1 ? ' ' : '') + '</span>';
            }).join('') + ')';
            window.showDiceResult('[' + d.charName + '] ' + d.label, d.total, detail);
        });

        if (S.playerSocket) {
            if (S.playerSocket.connected) S.playerSocket.emit('join-board', { missionId, role: 'ply' });
            else S.playerSocket.once('connect', () => S.playerSocket.emit('join-board', { missionId, role: 'ply' }));
        }

        if (window.innerWidth < 1600) canvasEl.style.height = Math.max(window.innerHeight * 0.55, 400) + 'px';
        else canvasEl.style.height = '';

        // 横竖屏切换时重新计算画板高度
        if (!window._boardResizeBound) {
            window._boardResizeBound = true;
            window.addEventListener('resize', function () {
                var cv = document.getElementById('playerBoardCanvas');
                if (cv) cv.style.height = window.innerWidth < 1600 ? Math.max(window.innerHeight * 0.55, 400) + 'px' : '';
            });
            window.addEventListener('orientationchange', function () {
                setTimeout(function () {
                    var cv = document.getElementById('playerBoardCanvas');
                    if (cv) cv.style.height = window.innerWidth < 1600 ? Math.max(window.innerHeight * 0.55, 400) + 'px' : '';
                }, 200);
            });
        }

        var diceDiv = document.createElement('div');
        diceDiv.id = 'diceResults';
        diceDiv.style.cssText = 'position:absolute;top:8px;left:8px;z-index:100;pointer-events:none;display:flex;flex-direction:column;gap:3px;';
        canvasEl.appendChild(diceDiv);
    } catch (e) { console.error('初始化画板失败', e); }
}

export function makeCtxMenu(x, y, innerHTML) {
    const div = document.createElement('div');
    div.style.cssText = 'position:fixed;left:' + x + 'px;top:' + y + 'px;z-index:99999;background:white;border:1px solid #e0e0e0;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,0.12);padding:4px 0;min-width:130px;';
    div.innerHTML = '<div class="ctx-arrow" style="position:absolute;top:-7px;left:12px;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:8px solid #c0392b;"></div>' + innerHTML;
    div.addEventListener('touchstart', function (e) { e.stopPropagation(); });
    div.addEventListener('pointerdown', function (e) { e.stopPropagation(); });
    return div;
}

export function showPlayerNpcContextMenu(imageId, x, y, missionId) {
    hidePlayerNpcMenu();
    S.playerNpcCtxMenu = makeCtxMenu(x, y,
        '<div class="ctx-item" onclick="hidePlayerNpcMenu();startNpcConnect(\'' + imageId + '\', \'' + missionId + '\')"><i class="fas fa-link" style="color:#c0392b;"></i> 连接 NPC</div>');
    document.body.appendChild(S.playerNpcCtxMenu);
    setTimeout(() => { document.addEventListener('mousedown', closeCtx, { once: false }); }, 0);
    function closeCtx(e) { if (!S.playerNpcCtxMenu || S.playerNpcCtxMenu.contains(e.target)) return; hidePlayerNpcMenu(); document.removeEventListener('mousedown', closeCtx); }
}

export function hidePlayerNpcMenu() { if (S.playerNpcCtxMenu) { S.playerNpcCtxMenu.remove(); S.playerNpcCtxMenu = null; } }

export function showNpcLineMenu(connId, x, y, missionId) {
    hidePlayerNpcMenu();
    S.playerNpcCtxMenu = makeCtxMenu(x, y,
        '<div class="ctx-item" onclick="hidePlayerNpcMenu();promptNpcLabel(\'' + connId + '\',\'' + missionId + '\')"><i class="fas fa-pen" style="color:#666;"></i> 编辑备注</div>' +
        '<div class="ctx-item" onclick="hidePlayerNpcMenu();deleteNpcConnection(\'' + connId + '\',\'' + missionId + '\')"><i class="fas fa-trash" style="color:#c0392b;"></i> 删除连线</div>');
    document.body.appendChild(S.playerNpcCtxMenu);
    setTimeout(() => { document.addEventListener('mousedown', closeCtx, { once: false }); }, 0);
    function closeCtx(e) { if (!S.playerNpcCtxMenu || S.playerNpcCtxMenu.contains(e.target)) return; hidePlayerNpcMenu(); document.removeEventListener('mousedown', closeCtx); }
}

export async function deleteNpcConnection(connId, missionId) {
    try {
        await fetch('/api/board/' + missionId + '/npc-connection/' + connId, { method: 'DELETE', headers: getAuthHeaders() });
        S.playerBoard.npcConnections = (S.playerBoard.npcConnections || []).filter(c => c.id !== connId);
        S.playerBoard.drawAll();
        showToast('连线已删除', 'success');
    } catch (e) { showToast('删除失败'); }
}

export function startNpcConnect(imageId, missionId) {
    S.npcConnectSourceId = imageId;
    S.npcConnectMissionId = missionId;
    S.playerBoard.clearHighlight();
    S.playerBoard.highlightImage(imageId);
    showFloatingCancelBtn();
    showToast('已选起点，点击目标 NPC 完成连线');
}

export function showFloatingCancelBtn() {
    var existing = document.getElementById('floatCancelConnect');
    if (existing) existing.remove();
    var btn = document.createElement('button');
    btn.id = 'floatCancelConnect';
    btn.textContent = '✕ 取消';
    btn.onclick = cancelNpcConnect;
    btn.style.cssText = 'position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:99999;padding:6px 18px;background:#c0392b;color:white;border:none;border-radius:20px;font-size:12px;font-weight:700;cursor:pointer;box-shadow:0 2px 8px rgba(192,57,43,0.4);transition:opacity 0.15s;';
    document.body.appendChild(btn);
}

export function hideFloatingCancelBtn() {
    var btn = document.getElementById('floatCancelConnect');
    if (btn) btn.remove();
}

export function cancelNpcConnect() {
    S.npcConnectSourceId = null;
    S.npcConnectMissionId = null;
    S.playerBoard.clearHighlight();
    hideFloatingCancelBtn();
    showToast('已取消连线');
}

async function finishNpcConnect(targetId) {
    if (!S.npcConnectSourceId || !S.npcConnectMissionId || S.npcConnectSourceId === targetId) return;
    hideFloatingCancelBtn();
    S.playerBoard.clearHighlight();
    showNpcTypeModal(function (connType) {
        if (!connType) { S.npcConnectSourceId = null; return; }
        createNpcConnection(S.npcConnectSourceId, targetId, connType);
    });
}

export { finishNpcConnect };

function showNpcTypeModal(callback) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.45);z-index:20000;display:flex;align-items:center;justify-content:center;padding:16px;box-sizing:border-box;';
    const types = [
        { type: 'friendly', label: '友善', icon: 'fa-handshake', color: '#27ae60', desc: '盟友 · 互助' },
        { type: 'hostile', label: '敌对', icon: 'fa-skull-crossbones', color: '#c0392b', desc: '仇敌 · 对抗' },
        { type: 'neutral', label: '中立', icon: 'fa-balance-scale', color: '#e6a817', desc: '中立 · 观望' },
        { type: 'unknown', label: '未知', icon: 'fa-question-circle', color: '#8e44ad', desc: '不明 · 待查' }
    ];
    overlay.innerHTML =
        '<div style="background:#fff;border-radius:14px;width:100%;max-width:320px;box-shadow:0 16px 48px rgba(0,0,0,0.3);overflow:hidden;">' +
            '<div style="padding:16px 20px 12px;text-align:center;">' +
                '<div style="width:44px;height:44px;margin:0 auto 8px;border-radius:50%;background:linear-gradient(135deg,#c0392b,#e74c3c);display:flex;align-items:center;justify-content:center;"><i class="fas fa-link" style="color:#fff;font-size:18px;"></i></div>' +
                '<div style="font-size:15px;font-weight:700;color:#333;">选择关系类型</div>' +
            '</div>' +
            '<div style="padding:4px 16px 12px;display:flex;flex-direction:column;gap:8px;">' +
                types.map(function (t) {
                    return '<button class="npc-type-btn" data-type="' + t.type + '" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border:2px solid #f0f0f0;border-radius:10px;cursor:pointer;font-size:14px;font-weight:700;background:#fff;transition:border-color 0.2s;width:100%;box-sizing:border-box;text-align:left;">' +
                        '<span style="width:36px;height:36px;border-radius:50%;background:' + t.color + ';display:flex;align-items:center;justify-content:center;flex-shrink:0;"><i class="fas ' + t.icon + '" style="color:#fff;font-size:14px;"></i></span>' +
                        '<span style="flex:1;"><span style="display:block;color:#333;">' + t.label + '</span><span style="display:block;font-size:11px;font-weight:400;color:#999;margin-top:2px;">' + t.desc + '</span></span>' +
                        '<span style="width:8px;height:8px;border-radius:50%;background:' + t.color + ';flex-shrink:0;"></span>' +
                    '</button>';
                }).join('') +
            '</div>' +
            '<div style="padding:0 16px 16px;">' +
                '<button class="npc-type-cancel" style="width:100%;padding:10px;border:none;border-radius:10px;background:#f5f5f5;cursor:pointer;font-size:13px;color:#888;font-weight:600;">取消</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(overlay);

    // 按钮悬停高亮
    var typeBtns = overlay.querySelectorAll('.npc-type-btn');
    typeBtns.forEach(function (b) {
        var color = b.querySelector('span:last-child').style.background;
        b.addEventListener('mouseenter', function () { b.style.borderColor = color; b.style.background = '#fafafa'; });
        b.addEventListener('mouseleave', function () { b.style.borderColor = '#f0f0f0'; b.style.background = '#fff'; });
    });
    overlay.querySelector('.npc-type-cancel').onclick = function () { overlay.remove(); callback(null); };
    // 延迟绑定关闭事件，避免触控弹出的手势残余事件（pointerup/click）立即触发关闭
    setTimeout(function () {
        overlay.onclick = function (e) { if (e.target === overlay) { overlay.remove(); callback(null); } };
        typeBtns.forEach(function (b) { b.onclick = function () { overlay.remove(); callback(b.dataset.type); }; });
    }, 300);
}

export { showNpcTypeModal };

async function createNpcConnection(nodeA, nodeB, connType) {
    try {
        const res = await fetch('/api/board/' + S.npcConnectMissionId + '/npc-connection', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + S.token },
            body: JSON.stringify({ nodeA, nodeB, connType })
        });
        const d = await res.json();
        if (d.success) {
            if (!S.playerBoard.npcConnections) S.playerBoard.npcConnections = [];
            S.playerBoard.npcConnections.push({ id: d.id, node_a: d.nodeA, node_b: d.nodeB, conn_type: connType, label: '' });
            S.playerBoard.drawAll();
            showToast('连线已创建', 'success');
        }
        S.npcConnectSourceId = null;
    } catch (e) { showToast('连线失败'); S.npcConnectSourceId = null; }
}

export { createNpcConnection };

export async function promptNpcLabel(connId, missionId) {
    const conn = (S.playerBoard.npcConnections || []).find(c => c.id === connId);
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:20000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div class="modal-box" style="background:white;border-radius:8px;padding:20px;min-width:280px;box-shadow:0 8px 32px rgba(0,0,0,0.2);">' +
        '<h3 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#333;"><i class="fas fa-tag"></i> 连线备注</h3>' +
        '<input type="text" class="npc-label-input" value="' + (conn ? conn.label : '') + '" placeholder="例如：情人、儿子、搭档" style="width:100%;padding:8px;border:1px solid #d0d5dd;border-radius:4px;font-size:13px;color:#333;box-sizing:border-box;">' +
        '<div style="display:flex;gap:8px;margin-top:12px;">' +
        '<button class="npc-label-cancel" style="flex:1;padding:6px;background:#eee;border:none;border-radius:4px;cursor:pointer;font-size:12px;color:#666;">取消</button>' +
        '<button class="npc-label-ok" style="flex:1;padding:6px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:700;">确定</button>' +
        '</div></div>';
    document.body.appendChild(overlay);

    const input = overlay.querySelector('.npc-label-input');
    overlay.querySelector('.npc-label-cancel').onclick = function () { overlay.remove(); };
    overlay.querySelector('.npc-label-ok').onclick = async function () {
        const label = input.value.trim();
        overlay.remove();
        try {
            await fetch('/api/board/' + missionId + '/npc-connection/' + connId, {
                method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + S.token },
                body: JSON.stringify({ label })
            });
            if (conn) conn.label = label;
            S.playerBoard.drawAll();
        } catch (e) { }
    };
    overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
    setTimeout(() => input.focus(), 100);
}

export async function showImagePopup(imageId) {
    const el = S.playerBoard.images[imageId];
    if (!el) return;
    const imgEl = el.querySelector('img');
    const nameEl = el.querySelector('.board-img-label');
    const isMap = el.dataset.isMapNode === '1';

    const count = document.querySelectorAll('.img-popup').length;
    const popup = document.createElement('div');
    popup.className = 'img-popup';
    popup.style.cssText = 'position:fixed;top:' + (60 + count * 25) + 'px;left:' + (60 + count * 25) + 'px;z-index:' + (20000 + count) + ';background:#1a252f;border:1px solid rgba(255,255,255,0.12);border-radius:8px;box-shadow:0 12px 40px rgba(0,0,0,0.5);width:200px;display:flex;flex-direction:column;';

    popup.innerHTML =
        '<div class="img-popup-header" style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;background:rgba(255,255,255,0.04);border-bottom:1px solid rgba(255,255,255,0.08);cursor:move;user-select:none;flex-shrink:0;">' +
        '<span style="font-size:11px;font-weight:700;color:#ccc;">' + (nameEl ? nameEl.textContent : '图片') + '<span style="font-size:8px;color:' + (isMap ? '#2980b9' : '#9b59b6') + ';margin-left:6px;">' + (isMap ? '地图' : 'NPC') + '</span></span>' +
        '<span class="img-popup-close" style="display:inline-block;width:0;height:0;border-left:9px solid transparent;border-right:9px solid transparent;border-top:14px solid #c0392b;cursor:pointer;"></span>' +
        '</div>' +
        '<div style="flex:1;display:flex;align-items:center;justify-content:center;overflow:auto;padding:8px;"><img src="' + (imgEl ? imgEl.src : '') + '" style="max-width:100%;max-height:100%;border-radius:3px;object-fit:contain;"></div>' +
        '<div class="img-popup-resize" style="position:absolute;right:0;bottom:0;width:0;height:0;border-left:14px solid transparent;border-bottom:14px solid #c0392b;cursor:nwse-resize;transition:border-bottom-color 0.15s;"></div>';

    document.body.appendChild(popup);

    var popupZ = (window._popupZ || 20000) + 1;
    window._popupZ = popupZ;
    popup.style.zIndex = popupZ;
    popup.addEventListener('pointerdown', function () {
        window._popupZ = (window._popupZ || 20000) + 1;
        popup.style.zIndex = window._popupZ;
    });

    popup.querySelector('.img-popup-close').onclick = function (e) { e.stopPropagation(); popup.remove(); };
    popup.querySelector('.img-popup-close').onmouseenter = function () { this.style.borderTopColor = '#e74c3c'; };
    popup.querySelector('.img-popup-close').onmouseleave = function () { this.style.borderTopColor = '#c0392b'; };
    popup.querySelector('.img-popup-resize').onmouseenter = function () { this.style.borderBottomColor = '#e74c3c'; };
    popup.querySelector('.img-popup-resize').onmouseleave = function () { this.style.borderBottomColor = '#c0392b'; };

    const resizeHandle = popup.querySelector('.img-popup-resize');
    resizeHandle.onpointerdown = function (e) {
        e.stopPropagation(); e.preventDefault();
        const sX = e.clientX, sY = e.clientY;
        const sW = popup.offsetWidth, sH = popup.offsetHeight;
        const ratio = sW / Math.max(1, sH);
        const onMove = function (ev) {
            var nw = Math.max(160, sW + ev.clientX - sX);
            popup.style.width = nw + 'px';
            popup.style.height = Math.max(100, nw / ratio) + 'px';
            if (popup.offsetLeft + popup.offsetWidth > window.innerWidth) {
                popup.style.width = Math.max(160, window.innerWidth - popup.offsetLeft - 10) + 'px';
            }
            if (popup.offsetTop + popup.offsetHeight > window.innerHeight) {
                popup.style.height = Math.max(100, window.innerHeight - popup.offsetTop - 10) + 'px';
            }
        };
        const onUp = function () { document.removeEventListener('pointermove', onMove); document.removeEventListener('pointerup', onUp); };
        document.addEventListener('pointermove', onMove);
        document.addEventListener('pointerup', onUp);
    };

    const header = popup.querySelector('.img-popup-header');
    let isDragging = false, startX, startY, startLeft, startTop;

    header.onpointerdown = function (e) {
        if (e.target.classList.contains('img-popup-close')) return;
        isDragging = true;
        startX = e.clientX; startY = e.clientY;
        startLeft = popup.offsetLeft; startTop = popup.offsetTop;
        header.setPointerCapture(e.pointerId);
    };

    header.onpointermove = function (e) {
        if (!isDragging) return;
        var nx = startLeft + e.clientX - startX;
        var ny = startTop + e.clientY - startY;
        nx = Math.max(0, Math.min(nx, window.innerWidth - 40));
        ny = Math.max(0, Math.min(ny, window.innerHeight - 40));
        popup.style.left = nx + 'px';
        popup.style.top = ny + 'px';
    };

    header.onpointerup = function () { isDragging = false; };
}

// ===== 天气显示 =====
let tianqiOptionsCache = null;
let currentWeatherCards = []; // 当前生效的天气卡（供弹窗展示）

async function loadTianqiOptions() {
    if (tianqiOptionsCache) return tianqiOptionsCache;
    try {
        const res = await fetch('/api/options');
        const data = await res.json();
        tianqiOptionsCache = Array.isArray(data.tianqi) ? data.tianqi : [];
    } catch (e) { tianqiOptionsCache = []; }
    return tianqiOptionsCache;
}

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// 确保 weatherBtn 在画板内（switchBoardMission 清空 innerHTML 后需重建）
function ensureWeatherButton(canvasEl) {
    if (document.getElementById('weatherBtn')) return;
    const btn = document.createElement('div');
    btn.id = 'weatherBtn';
    btn.className = 'weather-float-btn';
    btn.style.display = 'none';
    btn.onclick = openWeatherDetail;
    btn.innerHTML = '<svg class="weather-umbrella" viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12h1.5c0-.28.69-.75 2.5-.75S8.5 11.72 8.5 12H10c0-.28.69-.75 2.5-.75S15 11.72 15 12h1.5c0-.28.69-.75 2.5-.75s2.5.47 2.5.75H23c0-5.52-4.48-10-11-10zm0 2c3.88 0 7.19 2.86 7.88 6.55C18.7 9.83 17.05 9.5 15.5 9.5c-1.93 0-3.5.7-3.5.7s-1.57-.7-3.5-.7c-1.55 0-3.2.33-4.38.95C4.81 6.86 8.12 4 12 4zM11 13h2v7c0 .55-.45 1-1 1s-1-.45-1-1v-7z"/></svg><div class="weather-rain"></div>';
    canvasEl.appendChild(btn);
}

// 渲染天气：更新浮动按钮显隐 + 下雨动效 + 缓存卡片数据
function renderWeatherBar(cards) {
    currentWeatherCards = Array.isArray(cards) ? cards : [];
    const btn = document.getElementById('weatherBtn');
    if (!btn) return;
    if (!currentWeatherCards.length) {
        btn.style.display = 'none';
        btn.classList.remove('raining');
    } else {
        btn.style.display = 'flex';
        btn.classList.add('raining');
        btn.title = '当前 ' + currentWeatherCards.length + ' 个天气/事件生效，点击查看';
    }
}

// 根据 id JSON 字符串渲染（初始加载用）
async function renderWeatherBarByIds(weatherJson) {
    let ids = [];
    try { const a = JSON.parse(weatherJson || ''); ids = Array.isArray(a) ? a : []; } catch (e) { ids = []; }
    if (!ids.length) { renderWeatherBar([]); return; }
    await loadTianqiOptions();
    const cards = ids.map(function (id) { return (tianqiOptionsCache || []).find(function (c) { return c.id === id; }); }).filter(Boolean);
    renderWeatherBar(cards);
}

// 天气详情弹窗
// 递进展开：选了某 group 的 b 补 a，选了 c 补 a、b（详情用完整链）
function expandPlayerWeatherCards(cards) {
    const list = tianqiOptionsCache || [];
    const result = [];
    cards.forEach(card => {
        const siblings = list.filter(c => c.group === card.group).sort((a, b) => a.id.localeCompare(b.id));
        const myIdx = siblings.findIndex(c => c.id === card.id);
        siblings.slice(0, myIdx + 1).forEach(c => { if (!result.find(r => r.id === c.id)) result.push(c); });
    });
    result.sort((a, b) => {
        if (a.group !== b.group) return a.group - b.group;
        return a.id.localeCompare(b.id);
    });
    return result;
}

function openWeatherDetail() {
    const modal = document.getElementById('weatherDetailModal');
    if (!modal) return;
    const count = currentWeatherCards.length;

    // 选图标：1→T1, 2→T2, 3→T3, 4→T4, 5及以上→T5
    const iconLevel = Math.min(Math.max(count, 1), 5);
    const iconEl = document.getElementById('weatherModalIcon');
    if (iconEl) {
        iconEl.src = '/img/T' + iconLevel + '.webp';
        const wrap = iconEl.closest('.weather-img-wrap');
        if (wrap) wrap.setAttribute('data-level', iconLevel);
    }

    // 上方序号：只显示选中的（不含自动展开的弱效）
    const codesEl = document.getElementById('weatherModalCodes');
    if (count) {
        codesEl.innerHTML = currentWeatherCards.map(function (c, i) {
            return '<span class="weather-code-id">' + esc(c.id) + '</span>' +
                (i < count - 1 ? '<span class="weather-code-link"></span>' : '');
        }).join('');
    } else {
        codesEl.innerHTML = '<span class="weather-code-id" style="color:#ccc;">—</span>';
    }

    // 下方详细效果：展开后显示完整链（选 1c 则显示 1a 1b 1c）
    const detailEl = document.getElementById('weatherModalDetail');
    if (count) {
        const expanded = expandPlayerWeatherCards(currentWeatherCards);
        detailEl.innerHTML = expanded.map(function (c) {
            return '<div class="weather-detail-card">' +
                '<div class="weather-detail-head"><span class="weather-detail-id">' + esc(c.id) + '</span><span class="weather-detail-title">' + esc(c.title) + '</span></div>' +
                '<div class="weather-detail-text">' + esc(c.text) + '</div>' +
                '</div>';
        }).join('');
    } else {
        detailEl.innerHTML = '<div style="text-align:center;color:#999;padding:20px;">当前无生效的天气/事件</div>';
    }

    modal.style.display = 'flex';
}

function closeWeatherDetail() {
    document.getElementById('weatherDetailModal').style.display = 'none';
}

window.openWeatherDetail = openWeatherDetail;
window.closeWeatherDetail = closeWeatherDetail;
