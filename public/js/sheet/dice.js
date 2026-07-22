import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtmlText } from './ui.js';

export function rollDice(count, sides) {
    var results = [];
    for (var i = 0; i < count; i++) results.push(Math.floor(Math.random() * sides) + 1);
    var total = results.reduce(function (a, b) { return a + b; }, 0);
    var label = count + 'd' + sides;
    var detail = count > 1 ? '(' + results.join('+') + ')' : '';
    var charName = document.getElementById('pName').value || '未知';
    showDiceResult(label, total, detail);
    broadcastDiceResult(charName, label, total, results, 'normal');
}

export function rollCheck() {
    var results = [];
    for (var i = 0; i < 6; i++) results.push(Math.floor(Math.random() * 4) + 1);
    var count3 = results.filter(function (r) { return r === 3; }).length;
    var charName = document.getElementById('pName').value || '未知';
    var detail = results.map(function (r) {
        return '<span' + (r === 3 ? ' style="color:#ff6b6b;font-weight:900;"' : '') + '>' + r + '</span>';
    }).join(' ');
    showDiceResult('检定6d4', count3 + '个3', '(' + detail + ')');
    broadcastDiceResult(charName, '检定6d4', count3 + '个3', results, 'check');
}

export function broadcastDiceResult(charName, label, total, results, type) {
    if (S.currentPlayerBoardMissionId && S.playerSocket && S.playerSocket.connected) {
        S.playerSocket.emit('dice:roll', { missionId: S.currentPlayerBoardMissionId, charName: charName, label: label, total: total, results: results, type: type });
    }
}

export function showDiceResult(label, total, detail) {
    function esc(s) { if (!s) return ''; var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
    var container = document.getElementById('diceResults');
    if (!container) return;
    var el = document.createElement('div');
    el.className = 'dice-entry';
    var charName = document.getElementById('pName').value || '';
    el.innerHTML = (charName ? '<span class="dice-char">' + esc(charName) + '</span> ' : '') + '<span class="dice-label">' + label + '</span> <span class="dice-total">' + total + '</span>' + (detail ? ' <span class="dice-detail">' + detail + '</span>' : '');
    el.style.cssText = 'background:rgba(26,37,47,0.85);color:white;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;animation:diceFadeIn 0.2s ease;opacity:1;transition:opacity 0.5s;';
    container.appendChild(el);
    saveToHistory(el.innerHTML);
    setTimeout(function () { el.style.opacity = '0'; }, 4500);
    setTimeout(function () { if (el.parentNode) el.remove(); }, 5200);
    var entries = container.querySelectorAll('.dice-entry');
    if (entries.length > 20) entries[0].remove();
}

export function saveToHistory(html) {
    var ts = new Date().toLocaleTimeString();
    S.diceHistory.unshift({ time: ts, html: html });
    if (S.diceHistory.length > 50) S.diceHistory.pop();
    try { localStorage.setItem('ta_dice_history', JSON.stringify(S.diceHistory)); } catch (e) { }
}

export function showDiceHistory() {
    var existing = document.querySelector('.dice-hist-modal');
    if (existing) { existing.remove(); return; }
    var overlay = document.createElement('div');
    overlay.className = 'dice-hist-modal';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:30000;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:#1a252f;border-radius:8px;max-width:400px;width:90%;max-height:80vh;display:flex;flex-direction:column;box-shadow:0 8px 32px rgba(0,0,0,0.4);">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.1);"><h3 style="margin:0;font-size:14px;color:white;"><i class="fas fa-history"></i> 骰子历史</h3><button onclick="this.closest(\'.dice-hist-modal\').remove()" style="background:none;border:none;color:#999;font-size:16px;cursor:pointer;">&times;</button></div>' +
        '<div id="diceHistList" style="flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:4px;">' +
        S.diceHistory.map(function (h) { return '<div style="background:rgba(255,255,255,0.05);color:white;padding:4px 8px;border-radius:4px;font-size:11px;font-family:monospace;"><span style="color:#888;font-size:10px;">' + h.time + '</span> ' + h.html + '</div>'; }).join('') +
        '</div>' +
        '<div style="padding:8px;border-top:1px solid rgba(255,255,255,0.1);text-align:center;"><button onclick="clearDiceHistory()" style="background:#c0392b;color:white;border:none;border-radius:4px;padding:4px 12px;font-size:10px;cursor:pointer;">清除历史</button></div>' +
        '</div>';
    document.body.appendChild(overlay);
    overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
}

export function clearDiceHistory() {
    S.diceHistory.length = 0;
    try { localStorage.setItem('ta_dice_history', '[]'); } catch (e) { }
    document.querySelector('.dice-hist-modal').remove();
}

export function toggleDicePanel() {
    var panel = document.getElementById('diceFloatPanel');
    if (panel) { panel.remove(); return; }
    panel = document.createElement('div');
    panel.id = 'diceFloatPanel';
    panel.style.cssText = 'position:fixed;bottom:80px;right:16px;z-index:20000;background:#1a252f;border:1px solid rgba(255,255,255,0.15);border-radius:8px;padding:10px;display:flex;flex-wrap:wrap;gap:4px;max-width:220px;box-shadow:0 4px 16px rgba(0,0,0,0.4);';
    ['d4', 'd6', 'd8', 'd10', 'd12', 'd20', 'd%'].forEach(function (d, i) {
        var sides = [4, 6, 8, 10, 12, 20, 100][i];
        var btn = document.createElement('button');
        btn.textContent = d;
        btn.onclick = function () { rollDice(1, sides); };
        btn.style.cssText = 'flex:1 1 48px;padding:6px 0;border:1px solid rgba(255,255,255,0.2);border-radius:4px;background:rgba(255,255,255,0.08);color:white;font-size:12px;font-weight:700;cursor:pointer;';
        panel.appendChild(btn);
    });
    document.body.appendChild(panel);
    setTimeout(function () { document.addEventListener('mousedown', function close(e) { if (!panel.contains(e.target)) { panel.remove(); document.removeEventListener('mousedown', close); } }); }, 0);
}
