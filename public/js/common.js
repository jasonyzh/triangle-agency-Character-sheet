function showToast(msg, type) {
    var existing = document.querySelector('.toast');
    if (existing) existing.remove();
    var toast = document.createElement('div');
    toast.className = 'toast' + (type === 'success' ? ' success' : '');
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(function() { toast.classList.add('show'); }, 10);
    setTimeout(function() {
        toast.classList.remove('show');
        setTimeout(function() { toast.remove(); }, 300);
    }, 2500);
}

function getAuthHeaders() {
    var token = localStorage.getItem('ta_token');
    return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (token || '') };
}

function logout() {
    localStorage.removeItem('ta_uid');
    localStorage.removeItem('ta_token');
    localStorage.removeItem('ta_role');
    localStorage.removeItem('ta_is_admin');
    localStorage.removeItem('ta_is_manager');
    window.location.href = 'login.html';
}

function createTransition(text, targetUrl) {
    var overlay = document.getElementById('transition-overlay');
    if (!overlay) { window.location.href = targetUrl; return; }
    var textEl = overlay.querySelector('.loader-text');
    var textContent = textEl ? textEl.childNodes[0] : null;
    if (textContent) textContent.textContent = text || '加载中';
    overlay.classList.add('active');
    setTimeout(function() { window.location.href = targetUrl; }, 800);
}

function toggleSideMenu() {
    var menu = document.getElementById('sideMenu');
    var overlay = document.getElementById('sideMenuOverlay');
    if (menu) menu.classList.toggle('show');
    if (overlay) overlay.classList.toggle('show');
}

function closeSideMenu() {
    var menu = document.getElementById('sideMenu');
    var overlay = document.getElementById('sideMenuOverlay');
    if (menu) menu.classList.remove('show');
    if (overlay) overlay.classList.remove('show');
}

function initNav() {
    var role = parseInt(localStorage.getItem('ta_role') || '0');
    var btnManager = document.getElementById('btnManager');
    var btnConsole = document.getElementById('btnConsole');
    var deskBtnAdmin = document.getElementById('deskBtnAdmin');
    if (btnManager && role >= 1) btnManager.style.display = '';
    if (btnConsole && role >= 2) btnConsole.style.display = '';
    if (deskBtnAdmin && role >= 2) deskBtnAdmin.style.display = '';
}

function checkAuth() {
    var token = localStorage.getItem('ta_token');
    if (!token) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}
