export function createTransition(text, targetUrl) {
    const overlay = document.getElementById('transition-overlay');
    if (!overlay) { window.location.href = targetUrl; return; }
    const textEl = overlay.querySelector('.loader-text');
    const textContent = textEl ? textEl.childNodes[0] : null;
    if (textContent) textContent.textContent = text || '加载中';
    overlay.classList.add('active');
    setTimeout(() => { window.location.href = targetUrl; }, 800);
}

export function toggleSideMenu() {
    const menu = document.getElementById('sideMenu');
    const overlay = document.getElementById('sideMenuOverlay');
    if (menu) menu.classList.toggle('show');
    if (overlay) overlay.classList.toggle('show');
}

export function closeSideMenu() {
    const menu = document.getElementById('sideMenu');
    const overlay = document.getElementById('sideMenuOverlay');
    if (menu) menu.classList.remove('show');
    if (overlay) overlay.classList.remove('show');
}

export function initNav() {
    const role = parseInt(localStorage.getItem('ta_role') || '0');
    const btnManager = document.getElementById('btnManager');
    const btnConsole = document.getElementById('btnConsole');
    const deskBtnAdmin = document.getElementById('deskBtnAdmin');
    if (btnManager && role >= 1) btnManager.style.display = '';
    if (btnConsole && role >= 2) btnConsole.style.display = '';
    if (deskBtnAdmin && role >= 2) deskBtnAdmin.style.display = '';
}
