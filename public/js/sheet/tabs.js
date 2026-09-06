import { S, tabOrder, swiperWrapper, navBtns } from './state.js';

export function switchView(id, btn) {
    if (id === 'view-mail') {
        window.openMailModal();
        return;
    }
    window.closePhoneOverlay();
    window.closeBriefcase();
    window.closeAnomWindow();
    const i = tabOrder.indexOf(id);
    if (i !== -1) {
        S.currentTab = i;
        updateSwiper();
        navBtns.forEach(function (b) { b.classList.remove('active'); });
        if (btn) btn.classList.add('active');
        try { localStorage.setItem('ta_sheet_tab', id); } catch (e) { }
    }
}

export function updateSwiper() {
    swiperWrapper.style.transform = 'translateX(-' + (S.currentTab * 20) + '%)';
    document.querySelectorAll('.tab-view')[S.currentTab].scrollTop = 0;
    window.updateCharLayout();
    requestAnimationFrame(() => window.drawTrackSVG());
}

export function toggleCharBoard() {
    var toggle = document.getElementById('toggleCharBoard');
    var slider = toggle.querySelector('.toggle-slider');
    var opts = toggle.querySelectorAll('.toggle-opt');
    var isBoard = opts[0].classList.contains('active');
    if (isBoard) {
        opts[0].classList.remove('active');
        opts[1].classList.add('active');
        slider.classList.add('right');
        switchView('view-char', null);
    } else {
        opts[1].classList.remove('active');
        opts[0].classList.add('active');
        slider.classList.remove('right');
        switchView('view-board', null);
    }
}
