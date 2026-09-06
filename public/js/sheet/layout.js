import { S } from './state.js';

export function updateCharLayout() {
    const leftPanel = document.querySelector('.char-attrs-panel');
    const rightPanel = document.querySelector('.char-info-panel');
    const sideLeft = document.getElementById('char-side-left');
    const sideRight = document.getElementById('char-side-right');
    const colLeft = document.querySelector('.char-col-left');
    const colRight = document.querySelector('.char-col-right');
    const quickLeft = document.getElementById('quickBtnsLeft');
    const quickRight = document.getElementById('quickBtnsRight');
    if (!leftPanel || !rightPanel || !sideLeft || !sideRight || !colLeft || !colRight) return;
    const isDesktop = window.innerWidth >= 1600;
    if (isDesktop) {
        if (!sideLeft.contains(leftPanel)) sideLeft.appendChild(leftPanel);
        if (!sideRight.contains(rightPanel)) sideRight.appendChild(rightPanel);
        if (quickLeft && !sideLeft.contains(quickLeft)) sideLeft.appendChild(quickLeft);
        if (quickRight && !sideRight.contains(quickRight)) sideRight.appendChild(quickRight);
        sideLeft.classList.add('active');
        sideRight.classList.add('active');
    } else {
        if (!colLeft.contains(leftPanel)) colLeft.appendChild(leftPanel);
        if (!colLeft.contains(rightPanel)) colLeft.appendChild(rightPanel);
        if (quickLeft && quickLeft.parentElement && quickLeft.parentElement !== leftPanel.parentElement) {
            leftPanel.parentElement.appendChild(quickLeft);
        }
        if (quickRight && sideRight.contains(quickRight)) {
            colLeft.appendChild(quickRight);
        }
        sideLeft.classList.remove('active');
        sideRight.classList.remove('active');
    }
}

export function drawTrackSVG() {
    const isPhone = window.innerWidth < 768;
    const arrowSize = isPhone ? 2.5 : 4;
    document.querySelectorAll('.track-svg').forEach(svg => {
        svg.innerHTML = '';
        svg.style.display = '';
        const wrap = svg.parentElement;
        const snake = wrap.querySelector('.track-snake');
        if (!snake) return;
        const wrapRect = wrap.getBoundingClientRect();
        if (!snake.querySelector('[data-idx="30"]')) return;

        const getCenter = (idx) => {
            const cell = snake.querySelector('[data-idx="' + idx + '"]');
            if (!cell) return null;
            const r = cell.getBoundingClientRect();
            return { x: r.left + r.width / 2 - wrapRect.left, y: r.top + r.height / 2 - wrapRect.top };
        };

        const makeArrow = (x, y, angle) => {
            const s = arrowSize;
            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('transform', 'translate(' + x + ',' + y + ') rotate(' + angle + ')');
            const p = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
            p.setAttribute('points', -s + ',' + (-s) + ' ' + s + ',0 ' + (-s) + ',' + s);
            p.setAttribute('fill', '#95a5a6');
            g.appendChild(p);
            return g;
        };

        const seq = [];
        for (let i = 1; i <= 15; i++) seq.push(i);
        for (let i = 16; i <= 30; i++) seq.push(i);

        for (let i = 0; i < seq.length - 1; i++) {
            const aIdx = seq[i], bIdx = seq[i + 1];
            const ac = getCenter(aIdx);
            const bc = getCenter(bIdx);
            if (!ac || !bc) continue;
            const dx = bc.x - ac.x;
            const dy = bc.y - ac.y;
            let angle, mx, my;
            if (Math.abs(dx) > Math.abs(dy)) {
                angle = dx > 0 ? 0 : 180;
                mx = (ac.x + bc.x) / 2;
                my = ac.y;
            } else {
                angle = dy > 0 ? 90 : 270;
                mx = ac.x;
                my = (ac.y + bc.y) / 2;
            }
            svg.appendChild(makeArrow(mx, my, angle));
        }
    });
}

window.addEventListener('resize', () => { updateCharLayout(); drawTrackSVG(); });
