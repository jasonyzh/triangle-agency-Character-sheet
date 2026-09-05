// 异常能力模块图标（复刻自 svg-icons-preview.html 的四枚 SVG）
// check=成功时(对钩三角) x=失败时(八角叉) wave=三重升华(波纹三角) star=列表(星形三角)

const BLUE = '#2E5EA8';
const RED = '#D22837';

function checkIcon(color = BLUE) {
    return `<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M50 10 L92 88 L8 88 Z" fill="${color}" stroke="${color}" stroke-width="8" stroke-linejoin="round"/><path d="M31 57 L46 70 L71 39" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

function xIcon(color = RED) {
    return `<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M88.8 66.07 L66.07 88.8 L33.93 88.8 L11.2 66.07 L11.2 33.93 L33.93 11.2 L66.07 11.2 L88.8 33.93 Z" fill="${color}" stroke="${color}" stroke-width="6" stroke-linejoin="round"/><path d="M35 35 L65 65 M65 35 L35 65" fill="none" stroke="#fff" stroke-width="14" stroke-linecap="round"/></svg>`;
}

function starIcon(color = BLUE) {
    return `<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M50 10 L92 88 L8 88 Z" fill="${color}" stroke="${color}" stroke-width="8" stroke-linejoin="round"/><path d="M50 40 L55.17 54.88 L70.92 55.2 L58.37 64.72 L62.93 79.8 L50 70.8 L37.07 79.8 L41.63 64.72 L29.08 55.2 L44.83 54.88 Z" fill="#fff"/></svg>`;
}

// 波纹三角：实心三角 + 沿边法线外扩的波浪轮廓圈（运行时生成一次并缓存）
let _waveCache = null;
function buildWaveSvg(color = RED) {
    const P = [{ x: 50, y: 22 }, { x: 18, y: 82 }, { x: 82, y: 82 }];
    const seg = [
        Math.hypot(P[1].x - P[0].x, P[1].y - P[0].y),
        Math.hypot(P[2].x - P[1].x, P[2].y - P[1].y),
        Math.hypot(P[0].x - P[2].x, P[0].y - P[2].y)
    ];
    const L = seg[0] + seg[1] + seg[2];
    function pt(s) {
        s = ((s % L) + L) % L;
        let i = 0;
        while (s > seg[i]) { s -= seg[i]; i++; }
        const a = P[i], b = P[(i + 1) % 3];
        const dx = (b.x - a.x) / seg[i], dy = (b.y - a.y) / seg[i];
        return { x: a.x + dx * s, y: a.y + dy * s, nx: -dy, ny: dx };
    }
    const period = L / 7, steps = 48;
    function ringPath(off, amp, phase) {
        let d = '';
        for (let s = 0; s <= steps; s++) {
            const p = pt(L * s / steps);
            const disp = off + amp * Math.sin(2 * Math.PI * (L * s / steps) / period + phase);
            d += (s ? ' L' : 'M') + (p.x + p.nx * disp).toFixed(1) + ' ' + (p.y + p.ny * disp).toFixed(1);
        }
        return d + ' Z';
    }
    let rings = '';
    for (let k = 0; k < 9; k++) {
        const op = Math.max(0.1, 0.85 * Math.pow(1 - k / 9, 1.15)).toFixed(2);
        rings += `<path d="${ringPath(1.2 + k * 0.75, 0.7 + k * 0.42, k * 0.85)}" fill="none" stroke="${color}" stroke-width="1.6" opacity="${op}"/>`;
    }
    for (let k = 1; k <= 2; k++) {
        rings += `<path d="${ringPath(-1.5 * k, 0.6, k * 1.1)}" fill="none" stroke="${color}" stroke-width="1.3" opacity="0.25"/>`;
    }
    const core = `<path d="M50 22 L82 82 L18 82 Z" fill="${color}" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>`;
    return `<svg class="anom-ico" viewBox="8 8 84 84" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">${rings}${core}</svg>`;
}
function waveIcon(color = RED) {
    if (!_waveCache) _waveCache = {};
    if (!_waveCache[color]) _waveCache[color] = buildWaveSvg(color);
    return _waveCache[color];
}

export function anomIcon(name, color) {
    switch (name) {
        case 'check': return checkIcon(color);
        case 'x': return xIcon(color);
        case 'star': return starIcon(color);
        case 'wave': return waveIcon(color);
        default: return '';
    }
}

export const ANOM_ICON_SVGS = { check: checkIcon, x: xIcon, star: starIcon, wave: waveIcon };

// 给静态 HTML 中 <span data-anom-ico="wave"></span> 之类的占位注入图标
export function injectAnomIcons(root = document) {
    root.querySelectorAll('[data-anom-ico]').forEach(el => {
        const svg = anomIcon(el.dataset.anomIco);
        if (svg && !el.querySelector('svg')) el.insertAdjacentHTML('afterbegin', svg);
    });
}
