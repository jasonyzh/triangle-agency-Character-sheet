import { S, ATTRS } from './state.js';

export function renderTriangles(a, v) {
    const val = parseInt(v) || 0;
    const container = document.querySelector(`.attr-dots[data-attr="${a}"]`);
    if (!container) return;

    container.querySelectorAll('.tri-btn').forEach((tri, i) => {
        const idx = i + 1;
        if (idx <= val) {
            if (!tri.classList.contains('marked')) {
                tri.classList.add('active');
            }
        } else {
            tri.classList.remove('active', 'marked');
        }
    });
}

export function initAttrs() {
    const c = document.getElementById('attrs-list');
    c.innerHTML = '';
    ATTRS.forEach(a => {
        const d = document.createElement('div');
        d.className = 'attr-row';
        const triangles = Array(9).fill(0).map((_, i) => {
            const direction = i % 2 === 0 ? 'up' : 'down';
            return `<div class="tri-btn ${direction}" data-i="${i + 1}"></div>`;
        }).join('');
        d.innerHTML = `<div class="attr-label">${a}</div><div class="attr-input-wrapper"><button class="attr-btn attr-minus" data-attr="${a}">−</button><input type="text" class="attr-input" data-attr="${a}" value="0"><button class="attr-btn attr-plus" data-attr="${a}">+</button></div><div class="attr-dots-container"><div class="attr-dots" data-attr="${a}">${triangles}</div></div>`;
        c.appendChild(d);

        const inp = d.querySelector('input');
        inp.oninput = (e) => renderTriangles(a, e.target.value);

        const minusBtn = d.querySelector('.attr-minus');
        const plusBtn = d.querySelector('.attr-plus');

        minusBtn.onclick = () => {
            if (S.isReadOnly) return;
            let val = parseInt(inp.value) || 0;
            if (val > 0) {
                val--;
                inp.value = val;
                renderTriangles(a, val);
                window.triggerAutoSave();
            }
        };

        plusBtn.onclick = () => {
            if (S.isReadOnly) return;
            let val = parseInt(inp.value) || 0;
            if (val < 9) {
                val++;
                inp.value = val;
                renderTriangles(a, val);
                window.triggerAutoSave();
            }
        };

        const dotsContainer = d.querySelector('.attr-dots-container');

        dotsContainer.onclick = (e) => {
            if (S.isReadOnly) return;
            const max = parseInt(inp.value) || 0;
            if (max === 0) return;

            const allTris = d.querySelectorAll('.tri-btn');
            for (let idx = max; idx >= 1; idx--) {
                const tri = allTris[idx - 1];
                if (tri && tri.classList.contains('active') && !tri.classList.contains('marked')) {
                    tri.classList.remove('active');
                    tri.classList.add('marked');
                    window.triggerAutoSave();
                    return;
                }
            }
        };

        dotsContainer.oncontextmenu = (e) => {
            e.preventDefault();
            if (S.isReadOnly) return;
            const max = parseInt(inp.value) || 0;
            if (max === 0) return;

            const allTris = d.querySelectorAll('.tri-btn');
            for (let idx = 1; idx <= max; idx++) {
                const tri = allTris[idx - 1];
                if (tri && tri.classList.contains('marked')) {
                    tri.classList.remove('marked');
                    tri.classList.add('active');
                    window.triggerAutoSave();
                    return;
                }
            }
        };
    });
}

export function renderDots(a, v) {
    renderTriangles(a, v);
}

export function resetAllAttrs() {
    if (S.isReadOnly) return;
    ATTRS.forEach(a => {
        const container = document.querySelector(`.attr-dots[data-attr="${a}"]`);
        const input = document.querySelector(`.attr-input[data-attr="${a}"]`);
        if (!container || !input) return;

        const max = parseInt(input.value) || 0;
        const allTris = container.querySelectorAll('.tri-btn');
        for (let idx = 0; idx < max; idx++) {
            const tri = allTris[idx];
            if (tri && tri.classList.contains('marked')) {
                tri.classList.remove('marked');
                tri.classList.add('active');
            }
        }
    });
}

export function initDerivativeProgress() {
    document.querySelectorAll('.progress-cell').forEach(cell => {
        cell.onclick = () => {
            if (S.isReadOnly) return;
            cell.classList.toggle('active');
        };
    });
}
