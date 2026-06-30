import { S } from './state.js';

let cachedBranchId = null;

export async function checkDestructionAccess() {
    try {
        console.log('checkDestructionAccess, charId:', S.charId);
        const res = await fetch('/api/destruction-track/has-access?charId=' + S.charId, {
            headers: { 'Authorization': 'Bearer ' + S.token }
        });
        const data = await res.json();
        console.log('has-access response:', data);
        if (data.hasAccess) {
            const btn = document.getElementById('topEyeBtn');
            if (btn) btn.style.display = '';
            cachedBranchId = data.branchId;
        }
    } catch (e) {
        console.error('检查破坏条权限失败:', e);
    }
}

export async function openDestructionTrackModal() {
    const modal = document.getElementById('destruction-full-modal');
    modal.classList.add('active');
    try {
        if (!cachedBranchId) {
            const grid = document.getElementById('destructionViewGrid');
            if (grid) grid.innerHTML = '<div style="text-align:center;color:#aaa;padding:40px;">无法获取分部信息</div>';
            return;
        }

        const res = await fetch('/api/destruction-track?branchId=' + cachedBranchId, {
            headers: { 'Authorization': 'Bearer ' + S.token }
        });
        const data = await res.json();
        renderDestructionViewGrid(data.cells || []);
    } catch (e) {
        console.error('加载破坏条失败:', e);
    }
}

function renderDestructionViewGrid(activeCells) {
    const grid = document.getElementById('destructionViewGrid');
    if (!grid) return;
    grid.innerHTML = '';

    const colCount = 7;
    const rowCount = 6;

    for (let row = 0; row < rowCount; row++) {
        for (let col = 0; col < colCount; col++) {
            const isReverse = row % 2 === 1;
            const logicalCol = isReverse ? (colCount - 1 - col) : col;
            const cellIndex = row * colCount + logicalCol + 1;

            const cell = document.createElement('div');
            cell.className = 'p-cell dest-cell';
            cell.dataset.idx = cellIndex;
            if (activeCells.includes(cellIndex)) {
                cell.classList.add('active');
            }
            cell.textContent = cellIndex;
            grid.appendChild(cell);
        }
    }

    requestAnimationFrame(() => { requestAnimationFrame(() => drawDestructionViewSVG()); });
}

function drawDestructionViewSVG() {
    const svg = document.querySelector('.dest-view-svg');
    const grid = document.getElementById('destructionViewGrid');
    if (!svg || !grid) return;

    svg.innerHTML = '';
    const gridRect = grid.getBoundingClientRect();
    const cells = grid.querySelectorAll('.dest-cell');
    if (cells.length === 0) return;

    const posMap = {};
    cells.forEach(cell => {
        const idx = parseInt(cell.dataset.idx);
        const r = cell.getBoundingClientRect();
        posMap[idx] = {
            cx: r.left + r.width / 2 - gridRect.left,
            cy: r.top + r.height / 2 - gridRect.top
        };
    });

    svg.setAttribute('viewBox', `0 0 ${gridRect.width} ${gridRect.height}`);
    svg.removeAttribute('width');
    svg.removeAttribute('height');
    svg.style.width = '100%';
    svg.style.height = '100%';

    for (let i = 1; i < 42; i++) {
        const from = posMap[i];
        const to = posMap[i + 1];
        if (!from || !to) continue;

        const mx = (from.cx + to.cx) / 2;
        const my = (from.cy + to.cy) / 2;
        const angle = Math.atan2(to.cy - from.cy, to.cx - from.cx) * 180 / Math.PI;
        const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        const size = 3;
        const points = `${mx+size},${my} ${mx-size},${my-size} ${mx-size},${my+size}`;
        arrow.setAttribute('points', points);
        arrow.setAttribute('fill', 'rgba(52,152,219,0.5)');
        arrow.setAttribute('transform', `rotate(${angle},${mx},${my})`);
        svg.appendChild(arrow);
    }
}

export function closeDestructionTrackModal() {
    document.getElementById('destruction-full-modal').classList.remove('active');
}
