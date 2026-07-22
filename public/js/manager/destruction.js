import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast } from './ui.js';

let destructionCells = [];

export async function loadDestructionTrack() {
    if (!S.currentBranchId) {
        document.getElementById('destructionGrid').innerHTML = '<div style="text-align:center;color:#aaa;padding:40px;">请先选择分部</div>';
        return;
    }
    try {
        const res = await fetch('/api/destruction-track?branchId=' + S.currentBranchId, { headers: getAuthHeaders() });
        const data = await res.json();
        destructionCells = data.cells || [];
        renderDestructionGrid();
    } catch (e) {
        console.error('加载破坏条失败:', e);
    }
}

function renderDestructionGrid() {
    const grid = document.getElementById('destructionGrid');
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
            if (destructionCells.includes(cellIndex)) {
                cell.classList.add('active');
            }
            cell.textContent = cellIndex;
            cell.addEventListener('click', () => {
                cell.classList.toggle('active');
            });
            grid.appendChild(cell);
        }
    }

    requestAnimationFrame(() => { requestAnimationFrame(() => drawDestructionSVG()); });
}

function drawDestructionSVG() {
    const svg = document.querySelector('.dest-svg');
    const grid = document.getElementById('destructionGrid');
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

export async function saveDestructionTrack() {
    if (!S.currentBranchId) { showToast('请先选择分部'); return; }
    const cells = [];
    document.querySelectorAll('.dest-cell.active').forEach(cell => {
        cells.push(parseInt(cell.dataset.idx));
    });
    try {
        const res = await fetch('/api/destruction-track', {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ branchId: S.currentBranchId, cells })
        });
        const data = await res.json();
        if (data.success) {
            showToast('破坏条已保存', 'success');
        } else {
            showToast(data.message || '保存失败');
        }
    } catch (e) {
        showToast('保存失败');
    }
}

export { destructionCells };
