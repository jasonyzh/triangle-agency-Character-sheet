// ===== 办公室实验页：SVG 平面图（白色背景 + 红三角机构风） =====
var uid = localStorage.getItem('ta_uid');
var token = localStorage.getItem('ta_token');
if (!uid) window.location.href = 'login.html';

function goBack() { createTransition('返回终端', 'dashboard.html'); }
function escapeHtml(s) {
    if (s === undefined || s === null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// 视觉常量
var RED = '#e63946';
var RED_DARK = '#c1121f';
var RED_SOFT = '#fce8eb';
var INK = '#1a1a1a';

// ===== 工位绘制：俯视图，桌面=红色梯形(向坐者收窄)，显示器=白方块红框，椅子=圆 =====
// 参数：x,y 工位左上角；occupied 是否有人；char 角色
function drawWorkstation(x, y, occupied, char) {
    var W = 120, H = 84; // 工位占地
    var svg = '';
    var groupClass = 'ws-group' + (occupied ? '' : ' ws-empty');
    svg += '<g class="' + groupClass + '" transform="translate(' + x + ',' + y + ')" data-char="' + (char ? escapeHtml(JSON.stringify(char)) : '') + '">';

    // 地面方框（工位边界，淡线）
    svg += '<rect x="0" y="0" width="' + W + '" height="' + H + '" fill="none" stroke="' + RED + '" stroke-width="0.8" opacity="0.25" rx="2"/>';

    // 桌面：红色梯形（上宽下窄，模拟工位台面前视图俯瞰）
    svg += '<polygon class="ws-desk" points="14,30 106,30 96,60 24,60" fill="' + (occupied ? RED : '#fafafa') + '" stroke="' + RED + '" stroke-width="1.5"/>';

    // 桌面中央装饰：小倒三角（机构 logo 元素）
    svg += '<polygon points="60,38 54,52 66,52" fill="' + (occupied ? '#fff' : RED) + '" opacity="0.9"/>';

    // 显示器：白方块带红框（放在桌面顶部）
    svg += '<rect x="40" y="14" width="40" height="20" fill="#fff" stroke="' + RED + '" stroke-width="1.5" rx="1"/>';
    svg += '<line x1="44" y1="20" x2="76" y2="20" stroke="' + RED + '" stroke-width="0.8" opacity="0.5"/>';
    svg += '<line x1="44" y1="24" x2="70" y2="24" stroke="' + RED + '" stroke-width="0.8" opacity="0.5"/>';

    // 椅子：圆形（座位）+ 靠背小弧
    svg += '<circle cx="60" cy="72" r="7" fill="#fff" stroke="' + RED + '" stroke-width="1.5"/>';
    svg += '<path d="M53 70 Q60 64 67 70" fill="none" stroke="' + RED + '" stroke-width="1.5"/>';

    // 角色头像：首字圆框（放在椅子上方/桌面位置）
    if (occupied && char) {
        var first = (char.name || '?').trim().charAt(0) || '?';
        svg += '<g class="ws-avatar">';
        svg += '<circle cx="60" cy="45" r="11" fill="#fff" stroke="' + RED_DARK + '" stroke-width="2"/>';
        svg += '<text x="60" y="45" text-anchor="middle" dominant-baseline="central" font-size="13" font-weight="800" fill="' + RED_DARK + '" font-family="PingFang SC, Microsoft YaHei, sans-serif">' + escapeHtml(first) + '</text>';
        svg += '</g>';
    }

    svg += '</g>';
    return svg;
}

// ===== 绘制整间办公室平面图 =====
function drawOffice(characters) {
    var canvas = document.getElementById('officeCanvas');

    // 布局：4 排工位，每排 6 个，行间距 150，列间距 150
    var ROWS = 4, COLS = 6;
    var WS_W = 120, WS_H = 84;
    var GAP_X = 40, GAP_Y = 80;
    var PAD = 80; // 平面图内边距
    var totalW = PAD * 2 + COLS * WS_W + (COLS - 1) * GAP_X;
    var totalH = PAD * 2 + ROWS * WS_H + (ROWS - 1) * GAP_Y;

    var slots = ROWS * COLS; // 24 个工位
    var chars = characters.slice(0, slots);
    var charGrid = []; // 二维：排 → 列 → 角色|null
    for (var r = 0; r < ROWS; r++) {
        charGrid[r] = [];
        for (var c = 0; c < COLS; c++) {
            var idx = r * COLS + c;
            charGrid[r][c] = idx < chars.length ? chars[idx] : null;
        }
    }

    var svg = '<svg class="office-svg" viewBox="0 0 ' + totalW + ' ' + totalH + '" preserveAspectRatio="xMidYMid meet" style="min-width:' + totalW + 'px;">';

    // 房间外墙：红色粗线矩形
    svg += '<rect x="20" y="20" width="' + (totalW - 40) + '" height="' + (totalH - 40) + '" fill="#fff" stroke="' + RED + '" stroke-width="3" rx="4"/>';
    // 四角装饰：红色实心三角（机构标识）
    var corners = [[20,20,1,1],[totalW-20,20,-1,1],[20,totalH-20,1,-1],[totalW-20,totalH-20,-1,-1]];
    corners.forEach(function (cn) {
        var cx = cn[0], cy = cn[1], sx = cn[2], sy = cn[3];
        svg += '<polygon points="' + cx + ',' + (cy + 22 * sy) + ' ' + (cx + 22 * sx) + ',' + cy + ' ' + cx + ',' + cy + '" fill="' + RED + '"/>';
    });

    // 标题区（顶部）
    svg += '<text x="' + (totalW / 2) + '" y="48" text-anchor="middle" font-size="20" font-weight="800" fill="' + INK + '" letter-spacing="3" font-family="sans-serif">FLOOR PLAN — 收容库办公室</text>';
    svg += '<line x1="' + (totalW / 2 - 90) + '" y1="58" x2="' + (totalW / 2 + 90) + '" y2="58" stroke="' + RED + '" stroke-width="2"/>';

    // 中央通道线（红色虚线分隔左右）
    var midX = totalW / 2;
    svg += '<line x1="' + midX + '" y1="80" x2="' + midX + '" y2="' + (totalH - 80) + '" stroke="' + RED + '" stroke-width="1" stroke-dasharray="6 6" opacity="0.3"/>';

    // 绘制工位（两两背对：奇数排朝上坐，偶数排朝下坐，模拟成对工位组）
    for (var r = 0; r < ROWS; r++) {
        for (var c = 0; c < COLS; c++) {
            var x = PAD + c * (WS_W + GAP_X);
            var y = PAD + 20 + r * (WS_H + GAP_Y);
            var char = charGrid[r][c];
            svg += drawWorkstation(x, y, !!char, char);
        }
    }

    svg += '</svg>';
    canvas.innerHTML = svg;

    // 绑定悬停
    bindWorkstationHover();
}

// ===== 悬停浮窗 =====
function bindWorkstationHover() {
    var groups = document.querySelectorAll('.ws-group');
    var tooltip = document.getElementById('officeTooltip') || createTooltip();
    groups.forEach(function (g) {
        g.addEventListener('mouseenter', function () {
            var raw = g.getAttribute('data-char');
            if (!raw || raw === '') {
                tooltip.innerHTML = '<div class="office-tooltip-empty">空闲工位</div>';
            } else {
                try {
                    var c = JSON.parse(raw);
                    var funcTag = c.func && c.func !== '---' ? '<span class="office-tooltip-func">' + escapeHtml(c.func) + '</span><br>' : '';
                    tooltip.innerHTML =
                        '<div class="office-tooltip-name">' + escapeHtml(c.name) + '</div>' +
                        funcTag +
                        '<div class="office-tooltip-row"><b>' + (c.mvpCount || 0) + '</b> 次 MVP</div>' +
                        '<div class="office-tooltip-row">察看期 <b>' + (c.watchCount || 0) + '</b></div>' +
                        '<div class="office-tooltip-row">参与模组 <b>' + ((c.missions || []).length) + '</b></div>';
                } catch (e) {
                    tooltip.innerHTML = '<div class="office-tooltip-name">?</div>';
                }
            }
            tooltip.classList.add('show');
            positionTooltip(tooltip, g);
        });
        g.addEventListener('mouseleave', function () { tooltip.classList.remove('show'); });
        g.addEventListener('click', function () {
            // 移动端点击切换显示
            if (tooltip.classList.contains('show')) tooltip.classList.remove('show');
            else { tooltip.classList.add('show'); positionTooltip(tooltip, g); }
        });
    });
}

function createTooltip() {
    var t = document.createElement('div');
    t.className = 'office-tooltip';
    t.id = 'officeTooltip';
    document.body.appendChild(t);
    return t;
}

function positionTooltip(tooltip, anchor) {
    var rect = anchor.getBoundingClientRect();
    var tw = tooltip.offsetWidth || 220;
    var th = tooltip.offsetHeight || 120;
    var left = rect.right + 10;
    if (left + tw > window.innerWidth - 8) left = rect.left - tw - 10;
    if (left < 8) left = Math.max(8, (window.innerWidth - tw) / 2);
    var top = rect.top + rect.height / 2 - th / 2;
    if (top < 70) top = 70;
    if (top + th > window.innerHeight - 8) top = window.innerHeight - th - 8;
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
}

// 滚动时隐藏浮窗
document.querySelector('.office-canvas').addEventListener('scroll', function () {
    var t = document.getElementById('officeTooltip');
    if (t) t.classList.remove('show');
});

// ===== 加载角色数据 =====
// 复用广场接口（返回当前分部可见角色列表）
async function loadCharacters() {
    var currentBranchId = localStorage.getItem('ta_plaza_branch');
    if (!currentBranchId) {
        document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#999;">请先从广场选择一个分部</div>';
        return;
    }
    document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#999;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    try {
        var res = await fetch('/api/plaza/characters?branchId=' + currentBranchId, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        if (res.status === 401 || res.status === 403) { goBack(); return; }
        var data = await res.json();
        // 添加图例
        addLegend(data.length);
        drawOffice(data);
    } catch (e) {
        console.error('加载失败:', e);
        document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#e63946;">加载失败</div>';
    }
}

function addLegend(count) {
    if (document.querySelector('.office-legend')) return;
    var legend = document.createElement('div');
    legend.className = 'office-legend';
    legend.innerHTML =
        '<div class="office-legend-title">图例</div>' +
        '<div class="office-legend-item"><span class="office-legend-swatch" style="background:#e63946;"></span>有人工位 (' + count + ')</div>' +
        '<div class="office-legend-item"><span class="office-legend-swatch" style="background:#fafafa;border:1px dashed #e63946;"></span>空闲工位</div>';
    document.body.appendChild(legend);
}

loadCharacters();
