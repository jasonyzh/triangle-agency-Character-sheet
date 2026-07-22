// ===== 办公室实验页 v2：等距(isometric)伪3D 办公室 =====
// 白底 + 红三角机构配色。参数化生成器：isoBox 画立方体，按遮挡顺序自动排序
var uid = localStorage.getItem('ta_uid');
var token = localStorage.getItem('ta_token');
if (!uid) window.location.href = 'login.html';

function goBack() { createTransition('返回终端', 'dashboard.html'); }
function escapeHtml(s) {
    if (s === undefined || s === null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

var RED = '#e63946';
var RED_DARK = '#c1121f';
var RED_DARKER = '#9a0b16';
var RED_SOFT = '#fce8eb';
var RED_MID = '#f7b6bd';
var INK = '#1a1a1a';
var WHITE = '#ffffff';

// 等距投影：屏幕坐标 = (x - y) * cos30, (x + y) * sin30 - z)
// 简化用：sx = (x - y) * 0.866, sy = (x + y) * 0.5 - z
var COS30 = 0.8660254;
var SIN30 = 0.5;
var SCALE = 0.45;   // 工位整体缩放因子默认值（drawOffice 里按响应式覆盖）
function iso(x, y, z) {
    return [(x - y) * COS30 * SCALE, ((x + y) * SIN30 - z) * SCALE];
}

// 画一个等距立方体（box），返回 3 个可见面（顶/左/右）的多边形 + 深度排序键
// 输入：世界坐标 x,y(地面位置), z=底面高度, w=宽(x向), d=深(y向), h=高
// colors: {top, left, right} 三面颜色
function isoBox(x, y, z, w, d, h, colors, stroke) {
    // 8 顶点（但只画 3 个可见面：顶、左前、右前）
    // 底面四角
    var bA = iso(x, y, z);            // 左后
    var bB = iso(x + w, y, z);        // 右后
    var bC = iso(x + w, y + d, z);    // 右前
    var bD = iso(x, y + d, z);        // 左前
    // 顶面四角
    var tA = iso(x, y, z + h);
    var tB = iso(x + w, y, z + h);
    var tC = iso(x + w, y + d, z + h);
    var tD = iso(x, y + d, z + h);

    var s = stroke ? (' stroke="' + stroke + '" stroke-width="1" stroke-linejoin="round"') : '';
    // 右侧面（x+w 面，朝右下）
    var right = '<polygon points="' + bB.join(',') + ' ' + bC.join(',') + ' ' + tC.join(',') + ' ' + tB.join(',') + '" fill="' + colors.right + '"' + s + '/>';
    // 左侧面（y+d 面，朝左下）
    var left = '<polygon points="' + bD.join(',') + ' ' + bC.join(',') + ' ' + tC.join(',') + ' ' + tD.join(',') + '" fill="' + colors.left + '"' + s + '/>';
    // 顶面
    var top = '<polygon points="' + tA.join(',') + ' ' + tB.join(',') + ' ' + tC.join(',') + ' ' + tD.join(',') + '" fill="' + colors.top + '"' + s + '/>';

    // 深度排序键：用最靠近观察者的角（x+w, y+d）的 (x+y) 值，越大越靠前（后画）
    var depthKey = (x + w) + (y + d);
    return { svg: right + left + top, depthKey: depthKey };
}

// 画一个工位（桌子+显示器+椅子+键盘），返回 {svg, depthKey}
// x,y 为该工位在地面网格的左后角
// 尺寸参数（统一管理）：桌子 60长(x) × 34深(y) × 30高；椅子在桌子前方(y+侧)
function isoWorkstation(x, y, occupied, char, C) {
    C = C || { main: RED, dark: RED_DARK, darker: RED_DARKER, deep: '#7a0a11', soft: RED_SOFT, mid: RED_MID };
    var parts = [];

    // 工位尺寸
    var DW = 60, DD = 34, DH = 30;      // 桌子 宽/深/高
    var DX = x + 2, DY = y + 2;          // 桌子左后角
    var CW = 18, CD = 18;                // 椅子 宽/深（座位）
    var CX = x + (DW + 4 - CW) / 2 + 2;  // 椅子 x 居中于桌子
    var CY = DY + DD + 6;                // 椅子在桌子前方（y+ 朝观察者）

    // ===== 椅子（最后面，先画；在桌子前方，面向桌子）=====
    // 坐着的人面朝 y- 方向（朝桌子），所以椅背在最远端 = CY+CD（y 最大处）
    var chairColors = { top: WHITE, left: C.mid, right: C.dark };
    var chairBackColors = { top: C.soft, left: C.dark, right: C.darker };
    var stemColors = { top: INK, left: '#333', right: '#222' };
    // 椅子底盘（五星脚，扁盘）
    parts.push(isoBox(CX + 1, CY + 1, 0, CW - 2, CD - 2, 2, stemColors));
    // 中柱
    parts.push(isoBox(CX + CW / 2 - 2, CY + CD / 2 - 2, 2, 4, 4, 13, stemColors));
    // 椅座（座垫，人坐这里，面朝桌子）
    parts.push(isoBox(CX, CY, 15, CW, CD, 3, chairColors, C.main));
    // 椅背（薄高板，在座垫最远端 y+侧，朝外挡住人的背）
    parts.push(isoBox(CX, CY + CD - 3, 18, CW, 3, 16, chairBackColors, C.main));

    // ===== 桌腿（4根）=====
    var legColors = { top: C.dark, left: C.darker, right: C.deep };
    var LT = 3; // 腿粗
    parts.push(isoBox(DX, DY, 0, LT, LT, DH, legColors));                                  // 左后腿
    parts.push(isoBox(DX + DW - LT, DY, 0, LT, LT, DH, legColors));                        // 右后腿
    parts.push(isoBox(DX, DY + DD - LT, 0, LT, LT, DH, legColors));                        // 左前腿
    parts.push(isoBox(DX + DW - LT, DY + DD - LT, 0, LT, LT, DH, legColors));              // 右前腿

    // ===== 桌面（厚板）=====
    var deskColors = occupied
        ? { top: WHITE, left: C.soft, right: C.mid }
        : { top: '#fafafa', left: '#f0f0f0', right: '#e8e8e8' };
    parts.push(isoBox(DX, DY, DH, DW, DD, 3, deskColors, C.main));

    // 桌面装饰倒三角（机构logo，居中靠后）
    var tcx = DX + DW / 2, tcy = DY + 10;
    var triA = iso(tcx - 8, tcy + 5, DH + 3.1);
    var triB = iso(tcx + 8, tcy + 5, DH + 3.1);
    var triC = iso(tcx, tcy - 7, DH + 3.1);
    parts.push({
        svg: '<polygon points="' + triC.join(',') + ' ' + triA.join(',') + ' ' + triB.join(',') + '" fill="' + (occupied ? C.main : '#ddd') + '"/>',
        depthKey: DX + DY + 1000
    });

    // ===== 显示器（桌子后部，屏幕朝前=朝椅子/观察者）=====
    // 结构：底座(扁盘) + 支架(细柱) + 屏幕(薄立板，正面朝 y+ 朝椅子)
    var monCx = DX + DW / 2;             // 显示器居中
    var monBaseY = DY + 6;               // 底座位置（靠桌子后边）
    var monZ = DH + 3;                   // 底座顶面高度 = 桌面上
    var monW = 24, monThick = 2.5;       // 屏幕宽 / 厚度
    var monH = 20;                       // 屏幕高
    var screenZ = monZ + 5;              // 屏幕底部高度（支架上方）

    // 底座（桌面上的小扁盘）
    parts.push(isoBox(monCx - 5, monBaseY, monZ, 10, 6, 1.5, { top: C.dark, left: C.darker, right: C.deep }, C.main));
    // 支架（细柱，连接底座到屏幕）
    parts.push(isoBox(monCx - 1, monBaseY + 1.5, monZ + 1.5, 2, 2, 4, { top: '#444', left: '#333', right: '#222' }));

    // 屏幕：薄立板，手动画 正面(y+面) + 右厚度面(x+面)
    var sx0 = monCx - monW / 2, sx1 = monCx + monW / 2;
    var sy0 = monBaseY, sy1 = monBaseY + monThick;
    var sz0 = screenZ, sz1 = screenZ + monH;
    var m1 = iso(sx1, sy0, sz0), m2 = iso(sx1, sy1, sz0), m3 = iso(sx1, sy1, sz1), m4 = iso(sx1, sy0, sz1);
    parts.push({
        svg: '<polygon points="' + m1.join(',') + ' ' + m2.join(',') + ' ' + m3.join(',') + ' ' + m4.join(',') + '" fill="' + C.darker + '" stroke="' + C.main + '" stroke-width="0.8"/>',
        depthKey: monCx + sy0 + 1000
    });
    var f1 = iso(sx0, sy1, sz0), f2 = iso(sx1, sy1, sz0), f3 = iso(sx1, sy1, sz1), f4 = iso(sx0, sy1, sz1);
    parts.push({
        svg: '<polygon points="' + f1.join(',') + ' ' + f2.join(',') + ' ' + f3.join(',') + ' ' + f4.join(',') + '" fill="' + INK + '" stroke="' + C.main + '" stroke-width="1.2"/>',
        depthKey: monCx + sy1 + 1001
    });
    // 屏幕内容：在正面上画色框 + 内容线
    function lerp(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t]; }
    var pad = 0.18;
    var fc1 = lerp(lerp(f1, f2, pad), lerp(f4, f3, pad), pad);
    var fc2 = lerp(lerp(f1, f2, 1 - pad), lerp(f4, f3, 1 - pad), pad);
    var fc3 = lerp(lerp(f1, f2, 1 - pad), lerp(f4, f3, 1 - pad), 1 - pad);
    var fc4 = lerp(lerp(f1, f2, pad), lerp(f4, f3, pad), 1 - pad);
    parts.push({
        svg: '<polygon points="' + fc1.join(',') + ' ' + fc2.join(',') + ' ' + fc3.join(',') + ' ' + fc4.join(',') + '" fill="none" stroke="' + C.main + '" stroke-width="0.8" opacity="0.6"/>' +
            '<line x1="' + lerp(fc1, fc4, 0.35)[0] + '" y1="' + lerp(fc1, fc4, 0.35)[1] + '" x2="' + lerp(fc2, fc3, 0.35)[0] + '" y2="' + lerp(fc2, fc3, 0.35)[1] + '" stroke="' + C.main + '" stroke-width="0.6" opacity="0.5"/>',
        depthKey: monCx + sy1 + 1002
    });

    // 键盘（桌面中前部，靠近人）
    var kbY = DY + DD - 14;
    parts.push(isoBox(DX + DW / 2 - 9, kbY, DH + 3, 18, 8, 1, { top: INK, left: '#333', right: '#222' }, C.main));

    // 角色头像（首字圆框，悬浮在桌面+椅子之间上方，即"坐着的人"位置）
    // data-char 存在此处，悬停/点击只绑定到头像（避免整个工位触发跳动）
    if (occupied && char) {
        var first = (char.name || '?').trim().charAt(0) || '?';
        var avR = SCALE < 1.5 ? 16 : 30;  // 手机端头像小，电脑端大
        var center = iso(DX + DW / 2, CY + CD / 2, 50);
        var clipId = 'avclip_' + char.id;
        // 有头像图片用 image+clipPath(圆形)，否则首字圆框
        var innerAvatar;
        if (char.pAvatar) {
            innerAvatar = '<clipPath id="' + clipId + '"><circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '"/></clipPath>' +
                '<image href="' + escapeHtml(char.pAvatar) + '" x="' + (center[0] - avR) + '" y="' + (center[1] - avR) + '" width="' + (avR * 2) + '" height="' + (avR * 2) + '" clip-path="url(#' + clipId + ')" pointer-events="none" preserveAspectRatio="xMidYMid slice"/>' +
                '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '" fill="none" stroke="' + C.dark + '" stroke-width="4" pointer-events="none"/>';
        } else {
            innerAvatar = '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '" fill="' + WHITE + '" stroke="' + C.dark + '" stroke-width="4" pointer-events="none"/>' +
                '<text x="' + center[0] + '" y="' + center[1] + '" text-anchor="middle" dominant-baseline="central" font-size="' + Math.round(avR * 1.27) + '" font-weight="800" fill="' + C.dark + '" font-family="PingFang SC, Microsoft YaHei, sans-serif" pointer-events="none">' + escapeHtml(first) + '</text>';
        }
        // 头像下方名字（白字 + 深色描边，保证可读）
        var nameY = center[1] + avR + 18;
        var nameSize = SCALE < 1.5 ? 9 : 13;
        var nameText = escapeHtml((char.name || '').length > 6 ? (char.name || '').slice(0, 6) + '…' : (char.name || ''));
        parts.push({
            svg: '<g class="ws-avatar" data-char="' + escapeHtml(JSON.stringify(char)) + '" data-char-id="' + escapeHtml(char.id) + '">' +
                '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + (avR + 14) + '" fill="transparent" pointer-events="all"/>' +
                innerAvatar +
                '<text x="' + center[0] + '" y="' + nameY + '" text-anchor="middle" font-size="' + nameSize + '" font-weight="700" fill="#fff" stroke="#000" stroke-width="2.5" paint-order="stroke" font-family="PingFang SC, Microsoft YaHei, sans-serif" pointer-events="none">' + nameText + '</text>' +
                '</g>',
            depthKey: DX + DY + 1002
        });
    }

    // 按深度排序（小的先画=远的在后），合并（不包裹 group，由外层卡片包裹）
    parts.sort(function (a, b) { return a.depthKey - b.depthKey; });
    var merged = parts.map(function (p) { return p.svg; }).join('');

    var depthKey = (CX + CW) + (CY + CD);
    return {
        svg: merged,
        depthKey: depthKey
    };
}

// 确定性伪随机（基于种子，保证同一工位每次重绘形状一致）
function seededRand(seed) {
    var x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
}

// 画一个拼图感地砖：不规则顶面 + 厚度侧面 + 投影阴影
// 4 条边各细分为多段，中间点加扰动，形成参差拼图块
function drawPuzzleTile(b) {
    var TW = 72, TD = 82;
    var THICK = 8;  // 地砖厚度（世界坐标 z）
    var x0 = b.bx, x1 = b.bx + TW, y0 = b.by, y1 = b.by + TD;
    var seed = Math.abs(b.bx * 13 + b.by * 7);

    // 生成不规则顶面轮廓：4 条边各取端点 + 中间扰动点
    function jitterEdge(ax, ay, bx, by, segSeed, depth) {
        // 沿边取中点，垂直方向扰动
        var mx = (ax + bx) / 2, my = (ay + by) / 2;
        // 边的方向
        var dx = bx - ax, dy = by - ay;
        var len = Math.sqrt(dx * dx + dy * dy) || 1;
        // 垂直方向（向内为负，向外为正），扰动幅度
        var nx = -dy / len, ny = dx / len;
        var amp = (seededRand(segSeed) - 0.5) * 2 * depth;
        mx += nx * amp; my += ny * amp;
        return [mx, my];
    }

    var pts = [];
    var depth = 7; // 扰动幅度（世界坐标）
    // 顶面四角（世界坐标）+ 每条边一个扰动中点，构成 8 边形拼图块
    var corners = [[x0, y0], [x1, y0], [x1, y1], [x0, y1]];
    for (var i = 0; i < 4; i++) {
        var c0 = corners[i], c1 = corners[(i + 1) % 4];
        pts.push(c0);
        var mid = jitterEdge(c0[0], c0[1], c1[0], c1[1], seed + i * 31, depth);
        pts.push(mid);
    }

    // 投影顶面点 → 屏幕坐标
    var topPts = pts.map(function (p) { return iso(p[0], p[1], THICK); });
    // 底面点（z=0）用于画厚度侧面
    var botPts = pts.map(function (p) { return iso(p[0], p[1], 0); });

    var topPolyStr = topPts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');

    // 投影阴影（模糊，偏移）
    var shadowOffset = 6;
    var shadowStr = topPts.map(function (p) { return (p[0] + shadowOffset).toFixed(1) + ',' + (p[1] + shadowOffset).toFixed(1); }).join(' ');
    var shadow = '<polygon points="' + shadowStr + '" fill="#000" opacity="0.18" filter="url(#tileShadow)"/>';

    // 厚度侧面：底面四角对应顶面四角，画左右两个可见侧面（取最靠观察者的两条边）
    // 等距视图可见的是 y+ 侧和 x+ 侧的边 → 找轮廓中 y 最大 / x 最大的段
    // 简化：画底面整个多边形偏暗，再画顶面
    var botPolyStr = botPts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
    // 侧面：连接底面和顶面的"前缘"（取下半部分点构成侧面带）
    var sidePts = [];
    for (var k = 0; k < botPts.length; k++) {
        sidePts.push(botPts[k]);
        sidePts.push(topPts[k]);
    }
    // 画一个暗色侧面多边形（底面 → 顶面顺序闭合），模拟厚度
    var sidePoly = botPts.concat(topPts.slice().reverse()).map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
    var side = '<polygon points="' + sidePoly + '" fill="' + b.tileSide + '" opacity="0.55"/>';

    // 顶面
    var top = '<polygon points="' + topPolyStr + '" fill="' + b.tileShade + '" stroke="' + b.tileEdge + '" stroke-width="1.2" opacity="0.85"/>';

    return shadow + side + top;
}
// 关键：等距投影里 bx,by 同步增加 = 屏幕正下方；bx±/by∓ = 屏幕左右
// 响应式：手机(窄屏)每行2个(2-2-2)，电脑(宽屏)3-4-3-4 交错

// 三套完整配色（地砖+桌椅+显示器+浮窗）：按角色进度追踪哪项最多选择
// 红=职能最多(默认)，黄=现实最多，蓝=异常最多
var TILE_PALETTES = {
    func: { shades: ['#fde8eb', '#f9cdd2', '#f4b0b8', '#ef9aa4'], edge: RED, side: RED_DARKER,
            main: RED, dark: RED_DARK, darker: RED_DARKER, deep: '#7a0a11', soft: RED_SOFT, mid: RED_MID },
    real: { shades: ['#fff7d6', '#fce8a8', '#f7d678', '#f0c44c'], edge: '#d4a017', side: '#8a6a0a',
            main: '#e8a317', dark: '#c48a0a', darker: '#8a6a0a', deep: '#5a4505', soft: '#fce8a8', mid: '#f0c44c' },
    anom: { shades: ['#dceaff', '#b8d0f7', '#8fb0ec', '#6a90df'], edge: '#2c5fd6', side: '#1a3a8a',
            main: '#3a6fd6', dark: '#2c5fd6', darker: '#1a3a8a', deep: '#0f2a5c', soft: '#b8d0f7', mid: '#8fb0ec' }
};
function paletteForChar(char) {
    if (!char) return TILE_PALETTES.func;
    var tp = char.trackProgress || { func: 0, real: 0, anom: 0 };
    var max = Math.max(tp.func || 0, tp.real || 0, tp.anom || 0);
    if (max === 0) return TILE_PALETTES.func;
    if ((tp.anom || 0) === max) return TILE_PALETTES.anom;
    if ((tp.real || 0) === max) return TILE_PALETTES.real;
    return TILE_PALETTES.func;
}

function drawOffice(characters) {
    var canvas = document.getElementById('officeCanvas');
    var chars = sortChars(characters);  // 按当前排序模式重排

    var TW = 72, TD = 82;        // 单个工位占地（画布坐标）

    var isMobile = window.innerWidth < 768;
    // 工位缩放：电脑放大，手机缩小
    SCALE = isMobile ? 1.0 : 2.55;

    var SPREAD = TW + 6;         // 相邻工位 bx±/by∓ 步进（世界坐标）
    var VSTEP = TD + 24;         // 行距（世界坐标，bx,by 同步增加）

    // ===== 自适应每行工位数：根据容器宽度算每行能放几个，排满换行 =====
    // 单工位屏幕宽 ≈ (TW+TD)*cos30*SCALE + 缝隙
    var COS30 = 0.8660254;
    var wsScreenW = SPREAD * 2 * COS30 * SCALE + 8; // 相邻工位屏幕距 + 余量
    var containerW = (canvas.clientWidth || window.innerWidth) - 16;
    // 左右各留一个工位宽的空白（背景露出），所以可用宽度减去 2 个工位宽
    var availW = isMobile ? containerW : (containerW - wsScreenW * 2);
    var maxPerRow = Math.max(1, Math.floor(availW / wsScreenW));
    // 行工位数函数：N 和 N-1 交替（蜂窝交错，少的嵌在多的缝隙），手机至少 1-2
    var slotsForRow = isMobile
        ? function (row) { return (row % 2 === 0) ? 1 : 2; }
        : function (row) { return (row % 2 === 0) ? maxPerRow : Math.max(1, maxPerRow - 1); };

    var BASE_BX = 120, BASE_BY = 0;

    var bases = [];
    var idx = 0;
    var row = 0;
    while (idx < chars.length) {
        var slotsThisRow = slotsForRow(row);
        var cBx = BASE_BX + row * VSTEP;
        var cBy = BASE_BY + row * VSTEP;
        for (var s = 0; s < slotsThisRow && idx < chars.length; s++) {
            var char = chars[idx];
            idx++;
            var offsetUnit = s - (slotsThisRow - 1) / 2;
            var bx = cBx + offsetUnit * SPREAD;
            var by = cBy - offsetUnit * SPREAD;
            // 小幅抖动 ±4（有机感）
            bx += (Math.random() - 0.5) * 8;
            by += (Math.random() - 0.5) * 8;
            var palette = paletteForChar(char);
            bases.push({
                bx: bx, by: by,
                char: char, occupied: !!char,
                tileShade: char ? palette.shades[Math.floor(Math.random() * palette.shades.length)] : '#fafafa',
                tileEdge: char ? palette.edge : RED,
                tileSide: char ? palette.side : RED_DARKER,
                palette: palette  // 完整配色，传给 isoWorkstation
            });
        }
        row++;
    }

    // 第二步：地砖（拼图感不规则形状 + 厚度 + 阴影） + 桌子
    var tileItems = bases.map(function (b) {
        return { svg: drawPuzzleTile(b), depthKey: (b.bx + TW) + (b.by + TD) };
    });
    var deskItems = bases.map(function (b) {
        var ws = isoWorkstation(b.bx, b.by, b.occupied, b.char, b.palette);
        // data-char 存在头像 .ws-avatar 上（由 isoWorkstation 内部添加），外层 group 不存
        return { svg: '<g class="ws-group' + (b.occupied ? '' : ' ws-empty') + '">' + ws.svg + '</g>', depthKey: ws.depthKey };
    });
    tileItems.sort(function (a, b) { return a.depthKey - b.depthKey; });
    deskItems.sort(function (a, b) { return a.depthKey - b.depthKey; });

    // viewBox：遍历所有工位占地矩形的 4 个角（含椅子突出 + 高度），确保最边缘工位不被截断
    // 等距菱形屏幕边界由 4 角投影决定，必须全部 track
    var minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9;
    function track(x, y, z) {
        var p = iso(x, y, z);
        if (p[0] < minX) minX = p[0]; if (p[0] > maxX) maxX = p[0];
        if (p[1] < minY) minY = p[1]; if (p[1] > maxY) maxY = p[1];
    }
    var CHAIR_EXTEND = 60; // 椅子突出到 y+ 方向的最远距离（相对 by）
    bases.forEach(function (b) {
        var x0 = b.bx, x1 = b.bx + TW;
        var y0 = b.by, y1 = b.by + CHAIR_EXTEND;
        // 矩形 4 角，z=0（地面）和 z=60（顶部，含显示器/头像）
        track(x0, y0, 0); track(x1, y0, 0); track(x1, y1, 0); track(x0, y1, 0);
        track(x0, y0, 60); track(x1, y0, 60); track(x1, y1, 60); track(x0, y1, 60);
    });
    var pad = 56;   // viewBox 四周留白，覆盖拼图地块扰动+阴影，防止边缘被截
    var vbX = minX - pad, vbY = minY - pad;
    var vbW = (maxX - minX) + pad * 2, vbH = (maxY - minY) + pad * 2;

    // SVG：用真实像素尺寸（1 viewBox单位 = 1px），SCALE 直接控制工位大小
    // max-width:100% 防溢出，居中显示。绝不拉伸，避免溢出
    var svg = '<svg class="office-svg" viewBox="' + vbX + ' ' + vbY + ' ' + vbW + ' ' + vbH + '" width="' + vbW.toFixed(0) + '" height="' + vbH.toFixed(0) + '" preserveAspectRatio="xMidYMin meet">' +
        '<defs><filter id="tileShadow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur in="SourceGraphic" stdDeviation="3"/></filter></defs>' +
        tileItems.map(function (it) { return it.svg; }).join('') +
        deskItems.map(function (it) { return it.svg; }).join('') +
        '</svg>';

    canvas.innerHTML = svg;
    bindWorkstationHover();
}

// ===== 悬停/点击浮窗：只绑定到头像 .ws-avatar（避免整个工位触发跳动） =====
function bindWorkstationHover() {
    var avatars = document.querySelectorAll('.ws-avatar');
    var tooltip = document.getElementById('officeTooltip') || createTooltip();

    function fillAndShow(g) {
        var raw = g.getAttribute('data-char');
        if (!raw || raw === '') {
            tooltip.innerHTML = '<div class="office-tooltip-empty">无信息</div>';
        } else {
            try {
                var c = JSON.parse(raw);
                var missions = c.missions || [];
                var isMe = c.ownerId === uid;
                // 角色主题色（与地砖/桌椅同套配色）
                var P = paletteForChar(c);
                tooltip.style.borderColor = P.main;
                tooltip.style.boxShadow = '0 8px 24px ' + P.main + '30';
                // 三轴属性（职能/现实/异常），固定对应颜色色块
                var axisColor = { func: '#e63946', real: '#d4a017', anom: '#2c5fd6' };
                var axisRow = '<div class="office-axis-row">' +
                    '<span class="office-axis" style="border-color:' + axisColor.func + '"><i class="fas fa-briefcase" style="color:' + axisColor.func + '"></i> ' + escapeHtml(c.func || '---') + '</span>' +
                    '<span class="office-axis" style="border-color:' + axisColor.real + '"><i class="fas fa-fingerprint" style="color:' + axisColor.real + '"></i> ' + escapeHtml(c.real || '---') + '</span>' +
                    '<span class="office-axis" style="border-color:' + axisColor.anom + '"><i class="fas fa-bolt" style="color:' + axisColor.anom + '"></i> ' + escapeHtml(c.anom || '---') + '</span>' +
                    '</div>';
                // 统计三栏（MVP 数值用主题色高亮）
                var statsRow = '<div class="office-stats">' +
                    '<div class="office-stat"><span class="v" style="color:' + P.main + '">' + (c.mvpCount || 0) + '</span><span class="l">MVP</span></div>' +
                    '<div class="office-stat"><span class="v">' + (c.watchCount || 0) + '</span><span class="l">察看期</span></div>' +
                    '<div class="office-stat"><span class="v">' + missions.length + '</span><span class="l">出勤</span></div>' +
                    '</div>';
                // 全部模组列表（用角色主题色）
                var missionHtml = missions.length
                    ? '<div class="office-missions">' + missions.map(function (m) { return '<span class="office-mission-tag" style="background:' + P.main + '1a;color:' + P.dark + '">' + escapeHtml(m) + '</span>'; }).join('') + '</div>'
                    : '<div class="office-missions-empty">暂无模组记录</div>';
                // 签名（plazaMessage），本人显示编辑按钮；左边框用主题色
                var sigHtml = c.plazaMessage
                    ? '<div class="office-sig" style="border-left-color:' + P.main + '">' + escapeHtml(c.plazaMessage) + '</div>'
                    : '<div class="office-sig office-sig-empty" style="border-left-color:' + P.main + '50">' + (isMe ? '点击编辑添加签名' : '这个人很神秘') + '</div>';
                var editBtn = isMe ? '<button class="office-sig-edit" data-edit-id="' + escapeHtml(c.id) + '" style="color:' + P.main + ';border-color:' + P.main + '50"><i class="fas fa-pencil-alt"></i></button>' : '';

                tooltip.innerHTML =
                    '<div class="office-tip-name">' + escapeHtml(c.name) + '</div>' +
                    axisRow +
                    statsRow +
                    '<div class="office-tip-label">经历模组</div>' + missionHtml +
                    '<div class="office-tip-label">签名 ' + editBtn + '</div>' + sigHtml;
                // 绑定签名编辑按钮
                var editEl = tooltip.querySelector('.office-sig-edit');
                if (editEl) editEl.onclick = function () { openOfficeSigEdit(c.id); };
            } catch (e) { tooltip.innerHTML = '<div class="office-tip-name">?</div>'; }
        }
        tooltip.classList.add('show');
        positionTooltip(tooltip, g);
    }

    avatars.forEach(function (g) {
        g.style.cursor = 'pointer';
        // 电脑端：悬停显示，离开隐藏
        g.addEventListener('mouseenter', function () { fillAndShow(g); });
        g.addEventListener('mouseleave', function () { tooltip.classList.remove('show'); });
        // 点击/触摸：显示（不切换，避免 mouseenter+click 冲突关闭）
        g.addEventListener('click', function (e) {
            e.stopPropagation();
            fillAndShow(g);
        });
    });

    // 点击空白处关闭浮窗（手机端尤其需要）
    document.addEventListener('click', function (e) {
        if (!e.target.closest('.ws-avatar') && !e.target.closest('#officeTooltip')) {
            tooltip.classList.remove('show');
        }
    });
}

function createTooltip() {
    var t = document.createElement('div');
    t.className = 'office-tooltip';
    t.id = 'officeTooltip';
    document.body.appendChild(t);
    return t;
}

// ===== 签名编辑（复用 plazaMessage 接口，本人可编辑） =====
var editingOfficeChar = null;
function ensureOfficeEditModal() {
    if (document.getElementById('officeEditModal')) return document.getElementById('officeEditModal');
    var m = document.createElement('div');
    m.className = 'office-modal-overlay';
    m.id = 'officeEditModal';
    m.innerHTML =
        '<div class="office-modal">' +
            '<div class="office-modal-title">编辑签名</div>' +
            '<textarea class="office-modal-input" id="officeSigInput" maxlength="300" placeholder="写一句签名吧（他人可见）..."></textarea>' +
            '<div class="office-modal-hint"><span id="officeSigCount">0</span>/300</div>' +
            '<div class="office-modal-actions">' +
                '<button class="office-modal-btn cancel" onclick="closeOfficeSigEdit()">取消</button>' +
                '<button class="office-modal-btn save" onclick="saveOfficeSigEdit()">保存</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(m);
    var input = m.querySelector('#officeSigInput');
    input.oninput = function () { document.getElementById('officeSigCount').textContent = input.value.length; };
    return m;
}
function openOfficeSigEdit(charId) {
    var c = loadedChars.find(function (x) { return x.id === charId; });
    if (!c) return;
    editingOfficeChar = c;
    var modal = ensureOfficeEditModal();
    var input = document.getElementById('officeSigInput');
    input.value = c.plazaMessage || '';
    document.getElementById('officeSigCount').textContent = input.value.length;
    modal.classList.add('show');
    setTimeout(function () { input.focus(); }, 50);
}
function closeOfficeSigEdit() {
    document.getElementById('officeEditModal').classList.remove('show');
    editingOfficeChar = null;
}
async function saveOfficeSigEdit() {
    if (!editingOfficeChar) return;
    var message = document.getElementById('officeSigInput').value;
    try {
        var res = await fetch('/api/character/' + editingOfficeChar.id + '/plaza-message', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ message: message })
        });
        var data = await res.json();
        if (res.ok && data.success) {
            var editedId = editingOfficeChar.id;
            var idx = loadedChars.findIndex(function (x) { return x.id === editedId; });
            if (idx !== -1) loadedChars[idx].plazaMessage = data.message;
            // 同步 DOM 上头像的 data-char，让重新悬停读到新签名
            var av = document.querySelector('.ws-avatar[data-char-id="' + editedId + '"]');
            if (av && idx !== -1) av.setAttribute('data-char', JSON.stringify(loadedChars[idx]));
            closeOfficeSigEdit();
            // 若浮窗正显示该角色，立即刷新
            var tip = document.getElementById('officeTooltip');
            if (tip.classList.contains('show') && av) {
                tip.classList.remove('show');
                av.dispatchEvent(new Event('mouseenter'));
            }
            if (typeof showToast === 'function') showToast('签名已保存', 'success');
        } else {
            if (typeof showToast === 'function') showToast(data.message || '保存失败');
        }
    } catch (e) {
        console.error('保存签名失败:', e);
        if (typeof showToast === 'function') showToast('保存失败');
    }
}
function positionTooltip(tooltip, anchor) {
    var rect = anchor.getBoundingClientRect();
    var tw = tooltip.offsetWidth || 220, th = tooltip.offsetHeight || 120;
    var left = rect.right + 10;
    if (left + tw > window.innerWidth - 8) left = rect.left - tw - 10;
    if (left < 8) left = Math.max(8, (window.innerWidth - tw) / 2);
    var top = rect.top + rect.height / 2 - th / 2;
    if (top < 70) top = 70;
    if (top + th > window.innerHeight - 8) top = window.innerHeight - th - 8;
    tooltip.style.left = left + 'px'; tooltip.style.top = top + 'px';
}

var canvasEl = document.querySelector('.office-canvas');
if (canvasEl) canvasEl.addEventListener('scroll', function () {
    var t = document.getElementById('officeTooltip'); if (t) t.classList.remove('show');
});

var loadedChars = null; // 缓存已加载角色，供 resize 重绘
async function loadCharacters() {
    var currentBranchId = localStorage.getItem('ta_plaza_branch');
    if (!currentBranchId) {
        document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#999;"><i class="fas fa-circle-notch fa-spin"></i> 正在加载分部...</div>';
        return;
    }
    document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#999;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    try {
        var res = await fetch('/api/plaza/characters?branchId=' + currentBranchId, { headers: { 'Authorization': 'Bearer ' + token } });
        if (res.status === 401 || res.status === 403) { goBack(); return; }
        var data = await res.json();
        loadedChars = data;
        drawOffice(data);
    } catch (e) {
        console.error('加载失败:', e);
        document.getElementById('officeCanvas').innerHTML = '<div style="padding:40px;text-align:center;color:#e63946;">加载失败</div>';
    }
}

// 排序状态：mvp / watch / mission
var sortMode = localStorage.getItem('ta_office_sort') || 'mvp';
function setSortMode(mode) {
    sortMode = mode;
    localStorage.setItem('ta_office_sort', mode);
    document.querySelectorAll('.office-sort-btn').forEach(function (b) {
        b.classList.toggle('active', b.dataset.mode === mode);
    });
    if (loadedChars) drawOffice(loadedChars);
}
function sortChars(chars) {
    var arr = chars.slice();
    arr.sort(function (a, b) {
        if (sortMode === 'mvp') return (b.mvpCount || 0) - (a.mvpCount || 0);
        if (sortMode === 'watch') return (b.watchCount || 0) - (a.watchCount || 0);
        if (sortMode === 'mission') return ((b.missions ? b.missions.length : 0) - (a.missions ? a.missions.length : 0)) || ((b.mvpCount || 0) - (a.mvpCount || 0));
        return 0;
    });
    return arr;
}

function addLegend() {
    if (document.querySelector('.office-legend')) return;
    var legend = document.createElement('div');
    legend.className = 'office-legend';
    legend.innerHTML =
        '<div class="office-legend-title">排序</div>' +
        '<div class="office-sort-btns">' +
            '<button class="office-sort-btn' + (sortMode === 'mvp' ? ' active' : '') + '" data-mode="mvp" onclick="setSortMode(\'mvp\')"><i class="fas fa-medal"></i> MVP</button>' +
            '<button class="office-sort-btn' + (sortMode === 'watch' ? ' active' : '') + '" data-mode="watch" onclick="setSortMode(\'watch\')"><i class="fas fa-eye"></i> 察看期</button>' +
            '<button class="office-sort-btn' + (sortMode === 'mission' ? ' active' : '') + '" data-mode="mission" onclick="setSortMode(\'mission\')"><i class="fas fa-tasks"></i> 出勤</button>' +
        '</div>' +
        '<div class="office-legend-title" style="margin-top:8px;">分部</div>' +
        '<div id="officeBranchSelector" class="office-branch-selector"></div>' +
        '<div class="office-action-btns">' +
            '<button class="office-action-btn" onclick="locateMe()"><i class="fas fa-crosshairs"></i> 定位自己</button>' +
            '<button class="office-action-btn" onclick="editMySig()"><i class="fas fa-signature"></i> 我的签名</button>' +
        '</div>';
    document.body.appendChild(legend);
    loadBranches();
}

// ===== 分部切换（复用 /api/user/my-branches 或 /api/admin/branches） =====
var myBranches = [];
async function loadBranches() {
    var container = document.getElementById('officeBranchSelector');
    if (!container) return;
    try {
        var userRole = parseInt(localStorage.getItem('ta_role') || '0');
        var res;
        if (userRole >= 2) {
            res = await fetch('/api/admin/branches', { headers: { 'Authorization': 'Bearer ' + token } });
        } else {
            res = await fetch('/api/user/my-branches', { headers: { 'Authorization': 'Bearer ' + token } });
        }
        if (!res.ok) return;
        var data = await res.json();
        myBranches = data.branches || [];
        // 没有当前分部 → 自动选第一个
        var currentBranchId = localStorage.getItem('ta_plaza_branch');
        if ((!currentBranchId || !myBranches.some(function (b) { return b.id === currentBranchId; })) && myBranches.length > 0) {
            localStorage.setItem('ta_plaza_branch', myBranches[0].id);
        }
        renderBranchSelector();
        // 分部就绪后加载角色
        if (loadedChars === null) loadCharacters();
    } catch (e) { console.error('加载分部失败:', e); }
}
function renderBranchSelector() {
    var container = document.getElementById('officeBranchSelector');
    if (!container) return;
    container.innerHTML = '';
    var currentBranchId = localStorage.getItem('ta_plaza_branch');
    var current = myBranches.find(function (b) { return b.id === currentBranchId; });
    var btn = document.createElement('button');
    btn.className = 'office-branch-btn';
    btn.innerHTML = '<i class="fas fa-building"></i> ' + escapeHtml(current ? current.name : '选择分部') + ' <i class="fas fa-chevron-down" style="font-size:9px;opacity:0.5;"></i>';
    var dropdown = document.createElement('div');
    dropdown.className = 'office-branch-dropdown';
    myBranches.forEach(function (b) {
        var item = document.createElement('div');
        item.className = 'office-branch-item' + (b.id === currentBranchId ? ' active' : '');
        item.textContent = b.name;
        item.onmousedown = function (e) {
            e.preventDefault();
            localStorage.setItem('ta_plaza_branch', b.id);
            dropdown.style.display = 'none';
            renderBranchSelector();
            loadCharacters();
        };
        dropdown.appendChild(item);
    });
    container.appendChild(btn);
    container.appendChild(dropdown);
    btn.onclick = function (e) {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
    };
    document.addEventListener('click', function () { dropdown.style.display = 'none'; }, { once: true });
}

// 找到当前用户的所有角色（uid 是字符串，ownerId 可能是数字，统一 String 比较）
function myCharacters() {
    if (!loadedChars) return [];
    return loadedChars.filter(function (c) { return String(c.ownerId) === String(uid); });
}

// 定位到自己的工位（多个角色则循环定位下一个）
var locateMeIdx = 0;
function locateMe() {
    var mine = myCharacters();
    if (!mine.length) { showToast('当前分部没有你的角色'); return; }
    var target = mine[locateMeIdx % mine.length];
    locateMeIdx++;
    var av = document.querySelector('.ws-avatar[data-char-id="' + target.id + '"]');
    if (!av) { showToast('未找到工位：' + (target.name || '')); return; }
    var rect = av.getBoundingClientRect();
    var canvas = document.getElementById('officeCanvas');
    canvas.scrollTop += rect.top + rect.height / 2 - canvas.clientHeight / 2;
    av.classList.add('ws-avatar-flash');
    setTimeout(function () { av.classList.remove('ws-avatar-flash'); }, 1500);
    if (mine.length > 1) showToast('定位到 ' + (target.name || '') + ' (' + (locateMeIdx % mine.length || mine.length) + '/' + mine.length + ')');
}

// 修改自己的签名：多个角色弹选择列表，单个直接编辑
function editMySig() {
    var mine = myCharacters();
    if (!mine.length) { showToast('当前分部没有你的角色'); return; }
    if (mine.length === 1) { openOfficeSigEdit(mine[0].id); return; }
    // 多个角色：弹选择列表
    var list = mine.map(function (c) {
        var sig = c.plazaMessage ? escapeHtml(c.plazaMessage.length > 20 ? c.plazaMessage.slice(0, 20) + '…' : c.plazaMessage) : '<span style="color:#bbb;">未设置</span>';
        return '<div class="office-sig-pick" data-id="' + escapeHtml(c.id) + '">' +
            '<span class="office-sig-pick-name">' + escapeHtml(c.name || '未命名') + '</span>' +
            '<span class="office-sig-pick-sig">' + sig + '</span></div>';
    }).join('');
    showSigPickModal(list);
}

function showSigPickModal(listHtml) {
    var m = document.getElementById('officeSigPickModal');
    if (!m) {
        m = document.createElement('div');
        m.id = 'officeSigPickModal';
        m.className = 'office-modal-overlay';
        document.body.appendChild(m);
    }
    m.innerHTML =
        '<div class="office-modal">' +
            '<div class="office-modal-title">选择角色编辑签名</div>' +
            '<div class="office-sig-pick-list">' + listHtml + '</div>' +
            '<div class="office-modal-actions"><button class="office-modal-btn cancel" onclick="document.getElementById(\'officeSigPickModal\').classList.remove(\'show\')">关闭</button></div>' +
        '</div>';
    m.classList.add('show');
    m.querySelectorAll('.office-sig-pick').forEach(function (el) {
        el.onclick = function () {
            m.classList.remove('show');
            openOfficeSigEdit(el.getAttribute('data-id'));
        };
    });
}

// 布局依赖屏幕宽度（手机2个/电脑3-4），窗口变化时重新生成布局（debounce）
var officeResizeTimer = null;
window.addEventListener('resize', function () {
    if (!loadedChars) return;
    if (officeResizeTimer) clearTimeout(officeResizeTimer);
    officeResizeTimer = setTimeout(function () { drawOffice(loadedChars); }, 200);
});

// 初始化：先建面板（含分部选择器），loadBranches 会自动选分部并触发 loadCharacters
addLegend();
