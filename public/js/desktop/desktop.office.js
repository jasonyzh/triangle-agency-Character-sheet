/* 办公室（office.html 移植为桌面应用窗口）：等距 SVG 工位平面图 + 悬停信息卡
   + 排序（MVP/察看期/出勤）+ 分部切换（联动桌面开始菜单）+ 定位自己 + 签名编辑 */
(function () {
  'use strict';

  var $ = DA.$, esc = DA.esc, showToast = DA.showToast;
  function authH() { return window.DESKTOP.authHeaders(); }
  /* 属性值转义：在 esc 基础上多转义双引号（data-char 存 JSON 必需） */
  function escQ(s) { return esc(s).replace(/"/g, '&quot;'); }

  var uid = localStorage.getItem('ta_uid');

  /* ===== 视觉常量（对齐桌面红 #d8402f） ===== */
  var RED = '#d8402f';
  var RED_DARK = '#b5301f';
  var RED_DARKER = '#8f1f12';
  var RED_SOFT = '#fbe4e0';
  var RED_MID = '#f2b3a8';
  var INK = '#1a1a1a';
  var WHITE = '#ffffff';

  var COS30 = 0.8660254;
  var SIN30 = 0.5;
  var SCALE = 2.55;
  function iso(x, y, z) {
    return [(x - y) * COS30 * SCALE, ((x + y) * SIN30 - z) * SCALE];
  }

  /* 画一个等距立方体（box），返回 3 个可见面（顶/左/右）+ 深度排序键 */
  function isoBox(x, y, z, w, d, h, colors, stroke) {
    var bA = iso(x, y, z), bB = iso(x + w, y, z), bC = iso(x + w, y + d, z), bD = iso(x, y + d, z);
    var tA = iso(x, y, z + h), tB = iso(x + w, y, z + h), tC = iso(x + w, y + d, z + h), tD = iso(x, y + d, z + h);
    var s = stroke ? (' stroke="' + stroke + '" stroke-width="1" stroke-linejoin="round"') : '';
    var right = '<polygon points="' + bB.join(',') + ' ' + bC.join(',') + ' ' + tC.join(',') + ' ' + tB.join(',') + '" fill="' + colors.right + '"' + s + '/>';
    var left = '<polygon points="' + bD.join(',') + ' ' + bC.join(',') + ' ' + tC.join(',') + ' ' + tD.join(',') + '" fill="' + colors.left + '"' + s + '/>';
    var top = '<polygon points="' + tA.join(',') + ' ' + tB.join(',') + ' ' + tC.join(',') + ' ' + tD.join(',') + '" fill="' + colors.top + '"' + s + '/>';
    return { svg: right + left + top, depthKey: (x + w) + (y + d) };
  }

  /* 画一个工位（桌子+显示器+椅子+键盘+头像），x,y 为地面网格左后角 */
  function isoWorkstation(x, y, occupied, char, C) {
    C = C || { main: RED, dark: RED_DARK, darker: RED_DARKER, deep: '#6f150a', soft: RED_SOFT, mid: RED_MID };
    var parts = [];

    var DW = 60, DD = 34, DH = 30;
    var DX = x + 2, DY = y + 2;
    var CW = 18, CD = 18;
    var CX = x + (DW + 4 - CW) / 2 + 2;
    var CY = DY + DD + 6;

    /* 椅子（五星脚 + 中柱 + 座垫 + 椅背） */
    var chairColors = { top: WHITE, left: C.mid, right: C.dark };
    var chairBackColors = { top: C.soft, left: C.dark, right: C.darker };
    var stemColors = { top: INK, left: '#333', right: '#222' };
    parts.push(isoBox(CX + 1, CY + 1, 0, CW - 2, CD - 2, 2, stemColors));
    parts.push(isoBox(CX + CW / 2 - 2, CY + CD / 2 - 2, 2, 4, 4, 13, stemColors));
    parts.push(isoBox(CX, CY, 15, CW, CD, 3, chairColors, C.main));
    parts.push(isoBox(CX, CY + CD - 3, 18, CW, 3, 16, chairBackColors, C.main));

    /* 桌腿 ×4 + 桌面 */
    var legColors = { top: C.dark, left: C.darker, right: C.deep };
    var LT = 3;
    parts.push(isoBox(DX, DY, 0, LT, LT, DH, legColors));
    parts.push(isoBox(DX + DW - LT, DY, 0, LT, LT, DH, legColors));
    parts.push(isoBox(DX, DY + DD - LT, 0, LT, LT, DH, legColors));
    parts.push(isoBox(DX + DW - LT, DY + DD - LT, 0, LT, LT, DH, legColors));
    var deskColors = occupied
      ? { top: WHITE, left: C.soft, right: C.mid }
      : { top: '#fafafa', left: '#f0f0f0', right: '#e8e8e8' };
    parts.push(isoBox(DX, DY, DH, DW, DD, 3, deskColors, C.main));

    /* 桌面装饰倒三角（机构 logo） */
    var tcx = DX + DW / 2, tcy = DY + 10;
    var triA = iso(tcx - 8, tcy + 5, DH + 3.1);
    var triB = iso(tcx + 8, tcy + 5, DH + 3.1);
    var triC = iso(tcx, tcy - 7, DH + 3.1);
    parts.push({
      svg: '<polygon points="' + triC.join(',') + ' ' + triA.join(',') + ' ' + triB.join(',') + '" fill="' + (occupied ? C.main : '#ddd') + '"/>',
      depthKey: DX + DY + 1000
    });

    /* 显示器：底座 + 支架 + 屏幕（正面朝椅子/观察者） */
    var monCx = DX + DW / 2;
    var monBaseY = DY + 6;
    var monZ = DH + 3;
    var monW = 24, monThick = 2.5, monH = 20;
    var screenZ = monZ + 5;
    parts.push(isoBox(monCx - 5, monBaseY, monZ, 10, 6, 1.5, { top: C.dark, left: C.darker, right: C.deep }, C.main));
    parts.push(isoBox(monCx - 1, monBaseY + 1.5, monZ + 1.5, 2, 2, 4, { top: '#444', left: '#333', right: '#222' }));

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

    /* 键盘 */
    var kbY = DY + DD - 14;
    parts.push(isoBox(DX + DW / 2 - 9, kbY, DH + 3, 18, 8, 1, { top: INK, left: '#333', right: '#222' }, C.main));

    /* 角色头像（首字圆框或图片，悬浮于桌椅之间上方）；data-char 存此，悬停只绑头像 */
    if (occupied && char) {
      var first = (char.name || '?').trim().charAt(0) || '?';
      var avR = SCALE < 1.5 ? 16 : 30;
      var center = iso(DX + DW / 2, CY + CD / 2, 50);
      var clipId = 'avclip_' + char.id;
      var innerAvatar;
      if (char.pAvatar) {
        var avaUrl = char.pAvatar.indexOf('http') === 0 ? char.pAvatar : '/' + char.pAvatar;
        if (window.DA.avaSrc) avaUrl = window.DA.avaSrc(avaUrl);
          innerAvatar = '<clipPath id="' + clipId + '"><circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '"/></clipPath>' +
          '<image href="' + escQ(avaUrl) + '" x="' + (center[0] - avR) + '" y="' + (center[1] - avR) + '" width="' + (avR * 2) + '" height="' + (avR * 2) + '" clip-path="url(#' + clipId + ')" pointer-events="none" preserveAspectRatio="xMidYMid slice"/>' +
          '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '" fill="none" stroke="' + C.dark + '" stroke-width="4" pointer-events="none"/>';
      } else {
        innerAvatar = '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + avR + '" fill="' + WHITE + '" stroke="' + C.dark + '" stroke-width="4" pointer-events="none"/>' +
          '<text x="' + center[0] + '" y="' + center[1] + '" text-anchor="middle" dominant-baseline="central" font-size="' + Math.round(avR * 1.27) + '" font-weight="800" fill="' + C.dark + '" font-family="PingFang SC, Microsoft YaHei, sans-serif" pointer-events="none">' + esc(first) + '</text>';
      }
      var nameY = center[1] + avR + 18;
      var nameSize = SCALE < 1.5 ? 9 : 13;
      var nameText = esc((char.name || '').length > 6 ? (char.name || '').slice(0, 6) + '…' : (char.name || ''));
      parts.push({
        svg: '<g class="ws-avatar" data-char="' + escQ(JSON.stringify(char)) + '" data-char-id="' + escQ(char.id) + '">' +
          '<circle cx="' + center[0] + '" cy="' + center[1] + '" r="' + (avR + 14) + '" fill="transparent" pointer-events="all"/>' +
          innerAvatar +
          '<text x="' + center[0] + '" y="' + nameY + '" text-anchor="middle" font-size="' + nameSize + '" font-weight="700" fill="#fff" stroke="#000" stroke-width="2.5" paint-order="stroke" font-family="PingFang SC, Microsoft YaHei, sans-serif" pointer-events="none">' + nameText + '</text>' +
          '</g>',
        depthKey: DX + DY + 1002
      });
    }

    parts.sort(function (a, b) { return a.depthKey - b.depthKey; });
    return { svg: parts.map(function (p) { return p.svg; }).join(''), depthKey: (CX + CW) + (CY + CD) };
  }

  /* 确定性伪随机（同一地砖每次重绘形状一致） */
  function seededRand(seed) {
    var x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
  }

  /* 拼图感地砖：不规则顶面 + 厚度侧面 + 投影阴影 */
  function drawPuzzleTile(b) {
    var TW = 72, TD = 82, THICK = 8;
    var x0 = b.bx, x1 = b.bx + TW, y0 = b.by, y1 = b.by + TD;
    var seed = Math.abs(b.bx * 13 + b.by * 7);
    function jitterEdge(ax, ay, bx, by, segSeed, depth) {
      var mx = (ax + bx) / 2, my = (ay + by) / 2;
      var dx = bx - ax, dy = by - ay;
      var len = Math.sqrt(dx * dx + dy * dy) || 1;
      var nx = -dy / len, ny = dx / len;
      var amp = (seededRand(segSeed) - 0.5) * 2 * depth;
      mx += nx * amp; my += ny * amp;
      return [mx, my];
    }
    var pts = [];
    var depth = 7;
    var corners = [[x0, y0], [x1, y0], [x1, y1], [x0, y1]];
    for (var i = 0; i < 4; i++) {
      var c0 = corners[i], c1 = corners[(i + 1) % 4];
      pts.push(c0);
      pts.push(jitterEdge(c0[0], c0[1], c1[0], c1[1], seed + i * 31, depth));
    }
    var topPts = pts.map(function (p) { return iso(p[0], p[1], THICK); });
    var botPts = pts.map(function (p) { return iso(p[0], p[1], 0); });
    var topPolyStr = topPts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
    var shadowOffset = 6;
    var shadowStr = topPts.map(function (p) { return (p[0] + shadowOffset).toFixed(1) + ',' + (p[1] + shadowOffset).toFixed(1); }).join(' ');
    var shadow = '<polygon points="' + shadowStr + '" fill="#000" opacity="0.18" filter="url(#tileShadow)"/>';
    var sidePoly = botPts.concat(topPts.slice().reverse()).map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
    var side = '<polygon points="' + sidePoly + '" fill="' + b.tileSide + '" opacity="0.55"/>';
    var top = '<polygon points="' + topPolyStr + '" fill="' + b.tileShade + '" stroke="' + b.tileEdge + '" stroke-width="1.2" opacity="0.85"/>';
    return shadow + side + top;
  }

  /* 三套配色（地砖+桌椅+信息卡）：按进度追踪最多项选择 红=职能 黄=现实 蓝=异常 */
  var TILE_PALETTES = {
    func: { shades: ['#fde8eb', '#f9cdd2', '#f4b0b8', '#ef9aa4'], edge: RED, side: RED_DARKER,
            main: RED, dark: RED_DARK, darker: RED_DARKER, deep: '#6f150a', soft: RED_SOFT, mid: RED_MID },
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
    var canvas = $('officeCanvas');
    var chars = sortChars(characters);

    var TW = 72, TD = 82;
    var isMobile = window.innerWidth < 860;
    SCALE = isMobile ? 1.0 : 2.55;

    var SPREAD = TW + 6;
    var VSTEP = TD + 24;

    var COS = 0.8660254;
    var SPACING = SPREAD * 2 * COS * SCALE;       /* 相邻工位屏幕间距 */
    var tileScreenW = (TW + TD) * COS * SCALE;    /* 单工位（含地砖）屏幕宽 */
    var containerW = (canvas.clientWidth || window.innerWidth) - 16;
    /* 整行跨度 = (N-1)*SPACING + tileScreenW，电脑端左右各留 16px 即可
       （旧版预留两个工位宽，1280 下每行只剩 1 个、空间浪费）；上限 5 防止过宽屏排太密 */
    var availW = isMobile ? containerW : Math.max(containerW - 32, tileScreenW);
    var maxPerRow = Math.min(5, Math.max(1, Math.floor((availW - tileScreenW) / SPACING) + 1));
    var slotsForRow = isMobile
      ? function (row) { return (row % 2 === 0) ? 1 : 2; }
      : function (row) { return (row % 2 === 0) ? maxPerRow : Math.max(1, maxPerRow - 1); };

    var BASE_BX = 120, BASE_BY = 0;
    var bases = [];
    var idx = 0, row = 0;
    while (idx < chars.length) {
      var slotsThisRow = slotsForRow(row);
      var cBx = BASE_BX + row * VSTEP;
      var cBy = BASE_BY + row * VSTEP;
      for (var s = 0; s < slotsThisRow && idx < chars.length; s++) {
        var char = chars[idx];
        idx++;
        var offsetUnit = s - (slotsThisRow - 1) / 2;
        var bx = cBx + offsetUnit * SPREAD + (Math.random() - 0.5) * 8;
        var by = cBy - offsetUnit * SPREAD + (Math.random() - 0.5) * 8;
        var palette = paletteForChar(char);
        bases.push({
          bx: bx, by: by, char: char, occupied: !!char,
          tileShade: char ? palette.shades[Math.floor(Math.random() * palette.shades.length)] : '#fafafa',
          tileEdge: char ? palette.edge : RED,
          tileSide: char ? palette.side : RED_DARKER,
          palette: palette
        });
      }
      row++;
    }

    var tileItems = bases.map(function (b) {
      return { svg: drawPuzzleTile(b), depthKey: (b.bx + TW) + (b.by + TD) };
    });
    var deskItems = bases.map(function (b) {
      var ws = isoWorkstation(b.bx, b.by, b.occupied, b.char, b.palette);
      return { svg: '<g class="ws-group' + (b.occupied ? '' : ' ws-empty') + '">' + ws.svg + '</g>', depthKey: ws.depthKey };
    });
    tileItems.sort(function (a, b) { return a.depthKey - b.depthKey; });
    deskItems.sort(function (a, b) { return a.depthKey - b.depthKey; });

    /* viewBox：遍历所有工位占地矩形 4 角（含椅子突出+高度），确保边缘不被截断 */
    var minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9;
    function track(x, y, z) {
      var p = iso(x, y, z);
      if (p[0] < minX) minX = p[0]; if (p[0] > maxX) maxX = p[0];
      if (p[1] < minY) minY = p[1]; if (p[1] > maxY) maxY = p[1];
    }
    var CHAIR_EXTEND = 60;
    bases.forEach(function (b) {
      var x0 = b.bx, x1 = b.bx + TW;
      var y0 = b.by, y1 = b.by + CHAIR_EXTEND;
      track(x0, y0, 0); track(x1, y0, 0); track(x1, y1, 0); track(x0, y1, 0);
      track(x0, y0, 60); track(x1, y0, 60); track(x1, y1, 60); track(x0, y1, 60);
    });
    var pad = 56;
    var vbX = minX - pad, vbY = minY - pad;
    var vbW = (maxX - minX) + pad * 2, vbH = (maxY - minY) + pad * 2;

    var svg = '<svg class="office-svg" viewBox="' + vbX + ' ' + vbY + ' ' + vbW + ' ' + vbH + '" width="' + vbW.toFixed(0) + '" height="' + vbH.toFixed(0) + '" preserveAspectRatio="xMidYMin meet">' +
      '<defs><filter id="tileShadow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur in="SourceGraphic" stdDeviation="3"/></filter></defs>' +
      tileItems.map(function (it) { return it.svg; }).join('') +
      deskItems.map(function (it) { return it.svg; }).join('') +
      '</svg>';

    canvas.innerHTML = svg;
    bindWorkstationHover();
  }

  /* ===== 悬停/点击信息卡（只绑头像，避免整个工位触发） ===== */
  function ensureTooltip() {
    var t = document.getElementById('officeTooltip');
    if (!t) {
      t = document.createElement('div');
      t.className = 'office-tooltip';
      t.id = 'officeTooltip';
      document.body.appendChild(t);
    }
    return t;
  }

  function bindWorkstationHover() {
    var tooltip = ensureTooltip();
    function fillAndShow(g) {
      var raw = g.getAttribute('data-char');
      if (!raw || raw === '') {
        tooltip.innerHTML = '<div class="office-tooltip-empty">无信息</div>';
      } else {
        try {
          var c = JSON.parse(raw);
          var missions = c.missions || [];
          var isMe = String(c.ownerId) === String(uid);
          var P = paletteForChar(c);
          tooltip.style.borderColor = P.main;
          tooltip.style.boxShadow = '0 8px 24px ' + P.main + '30';
          var axisColor = { func: '#d8402f', real: '#d4a017', anom: '#2c5fd6' };
          var axisRow = '<div class="office-axis-row">' +
            '<span class="office-axis" style="border-color:' + axisColor.func + '"><i class="fas fa-briefcase" style="color:' + axisColor.func + '"></i> ' + esc(c.func || '---') + '</span>' +
            '<span class="office-axis" style="border-color:' + axisColor.real + '"><i class="fas fa-fingerprint" style="color:' + axisColor.real + '"></i> ' + esc(c.real || '---') + '</span>' +
            '<span class="office-axis" style="border-color:' + axisColor.anom + '"><i class="fas fa-bolt" style="color:' + axisColor.anom + '"></i> ' + esc(c.anom || '---') + '</span>' +
            '</div>';
          var statsRow = '<div class="office-stats">' +
            '<div class="office-stat"><span class="v" style="color:' + P.main + '">' + (c.mvpCount || 0) + '</span><span class="l">MVP</span></div>' +
            '<div class="office-stat"><span class="v">' + (c.watchCount || 0) + '</span><span class="l">察看期</span></div>' +
            '<div class="office-stat"><span class="v">' + missions.length + '</span><span class="l">出勤</span></div>' +
            '</div>';
          var missionHtml = missions.length
            ? '<div class="office-missions">' + missions.map(function (m) { return '<span class="office-mission-tag" style="background:' + P.main + '1a;color:' + P.dark + '">' + esc(m) + '</span>'; }).join('') + '</div>'
            : '<div class="office-missions-empty">暂无模组记录</div>';
          var sigHtml = c.plazaMessage
            ? '<div class="office-sig" style="border-left-color:' + P.main + '">' + esc(c.plazaMessage) + '</div>'
            : '<div class="office-sig office-sig-empty" style="border-left-color:' + P.main + '50">' + (isMe ? '点击编辑添加签名' : '这个人很神秘') + '</div>';
          var editBtn = isMe ? '<button class="office-sig-edit" data-edit-id="' + escQ(c.id) + '" style="color:' + P.main + ';border-color:' + P.main + '50"><i class="fas fa-pencil-alt"></i></button>' : '';
          tooltip.innerHTML =
            '<div class="office-tip-name">' + esc(c.name) + '</div>' +
            axisRow + statsRow +
            '<div class="office-tip-label">经历模组</div>' + missionHtml +
            '<div class="office-tip-label">签名 ' + editBtn + '</div>' + sigHtml;
          var editEl = tooltip.querySelector('.office-sig-edit');
          if (editEl) editEl.onclick = function () { openSigEdit(c.id); };
        } catch (e) { tooltip.innerHTML = '<div class="office-tip-name">?</div>'; }
      }
      tooltip.classList.add('show');
      positionTooltip(tooltip, g);
    }

    Array.prototype.forEach.call(document.querySelectorAll('#officeCanvas .ws-avatar'), function (g) {
      g.style.cursor = 'pointer';
      g.style.touchAction = 'manipulation';
      g.addEventListener('mouseenter', function () { fillAndShow(g); });
      g.addEventListener('mouseleave', function () { tooltip.classList.remove('show'); });
      g.addEventListener('pointerdown', function (e) {
        e.preventDefault();
        e.stopPropagation();
        fillAndShow(g);
      });
      g.addEventListener('touchstart', function (e) {
        e.preventDefault();
        e.stopPropagation();
        fillAndShow(g);
      }, { passive: false });
    });
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
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
  }

  /* 滚动/点击空白处隐藏浮窗（只在 start 时绑一次） */
  function bindGlobalDismiss() {
    var canvas = $('officeCanvas');
    canvas.addEventListener('scroll', function () {
      var t = document.getElementById('officeTooltip');
      if (t) t.classList.remove('show');
    });
    document.addEventListener('pointerdown', function (e) {
      var t = document.getElementById('officeTooltip');
      if (t && t.classList.contains('show') && !e.target.closest('.ws-avatar') && !e.target.closest('#officeTooltip')) {
        t.classList.remove('show');
      }
    }, { passive: true });
  }

  /* ===== 数据加载（分部用桌面当前分部 ta_current_branch） ===== */
  var loadedChars = null;
  function curBranchId() { return localStorage.getItem('ta_current_branch') || ''; }

  function loadCharacters() {
    var canvas = $('officeCanvas');
    var branchId = curBranchId();
    if (!branchId) {
      canvas.innerHTML = '<div class="office-hint">请先在左下角开始菜单（或上方分部选择）选定分部</div>';
      return;
    }
    canvas.innerHTML = '<div class="office-hint"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    fetch('/api/plaza/characters?branchId=' + encodeURIComponent(branchId), { headers: authH() })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) throw new Error('无权访问该分部（或登录已失效）');
        return r.ok ? r.json() : [];
      })
      .then(function (data) {
        loadedChars = data;
        drawOffice(data);
      })
      .catch(function (e) {
        console.error('办公室加载失败:', e);
        canvas.innerHTML = '<div class="office-hint">' + esc(e.message || '加载失败') + '</div>';
      });
  }

  /* 排序：mvp / watch / mission（记忆在 localStorage） */
  var sortMode = localStorage.getItem('ta_office_sort') || 'mvp';
  function setSortMode(mode) {
    sortMode = mode;
    localStorage.setItem('ta_office_sort', mode);
    syncSortBtns();
    if (loadedChars) drawOffice(loadedChars);
  }
  function syncSortBtns() {
    Array.prototype.forEach.call(document.querySelectorAll('.office-sort-btn'), function (b) {
      b.classList.toggle('active', b.dataset.mode === sortMode);
    });
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

  /* ===== 分部切换（与桌面开始菜单共用 ta_current_branch，经 DESKTOP.setBranch 全局联动） ===== */
  var myBranches = [];
  function loadBranches() {
    var container = $('officeBranchSel');
    if (!container) return;
    var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
    var url = role >= 2 ? '/api/admin/branches' : '/api/user/my-branches';
    fetch(url, { headers: authH() })
      .then(function (r) { return r.ok ? r.json() : { branches: [] }; })
      .then(function (d) {
        myBranches = d.branches || [];
        renderBranchSelector();
        if (loadedChars === null && curBranchId()) loadCharacters();
      })
      .catch(function () {});
  }
  function renderBranchSelector() {
    var container = $('officeBranchSel');
    if (!container) return;
    container.innerHTML = '';
    var currentBranchId = curBranchId();
    var current = null;
    for (var i = 0; i < myBranches.length; i++) if (myBranches[i].id === currentBranchId) current = myBranches[i];
    var btn = document.createElement('button');
    btn.className = 'office-branch-btn';
    btn.title = current ? current.name : '选择分部';
    btn.innerHTML = '<i class="fas fa-building"></i> ' + esc(current ? current.name : '选择分部') + ' <i class="fas fa-chevron-down"></i>';
    var dropdown = document.createElement('div');
    dropdown.className = 'office-branch-dropdown';
    myBranches.forEach(function (b) {
      var item = document.createElement('div');
      item.className = 'office-branch-item' + (b.id === currentBranchId ? ' active' : '');
      item.textContent = b.name;
      item.onmousedown = function (e) {
        e.preventDefault();
        dropdown.style.display = 'none';
        if (b.id === currentBranchId) return;
        if (window.DESKTOP.setBranch) window.DESKTOP.setBranch(b.id);   /* 全局联动：开始菜单/角色/监控/办公室 */
        else { localStorage.setItem('ta_current_branch', b.id); renderBranchSelector(); loadCharacters(); }
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

  /* ===== 定位自己 + 签名编辑 ===== */
  function myCharacters() {
    if (!loadedChars) return [];
    return loadedChars.filter(function (c) { return String(c.ownerId) === String(uid); });
  }

  var locateMeIdx = 0;
  function locateMe() {
    var mine = myCharacters();
    if (!mine.length) { showToast('当前分部没有你的角色'); return; }
    var target = mine[locateMeIdx % mine.length];
    locateMeIdx++;
    var av = document.querySelector('#officeCanvas .ws-avatar[data-char-id="' + target.id + '"]');
    if (!av) { showToast('未找到工位：' + (target.name || '')); return; }
    var canvas = $('officeCanvas');
    var rect = av.getBoundingClientRect();
    var cRect = canvas.getBoundingClientRect();
    canvas.scrollTop += (rect.top + rect.height / 2) - (cRect.top + cRect.height / 2);
    av.classList.add('ws-avatar-flash');
    setTimeout(function () { av.classList.remove('ws-avatar-flash'); }, 1500);
    if (mine.length > 1) showToast('定位到 ' + (target.name || '') + ' (' + (locateMeIdx % mine.length || mine.length) + '/' + mine.length + ')');
  }

  /* 签名编辑（复用 plazaMessage 接口，本人可编辑） */
  var editingChar = null;
  function openSigEdit(charId) {
    var c = null;
    for (var i = 0; i < (loadedChars || []).length; i++) if (loadedChars[i].id === charId) c = loadedChars[i];
    if (!c) return;
    editingChar = c;
    var input = $('officeSigInput');
    input.value = c.plazaMessage || '';
    $('officeSigCount').textContent = input.value.length;
    $('officeSigMask').classList.add('show');
    setTimeout(function () { input.focus(); }, 50);
  }
  function closeSigEdit() {
    $('officeSigMask').classList.remove('show');
    editingChar = null;
  }
  function saveSigEdit() {
    if (!editingChar) return;
    var message = $('officeSigInput').value;
    fetch('/api/character/' + editingChar.id + '/plaza-message', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
      body: JSON.stringify({ message: message })
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d.success) throw new Error(d.message || '保存失败');
      var editedId = editingChar.id;
      for (var i = 0; i < loadedChars.length; i++) if (loadedChars[i].id === editedId) loadedChars[i].plazaMessage = d.message;
      var av = document.querySelector('#officeCanvas .ws-avatar[data-char-id="' + editedId + '"]');
      if (av) av.setAttribute('data-char', JSON.stringify(loadedChars[i]));
      closeSigEdit();
      var tip = document.getElementById('officeTooltip');
      if (tip.classList.contains('show') && av) {
        tip.classList.remove('show');
        av.dispatchEvent(new Event('mouseenter'));
      }
      showToast('签名已保存');
    })
    .catch(function (e) { showToast(e.message || '保存失败'); });
  }

  /* 多角色时先选择要编辑签名的角色 */
  function editMySig() {
    var mine = myCharacters();
    if (!mine.length) { showToast('当前分部没有你的角色'); return; }
    if (mine.length === 1) { openSigEdit(mine[0].id); return; }
    var list = $('officeSigPickList');
    list.innerHTML = '';
    mine.forEach(function (c) {
      var item = document.createElement('div');
      item.className = 'office-sig-pick';
      item.innerHTML = '<span class="office-sig-pick-name">' + esc(c.name || '未命名') + '</span>' +
        '<span class="office-sig-pick-sig">' + (c.plazaMessage ? esc(c.plazaMessage.length > 20 ? c.plazaMessage.slice(0, 20) + '…' : c.plazaMessage) : '未设置') + '</span>';
      item.onclick = function () {
        $('officeSigPickMask').classList.remove('show');
        openSigEdit(c.id);
      };
      list.appendChild(item);
    });
    $('officeSigPickMask').classList.add('show');
  }

  /* ===== 窗口尺寸变化重绘（最大化/窗口化切换不改 viewport，用 ResizeObserver） ===== */
  var redrawTimer = null;
  function requestRedraw() {
    if (!loadedChars) return;
    if (redrawTimer) clearTimeout(redrawTimer);
    redrawTimer = setTimeout(function () { drawOffice(loadedChars); }, 180);
  }

  /* ===== 生命周期：start（首次打开）/ close（关闭）/ reload（分部变化） ===== */
  var wired = false;
  function start() {
    if (!wired) {
      wired = true;
      bindGlobalDismiss();
      syncSortBtns();
      Array.prototype.forEach.call(document.querySelectorAll('.office-sort-btn'), function (b) {
        b.addEventListener('click', function () { setSortMode(b.dataset.mode); });
      });
      $('officeLocate').addEventListener('click', locateMe);
      $('officeMySig').addEventListener('click', editMySig);
      $('officeSigClose').addEventListener('click', closeSigEdit);
      $('officeSigCancel').addEventListener('click', closeSigEdit);
      $('officeSigSave').addEventListener('click', saveSigEdit);
      $('officeSigMask').addEventListener('click', function (e) { if (e.target === this) closeSigEdit(); });
      $('officeSigPickClose').addEventListener('click', function () { $('officeSigPickMask').classList.remove('show'); });
      $('officeSigInput').addEventListener('input', function () { $('officeSigCount').textContent = this.value.length; });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && $('officeSigMask').classList.contains('show')) closeSigEdit();
        if (e.key === 'Escape' && $('officeSigPickMask').classList.contains('show')) $('officeSigPickMask').classList.remove('show');
      });
      if (typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(requestRedraw).observe($('officeCanvas'));
      } else {
        window.addEventListener('resize', requestRedraw);
      }
    }
    loadBranches();
    if (curBranchId()) loadCharacters();
    else $('officeCanvas').innerHTML = '<div class="office-hint">请先在左下角开始菜单（或上方分部选择）选定分部</div>';
  }
  function close() {
    var t = document.getElementById('officeTooltip');
    if (t) t.classList.remove('show');
  }
  function reload() {
    renderBranchSelector();
    loadCharacters();
  }

  DA.feats.office = { start: start, close: close, reload: reload };
})();
