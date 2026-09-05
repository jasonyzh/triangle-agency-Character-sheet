/* 外勤OS：任务画板 + 骰子 + socket 同步 + 左侧档案面板 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid, cardData = DA.cardData;

  /* ========== 外勤OS（左档案面板 + 画板） ========== */
  /* ========== 画板连线与弹窗（复刻 sheet 端功能） ========== */
  var bConn = { sourceId: null, missionId: "" };
  function boardOnClick(imageId) {
    if (!bConn.sourceId || bConn.sourceId === imageId) return;
    var target = bConn.sourceId;
    bConn.sourceId = null;
    if (boardCtl && boardCtl.core) boardCtl.core.clearHighlight();
    var mid = bConn.missionId;
    boardTypeModal(function (connType) {
      if (!connType) return;
      fetch('/api/board/' + mid + '/npc-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify({ nodeA: target, nodeB: imageId, connType: connType })
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success && boardCtl && boardCtl.core) {
          if (!boardCtl.core.npcConnections) boardCtl.core.npcConnections = [];
          boardCtl.core.npcConnections.push({ id: d.id, node_a: d.nodeA, node_b: d.nodeB, conn_type: connType, label: '' });
          boardCtl.core.drawAll();
          showToast('连线已创建');
        } else showToast(d.message || '连线失败');
      }).catch(function () { showToast('连线失败'); });
    });
  }
  function boardOnImageRightClick(imageId, x, y) {
    var el = boardCtl && boardCtl.core ? boardCtl.core.images[imageId] : null;
    if (!el || el.dataset.isMapNode === '1') return;
    if (bConn.sourceId) return;
    bConn.sourceId = imageId;
    bConn.missionId = boardCtl ? (boardCtl.missionId || '') : '';
    if (boardCtl && boardCtl.core) { boardCtl.core.clearHighlight(); boardCtl.core.highlightImage(imageId); }
    showToast('已选起点，点击目标 NPC 完成连线');
  }
  function boardLineLabelModal(connId) {
    var conn = boardCtl && boardCtl.core ? (boardCtl.core.npcConnections || []).find(function (c) { return c.id === connId; }) : null;
    var wrap = document.createElement("div");
    wrap.className = "char-mask show";
    wrap.style.zIndex = "70";
    wrap.innerHTML = '<div class="char-modal" style="width:360px;max-width:calc(100vw - 48px);">'
      + '<div class="cm-head"><b>连线备注</b><span class="cm-close" id="bLineClose">×</span></div>'
      + '<div class="em-body"><input class="de-input" id="bLineInput" style="width:100%;" placeholder="例如：情人、儿子、搭档" value="' + (conn ? esc(conn.label || '') : '') + '"></div>'
      + '<div class="cm-foot" style="display:flex;gap:10px;justify-content:flex-end;">'
      + '<button class="cm-create" id="bLineCancel" style="background:#fff;color:#7a6f74;border:1px solid #f0e7e4;">取消</button>'
      + '<button class="cm-create" id="bLineOk" style="background:#fff;color:#c2483a;border:1px solid #f0e7e4;">确定</button></div></div>';
    document.body.appendChild(wrap);
    function close() { wrap.remove(); }
    wrap.querySelector('#bLineClose').onclick = close;
    wrap.querySelector('#bLineCancel').onclick = close;
    wrap.querySelector('#bLineOk').onclick = function () {
      var label = wrap.querySelector('#bLineInput').value.trim();
      close();
      if (boardCtl && boardCtl.core && bConn.missionId) {
        fetch('/api/board/' + bConn.missionId + '/npc-connection/' + connId, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
          body: JSON.stringify({ label: label })
        }).then(function (r) { return r.json(); }).catch(function () {});
      }
      if (conn) conn.label = label;
      if (boardCtl && boardCtl.core) boardCtl.core.drawAll();
    };
    setTimeout(function () { var i = wrap.querySelector('#bLineInput'); if (i) i.focus(); }, 80);
  }
  function boardLineMenu(connId, x, y) {
    var old = document.getElementById('bCtxMenu'); if (old) old.remove();
    var menu = document.createElement("div");
    menu.id = "bCtxMenu";
    menu.style.cssText = 'position:fixed;left:' + Math.min(x, window.innerWidth - 140) + 'px;top:' + y + 'px;z-index:80;background:#fff;border:1px solid #f0e7e4;border-radius:10px;box-shadow:0 12px 32px rgba(60,20,15,.25);padding:5px;min-width:130px;';
    menu.innerHTML = '<div class="b-ctx" data-act="edit" style="padding:8px 12px;font-size:12.5px;color:#555;cursor:pointer;border-radius:7px;">✏ 编辑备注</div>'
      + '<div class="b-ctx" data-act="del" style="padding:8px 12px;font-size:12.5px;color:#c0392b;cursor:pointer;border-radius:7px;">🗑 删除连线</div>';
    document.body.appendChild(menu);
    menu.querySelector('[data-act="edit"]').onclick = function () { menu.remove(); boardLineLabelModal(connId); };
    menu.querySelector('[data-act="del"]').onclick = function () {
      menu.remove();
      if (!confirm('确定删除这条连线吗？')) return;
      if (!bConn.missionId) return;
      fetch('/api/board/' + bConn.missionId + '/npc-connection/' + connId, { method: 'DELETE', headers: authH() })
        .then(function (r) { return r.json(); }).then(function (d) {
          if (boardCtl && boardCtl.core) {
            boardCtl.core.npcConnections = (boardCtl.core.npcConnections || []).filter(function (c) { return c.id !== connId; });
            boardCtl.core.drawAll();
          }
          showToast(d.success ? '连线已删除' : (d.message || '删除失败'));
        }).catch(function () { showToast('删除失败'); });
    };
    document.addEventListener("mousedown", function h(e) {
      if (!menu || !document.body.contains(menu)) { document.removeEventListener("mousedown", h); return; }
      if (!menu.contains(e.target)) menu.remove();
    });
  }
  function boardTypeModal(cb) {
    var wrap = document.createElement("div");
    wrap.className = "char-mask show";
    wrap.style.zIndex = "70";
    wrap.innerHTML = '<div class="char-modal" style="width:300px;max-width:calc(100vw - 48px);">'
      + '<div class="cm-head"><b>选择关系类型</b><span class="cm-close" id="bTypeClose">×</span></div>'
      + '<div class="em-body"><div style="display:flex;flex-direction:column;gap:8px;">'
      + '<button class="cm-create b-type" data-t="friendly" style="background:#27ae60;color:#fff;font-weight:600;">友善</button>'
      + '<button class="cm-create b-type" data-t="hostile" style="background:#c0392b;color:#fff;font-weight:600;">敌对</button>'
      + '<button class="cm-create b-type" data-t="neutral" style="background:#f39c12;color:#fff;font-weight:600;">中立</button>'
      + '<button class="cm-create b-type" data-t="unknown" style="background:#8e44ad;color:#fff;font-weight:600;">未知</button>'
      + '</div></div></div>';
    document.body.appendChild(wrap);
    wrap.querySelector('#bTypeClose').onclick = function () { wrap.remove(); cb(null); };
    Array.prototype.forEach.call(wrap.querySelectorAll('.b-type'), function (bt) {
      bt.onclick = function () { wrap.remove(); cb(bt.dataset.t); };
    });
  }
  function boardImgInfo(imageId) {
    var el = boardCtl && boardCtl.core ? boardCtl.core.images[imageId] : null;
    if (!el) return;
    var label = el.querySelector('.board-img-label');
    var isMap = el.dataset.isMapNode === '1';
    var img = el.querySelector('img');
    var txt = (label ? label.textContent : '图片') + (isMap ? ' · 地图节点' : ' · NPC 图片');
    if (img && img.naturalWidth) txt += ' · ' + Math.round(img.naturalWidth) + '×' + Math.round(img.naturalHeight);
    showToast(txt);
  }
  var __BOARD_ANCHOR = 1;
  var ringSaveT = null;
  function ringChange(k, delta) {
    var cc = cardData();
    if (!cc || !cc.attrs || !cc.attrs[k]) return;
    var cap = parseInt(cc.attrs[k].v) || 0;
    var cur = (cc.attrs[k].cur != null) ? parseInt(cc.attrs[k].cur) : cap;
    cur = Math.max(0, Math.min(cur, cap));
    var next = delta < 0 ? Math.max(0, cur - 1) : Math.min(cap, cur + 1);
    if (next === cur) return;
    cc.attrs[k].cur = String(next);
    var ch = window.DESKTOP.getCurChar();
    if (ch) ch.data = JSON.stringify(cc);
    var fig = document.querySelector('.bsp-ringfig[data-k="' + CSS.escape(k) + '"]');
    if (fig) {
      var pct = cap > 0 ? next / cap : 0;
      var C = 2 * Math.PI * 24;
      var pr = fig.querySelector('.pr');
      if (pr) pr.setAttribute('stroke-dashoffset', (C * (1 - pct)).toFixed(1));
      var t = fig.querySelector('b');
      if (t) t.textContent = next + '/' + cap;
    }
    if (ringSaveT) clearTimeout(ringSaveT);
    ringSaveT = setTimeout(function () {
      fetch('/api/character/' + cid(), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify(cc)
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) showToast('资质保证已保存');
        else showToast(d.message || '保存失败');
      }).catch(function () { showToast('保存失败'); });
    }, 700);
  }

  function sidePanelHtml(c) {
    if (!c) return '<div class="pane-empty">未选择角色</div>';
    var sum = function (arr) { return (arr || []).reduce(function (s, r) { return s + (r.count || 1); }, 0); };

    /* 头部：头像 + 姓名 + 三标签 */
    var ava = c.pAvatar
      ? '<img src="' + (c.pAvatar.indexOf('http') === 0 ? c.pAvatar : '/' + c.pAvatar) + '" alt="">'
      : '<span>' + esc((c.pName || '？').charAt(0)) + '</span>';
    var tags = [['异常', c.pAnom], ['现实', c.pReal], ['职能', c.pFunc]]
      .filter(function (r) { return r[1]; })
      .map(function (r) { return '<span class="bsp-tag">' + r[0] + ' · ' + esc(r[1]) + '</span>'; }).join('');

    /* 四统计：MVP / 察看期 / 职能 / 嘉奖 */
    var stats = [
      ['MVP', sum(c.mvpRecords), 'MVP'], ['察看期', sum(c.watchRecords), '察看期'],
      ['嘉奖', sum(c.rewards), '嘉奖'], ['申诫', sum(c.reprimands), '申诫']
    ].map(function (r) {
      return '<div class="bsp-stat"><span class="bsp-stat-l">' + r[0] + '</span><b>' + esc(r[1]) + '</b><span class="bsp-stat-v">' + r[2] + '</span></div>';
    }).join('');

    /* 现实触发器 */
    var trig = '';
    if (c.pTrig2) trig = '<div class="bsp-card bsp-trig"><div class="bsp-card-h"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 4 L6 11 h3.5 L8.5 20 L15 12.5 h-3.8 L14 4.5 Z"/></svg><b>现实触发器</b></div><div class="bsp-trig-text">' + c.pTrig2 + '</div></div>';

    /* 资质保证：9 环 3×3 */
    var attrs = c.attrs || {};
    var keys = Object.keys(attrs);
    var rings = keys.map(function (k) {
      var v = parseInt((attrs[k] || {}).v) || 0;
      var cur = (attrs[k] && attrs[k].cur != null) ? parseInt(attrs[k].cur) : v;
      cur = Math.max(0, Math.min(cur, v));
      var pct = v > 0 ? cur / v : 0;
      var C = 2 * Math.PI * 24;
      return '<div class="bsp-ring"><div class="bsp-ringfig" data-k="' + esc(k) + '"><svg viewBox="0 0 60 60">'
        + '<circle class="tr" cx="30" cy="30" r="24"/><circle class="pr" cx="30" cy="30" r="24" '
        + 'stroke-dasharray="' + C.toFixed(1) + '" stroke-dashoffset="' + (C * (1 - pct)).toFixed(1) + '"/>'
        + '</svg><b>' + cur + '/' + v + '</b></div><span>' + esc(k) + '</span></div>';
    }).join('');
    var attrCard = rings
      ? '<div class="bsp-card bsp-attrs"><div class="bsp-card-h"><b>资质保证</b><span class="bsp-count">' + keys.length + ' 项能力评估</span></div><div class="bsp-rings">' + rings + '</div></div>'
      : '';

    /* 评估行为 chips */
    var perms = [c.perm1, c.perm2, c.perm3].filter(Boolean);
    var permCard = perms.length
      ? '<div class="bsp-card bsp-perms"><div class="bsp-card-h"><b>评估行为</b><span class="bsp-more">查看更多 ›</span></div><div class="bsp-perm-list">'
        + perms.map(function (p) { return '<span class="bsp-perm">' + esc(p) + '</span>'; }).join('') + '</div></div>'
      : '';

    return '<div class="bsp-card bsp-top">'
      + '<div class="bsp-id"><div class="bsp-ava">' + ava + '</div><div class="bsp-idinfo"><label>姓名</label><b>'
      + esc(c.pName || '未命名特工') + '</b></div></div>'
      + (tags ? '<div class="bsp-tags">' + tags + '</div>' : '')
      + '<div class="bsp-stats">' + stats + '</div>'
      + '</div>'
      + trig
      + attrCard
      + permCard
      + '<button class="bsp-sheet" id="bspOpenSheet">查看完整档案 ›</button>';
  }
  function BoardApp() {
    var self = this;
    window.__boardDbg = this;
    this.sock = null;
    this.core = null;
    this.missionId = '';
    this.callbacks = function () {
      return {
        editable: true, role: 'player', imageBaseUrl: '/',
        onImageMove: function (id, x, y) {
          fetch('/api/board/' + self.missionId + '/image/' + id, {
            method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
            body: JSON.stringify({ x: x, y: y, role: 'player' })
          });
          self.sock.emit('board:image-move', { imageId: id, x: x, y: y });
        },
        onImageResize: function (id, w, h) {
          fetch('/api/board/' + self.missionId + '/image/' + id, {
            method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
            body: JSON.stringify({ w: w, h: h, role: 'player' })
          });
          self.sock.emit('board:image-resize', { imageId: id, w: w, h: h });
        },
        onImageClick: function (imageId) { boardOnClick(imageId); },
        onImageRightClick: function (imageId, x, y) { boardOnImageRightClick(imageId, x, y); },
        onNpcLineDblClick: function (connId) { boardLineLabelModal(connId); },
        onNpcLineRightClick: function (connId, x, y) { boardLineMenu(connId, x, y); },
        onImageDblClick: function (imageId) { boardImgInfo(imageId); }
      };
    };
    /* ========== 投掷（骰子） ========== */
    this.charName = function () {
      var c = window.DESKTOP.getCurChar();
      return (c && c.name) || '未知';
    };
    this.mountDice = function () {
      var canvas = $('boardCanvas');
      if (canvas && !document.getElementById('diceResults')) {
        var dv = document.createElement('div');
        dv.id = 'diceResults';
        canvas.appendChild(dv);
      }
    };
    this.showResult = function (label, total, detail) {
      var container = document.getElementById('diceResults');
      if (!container) return;
      var el = document.createElement('div');
      el.className = 'dice-entry';
      el.innerHTML = '<span class="dice-char">' + esc(self.charName()) + '</span> <span class="dice-label">' + label + '</span> <span class="dice-total">' + total + '</span>' + (detail ? ' <span class="dice-detail">' + detail + '</span>' : '');
      container.appendChild(el);
      this.saveHistory(el.innerHTML);
      setTimeout(function () { el.style.opacity = '0'; }, 4500);
      setTimeout(function () { if (el.parentNode) el.remove(); }, 5200);
      var entries = container.querySelectorAll('.dice-entry');
      if (entries.length > 20) entries[0].remove();
    };
    this.rollDice = function (count, sides) {
      var results = [];
      for (var i = 0; i < count; i++) results.push(Math.floor(Math.random() * sides) + 1);
      var total = results.reduce(function (a, b) { return a + b; }, 0);
      var label = count + 'd' + sides;
      var detail = count > 1 ? '(' + results.join('+') + ')' : '';
      this.showResult(label, total, detail);
      this.broadcast(self.charName(), label, total, results, 'normal');
    };
    this.rollCheck = function () {
      var results = [];
      for (var i = 0; i < 6; i++) results.push(Math.floor(Math.random() * 4) + 1);
      var count3 = results.filter(function (r) { return r === 3; }).length;
      var detail = '(' + results.map(function (r) {
        return '<span' + (r === 3 ? ' style="color:#ff6b6b;font-weight:900;"' : '') + '>' + r + '</span>';
      }).join(' ') + ')';
      this.showResult('检定6d4', count3 + '个3', detail);
      this.broadcast(self.charName(), '检定6d4', count3 + '个3', results, 'check');
    };
    this.broadcast = function (charName, label, total, results, type) {
      if (this.missionId && this.sock && this.sock.connected) {
        this.sock.emit('dice:roll', { missionId: this.missionId, charName: charName, label: label, total: total, results: results, type: type });
      }
    };
    this.wireDice = function () {
      var self2 = self;
      Array.prototype.forEach.call(document.querySelectorAll('.dice-bar [data-roll]'), function (b) {
        b.addEventListener('click', function () { self2.rollDice(1, parseInt(b.dataset.roll, 10)); });
      });
      var chk = document.querySelector('.dice-bar [data-check]');
      if (chk) chk.addEventListener('click', function () { self2.rollCheck(); });
      var h = document.querySelector('.dice-bar [data-hist]');
      if (h) h.addEventListener('click', function () { self2.showHistory(); });
    };
    this.saveHistory = function (html) {
      var ts = new Date().toLocaleTimeString();
      try {
        var h = JSON.parse(localStorage.getItem('ta_dice_history') || '[]');
        h.unshift({ time: ts, html: html });
        if (h.length > 50) h.pop();
        localStorage.setItem('ta_dice_history', JSON.stringify(h));
      } catch (e) {}
    };
    this.showHistory = function () {
      var existing = document.querySelector('.dice-hist-modal');
      if (existing) { existing.remove(); return; }
      var h = [];
      try { h = JSON.parse(localStorage.getItem('ta_dice_history') || '[]'); } catch (e) {}
      var overlay = document.createElement('div');
      overlay.className = 'dice-hist-modal';
      var rows = h.map(function (x) {
        return '<div class="dice-hist-row"><span class="h-time">' + x.time + '</span> ' + x.html + '</div>';
      }).join('') || '<div class="pane-empty" style="color:#888;">暂无记录</div>';
      overlay.innerHTML = '<div class="dice-hist-box">'
        + '<div class="dice-hist-head"><b>骰子历史</b><button class="dice-hist-close">×</button></div>'
        + '<div class="dice-hist-list">' + rows + '</div>'
        + '<div class="dice-hist-foot"><button class="dice-hist-clear">清除历史</button></div>'
        + '</div>';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', function (e) { if (e.target === overlay) overlay.remove(); });
      overlay.querySelector('.dice-hist-close').addEventListener('click', function () { overlay.remove(); });
      overlay.querySelector('.dice-hist-clear').addEventListener('click', function () {
        try { localStorage.setItem('ta_dice_history', '[]'); } catch (e) {}
        overlay.querySelector('.dice-hist-list').innerHTML = '<div class="pane-empty" style="color:#888;">暂无记录</div>';
      });
    };
    this.renderSide = function () {
      var c = cardData();
      $('boardSide').innerHTML = c ? sidePanelHtml(c) : '<div class="pane-empty">未选择角色</div>';
      var side2 = $('boardSide');
      if (!side2.dataset.ringwired) {
        side2.dataset.ringwired = '1';
        side2.addEventListener('click', function (e) {
          var f = e.target.closest('.bsp-ringfig');
          if (f && e.button !== 2) ringChange(f.dataset.k, -1);
        });
        side2.addEventListener('contextmenu', function (e) {
          var f = e.target.closest('.bsp-ringfig');
          if (f) { e.preventDefault(); ringChange(f.dataset.k, +1); }
        });
      }
      var bsb = document.getElementById('bspOpenSheet');
      if (bsb) bsb.addEventListener('click', function () {
        /* 掐死老页面入口：改为打开页内「我的文档」角色档案视图 */
        var docsDico = document.querySelector('.dico[data-app="docs"]');
        if (docsDico) docsDico.click();
      });
    };
    this.open = function () {
      this.renderSide();
      window.DESKTOP.onCardReady(function () { self.renderSide(); });
      this.wireDice();
      var sel = $('boardMissionSel');
      sel.innerHTML = '<option value="">-- 选择任务 --</option>';
      var saved = localStorage.getItem('ta_board_mission_' + cid()) || '';
      this.sock = io({ auth: { token: window.DESKTOP.getToken() } });
      this.sock.on('connect', function () { if (self.missionId) self.sock.emit('join-board', { missionId: self.missionId, role: 'ply' }); });
      this.sock.on('board:image-move', function (d) { if (self.core) { self.core.moveImage(d.imageId, d.x, d.y); self.core.drawAll(); } });
      this.sock.on('board:image-resize', function (d) { if (self.core) { self.core.resizeImage(d.imageId, d.w, d.h); self.core.drawAll(); } });
      this.sock.on('board:image-add', function (d) {
        if (self.core) self.core.addImage({ id: d.id, imageFile: d.imageFile || d.image_lib_filename, x: d.p_x, y: d.p_y, w: d.p_w, h: d.p_h, name: d.name || '', isMapNode: d.is_map_node });
      });
      this.sock.on('board:image-remove', function (d) { if (self.core) { self.core.removeImage(d.imageId); self.core.drawAll(); } });
      this.sock.on('weather:update', function (d) {
        var cards = (d && d.weather) || [];
        if (self.missionId) { DA.weather.weatherByMission[self.missionId] = cards; DA.weather.renderWeather(); }
      });
      this.sock.on('dice:roll', function (d) {
        var detail = '(' + (d.results || []).map(function (r) {
          var hot = d.type === 'check' && r === 3;
          return '<span' + (hot ? ' style="color:#ff6b6b;font-weight:900;"' : '') + '>' + r + '</span>';
        }).join(' ') + ')';
        self.showResult('[' + (d.charName || '未知') + '] ' + (d.label || ''), d.total, detail);
      });
      fetch('/api/character/' + cid() + '/mission-boards', { headers: authH() })
        .then(function (r) { return r.json(); })
        .then(function (list) {
          (list || []).forEach(function (m) {
            var o = document.createElement('option');
            o.value = m.mission_id; o.textContent = m.mission_name;
            sel.appendChild(o);
          });
          if (saved && list.some(function (m) { return m.mission_id === saved; })) {
            sel.value = saved;
            self.missionId = saved;
            self.load(saved);
          }
        }).catch(function () {});
      sel.onchange = function () { self.load(sel.value); };
      this.core = new BoardCore($('boardCanvas'), this.callbacks());
    };
    this.load = function (missionId) {
      this.missionId = missionId;
      localStorage.setItem('ta_board_mission_' + cid(), missionId || '');
      if (this.sock && missionId) this.sock.emit('join-board', { missionId: missionId, role: 'ply' });
      var canvas = $('boardCanvas');
      canvas.innerHTML = '';
      this.mountDice();
      this.core = new BoardCore(canvas, this.callbacks());
      if (!missionId) return;
      var self = this;
      Promise.all([
        fetch('/api/board/' + missionId, { headers: authH() }).then(function (r) { return r.json(); }),
        fetch('/api/board/' + missionId + '/npc-connections', { headers: authH() }).then(function (r) { return r.json(); })
      ]).then(function (rs) {
        var data = rs[0] || {}, npc = rs[1];
        if (!self.core) return;
        self.core.loadImages(data.images || []);
        if (data.board && data.board.show_connections) self.core.setConnections(data.connections || []);
        var npcArr = Array.isArray(npc) ? npc : ((npc && (npc.connections || npc.npc_connections)) || []);
        self.core.setNpcConnections(npcArr);
      }).catch(function () { showToast('画板加载失败'); });
    };
    this.leave = function () {
      if (this.sock) { try { this.sock.emit('leave-board'); this.sock.disconnect(); } catch (e) {} }
      this.sock = null; this.core = null;
    };
  }

  var boardCtl = null;
  DA.feats.board = {
    start: function () { boardCtl = new BoardApp(); boardCtl.open(); },
    close: function () { if (boardCtl) { boardCtl.leave(); boardCtl = null; } },
    refreshSide: function () { if (boardCtl) boardCtl.renderSide(); }
  };
})();
