/* 生涯：进度追踪浮窗 + 考勤卡 + 高墙文件解锁标记 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid, cardData = DA.cardData;

  var careerCtl = null;

  /* ========== 生涯浮窗 ========== */
  var careerFloat = $('winCareer');
  function setCareerBtn(on) { var b = $('tbCareer'); if (b) b.classList.toggle('open', !!on); }
  function openCareerFloat() {
    careerCtl = careerCtl || new CareerApp();
    careerCtl.open();
    careerFloat.classList.add('show');
    window.DESKTOP.bringToFront(careerFloat);
    setCareerBtn(true);
  }
  function closeCareerFloat() {
    careerFloat.classList.remove('show');
    setCareerBtn(false);
  }
  $('tbCareer').addEventListener('click', function (e) {
    e.stopPropagation();
    if (careerFloat.classList.contains('show')) closeCareerFloat();
    else openCareerFloat();
  });
  Array.prototype.forEach.call(careerFloat.querySelectorAll('[data-close]'), function (b) {
    b.addEventListener('click', closeCareerFloat);
  });
  careerFloat.addEventListener('mousedown', function () { window.DESKTOP.bringToFront(careerFloat); });
  window.DESKTOP.makeDraggable(careerFloat);
  /* ========== 生涯（进度追踪复刻） ========== */
  var careerCtl = null;
  function CareerApp() {
    var self = this;
    this.editMode = false;
    this.granted = [];
    this.saveT = null;
    this.scheduleSave = function () {
      clearTimeout(this.saveT);
      this.saveT = setTimeout(function () { careerCtl.save(); }, 800);
    };
    this.open = function () {
      this.apply();
      this.loadGranted();
      this.markGranted();
      var self = this;
      /* 等展开动画与布局稳定后再画箭头，否则首开方向会错 */
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { self.drawAll(); });
        setTimeout(function () { self.drawAll(); }, 300);
      });
    };
    this.setEdit = function (on) {
      this.editMode = on;
      $('winCareer').classList.toggle('track-editing', on);
    };
    this.loadGranted = function () {
      /* 与高墙文件窗口同源：documents/list（管理员全可见，玩家按授权） */
      var q = cid() ? '?charId=' + encodeURIComponent(cid()) : '';
      fetch('/api/documents/list' + q, { headers: authH() })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (files) {
          self.granted = (files || []).filter(function (f) { return f.allowed; })
            .map(function (f) { return (f.filename || '').toLowerCase().replace(/\.md$/, ''); });
          self.markGranted();
        }).catch(function () {});
    };
    this.markGranted = function () {
      var codes = self.granted;
      $('careerBody').querySelectorAll('.p-cell span').forEach(function (span) {
        var code = (span.textContent || '').trim().toLowerCase();
        var cell = span.closest('.p-cell');
        if (cell) cell.classList.toggle('granted', !!code && codes.indexOf(code) >= 0);
      });
    };
    this.apply = function () {
      var c = cardData();
      [['f', 'pf', 'pf_ign'], ['r', 'pr', 'pr_ign'], ['a', 'pa', 'pa_ign']].forEach(function (t) {
        var active = c ? (c[t[1]] || []) : [];
        var ign = c ? (c[t[2]] || []) : [];
        var snake = document.querySelector('.track-snake[data-type="' + t[0] + '"]');
        if (!snake) return;
        snake.querySelectorAll('.p-cell').forEach(function (cell) {
          var idx = parseInt(cell.dataset.idx, 10);
          cell.classList.toggle('active', active.indexOf(idx) >= 0);
          cell.classList.toggle('ignored', ign.indexOf(idx) >= 0);
        });
      });
    };
    this.drawAll = function () {
      var self2 = this;
      ['f', 'r', 'a'].forEach(function (t) { self2.drawTrack(t); });
    };
    this.drawTrack = function (type) {
      var svg = document.querySelector('.track-svg[data-type="' + type + '"]');
      var snake = document.querySelector('.track-snake[data-type="' + type + '"]');
      if (!svg || !snake) return;
      svg.innerHTML = '';
      var wrap = svg.parentElement;
      var wrapRect = wrap.getBoundingClientRect();
      if (!snake.querySelector('[data-idx="30"]')) return;
      function center(idx) {
        var cell = snake.querySelector('[data-idx="' + idx + '"]');
        var r = cell.getBoundingClientRect();
        return { x: r.left + r.width / 2 - wrapRect.left, y: r.top + r.height / 2 - wrapRect.top };
      }
      function arrow(x, y, angle) {
        var s = 4;
        var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('transform', 'translate(' + x + ',' + y + ') rotate(' + angle + ')');
        var p = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        p.setAttribute('points', -s + ',' + (-s) + ' ' + s + ',0 ' + (-s) + ',' + s);
        p.setAttribute('fill', '#95a5a6');
        g.appendChild(p);
        return g;
      }
      var seq = [];
      for (var i = 1; i <= 30; i++) seq.push(i);
      for (i = 0; i < seq.length - 1; i++) {
        var ac = center(seq[i]), bc = center(seq[i + 1]);
        var dx = bc.x - ac.x, dy = bc.y - ac.y;
        var angle, mx, my;
        if (Math.abs(dx) > Math.abs(dy)) { angle = dx > 0 ? 0 : 180; mx = (ac.x + bc.x) / 2; my = ac.y; }
        else { angle = dy > 0 ? 90 : 270; mx = ac.x; my = (ac.y + bc.y) / 2; }
        svg.appendChild(arrow(mx, my, angle));
      }
    };
    this.save = function () {
      var c = cardData();
      if (!c) { showToast('未选择角色'); return; }
      ['f', 'r', 'a'].forEach(function (t) {
        var snake = document.querySelector('.track-snake[data-type="' + t + '"]');
        var act = [], ign = [];
        snake.querySelectorAll('.p-cell').forEach(function (cell) {
          var idx = parseInt(cell.dataset.idx, 10);
          if (cell.classList.contains('active')) act.push(idx);
          if (cell.classList.contains('ignored')) ign.push(idx);
        });
        c[{ f: 'pf', r: 'pr', a: 'pa' }[t]] = act;
        c[{ f: 'pf_ign', r: 'pr_ign', a: 'pa_ign' }[t]] = ign;
      });
      fetch('/api/character/' + cid(), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify(c)
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (!d.success) throw new Error('fail');
        window.DESKTOP.getCurChar().data = JSON.stringify(c);
        updateCareerCard();
        showToast('生涯进度已保存');
      }).catch(function () { showToast('保存失败，请重试'); });
    };
    this.openDoc = function (code) {
      fetch('/api/documents/read/' + encodeURIComponent(code + '.md'), { headers: authH() })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var md = window.marked;
          var html = md ? (typeof md.parse === 'function' ? md.parse(d.content) : md(d.content)) : '<pre style="white-space:pre-wrap;">' + esc(d.content) + '</pre>';
          $('mvSubject').textContent = code + ' 高墙文件';
          $('mvMeta').textContent = '高墙档案库 · 已解锁';
          var c = $('mvContent');
          c.innerHTML = html;
          c.style.whiteSpace = 'normal';
          $('mailViewMask').classList.add('show');
        }).catch(function () { showToast('读取失败'); });
    };
  }
  window.DESKTOP.syncCareerApply = function () { if (document.getElementById('winCareer').classList.contains('show') && careerCtl) careerCtl.apply(); };
  var careerCtl = null;
  function updateCareerCard() {
    var c = cardData();
    var map = { F: ['pf', 'careerBarF', 'careerPctF'], R: ['pr', 'careerBarR', 'careerPctR'], A: ['pa', 'careerBarA', 'careerPctA'] };
    Object.keys(map).forEach(function (k) {
      var n = c ? (c[map[k][0]] || []).length : 0;
      var pct = Math.round(n / 30 * 100);
      $(map[k][1]).style.width = pct + '%';
      $(map[k][2]).textContent = pct + '%';
    });
  }
  window.DESKTOP.onCardReady(updateCareerCard);
  window.DESKTOP.onCardReady(updateKaoqin);
  function updateKaoqin() {
    var c = cardData();
    var sum = function (arr) { return (arr || []).reduce(function (s, r) { return s + (r.count || 1); }, 0); };
    var set = function (id, v) { var e = $(id); if (e) e.textContent = v; };
    set('kqMvp', c ? sum(c.mvpRecords) : 0);
    set('kqWatch', c ? sum(c.watchRecords) : 0);
    set('kqBonus', c ? sum(c.rewards) : 0);
    set('kqRep', c ? sum(c.reprimands) : 0);
  }

  /* 生涯窗口事件（只绑一次） */
  $('careerEditBtn').addEventListener('click', function () { careerCtl.setEdit(!careerCtl.editMode); });
  $('careerBody').addEventListener('click', function (e) {
    var cell = e.target.closest('.p-cell');
    if (!cell) return;
    if (!careerCtl.editMode) {
      var span = cell.querySelector('span');
      if (span && span.textContent.trim() && cell.classList.contains('granted')) careerCtl.openDoc(span.textContent.trim());
      else if (span && span.textContent.trim()) showToast('该高墙文件未授权，无法查看');
      return;
    }
    if (cell.classList.contains('active')) { cell.classList.remove('active'); cell.classList.add('ignored'); }
    else if (cell.classList.contains('ignored')) { cell.classList.remove('ignored'); }
    else { cell.classList.add('ignored'); cell.classList.remove('ignored'); cell.classList.add('active'); }
    careerCtl.scheduleSave();
  });
  $('careerBody').addEventListener('contextmenu', function (e) {
    var cell = e.target.closest('.p-cell');
    if (!cell || !careerCtl.editMode) return;
    e.preventDefault();
    cell.classList.remove('active');
    cell.classList.add('ignored');
    careerCtl.scheduleSave();
  });
  window.addEventListener('resize', function () {
    if (document.getElementById('winCareer').classList.contains('show') && careerCtl) careerCtl.drawAll();
  });

  DA.career = { openFloat: openCareerFloat };
})();
