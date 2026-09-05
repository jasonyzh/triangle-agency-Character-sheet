/* 桌面窗口管理：APPWINS/任务栏/打开关闭最小化/持久化恢复 + 入口绑定 + 图标权限 */
(function () {
  'use strict';
  var $ = DA.$, showToast = DA.showToast;

  /* ========== 窗口开关与入口（多开维持，任务栏常驻直到关闭） ========== */
  var APPWINS = { docs: 'winDocs', board: 'winBoard', shop: 'winShop', highwall: 'winHW', 'siphon-shop': 'winSiphonShop', office: 'winOffice',
    'm-char': 'winMChar', 'm-missions': 'winMMissions', 'm-items': 'winMItems', 'm-siphon': 'winMSiphon',
    'm-anomaly': 'winMAnomaly', 'm-dest': 'winMDest', 'm-apps': 'winMApps', 'm-npc': 'winMNpc',
    'm-admin': 'winMAdmin' };
  var APP_META = {
    docs: { title: '我的档案', ico: '<svg viewBox="0 0 48 48"><rect x="10" y="6" width="28" height="36" rx="3" fill="#fff"/></svg>' },
    board: { title: '外勤OS', ico: '<svg viewBox="0 0 48 48"><rect x="6" y="8" width="36" height="26" rx="2" fill="#fff"/><rect x="20" y="34" width="8" height="4" fill="#fff"/></svg>' },
    mail: { title: '邮箱', ico: '<svg viewBox="0 0 48 48"><rect x="7" y="12" width="34" height="24" rx="3" fill="#fff"/></svg>' },
    shop: { title: '职员内购', ico: '<svg viewBox="0 0 48 48"><path d="M11 17 h26 l-2.6 23 a3 3 0 0 1 -3 2.7 h-14.8 a3 3 0 0 1 -3 -2.7 Z" fill="#fff"/></svg>' },
    'siphon-shop': { title: '虹吸商店', ico: '<svg viewBox="0 0 48 48"><path d="M12 8 h24 l-8 13 v14 l-8 5 v-19 Z" fill="#fff"/></svg>' },
    highwall: { title: '高墙文件', ico: '<svg viewBox="0 0 48 48"><rect x="8" y="8" width="32" height="32" rx="4" fill="#fff"/></svg>' },
    office: { title: '办公室', ico: '<svg viewBox="0 0 48 48"><path d="M9 42 V14 a2 2 0 0 1 2 -2 h12 a2 2 0 0 1 2 2 v28 Z" fill="#fff"/><path d="M25 42 V22 a2 2 0 0 1 2 -2 h11 a2 2 0 0 1 2 2 v20 Z" fill="#fff" opacity=".82"/></svg>' },
    'm-char': { title: '特工档案', ico: '<svg viewBox="0 0 48 48"><circle cx="18" cy="17" r="7" fill="#fff"/><path d="M6 38 a12 12 0 0 1 24 0 Z" fill="#fff"/></svg>' },
    'm-missions': { title: '外勤任务', ico: '<svg viewBox="0 0 48 48"><rect x="8" y="6" width="32" height="36" rx="4" fill="#fff"/></svg>' },
    'm-items': { title: '申领物', ico: '<svg viewBox="0 0 48 48"><path d="M7 18 h34 v20 a3 3 0 0 1 -3 3 H10 a3 3 0 0 1 -3 -3 Z" fill="#fff"/></svg>' },
    'm-siphon': { title: 'Siphon', ico: '<svg viewBox="0 0 48 48"><path d="M4 24 C11 13 37 13 44 24 C37 35 11 35 4 24 Z" fill="#fff"/><circle cx="24" cy="24" r="6.5" fill="#e8907f"/></svg>' },
    'm-anomaly': { title: '异常', ico: '<svg viewBox="0 0 48 48"><path d="M26 4 L10 28 h9 L17 44 L36 19 h-10 Z" fill="#fff"/></svg>' },
    'm-dest': { title: '破坏条', ico: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="14" fill="#fff"/></svg>' },
    'm-apps': { title: '申请', ico: '<svg viewBox="0 0 48 48"><path d="M10 6 h20 l8 8 v28 a2 2 0 0 1 -2 2 H10 a2 2 0 0 1 -2 -2 V8 a2 2 0 0 1 2 -2 Z" fill="#fff"/></svg>' },
    'm-npc': { title: 'NPC', ico: '<svg viewBox="0 0 48 48"><path d="M8 6 h24 l8 8 v20 a4 4 0 0 1 -4 4 H8 a4 4 0 0 1 -4 -4 V10 a4 4 0 0 1 4 -4 Z" fill="#fff"/></svg>' },
    'm-admin': { title: '设置', ico: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="14" fill="#fff"/></svg>' },
  };
  var boardCtl = null;
  var mailCtl = null;
  var shopCtl = null;

  function taskBtn(key) { return $('taskWins').querySelector('[data-task="' + key + '"]'); }
  function addTaskBtn(key) {
    if (taskBtn(key)) return;
    var b = document.createElement('button');
    b.className = 'tb-win active';
    b.dataset.task = key;
    b.title = APP_META[key].title;
    b.innerHTML = APP_META[key].ico + '<span>' + APP_META[key].title + '</span>';
    b.addEventListener('click', function () {
      if ($(APPWINS[key]).classList.contains('show')) minimizeApp(key);
      else openApp(key);
    });
    $('taskWins').appendChild(b);
    return b;
  }
  function removeTaskBtn(key) { var b = taskBtn(key); if (b) b.remove(); }

  function visibleApps() {
    return Object.keys(APPWINS).filter(function (k) { return $(APPWINS[k]).classList.contains('show'); });
  }
  function syncTaskStates() {
    Object.keys(APPWINS).forEach(function (k) {
      var b = taskBtn(k);
      if (b) b.classList.toggle('active', $(APPWINS[k]).classList.contains('show'));
    });
  }
  function openApp(key) {
    var w = $(APPWINS[key]);
    if (!w.dataset.started) {
      w.dataset.started = '1';
      var f = DA.feats[key];
      if (f && f.start) f.start();
    }
    /* 系统设置仅超管可打开（图标已隐藏，这里防绕过） */
    if (key === 'm-admin' && parseInt(localStorage.getItem('ta_role') || '0', 10) < 2) {
      showToast('需要超级管理员权限');
      return;
    }
    w.classList.add('show');
    /* 我的文档默认窗口化（可点最大化切全屏） */
    if (key === 'docs') {
      w.classList.add('windowed');
      var mb = w.querySelector('[data-maxbtn]');
      if (mb) mb.title = '最大化';
    }
    addTaskBtn(key);
    window.DESKTOP.bringToFront(w);
    syncTaskStates();
    persistApps();
    /* 管理台窗口：每次打开刷新数据 + 分部选择器 */
    if (key.slice(0, 2) === 'm-' && window.MANAGER_APP) window.MANAGER_APP.startApp(key);
  }
  function minimizeApp(key) {
    $(APPWINS[key]).classList.remove('show');
    syncTaskStates();
    persistApps();
  }
  function persistApps() {
    var open = Object.keys(APPWINS).filter(function (k) { return taskBtn(k); });
    localStorage.setItem('ta_desktop_apps', JSON.stringify({ open: open, visible: visibleApps() }));
  }
  function closeApp(key) {
    $(APPWINS[key]).classList.remove('show');
    removeTaskBtn(key);
    delete $(APPWINS[key]).dataset.started;
    var f = DA.feats[key];
    if (f && f.close) f.close();
    syncTaskStates();
    persistApps();
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-appclose]'), function (b) {
    b.addEventListener('click', function () {
      var w = b.closest('.appwin');
      Object.keys(APPWINS).forEach(function (k) { if (APPWINS[k] === w.id) closeApp(k); });
    });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && DA.mail) DA.mail.closeFloat();
    if (e.key === 'Escape' && document.querySelector('.appwin.show')) {
      visibleApps().forEach(function (k) { minimizeApp(k); });
    }
  });
  document.querySelector('.cards').addEventListener('click', function (e) {
    var card = e.target.closest('.wcard[data-app]');
    if (!card) return;
    if (card.dataset.app === 'career') DA.career.openFloat();
    else openApp(card.dataset.app);
  });

  document.querySelector('.dicons').addEventListener('click', function (e) {
    if (window.__iconDrag) return;   /* 拖拽排序后误触忽略 */
    var dico = e.target.closest('.dico');
    if (!dico) return;
    var key = dico.dataset.app;
    if (key === 'history') { showToast('历史记录：建设中，敬请期待'); return; }
    if (key === 'gt-terminal') {
      /* 总经理终端：带第一个进行中任务打开 mission-panel */
      fetch('/api/manager/missions?status=active', { headers: window.DESKTOP.authHeaders() })
        .then(function (r) { return r.json(); })
        .then(function (list) {
          var mid = (list && list[0] && list[0].id) || '';
          window.open('mission-panel.html' + (mid ? '?missionId=' + encodeURIComponent(mid) : ''), '_blank');
        })
        .catch(function () { window.open('mission-panel.html', '_blank'); });
      return;
    }
    if (!APPWINS[key]) return;
    openApp(key);
  });
  /* ========== 应用窗口：窗口化/最大化切换 + 可拖动 ========== */
  Array.prototype.forEach.call(document.querySelectorAll('[data-maxbtn]'), function (b) {
    b.addEventListener('click', function () {
      var w = b.closest('.appwin');
      var winned = w.classList.toggle('windowed');
      b.title = winned ? '最大化' : '向下还原';
      if (!winned) {
        w.style.left = ''; w.style.top = ''; w.style.right = ''; w.style.bottom = ''; w.style.marginLeft = '';
      }
    });
  });
  ['winDocs', 'winBoard', 'winShop', 'winHW', 'winOffice'].forEach(function (id) {
    window.DESKTOP.makeDraggable($(id), true);
  });
  ['winDocs', 'winBoard', 'winShop', 'winHW', 'winOffice', 'winCareer', 'winAnom', 'winReal', 'winItem', 'winMail'].forEach(function (id) {
    window.DESKTOP.registerWin($(id));
  });
  /* 管理台窗口：自动注册层叠顺序 + 窗口化拖动 */
  Array.prototype.forEach.call(document.querySelectorAll('.appwin.mgr-win'), function (w) {
    window.DESKTOP.registerWin(w);
    window.DESKTOP.makeDraggable(w, true);
  });

  /* ========== 桌面图标：拖动任意排序 + 按账号持久化 ========== */
  (function initIconSort() {
    var wrap = document.querySelector('.dicons');
    if (!wrap) return;
    var KEY = 'ta_desktop_icons_' + (localStorage.getItem('ta_uid') || 'anon');
    function icons() {
      return Array.prototype.slice.call(wrap.children).filter(function (c) { return c.classList.contains('dico'); });
    }
    function persist() {
      try { localStorage.setItem(KEY, JSON.stringify(icons().map(function (el) { return el.dataset.app; }))); } catch (e) {}
    }
    /* 恢复保存的顺序 */
    try {
      var saved = JSON.parse(localStorage.getItem(KEY) || 'null');
      if (Array.isArray(saved) && saved.length) {
        var map = {};
        icons().forEach(function (el) { map[el.dataset.app] = el; });
        saved.forEach(function (app) { var el = map[app]; if (el) wrap.appendChild(el); });
        persist();
      }
    } catch (e) {}

    var dragging = null;
    icons().forEach(function (el) {
      el.draggable = true;
      el.addEventListener('dragstart', function (e) {
        dragging = el;
        el.classList.add('dragging');
        window.__iconDrag = true;
        try { e.dataTransfer.effectAllowed = 'move'; } catch (err) {}
      });
      el.addEventListener('dragend', function () {
        el.classList.remove('dragging');
        dragging = null;
        setTimeout(function () { window.__iconDrag = false; }, 80);
        persist();
      });
    });
    wrap.addEventListener('dragover', function (e) {
      e.preventDefault();
      if (!dragging) return;
      var target = e.target.closest ? e.target.closest('.dico') : null;
      if (!target || target === dragging) return;
      var rect = target.getBoundingClientRect();
      var before = (e.clientY - rect.top) < rect.height / 2;
      wrap.insertBefore(dragging, before ? target : target.nextSibling);
    });
  })();

  /* ========== 管理台/系统设置入口权限：经理(1)见管理台图标，超管(2)另见设置图标 ========== */
  (function gateManagerIcons() {
    var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
    Array.prototype.forEach.call(document.querySelectorAll('.dico.mgr-only'), function (d) {
      if (role >= 1) d.classList.add('granted');
    });
    Array.prototype.forEach.call(document.querySelectorAll('.dico.admin-only'), function (d) {
      if (role >= 2) d.classList.add('granted');
    });
  })();
  /* ========== 恢复上次打开的应用（刷新不关闭） ========== */
  (function restoreApps() {
    var saved;
    try { saved = JSON.parse(localStorage.getItem('ta_desktop_apps') || 'null'); } catch (e) {}
    if (!saved || !saved.open || !saved.open.length) return;
    saved.open.forEach(function (k) { if (APPWINS[k]) addTaskBtn(k); });
    var visList = Array.isArray(saved.visible) ? saved.visible : (saved.visible ? [saved.visible] : []);
    visList.forEach(function (vis) {
      if (!APPWINS[vis]) return;
      var w = $(APPWINS[vis]);
      w.dataset.started = '1';
      w.classList.add('show');
      if (vis === 'docs') w.classList.add('windowed');
      var b = taskBtn(vis);
      if (b) b.classList.add('active');
      var rf = DA.feats[vis];
      if (rf && rf.start) rf.start();
    });
  })();
})();
