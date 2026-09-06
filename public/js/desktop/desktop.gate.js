/* 新职员门禁 + 加入分部（desktop.gate.js）
   1) 门禁：未加入任何分部的普通职员（role=0）登录后，全屏遮罩盖住整个桌面，
      选择分部提交申请（可同时申请多个）；任一申请通过经 Socket.IO 实时推送，
      遮罩中央显示「欢迎您，新特工」后整层缩小解锁并自动选中该分部。
   2) 加入分部窗口：桌面「加入分部」图标（所有职员可见），随时申请加入更多分部，
      审批通过/拒绝同样实时推送（toast + 分部下拉刷新）。
   设计：浅色主题 —— 搜索 / 状态标签 / 卡片网格（图标+人数）/ 分页，两个表面共用。
   数据入口：desktop.js loadBranches() → DA.feats.gate.check(branchList, role) */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH;

  var gateEl = $('gateMask');
  if (!gateEl) return;

  var PAGE_SIZE = 12;
  var ICONS = ['fa-bullseye', 'fa-chart-bar', 'fa-bullhorn', 'fa-users', 'fa-wrench',
    'fa-shield-alt', 'fa-lightbulb', 'fa-globe', 'fa-graduation-cap', 'fa-file-alt',
    'fa-heart', 'fa-ellipsis-h'];

  var sock = null;
  var active = false;      /* 门禁遮罩是否生效 */
  var welcoming = false;   /* 欢迎动画播放中（忽略后续推送，统一由 afterJoin 刷新） */
  var data = null;         /* /api/branches 全量分部 */

  function loggedIn() { return !!(localStorage.getItem('ta_token') && localStorage.getItem('ta_uid')); }
  function iconFor(id) {
    var h = 0, s = String(id || '');
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return ICONS[h % ICONS.length];
  }

  /* ---------- 表面注册：门禁遮罩 / 加入分部窗口各持独立筛选状态 ---------- */
  var surfaces = [];
  function registerSurface(root) {
    var s = {
      root: root,
      st: { tab: 'all', q: '', page: 1 },
      list: root.querySelector('.gj-grid'),
      tabs: root.querySelector('.gj-tabs'),
      count: root.querySelector('.gj-count'),
      pager: root.querySelector('.gj-pager'),
      input: root.querySelector('.gj-q'),
      btn: root.querySelector('.gj-searchbtn')
    };
    if (!s.list) return;
    root.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-apply],[data-reapply],[data-retry],.gtab,.gpage') : null;
      if (!t) return;
      if (t.hasAttribute('data-retry')) { refresh(); return; }
      if (t.hasAttribute('data-apply') || t.hasAttribute('data-reapply')) {
        apply(t.getAttribute('data-apply') || t.getAttribute('data-reapply'), t);
        return;
      }
      if (t.classList.contains('gtab')) {
        s.st.tab = t.getAttribute('data-f') || 'all';
        s.st.page = 1;
        Array.prototype.forEach.call(s.tabs.querySelectorAll('.gtab'), function (b) { b.classList.toggle('active', b === t); });
        renderSurface(s);
        return;
      }
      if (t.classList.contains('gpage') && !t.disabled) {
        s.st.page = parseInt(t.getAttribute('data-page'), 10) || 1;
        renderSurface(s);
        if (s.list.scrollIntoView) s.list.scrollIntoView({ block: 'nearest' });
      }
    });
    function doSearch() {
      s.st.q = (s.input ? s.input.value : '').trim();
      s.st.page = 1;
      renderSurface(s);
    }
    if (s.btn) s.btn.addEventListener('click', doSearch);
    if (s.input) s.input.addEventListener('keydown', function (e) { if (e.key === 'Enter') doSearch(); });
    if (s.input) s.input.addEventListener('input', doSearch);
    surfaces.push(s);
  }
  registerSurface(gateEl);
  (function () { var w = $('winBranchJoin'); if (w) registerSurface(w); })();

  /* ---------- 筛选 / 渲染 ---------- */
  function filtered(st) {
    var list = (data || []).slice();
    if (st.tab === 'pending') list = list.filter(function (b) { return b.application_status === 'pending'; });
    else if (st.tab === 'joined') list = list.filter(function (b) { return b.joined; });
    else if (st.tab === 'can') list = list.filter(function (b) { return !b.joined && b.application_status !== 'pending'; });
    if (st.q) {
      var q = st.q.toLowerCase();
      list = list.filter(function (b) { return (b.name || '').toLowerCase().indexOf(q) >= 0; });
    }
    return list;
  }

  function cardHtml(b) {
    var st = b.application_status, action;
    /* 「已加入」只看 joined：被移出分部后历史申请虽是 approved，仍应允许再次申请 */
    if (b.joined) action = '<span class="gj-badge gj-joined"><i class="fas fa-check"></i> 已加入</span>';
    else if (st === 'pending') action = '<span class="gj-badge gj-pending"><i class="fas fa-hourglass-half"></i> 申请中</span>';
    else if (st === 'rejected') action = '<button class="gj-apply" data-reapply="' + esc(b.id) + '">重新申请</button>';
    else action = '<button class="gj-apply" data-apply="' + esc(b.id) + '">申请加入</button>';
    /* 分部设置过图标则用图片，否则按 ID 确定性取一个图标；介绍短语优先于建分部时的描述 */
    var icon = b.icon
      ? '<span class="gj-ico"><img src="' + esc(b.icon) + '" alt=""></span>'
      : '<span class="gj-ico"><i class="fas ' + iconFor(b.id) + '"></i></span>';
    return '<div class="gj-card">' +
      '<div class="gj-top">' + icon +
      '<div class="gj-info"><b>' + esc(b.name) + '</b><span>' + (esc(b.intro || b.description) || '暂无描述') + '</span></div></div>' +
      '<div class="gj-bottom"><span class="gj-members"><i class="fas fa-user"></i> ' + (b.user_count || 0) + ' 人</span>' + action + '</div>' +
      '</div>';
  }

  function pagerHtml(pages, cur) {
    if (pages <= 0) return '';
    var btn = function (p, label, dis, act) {
      return '<button class="gpage' + (act ? ' active' : '') + '" data-page="' + p + '"' + (dis ? ' disabled' : '') + '>' + label + '</button>';
    };
    var html = btn(cur - 1, '<i class="fas fa-chevron-left"></i>', cur <= 1, false);
    for (var p = 1; p <= pages; p++) html += btn(p, p, false, p === cur);
    html += btn(cur + 1, '<i class="fas fa-chevron-right"></i>', cur >= pages, false);
    return html;
  }

  function renderSurface(s) {
    if (!data) return;
    var list = filtered(s.st);
    var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    if (s.st.page > pages) s.st.page = pages;
    var vis = list.slice((s.st.page - 1) * PAGE_SIZE, s.st.page * PAGE_SIZE);
    s.list.innerHTML = vis.length ? vis.map(cardHtml).join('') : '<div class="gate-empty">没有匹配的分部</div>';
    if (s.count) s.count.textContent = '共 ' + list.length + ' 个分部';
    if (s.pager) s.pager.innerHTML = pagerHtml(pages, s.st.page);
  }

  function renderAll() { surfaces.forEach(renderSurface); }

  function refresh() {
    if (!loggedIn()) return;
    fetch('/api/branches', { headers: authH() })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.success) return;
        data = d.branches || [];
        renderAll();
      })
      .catch(function () {
        var s = surfaces[0];
        if (s && s.list && !data) s.list.innerHTML = '<div class="gate-empty">获取分部列表失败 <button class="gj-apply" data-retry>重试</button></div>';
      });
  }

  function apply(branchId, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '提交中…'; }
    fetch('/api/branch-application', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authH()),
      body: JSON.stringify({ branchId: branchId })
    })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (res.ok && res.d.success) showToast('申请已提交，等待审批');
        else showToast((res.d && res.d.message) || '申请失败');
        refresh();
      })
      .catch(function () { showToast('申请失败，请重试'); refresh(); });
  }

  /* ---------- 门禁遮罩控制 ---------- */
  function showGate() {
    active = true;
    gateEl.classList.remove('welcome', 'leave');
    gateEl.classList.add('show');
    refresh();
  }

  function hideGate() {
    active = false;
    welcoming = false;
    gateEl.classList.remove('show', 'welcome', 'leave');
  }

  /* desktop.js loadBranches() 回调：普通职员且无任何分部 → 门禁；其余 → 确保遮罩收起 */
  function check(branchList, role) {
    if (!loggedIn()) return;
    ensureSock();
    if (role === 0 && !(branchList && branchList.length)) { if (!active) showGate(); }
    else if (active) hideGate();
  }

  /* ---------- 审批结果推送 ---------- */
  function afterJoin(branch) {
    /* 新职员首次入部：自动选中新分部；随后必须重拉分部列表刷新下拉（本地 branchList 已过期） */
    if (!localStorage.getItem('ta_current_branch') && branch && branch.branchId && window.DESKTOP && window.DESKTOP.setBranch) {
      window.DESKTOP.setBranch(branch.branchId);
    }
    if (window.DESKTOP && window.DESKTOP.loadBranches) window.DESKTOP.loadBranches();
    refresh();
  }

  function onApproved(branch) {
    if (active && !welcoming) {
      /* 欢迎动画：三角描边绘入 + 勾选弹出 + 文字浮现 → 停留 → 整层淡出露出桌面 */
      welcoming = true;
      var sub = $('gateWelcomeSub');
      if (sub) sub.textContent = branch && branch.branchName ? '已加入「' + branch.branchName + '」' : '';
      gateEl.classList.add('welcome');
      setTimeout(function () {
        gateEl.classList.add('leave');
        setTimeout(function () {
          hideGate();
          afterJoin(branch);
        }, 800);
      }, 2600);
    } else if (!active && !welcoming) {
      showToast('已加入「' + (branch.branchName || '新分部') + '」');
      afterJoin(branch);
    }
    /* welcoming 中的后续推送忽略：afterJoin 已统一刷新 */
  }

  function onRejected(branch) {
    showToast('加入「' + (branch.branchName || '') + '」的申请被拒绝');
    refresh();
  }

  function ensureSock() {
    if (sock || typeof io === 'undefined' || !window.DESKTOP || !window.DESKTOP.getToken()) return;
    sock = io({ auth: { token: window.DESKTOP.getToken() } });
    sock.on('branch:reviewed', function (d) {
      if (!d || !d.status) return;
      if (d.status === 'approved') onApproved(d);
      else if (d.status === 'rejected') onRejected(d);
    });
  }

  /* ---------- 桌面「加入分部」窗口生命周期（desktop.shell.js openApp 调用） ---------- */
  DA.feats['branch-join'] = {
    start: function () { refresh(); },
    reload: function () { refresh(); },
    close: function () {}
  };

  DA.feats.gate = { check: check };

  /* 冷启动自检：desktop.js 解析时已抢先调用过一次 loadBranches（当时 gate 尚未加载），
     这里补拉一次 my-branches 判定是否需要门禁；登录流程则由 loadBranches 的 check 钩子覆盖 */
  (function selfCheck() {
    if (!loggedIn()) return;
    ensureSock();
    var r = parseInt(localStorage.getItem('ta_role') || '0', 10);
    if (r !== 0) return;
    fetch('/api/user/my-branches', { headers: authH() })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (d) {
        if (!d || !d.success) return;
        check(d.branches || [], r);
      })
      .catch(function () {});
  })();
})();
