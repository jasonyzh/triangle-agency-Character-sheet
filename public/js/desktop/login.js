(function () {
  'use strict';

  /* ================= 场景自适应缩放（cover） ================= */
  var scene = document.getElementById('scene');
  function fit() {
    var s = Math.max(window.innerWidth / 1600, window.innerHeight / 900);
    scene.style.setProperty('--s', s);
  }
  window.addEventListener('resize', fit);
  fit();

  /* ================= 键盘按键生成 ================= */
  var kb = document.getElementById('kbRows');
  var rows = [14, 14, 13, 12];
  rows.forEach(function (n) {
    var row = document.createElement('div');
    row.className = 'kb-row';
    for (var i = 0; i < n; i++) {
      var k = document.createElement('i');
      k.className = 'kb-key';
      row.appendChild(k);
    }
    kb.appendChild(row);
  });
  var spaceRow = document.createElement('div');
  spaceRow.className = 'kb-row';
  var space = document.createElement('i');
  space.className = 'kb-key space';
  spaceRow.appendChild(space);
  kb.appendChild(spaceRow);

  /* ================= 登录逻辑（真实接口 /api/login） ================= */
  var state = 'idle';
  var userInput = document.getElementById('userInput');
  var passInput = document.getElementById('passInput');
  var goBtn = document.getElementById('goBtn');
  var errTxt = document.getElementById('errTxt');

  function showErr(msg) {
    errTxt.textContent = msg;
    errTxt.classList.add('show');
    clearTimeout(showErr.t);
    showErr.t = setTimeout(function () { errTxt.classList.remove('show'); }, 2600);
  }

  function tryLogin() {
    if (state !== 'idle') return;
    var u = userInput.value.trim();
    var p = passInput.value;
    if (!u) { showErr('Please enter your username'); return; }
    if (!p) { showErr('Please enter your password'); return; }
    state = 'loading';
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data.success) {
        showErr(data.message || '账号或密码错误');
        state = 'idle';
        return;
      }
      localStorage.setItem('ta_uid', data.userId);
      localStorage.setItem('ta_token', data.token);
      localStorage.setItem('ta_role', data.role);
      if (data.isAdmin) localStorage.setItem('ta_is_admin', 'true'); else localStorage.removeItem('ta_is_admin');
      if (data.isManager) localStorage.setItem('ta_is_manager', 'true'); else localStorage.removeItem('ta_is_manager');
      if (data.branches && data.branches.length) localStorage.setItem('ta_current_branch', data.branches[0].id);
      zoomToDesktop();
    })
    .catch(function () {
      showErr('Server connection failed');
      state = 'idle';
    });
  }
  window.tryLogin = tryLogin;
  goBtn.addEventListener('click', tryLogin);

  /* 电脑端成功动画：三角填满屏幕区域(0.6s) → 屏幕放大填满视口(0.9s) → 跳转 desktop.html 倒放缩小 */
  function zoomToDesktop() {
    var fill = document.getElementById('triFill');
    var ms = document.querySelector('.m-screen');
    if (!fill || !ms) { location.href = 'desktop.html'; return; }
    sessionStorage.setItem('ta_tri_intro', '1');
    /* 预加载 desktop.html：动画期间后台完成解析/资源加载，跳转后无白屏闪烁 */
    var pre = document.createElement('iframe');
    pre.src = 'desktop.html';
    pre.setAttribute('aria-hidden', 'true');
    pre.style.cssText = 'position:fixed;left:-8px;top:-8px;width:4px;height:4px;opacity:0;pointer-events:none;border:0;';
    document.body.appendChild(pre);
    fill.classList.add('active');
    setTimeout(function () {
      var r = ms.getBoundingClientRect();
      var vw = window.innerWidth, vh = window.innerHeight;
      var scale = Math.max(vw / r.width, vh / r.height) * 1.03;
      var tx = vw / 2 - (r.left + r.width / 2);
      var ty = vh / 2 - (r.top + r.height / 2);
      ms.style.transition = 'transform .9s cubic-bezier(.65,.05,.25,1)';
      ms.style.transformOrigin = 'center center';
      ms.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
      ms.style.borderRadius = '0';
    }, 600);
    setTimeout(function () { location.href = 'desktop.html'; }, 1600);
  }

  function reduceMotion() { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }

  passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') tryLogin(); });
  userInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') tryLogin(); });

  window.resetLogin = function () {
    document.getElementById('welcomeOverlay').classList.remove('show');
    passInput.value = '';
    state = 'idle';
  };
})();
