(function () {
  'use strict';

  /* ============ 登录层（desktop.html 内嵌）：桌面场景缩放 ============ */
  var scene = document.getElementById('scene');
  function fit() {
    var s = Math.max(window.innerWidth / 1600, window.innerHeight / 900);
    if (scene) scene.style.setProperty('--s', s);
  }
  window.addEventListener('resize', fit);
  fit();

  /* ============ 键盘按键生成 ============ */
  var kb = document.getElementById('kbRows');
  if (kb) {
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
  }

  var isMobile = function () { return window.matchMedia('(max-width: 860px)').matches; };
  function showLoginStage() {
    resetStage();
    var stage = document.getElementById('loginStage');
    if (stage) stage.classList.add('show');
  }
  function hideLoginStage() {
    var stage = document.getElementById('loginStage');
    if (stage) stage.classList.remove('show');
  }
  /* 重置登录层到初始状态（登出后显示/重新登录时避免残留放大/三角状态） */
  function resetStage() {
    var fill = document.getElementById('triFill');
    if (fill) fill.classList.remove('active');
    var fillM = document.getElementById('triFillM');
    if (fillM) fillM.classList.remove('active');
    var ms = document.querySelector('#loginStage .m-screen');
    if (ms) {
      ms.style.transition = '';
      ms.style.transform = '';
      ms.style.transformOrigin = '';
      ms.style.borderRadius = '';
      ms.style.background = '';
    }
    var st = document.querySelector('#loginStage .stage');
    if (st) {
      st.style.transition = '';
      st.style.transform = '';
      st.style.transformOrigin = '';
    }
    var intro = document.getElementById('triIntro');
    if (intro) {
      intro.classList.remove('show', 'active');
      intro.style.display = 'none';
      var sh = intro.querySelector('.tri-shape');
      if (sh) { sh.style.transform = ''; }
      var svgEl = intro.querySelector('svg');
      if (svgEl) { svgEl.style.width = ''; svgEl.style.height = ''; }
    }
    var mask = document.getElementById('mLoadingMask');
    if (mask) mask.classList.remove('show');
    var mmsg = document.getElementById('mMsg');
    if (mmsg) mmsg.classList.remove('show');
    var merr = document.getElementById('errTxt');
    if (merr) merr.classList.remove('show');
  }

  /* 缩小段：triIntro 初始画面与放大段结束画面精确同步（scale/logo 尺寸取自上一段），无跳变 */

  /* ============ 登录逻辑（真实接口 /api/login） ============ */
  var state = 'idle';
  var userInput = document.getElementById('userInput');
  var passInput = document.getElementById('passInput');
  var goBtn = document.getElementById('goBtn');
  var errTxt = document.getElementById('errTxt');
  var mUser = document.getElementById('mUser');
  var mPass = document.getElementById('mPass');
  var mBtn = document.getElementById('mBtn');
  var mMsg = document.getElementById('mMsg');

  function showErr(msg) {
    if (!errTxt) return;
    errTxt.textContent = msg;
    errTxt.classList.add('show');
    clearTimeout(showErr.t);
    showErr.t = setTimeout(function () { errTxt.classList.remove('show'); }, 2600);
  }
  function showMErr(msg) {
    if (!mMsg) return;
    mMsg.textContent = msg;
    mMsg.classList.add('show');
    clearTimeout(showMErr.t);
    showMErr.t = setTimeout(function () { mMsg.classList.remove('show'); }, 2600);
  }

  function applySession(data) {
    localStorage.setItem('ta_uid', data.userId);
    localStorage.setItem('ta_token', data.token);
    localStorage.setItem('ta_role', data.role);
    if (data.isAdmin) localStorage.setItem('ta_is_admin', 'true'); else localStorage.removeItem('ta_is_admin');
    if (data.isManager) localStorage.setItem('ta_is_manager', 'true'); else localStorage.removeItem('ta_is_manager');
    if (data.branches && data.branches.length && !localStorage.getItem('ta_current_branch')) {
      localStorage.setItem('ta_current_branch', data.branches[0].id);
    }
  }

  /* 电脑端两段式过场：
     放大段：三角旋转展开填满屏幕区域(0.85s) → 整个 m-screen 放大填满视口(0.9s)
     缩小段：切换独立 triIntro 全屏三角旋转缩小露出桌面(1.5s) */
  function zoomToDesktop() {
    var fill = document.getElementById('triFill');
    var ms = document.querySelector('#loginStage .m-screen');
    if (!fill || !ms) { finishLogin(); return; }
    fill.classList.add('active');
    setTimeout(function () {
      /* 屏幕四角原露 loginbg，补成与三角同色渐变，放大后全屏纯红 */
      ms.style.background = 'linear-gradient(180deg, #e0503a 0%, #d0402c 100%)';
      var r = ms.getBoundingClientRect();
      var vw = window.innerWidth, vh = window.innerHeight;
      var scale = Math.max(vw / r.width, vh / r.height) * 1.03;
      var tx = vw / 2 - (r.left + r.width / 2);
      var ty = vh / 2 - (r.top + r.height / 2);
      ms.style.transition = 'transform .9s cubic-bezier(.65,.05,.25,1)';
      ms.style.transformOrigin = 'center center';
      ms.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
      ms.style.borderRadius = '0';
    }, 900);
    setTimeout(finishLogin, 1800);
  }

  /* 缩小段：triIntro 满屏出现（无动画）→ 停留 → active 缓慢缩小露出桌面 */
  function finishLogin() {
    var intro = document.getElementById('triIntro');
    if (intro) {
      intro.classList.add('show');
      setTimeout(function () { intro.classList.add('active'); }, 400);
      setTimeout(function () {
        intro.style.display = 'none';
        intro.classList.remove('show', 'active');
      }, 1900);
    }
    setTimeout(function () { hideLoginStage(); }, 200);
    /* 通知桌面核心：登录成功，开始加载用户数据 */
    try {
      if (window.DESKTOP && window.DESKTOP.onLoginOK) window.DESKTOP.onLoginOK();
      window.dispatchEvent(new CustomEvent('ta:login-ok'));
    } catch (e) {
      /* 数据加载异常不阻断过场动画 */
    }
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
      applySession(data);
      zoomToDesktop();
    })
    .catch(function () {
      showErr('Server connection failed');
      state = 'idle';
    });
  }

  /* 手机端：loading 遮罩 → 直接进入桌面（同页） */
  function mLogin() {
    if (!isMobile()) return;
    if (state !== 'idle') return;
    var u = mUser.value.trim();
    var p = mPass.value;
    if (!u) { showMErr('Please enter your username'); return; }
    if (!p) { showMErr('Please enter your password'); return; }
    state = 'loading';
    mMsg.classList.remove('show');
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data.success) {
        showMErr(data.message || '账号或密码错误');
        state = 'idle';
        return;
      }
      applySession(data);
      zoomMobile();
    })
    .catch(function () {
      showMErr('Server connection failed');
      state = 'idle';
    });
  }

  /* 手机端过场：
     ①红三角旋转遮盖手机屏幕(0.85s，表单/按钮被红盖住)
     ②整个手持手机与 svg 同步放大 1200% 往屏幕外飘(1.2s)
     ③消失后切 triIntro 全屏红缩小露出桌面 */
  function zoomMobile() {
    var fill = document.getElementById('triFillM');
    var st = document.querySelector('#loginStage .stage');
    if (!fill || !st) { finishLogin(); return; }
    fill.classList.add('active');
    setTimeout(function () {
      st.style.transition = 'transform 1.2s cubic-bezier(.55,.05,.5,1)';
      st.style.transformOrigin = 'center center';
      st.style.transform = 'scale(3)';
    }, 900);
    setTimeout(finishLogin, 2300);
  }

  if (goBtn) goBtn.addEventListener('click', tryLogin);
  if (userInput) userInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') tryLogin(); });
  if (passInput) passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') tryLogin(); });
  if (mBtn) mBtn.addEventListener('click', mLogin);
  if (mUser) mUser.addEventListener('keydown', function (e) { if (e.key === 'Enter') mLogin(); });
  if (mPass) mPass.addEventListener('keydown', function (e) { if (e.key === 'Enter') mLogin(); });

  /* 注册开关（登录层内） */
  fetch('/api/register/status')
    .then(function (r) { return r.json(); })
    .then(function (data) {
      var rl = document.getElementById('regLink');
      var mrl = document.getElementById('mRegLink');
      if (data.registrationEnabled) {
        if (rl) rl.style.display = 'block';
        if (mrl) mrl.style.display = 'block';
      }
    })
    .catch(function () {});

  /* 未登录（desktop.js 检测后调用）：显示登录层 */
  window.LS = { show: showLoginStage, hide: hideLoginStage };
})();
