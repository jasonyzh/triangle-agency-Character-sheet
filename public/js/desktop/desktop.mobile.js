/* 手机端专属逻辑：Dock 快捷入口 + 邮箱徽章同步 + 负一屏手势/指示点/时钟
   仅在 ≤860px 生效；桌面端 DOM 存在但 display:none，不绑定也无副作用 */
(function () {
  'use strict';

  /* ================= Dock：5 快捷入口 ================= */
  var dock = document.getElementById('maDock');
  if (dock) {
    dock.addEventListener('click', function (e) {
      var btn = e.target.closest('.ma-dock-btn');
      if (!btn) return;
      /* 角色 → 触发对应桌面图标（复用 shell 的图标点击委托/关闭链路） */
      if (btn.dataset.maApp) {
        var dico = document.querySelector('.dico[data-app="' + btn.dataset.maApp + '"]');
        if (dico) dico.click();
        return;
      }
      /* 异常/关系/物品/邮箱 → 触发任务栏按钮（复用 bindWin 渲染与开关） */
      if (btn.dataset.maTb) {
        var tb = document.getElementById(btn.dataset.maTb);
        if (tb) tb.click();
      }
    });
  }

  /* ================= 邮箱未读徽章同步（tbMailBadge → maMailBadge） ================= */
  var srcBadge = document.getElementById('tbMailBadge');
  var dstBadge = document.getElementById('maMailBadge');
  if (srcBadge && dstBadge) {
    var syncBadge = function () {
      dstBadge.textContent = srcBadge.textContent;
      dstBadge.style.display = srcBadge.style.display;
    };
    new MutationObserver(syncBadge).observe(srcBadge, { attributes: true, childList: true, characterData: true });
    syncBadge();
  }

  /* ================= 三屏切换：主屏(home) / 负一屏(minus) / 角色选择屏(profile) ================= */
  function maScreen() { return document.body.dataset.ma || 'home'; }
  function setScreen(name) { document.body.dataset.ma = name; renderDots(); }

  /* 页面指示点（dock 上方，3 个：左负一屏 / 中主屏 / 右角色屏） */
  var dots = document.createElement('div');
  dots.id = 'maDots';
  dots.innerHTML = '<i data-ma-dot="minus"></i><i data-ma-dot="home"></i><i data-ma-dot="profile"></i>';
  document.body.appendChild(dots);
  dots.addEventListener('click', function (e) {
    var d = e.target.closest('[data-ma-dot]');
    if (d) setScreen(d.dataset.maDot);
  });
  function renderDots() {
    var cur = maScreen();
    Array.prototype.forEach.call(dots.querySelectorAll('i'), function (i) {
      i.classList.toggle('active', i.dataset.maDot === cur);
    });
  }
  renderDots();

  /* 水平滑动手势（屏位：负一屏在左 / 桌面居中 / 角色屏在右）：
     桌面右滑→负一屏、左滑→角色屏；负一屏右滑回桌面；角色屏左滑回桌面 */
  var tx = null, ty = null;
  document.addEventListener('touchstart', function (e) {
    if (e.touches.length !== 1) { tx = null; return; }
    tx = e.touches[0].clientX; ty = e.touches[0].clientY;
  }, { passive: true });
  /* 水平滑动意图明确时阻止浏览器接管（否则 touchend 不触发，滑回中间失效）；
     cancelable=false 说明浏览器已开始滚动、事件不可取消，跳过以免控制台刷 [Intervention] */
  document.addEventListener('touchmove', function (e) {
    if (tx === null || !e.touches.length || !e.cancelable) return;
    var dx = Math.abs(e.touches[0].clientX - tx);
    var dy = Math.abs(e.touches[0].clientY - ty);
    if (dx > dy + 10 && dx > 30) e.preventDefault();
  }, { passive: false });
  document.addEventListener('touchend', function (e) {
    if (tx === null) return;
    var dx = e.changedTouches[0].clientX - tx;
    var dy = e.changedTouches[0].clientY - ty;
    tx = null;
    if (Math.abs(dx) < 60 || Math.abs(dy) > 50) return;
    var cur = maScreen();
    if (cur === 'home') {
      if (dx > 0) setScreen('minus');       /* 右滑 → 左侧负一屏拉入 */
      else if (dx < 0) setScreen('profile'); /* 左滑 → 右侧角色屏拉入 */
    } else if (cur === 'minus') {
      if (dx < 0) setScreen('home');         /* 左滑推回桌面（负一屏在左侧，反向推回） */
    } else if (cur === 'profile') {
      if (dx > 0) setScreen('home');         /* 右滑推回桌面（角色屏在右侧） */
    }
  }, { passive: true });

  /* ================= 负一屏大时钟（作为负一屏首元素，随卡片滚动） ================= */
  var maClock = document.createElement('div');
  maClock.id = 'maClock';
  var cardsBox = document.querySelector('.cards');
  if (cardsBox) cardsBox.insertBefore(maClock, cardsBox.firstChild);
  function tickClock() {
    var d = new Date();
    var h = d.getHours(), m = d.getMinutes();
    maClock.textContent = (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m;
  }
  tickClock();
  setInterval(tickClock, 10000);

  /* ================= APP 弹窗「返回桌面」按钮 ================= */
  /* 返回桌面 = 真的回到手机桌面：关闭所有已打开的窗口/浮窗 + 收起配置页 + 切回主屏 */
  var backSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 5 L7.5 12 l7 7"/></svg>';
  function goDesktop() {
    Array.prototype.forEach.call(document.querySelectorAll('.appwin.show'), function (w) {
      var c = w.querySelector('[data-appclose]');
      if (c) c.click();
    });
    ['winAnom', 'winReal', 'winItem', 'winMail', 'winCareer'].forEach(function (id) {
      var w = document.getElementById(id);
      if (w && w.classList.contains('show')) {
        var c = w.querySelector('[data-close]');
        if (c) c.click();
      }
    });
    closeProfile();
    setScreen('home');
  }
  function injectBack(win) {
    if (!win || win.querySelector('.ma-back')) return;
    var head = win.querySelector('.dwin-head');
    if (!head) return;
    var btn = document.createElement('button');
    btn.className = 'ma-back';
    btn.title = '返回桌面';
    btn.innerHTML = backSvg + '<span>返回桌面</span>';
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      goDesktop();
    });
    /* 头部末尾 = 右上角（关闭/最小化按钮手机端隐藏） */
    head.appendChild(btn);
  }
  Array.prototype.forEach.call(document.querySelectorAll('.appwin'), injectBack);
  ['winAnom', 'winReal', 'winItem', 'winMail', 'winCareer'].forEach(function (id) {
    injectBack(document.getElementById(id));
  });

  /* ================= 手机端桌面背景：随三轨主题切换 =================
     黄(现实占优)=phonebgyellow / 蓝(异常占优)=phonebluebg / 默认红=phone-bg；桌面端保持三层背景 */
  var bgImg = document.querySelector('img.bg');
  if (bgImg) {
    var desktopBg = 'img/desktopbg.webp';
    var themeBg = function () {
      if (document.body.classList.contains('bg-yellow')) return 'img/phonebgyellow.webp';
      if (document.body.classList.contains('bg-blue')) return 'img/phonebluebg.webp';
      return 'img/phone-bg.webp';
    };
    var applyBg = function () {
      var want = window.matchMedia('(max-width: 860px)').matches ? themeBg() : desktopBg;
      if (bgImg.getAttribute('src') !== want) bgImg.setAttribute('src', want);
    };
    applyBg();
    window.addEventListener('resize', applyBg);
    /* 主题类由生涯三轨重算切换，监听 body class 变化同步换背景 */
    new MutationObserver(applyBg).observe(document.body, { attributes: true, attributeFilter: ['class'] });
  }

  /* ================= UNL3ASH：异常能力窗口打开时，显示于其标题栏中央（仅手机端） ================= */
  /* 实现：按钮插入 winAnom 标题栏内作为 flex 子元素（margin:0 auto 水平居中、
     align-items:center 垂直居中），窗口关闭随头部一起隐藏，无需像素计算 */
  var unlashBtn = document.getElementById('btnUnlash');
  var unlashHome = unlashBtn ? { parent: unlashBtn.parentElement, before: unlashBtn.nextSibling } : null;
  var winAnomEl = document.getElementById('winAnom');
  function moveUnlash() {
    /* 手机端把按钮移出被隐藏的 taskbar 挂进异常窗口标题栏，桌面端放回原位 */
    if (!unlashBtn || !winAnomEl) return;
    var mobile = window.matchMedia('(max-width: 860px)').matches;
    var head = winAnomEl.querySelector('.dwin-head');
    if (mobile && head && unlashBtn.parentElement !== head) {
      var back = head.querySelector('.ma-back');
      if (back) head.insertBefore(unlashBtn, back);
      else head.appendChild(unlashBtn);
    } else if (!mobile && unlashHome && unlashBtn.parentElement !== unlashHome.parent) {
      unlashHome.parent.insertBefore(unlashBtn, unlashHome.before);
    }
  }
  moveUnlash();
  window.addEventListener('resize', moveUnlash);

  /* ================= 外勤OS：任务选择下拉移到窗口标题栏（仅手机端，resize 双向） ================= */
  var boardSel = document.getElementById('boardMissionSel');
  var boardHead = document.querySelector('#winBoard .dwin-head');
  var selHome = null; /* 桌面端原位置（toolbar 内 dice-bar 之前） */
  function moveBoardSel() {
    if (!boardSel || !boardHead) return;
    var mobile = window.matchMedia('(max-width: 860px)').matches;
    if (mobile) {
      if (boardSel.parentElement !== boardHead) {
        var back = boardHead.querySelector('.ma-back');
        if (back) boardHead.insertBefore(boardSel, back);
        else boardHead.appendChild(boardSel);
      }
    } else if (selHome && boardSel.parentElement !== selHome.parent) {
      selHome.parent.insertBefore(boardSel, selHome.before);
    }
  }
  if (boardSel) {
    selHome = { parent: boardSel.parentElement, before: boardSel.nextSibling };
    moveBoardSel();
    window.addEventListener('resize', moveBoardSel);
  }
  var profilePop = document.getElementById('profilePop');
  function openProfile() {
    var logo = document.getElementById('tbLogo');
    if (logo) logo.classList.add('active');
    setScreen('profile');
  }
  function closeProfile() {
    var logo = document.getElementById('tbLogo');
    if (logo) logo.classList.remove('active');
    if (maScreen() === 'profile') setScreen('home');
  }
  /* 配置页右上角返回桌面 */
  if (profilePop && !profilePop.querySelector('.ma-back')) {
    var pb = document.createElement('button');
    pb.className = 'ma-back';
    pb.title = '返回桌面';
    pb.innerHTML = backSvg + '<span>返回桌面</span>';
    pb.addEventListener('click', function (e) {
      e.stopPropagation();
      goDesktop();
    });
    profilePop.insertBefore(pb, profilePop.firstChild);
  }
})();
