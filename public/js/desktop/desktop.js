(function () {
  'use strict';

  /* ================= 会话过期自动弹出登录层 =================
     token 过期/无效时后端返回 403（message=“登录已过期”），无 token 时 401。
     统一拦截 /api/ 的这两类响应：清掉本地会话并展开桌面自带登录层（同页登录，与登出同链路）；
     “权限不足”等其它 403 不干预。并发请求同时触发时只弹出一次。 */
  (function () {
    var _fetch = window.fetch.bind(window);
    var redirected = false;
    function goLogin() {
      redirected = true;
      ['ta_token', 'ta_uid', 'ta_role', 'ta_current_char', 'ta_is_admin', 'ta_is_manager'].forEach(function (k) { localStorage.removeItem(k); });
      if (window.DESKTOP && window.DESKTOP.resetPrivilegedUi) window.DESKTOP.resetPrivilegedUi();
      /* 登录层脚本（login-stage.js）在 desktop.js 之后加载，极端时序下可能尚未就绪：
         逐帧重试直到可用；若长时间不可用，整页刷新重新初始化。 */
      var tries = 0;
      (function showLayer() {
        if (window.LS) {
          window.LS.show();
          /* 提示放 show 之后写：show 内部 resetStage 会清掉 errTxt/mMsg 的提示。
             resetStage 还会被 manager 模块的守卫再触发一次，故延迟再写一遍兜底。 */
          var setMsg = function () {
            var msg = '登录已过期，请重新登录';
            var tb = document.getElementById('errTxt');
            var mb = document.getElementById('mMsg');
            if (tb) { tb.textContent = msg; tb.classList.add('show'); }
            if (mb) { mb.textContent = msg; mb.classList.add('show'); }
          };
          setMsg();
          setTimeout(setMsg, 500);
          return;
        }
        if (++tries < 40) setTimeout(showLayer, 50);
        else location.reload();
      })();
    }
    window.fetch = function (input, init) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      return _fetch(input, init).then(function (res) {
        if (!redirected && url.indexOf('/api/') === 0 && (res.status === 401 || res.status === 403) && typeof res.json === 'function') {
          return res.clone().json().then(function (body) {
            if (res.status === 401 || (res.status === 403 && body && body.message === '登录已过期')) goLogin();
            return res;
          }).catch(function () {
            if (res.status === 401) goLogin();
            return res;
          });
        }
        return res;
      });
    };
  })();

  /* ================= 时钟 ================= */
  function tick() {
    var d = new Date();
    var h = d.getHours(), m = d.getMinutes();
    var ampm = h >= 12 ? 'PM' : 'AM';
    var h12 = h % 12; if (h12 === 0) h12 = 12;
    var t = h12 + ':' + (m < 10 ? '0' : '') + m + ' ' + ampm;
    var a = document.getElementById('tbTime');
    var b = document.getElementById('trayTime');
    if (a) a.textContent = t;
    if (b) b.textContent = t;
  }
  tick();
  setInterval(tick, 10000);

  /* ================= 个人资料面板 ================= */
  var profilePop = document.getElementById('profilePop');
  var tbLogo = document.getElementById('tbLogo');

  if (tbLogo && profilePop) {
    tbLogo.addEventListener('click', function (e) {
      e.stopPropagation();
      var showing = profilePop.classList.toggle('show');
      tbLogo.classList.toggle('active');
      if (showing) bringToFrontEl(profilePop);
    });
    document.addEventListener('click', function (e) {
      if (!profilePop.classList.contains('show')) return;
      if (profilePop.contains(e.target) || tbLogo.contains(e.target)) return;
      profilePop.classList.remove('show');
      tbLogo.classList.remove('active');
    });
  }

  /* Power → 登出：清会话，重新显示登录层（同页，无跳转） */
  var ppLogout = document.getElementById('ppLogout');
  if (ppLogout) ppLogout.addEventListener('click', function () {
    localStorage.removeItem('ta_token');
    localStorage.removeItem('ta_uid');
    localStorage.removeItem('ta_role');
    localStorage.removeItem('ta_current_char');
    /* 清掉本账号的管理台窗口/图标点亮，防止换号后残留 */
    if (window.DESKTOP && window.DESKTOP.resetPrivilegedUi) window.DESKTOP.resetPrivilegedUi();
    if (window.LS) window.LS.show();
  });

  /* ================= 档案同步：账号名 + 角色卡（异常/现实/职能/头像） ================= */
  var uid = localStorage.getItem('ta_uid');
  var token = localStorage.getItem('ta_token') || '';
  var authHeaders = { 'Authorization': 'Bearer ' + token, 'Cache-Control': 'no-cache' };
  var CHAR_KEY = 'ta_current_char';
  var accountName = '特工';
  var myChars = [];          /* 全部未归档角色 */
  var charsLoaded = false;   /* 角色列表是否已返回（决定面板何时渲染） */
  var cardCbs = [];          /* 卡片数据就绪后的回调 */
  var activeCharId = localStorage.getItem(CHAR_KEY) || null;

  if (!uid || !token) {
    /* 未登录：桌面壳已渲染，覆盖登录层；登录成功后由 onLoginOK 首次加载 */
    var lsEl = document.getElementById('loginStage');
    if (lsEl) lsEl.classList.add('show');
  }
  else loadProfile();

  /* ================= 分部：统一在左下角开始菜单选择（角色 / 管理台共用） ================= */
  var branchList = [];     /* [{id, name}] */
  var ppBranchSel = document.getElementById('ppBranchSel');
  var cmBranchSel = document.getElementById('cmBranchSel');

  function curBranchId() { return localStorage.getItem('ta_current_branch') || ''; }

  function loadBranches() {
    var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
    var url = role >= 2 ? '/api/admin/branches' : '/api/user/my-branches';
    fetch(url, { headers: authHeaders })
      .then(function (r) {
        if (!r.ok) return { __failed: true };
        return r.json();
      })
      .then(function (d) {
        if (d && d.__failed) return; /* 拉取失败不动现有渲染，也不做门禁判定 */
        branchList = (d && d.branches) || [];
        renderBranchSels();
        /* 新职员门禁：普通职员且无任何分部时由 desktop.gate.js 盖红色遮罩 */
        if (window.DA && DA.feats.gate) DA.feats.gate.check(branchList, role);
      })
      .catch(function () {});
  }

  function renderBranchSels() {
    var cur = curBranchId();
    [ppBranchSel, cmBranchSel].forEach(function (sel) {
      if (!sel) return;
      var html = '<option value="">-- 请选择分部 --</option>';
      branchList.forEach(function (b) {
        html += '<option value="' + b.id + '"' + (b.id === cur ? ' selected' : '') + '>' + esc(b.name || b.id) + '</option>';
      });
      sel.innerHTML = html;
      sel.value = cur;
    });
    if (charMask.classList.contains('show')) renderCharList();
  }

  /* ========== 高墙文档解锁门禁：X2→虹吸商店图标，U2→UNL3ASH 按钮 ========== */
  function checkUnlock(code, cb) {
    if (!activeCharId) { cb(false); return; }
    fetch('/api/character/' + encodeURIComponent(activeCharId) + '/check-' + code, { headers: authHeaders })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .then(function (d) { cb(!!d.unlocked); })
      .catch(function () { cb(false); });
  }
  function updateUnlockGates() {
    checkUnlock('x2', function (ok) {
      Array.prototype.forEach.call(document.querySelectorAll('.dico.x2-only'), function (d) {
        d.classList.toggle('granted', ok);
      });
    });
    checkUnlock('u2', function (ok) {
      var b = document.getElementById('btnUnlash');
      if (b) b.style.display = ok ? '' : 'none';
    });
    checkDestGate();
  }

  /* ========== 破坏条可见门禁：角色拥有 L10/Q3/X3 任一文件权限时对玩家开放 ==========
     经理/超管随时可见可编辑；玩家仅可查看（格子不可点、保存按钮隐藏，后端 PUT 也限经理） */
  function checkDestGate() {
    var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
    var dico = document.querySelector('.dico[data-app="m-dest"]');
    if (!dico) return;
    if (role >= 1) {   /* 经理/超管：随时可见可编辑 */
      document.body.classList.remove('dest-readonly');
      dico.classList.add('granted');
      return;
    }
    document.body.classList.add('dest-readonly');
    if (!activeCharId) { dico.classList.remove('granted'); return; }
    fetch('/api/documents/list?charId=' + encodeURIComponent(activeCharId), { headers: authHeaders })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (list) {
        var has = (Array.isArray(list) ? list : []).some(function (f) {
          return /^(L10|Q3|X3)\.md$/i.test(String(f.filename || ''));
        });
        dico.classList.toggle('granted', has);
      })
      .catch(function () { dico.classList.remove('granted'); });
  }

  /* UNL3ASH：确认弹窗 → POST u2-unleash（后端校验 U2 授权 + 申诫≥3） */
  function openUnlash() {
    var c = curChar();
    if (!c) { showToast('未选择角色'); return; }
    var arr = []; try { arr = (JSON.parse(c.data || '{}').reprimands) || []; } catch (e) {}
    var bal = arr.reduce(function (sum, r) { return sum + (r.count || 1); }, 0);
    document.getElementById('unlashBal').textContent = bal;
    document.getElementById('unlashMask').classList.add('show');
  }
  function closeUnlash() { document.getElementById('unlashMask').classList.remove('show'); }
  function doUnlash() {
    var btn = document.getElementById('unlashGo');
    btn.disabled = true;
    fetch('/api/character/' + activeCharId + '/u2-unleash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      btn.disabled = false;
      if (d.success) {
        closeUnlash();
        showToast(d.message || '已消耗3点申诫');
        loadProfile();
      } else {
        closeUnlash();
        showToast(d.message || '申诫不足3点，使用失败');
      }
    })
    .catch(function () { btn.disabled = false; showToast('使用失败，请重试'); });
  }
  var ulBtn = document.getElementById('btnUnlash');
  if (ulBtn) ulBtn.addEventListener('click', openUnlash);
  document.getElementById('unlashClose').addEventListener('click', closeUnlash);
  document.getElementById('unlashCancel').addEventListener('click', closeUnlash);
  document.getElementById('unlashGo').addEventListener('click', doUnlash);
  document.getElementById('unlashMask').addEventListener('click', function (e) { if (e.target === this) closeUnlash(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.getElementById('unlashMask').classList.contains('show')) closeUnlash();
  });

  /* ========== 区域监控卡：当前分部散逸端 ========== */
  var scatterTimer = null;
  function loadScatter() {
    var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
    var url = role >= 1 ? '/api/admin/branches' : '/api/user/branch-scatter';
    fetch(url, { headers: authHeaders })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var list = (d && (d.branches || d)) || [];
        var cur = curBranchId();
        var b = null;
        for (var i = 0; i < list.length; i++) if (list[i].id === cur) b = list[i];
        var num = b ? (b.total_scatter || 0) : 0;
        /* 散逸端 ≥11 时开启底部提醒气泡轮播（desktop.scatter-tips.js）。
           __taScatter 兜底：本回调可能早于 scatter-tips.js 加载执行（守卫跳过），其初始化时补读 */
        window.__taScatter = num;
        if (window.DA && window.DA.feats.scatterTips) window.DA.feats.scatterTips.update(num);
        countUpScatter(num);
      })
      .catch(function () {});
  }
  /* 阈值状态：0/11/22/33/44/55/66/77 递增分档，越往上越红 */
  var ST_NAMES = ['正常', '稳定', '波动', '警戒', '高危', '危险', '极危', '灾厄'];
  var ST_COLORS = ['#27ae60', '#7cb342', '#c0ca33', '#f39c12', '#e67e22', '#e74c3c', '#d3545c', '#b71c1c'];
  function scatterState(v) {
    var idx = 0;
    var th = [11, 22, 33, 44, 55, 66, 77];
    for (var i = 0; i < th.length; i++) if (v >= th[i]) idx = i + 1;
    return { idx: idx, name: ST_NAMES[idx], color: ST_COLORS[idx], cls: 'st' + idx };
  }
  function applyScatterState(v) {
    var num = document.getElementById('wScatterNum');
    var live = document.querySelector('.wscatter-live');
    if (!num || !live) return;
    var st = scatterState(v);
    for (var i = 0; i < 8; i++) num.classList.remove('st' + i);
    num.classList.add(st.cls);
    var dot = live.querySelector('i');
    var txt = live.querySelector('span');
    if (dot) dot.style.background = st.color;
    if (txt) { txt.textContent = '当前状态 · ' + st.name; txt.style.color = st.color; }
    live.style.background = st.color + '1f';
  }

  function countUpScatter(target) {
    var el = document.getElementById('wScatterNum');
    if (!el) return;
    clearInterval(scatterTimer);
    var i = 0, steps = 22;
    scatterTimer = setInterval(function () {
      i++;
      var cur = Math.round(target * i / steps);
      el.textContent = cur;
      applyScatterState(cur);
      if (i >= steps) { clearInterval(scatterTimer); el.textContent = target; applyScatterState(target); }
    }, 25);
  }

  function saveBranch(id) {
    localStorage.setItem('ta_current_branch', id || '');
    renderBranchSels();
    loadProfile();   /* 角色列表按分部重拉 */
    loadScatter();   /* 区域监控散逸端按分部刷新 */
    if (window.MANAGER_APP && window.MANAGER_APP.setBranch) window.MANAGER_APP.setBranch(id || '');
    /* 办公室窗口随分部刷新 */
    if (window.DA && window.DA.feats.office && window.DA.feats.office.reload) window.DA.feats.office.reload();
  }

  /* 角色弹窗开着时同步刷新列表（分部切换 / 角色数据异步到达后） */
  function refreshCharModalList() {
    var cm = document.getElementById('charMask');
    if (cm && cm.classList.contains('show')) renderCharList();
  }
  if (ppBranchSel) ppBranchSel.addEventListener('change', function () { saveBranch(this.value); });
  if (cmBranchSel) cmBranchSel.addEventListener('change', function () { saveBranch(this.value); });
  if (uid && token) { loadBranches(); loadScatter(); }

  /* showToast 在桌面应用底座（desktop.apps.js）中，经 DA 桥接 */
  function showToast(msg) { if (window.DA && window.DA.showToast) window.DA.showToast(msg); }

  function setText(id, txt) {
    var el = document.getElementById(id);
    if (el) el.textContent = txt;
  }

  function loadProfile() {
    fetch('/api/verify-token', { headers: authHeaders })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && d.username) { accountName = d.username; if (charsLoaded) renderPanel(); }
      })
      .catch(function () {});

    /* 未选分部时不加载角色：选择角色前必须先选分部 */
    if (!curBranchId()) {
      myChars = [];
      charsLoaded = true;
      activeCharId = null;
      localStorage.removeItem(CHAR_KEY);
      renderPanel();
      cardCbs.splice(0).forEach(function (cb) { try { cb(); } catch (e) {} });
      refreshCharModalList();
      updateUnlockGates();
      return;
    }

    fetch('/api/characters?userId=' + encodeURIComponent(uid) + '&branchId=' + encodeURIComponent(curBranchId()) + '&_t=' + Date.now(), { headers: authHeaders })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (list) {
        myChars = (list || []).filter(function (c) { return !c.isArchived; });
        charsLoaded = true;
        /* 激活角色：上次记住的 → 第一张；失效则回落 */
        if (!myChars.some(function (c) { return c.id === activeCharId; })) {
          activeCharId = myChars.length ? myChars[0].id : null;
          if (activeCharId) localStorage.setItem(CHAR_KEY, activeCharId);
          else localStorage.removeItem(CHAR_KEY);
        }
        renderPanel();
        cardCbs.splice(0).forEach(function (cb) { try { cb(); } catch (e) {} });
        refreshCharModalList();
        updateUnlockGates();
        if (window.DA && window.DA.mail && window.DA.mail.refreshBadge) window.DA.mail.refreshBadge();
        /* 已打开的浮窗随最新角色卡刷新 */
        if (document.getElementById('winItem').classList.contains('show')) renderItemWin();
        if (document.getElementById('winReal').classList.contains('show')) renderRealWin();
        if (document.getElementById('winAnom').classList.contains('show')) renderAnomWin();
        window.DESKTOP.syncCareerApply();
        if (window.DA && window.DA.board && window.DA.board.refreshSide) window.DA.board.refreshSide();
        /* 我的档案窗口开着时（如新建角色后自动打开），新数据到达后刷新内容 */
        if (document.getElementById('winDocs').classList.contains('show') && window.DA && window.DA.feats.docs && window.DA.feats.docs.rerender) window.DA.feats.docs.rerender();
      })
      .catch(function () {});
  }

  function curChar() {
    for (var i = 0; i < myChars.length; i++) if (myChars[i].id === activeCharId) return myChars[i];
    return null;
  }

  function renderPanel() {
    var c = curChar();
    if (!c) {
      setText('ppName', accountName);
      setText('ppRole', curBranchId() ? '未创建角色卡' : '请先选择分部');
      setText('ppAnom', '---'); setText('ppReal', '---'); setText('ppFunc', '---');
      return;
    }
    var card = {};
    try { card = JSON.parse(c.data) || {}; } catch (e) {}
    setText('ppName', c.name || accountName);
    setText('ppRole', accountName);
    setText('ppAnom', c.anom || '---');
    setText('ppReal', c.real || '---');
    setText('ppFunc', c.func || '---');
    setAva(document.getElementById('ppAva'), card.pAvatar, c.name);
  }

  function setAva(box, pAvatar, name) {
    if (!pAvatar) {
      /* 无头像：重置为默认剪影，避免残留上一个角色的头像（切换角色时头像不变的根因） */
      box.innerHTML = '<svg viewBox="0 0 96 96"><circle cx="48" cy="48" r="48" fill="#f6e3df"/><path d="M30 30 a18 18 0 0 1 36 0 v4 h-36 Z" fill="#332b36"/><circle cx="48" cy="42" r="12" fill="#eeb89a"/><path d="M20 96 a28 26 0 0 1 56 0 Z" fill="#c0392b"/></svg>';
      return;
    }
    var url = pAvatar.indexOf('http') === 0 ? (window.DA && window.DA.avaSrc ? window.DA.avaSrc(pAvatar) : pAvatar) : '/' + (window.DA && window.DA.avaSrc ? window.DA.avaSrc(pAvatar) : pAvatar);
    var img = document.createElement('img');
    img.src = url;
    img.alt = '';
    box.innerHTML = '';
    box.appendChild(img);
  }

  /* 头部点击 → 角色切换弹窗 */
  document.querySelector('.pp-head').addEventListener('click', openCharModal);

  /* ================= 角色切换弹窗 ================= */
  var charMask = document.getElementById('charMask');
  document.getElementById('cmClose').addEventListener('click', closeCharModal);
  charMask.addEventListener('click', function (e) { if (e.target === charMask) closeCharModal(); });

  function openCharModal() {
    renderCharList();
    charMask.classList.add('show');
  }
  function closeCharModal() { charMask.classList.remove('show'); }

  function renderCharList() {
    var list = document.getElementById('cmList');
    var createBtn = document.getElementById('cmCreate');
    /* 必须先选分部 */
    if (!curBranchId()) {
      list.innerHTML = '<div class="cm-hint">请先在上方（或左下角开始菜单）选择分部</div>';
      if (createBtn) createBtn.disabled = true;
      return;
    }
    if (createBtn) createBtn.disabled = branchList.length === 0;
    list.innerHTML = '';
    if (!myChars.length) {
      var empty = document.createElement('div');
      empty.className = 'cm-empty';
      empty.textContent = '该分部下还没有角色，点击下方创建';
      list.appendChild(empty);
      return;
    }
    myChars.forEach(function (c) {
      var card = {};
      try { card = JSON.parse(c.data) || {}; } catch (e) {}
      var item = document.createElement('div');
      item.className = 'cm-item' + (c.id === activeCharId ? ' active' : '');

      var ava = document.createElement('div');
      ava.className = 'cm-ava';
      if (card.pAvatar) setAva(ava, card.pAvatar, c.name);
      else ava.textContent = (c.name || '？').charAt(0);

      var info = document.createElement('div');
      info.className = 'cm-info';
      var nameRow = document.createElement('div');
      nameRow.className = 'cm-name';
      nameRow.append(c.name || '未命名');
      if (c.id === activeCharId) {
        var tag = document.createElement('span');
        tag.className = 'cm-tag';
        tag.textContent = '当前';
        nameRow.appendChild(tag);
      }
      var sub = document.createElement('div');
      sub.className = 'cm-sub';
      sub.textContent = '异常 ' + (c.anom || '---') + ' · 现实 ' + (c.real || '---') + ' · 职能 ' + (c.func || '---');
      info.appendChild(nameRow);
      info.appendChild(sub);

      var edit = document.createElement('span');
      edit.className = 'cm-edit';
      edit.title = '查看角色档案';
      edit.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20 h4.5 L20 8.5 a2.1 2.1 0 0 0 -4.5 -4.5 L4 15.5 Z"/><path d="M13.5 5.5 L18.5 10.5"/></svg>';
      edit.addEventListener('click', function (e) {
        e.stopPropagation();
        /* 掐死老页面入口：改为打开页内「我的文档」角色档案视图 */
        activateChar(c.id);
        var docsDico = document.querySelector('.dico[data-app="docs"]');
        if (docsDico) docsDico.click();
      });

      var del = document.createElement('span');
      del.className = 'cm-del';
      del.title = '删除角色';
      del.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7 h16"/><path d="M9 7 V5 a1.5 1.5 0 0 1 1.5 -1.5 h3 A1.5 1.5 0 0 1 15 5 v2"/><path d="M6.5 7 l1 13 a1.5 1.5 0 0 0 1.5 1.4 h6 a1.5 1.5 0 0 0 1.5 -1.4 l1 -13"/><path d="M10 11.5 v5.5 M14 11.5 v5.5"/></svg>';
      del.addEventListener('click', function (e) {
        e.stopPropagation();
        openCharDelete(c);
      });

      item.appendChild(ava);
      item.appendChild(info);
      item.appendChild(edit);
      item.appendChild(del);
      item.addEventListener('click', function () { activateChar(c.id); });
      list.appendChild(item);
    });
  }

  /* 切换角色：关闭所有已打开窗口——应用窗口点 data-appclose 走 shell 关闭链路（清任务栏/started 标记），
     浮窗点 data-close；保证下次打开一律按新角色重新渲染，不残留旧角色内容 */
  function closeAllWins() {
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
  }

  function activateChar(id) {
    activeCharId = id;
    localStorage.setItem(CHAR_KEY, id);
    renderPanel();
    renderCharList();
    closeAllWins();
    /* 生涯卡片（含背景主题）随新角色刷新 */
    if (window.DA && window.DA.feats.career && window.DA.feats.career.refresh) window.DA.feats.career.refresh();
    updateUnlockGates();   /* 破坏条等门禁随新角色重新判定 */
    /* 面板同步新角色后关闭弹窗 */
    setTimeout(closeCharModal, 180);
  }

  /* 创建新角色 → POST /api/character（必须先选分部） → 激活 */
  document.getElementById('cmCreate').addEventListener('click', function () {
    var btn = this;
    var branchId = curBranchId();
    if (!branchId) { showToast('请先选择分部'); return; }
    if (btn.disabled) return;
    btn.disabled = true;
    var label = btn.textContent;
    btn.textContent = '创建中…';
    fetch('/api/character', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ userId: uid, branchId: branchId })
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d.success) throw new Error(d.message || '创建失败');
      activeCharId = d.id;
      localStorage.setItem(CHAR_KEY, d.id);
      closeAllWins();           /* 关掉旧角色的窗口 */
      loadProfile();            /* 重新拉列表并以新角色激活 */
      closeCharModal();
      /* 新角色建档后立刻打开他的档案；列表数据到达后由 loadProfile 的 rerender 钩子刷新内容 */
      var docsDico = document.querySelector('.dico[data-app="docs"]');
      if (docsDico) docsDico.click();
    })
    .catch(function () { alert('创建失败，请重试'); })
    .finally(function () { btn.disabled = false; btn.textContent = label; });
  });

  /* ========== 删除自己的角色（选择角色弹窗 → 垃圾桶 → 输入角色名确认；确认弹窗为最高层级） ========== */
  var delTarget = null;
  function openCharDelete(c) {
    delTarget = c;
    document.getElementById('charDelName').textContent = c.name || '未命名';
    var inp = document.getElementById('charDelInput');
    inp.value = '';
    document.getElementById('charDelGo').disabled = true;
    document.getElementById('charDelMask').classList.add('show');
    setTimeout(function () { inp.focus(); }, 60);
  }
  function closeCharDelete() {
    document.getElementById('charDelMask').classList.remove('show');
    delTarget = null;
  }
  document.getElementById('charDelInput').addEventListener('input', function () {
    var name = delTarget ? String(delTarget.name || '').trim() : '';
    this.value = this.value.trim() ? this.value : '';
    document.getElementById('charDelGo').disabled = !name || this.value.trim() !== name;
  });

  /* ========== 破坏条玩家只读视图（manager 模块玩家不加载，这里独立渲染） ==========
     经理/超管走 manager-main 的 TAB_LOADERS；玩家打开窗口时渲染 42 格只读快照（无箭头/无点击/无保存） */
  function renderDestReadonly() {
    var grid = document.getElementById('destructionGrid');
    if (!grid) return;
    var branch = localStorage.getItem('ta_current_branch') || '';
    if (!branch) { grid.innerHTML = '<div style="text-align:center;color:#aaa;padding:40px;">请先选择分部</div>'; return; }
    grid.innerHTML = '<div style="text-align:center;color:#aaa;padding:40px;">加载中...</div>';
    fetch('/api/destruction-track?branchId=' + encodeURIComponent(branch), { headers: authHeaders })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var cells = d.cells || [];
        var colCount = 7, rowCount = 6, html = '';
        for (var row = 0; row < rowCount; row++) {
          for (var col = 0; col < colCount; col++) {
            var logicalCol = row % 2 === 1 ? (colCount - 1 - col) : col;
            var idx = row * colCount + logicalCol + 1;
            html += '<div class="p-cell dest-cell' + (cells.indexOf(idx) >= 0 ? ' active' : '') + '" data-idx="' + idx + '">' + idx + '</div>';
          }
        }
        grid.innerHTML = html;
      })
      .catch(function () { grid.innerHTML = '<div style="text-align:center;color:#aaa;padding:40px;">加载失败</div>'; });
  }
  /* 本脚本执行时 window.DA 尚未创建（apps.js 在其后加载），注册挂到 DOMContentLoaded：
     若散逸端门禁此前已判定只读，则在此注册玩家只读渲染入口；否则由后到的门禁直接走 manager 链路 */
  document.addEventListener('DOMContentLoaded', function () {
    window.DA.feats['m-dest'] = {
      start: function () {
        /* 仅玩家只读渲染；经理/超管由 manager-main 的 TAB_LOADERS 正常加载编辑 */
        if (document.body.classList.contains('dest-readonly')) renderDestReadonly();
      }
    };
    if (window.__taScatter !== undefined && window.DA.feats.scatterTips) window.DA.feats.scatterTips.update(window.__taScatter);
  });
  document.getElementById('charDelGo').addEventListener('click', function () {
    var btn = this;
    if (!delTarget || btn.disabled) return;
    btn.disabled = true;
    var delId = delTarget.id, delName = delTarget.name;
    fetch('/api/character/' + encodeURIComponent(delId), {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      btn.disabled = false;
      if (!d.success) throw new Error(d.message || '删除失败');
      closeCharDelete();
      showToast('已删除角色「' + (delName || '未命名') + '」');
      if (activeCharId === delId) {
        activeCharId = null;
        localStorage.removeItem(CHAR_KEY);
      }
      closeCharModal();
      loadProfile();   /* 列表/激活角色回落/面板全部刷新 */
    })
    .catch(function (e) { btn.disabled = false; showToast(e.message || '删除失败，请重试'); });
  });
  document.getElementById('charDelClose').addEventListener('click', closeCharDelete);
  document.getElementById('charDelCancel').addEventListener('click', closeCharDelete);
  document.getElementById('charDelMask').addEventListener('click', function (e) { if (e.target === this) closeCharDelete(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.getElementById('charDelMask').classList.contains('show')) closeCharDelete();
  });

  /* ================= 浮窗：异常能力 / 关系网 / 物品（窗内直接编辑/新建，保存回角色卡） ================= */
  function esc(s) {
    return s ? String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
  }
  function activeData() {
    var c = curChar();
    if (!c) return null;
    var card = {};
    try { card = JSON.parse(c.data) || {}; } catch (e) {}
    return card;
  }
  function winEmpty(msg) { return '<div class="dwin-empty">' + msg + '</div>'; }
  /* 富文本 → 编辑用纯文本 */
  function htmlToText(html) {
    var t = String(html || '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li)>/gi, '\n');
    var d = document.createElement('div');
    d.innerHTML = t;
    return (d.textContent || '').replace(/\u00a0/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  }
  /* 编辑用纯文本 → 存档富文本 */
  function textToHtml(t) {
    return esc(String(t || '').trim()).replace(/\n/g, '<br>');
  }

  /* --- sheet 原版异常模块图标（复刻 common-modules/anom-icons.js） --- */
  var ICON_BLUE = '#2E5EA8', ICON_RED = '#D22837';
  function icoCheck() {
    return '<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M50 10 L92 88 L8 88 Z" fill="' + ICON_BLUE + '" stroke="' + ICON_BLUE + '" stroke-width="8" stroke-linejoin="round"/><path d="M31 57 L46 70 L71 39" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  }
  function icoX() {
    return '<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M88.8 66.07 L66.07 88.8 L33.93 88.8 L11.2 66.07 L11.2 33.93 L33.93 11.2 L66.07 11.2 L88.8 33.93 Z" fill="' + ICON_RED + '" stroke="' + ICON_RED + '" stroke-width="6" stroke-linejoin="round"/><path d="M35 35 L65 65 M65 35 L35 65" fill="none" stroke="#fff" stroke-width="14" stroke-linecap="round"/></svg>';
  }
  function icoStar() {
    return '<svg class="anom-ico" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M50 10 L92 88 L8 88 Z" fill="' + ICON_BLUE + '" stroke="' + ICON_BLUE + '" stroke-width="8" stroke-linejoin="round"/><path d="M50 40 L55.17 54.88 L70.92 55.2 L58.37 64.72 L62.93 79.8 L50 70.8 L37.07 79.8 L41.63 64.72 L29.08 55.2 L44.83 54.88 Z" fill="#fff"/></svg>';
  }
  function icoWave() {
    var P = [{ x: 50, y: 22 }, { x: 18, y: 82 }, { x: 82, y: 82 }];
    var seg = [Math.hypot(P[1].x - P[0].x, P[1].y - P[0].y), Math.hypot(P[2].x - P[1].x, P[2].y - P[1].y), Math.hypot(P[0].x - P[2].x, P[0].y - P[2].y)];
    var L = seg[0] + seg[1] + seg[2];
    function pt(s) {
      s = ((s % L) + L) % L;
      var i = 0;
      while (s > seg[i]) { s -= seg[i]; i++; }
      var a = P[i], b = P[(i + 1) % 3];
      var dx = (b.x - a.x) / seg[i], dy = (b.y - a.y) / seg[i];
      return { x: a.x + dx * s, y: a.y + dy * s, nx: -dy, ny: dx };
    }
    var period = L / 7, steps = 48;
    function ringPath(off, amp, phase) {
      var d = '';
      for (var s = 0; s <= steps; s++) {
        var p = pt(L * s / steps);
        var disp = off + amp * Math.sin(2 * Math.PI * (L * s / steps) / period + phase);
        d += (s ? ' L' : 'M') + (p.x + p.nx * disp).toFixed(1) + ' ' + (p.y + p.ny * disp).toFixed(1);
      }
      return d + ' Z';
    }
    var rings = '';
    for (var k = 0; k < 9; k++) {
      var op = Math.max(0.1, 0.85 * Math.pow(1 - k / 9, 1.15)).toFixed(2);
      rings += '<path d="' + ringPath(1.2 + k * 0.75, 0.7 + k * 0.42, k * 0.85) + '" fill="none" stroke="' + ICON_RED + '" stroke-width="1.6" opacity="' + op + '"/>';
    }
    for (var k2 = 1; k2 <= 2; k2++) {
      rings += '<path d="' + ringPath(-1.5 * k2, 0.6, k2 * 1.1) + '" fill="none" stroke="' + ICON_RED + '" stroke-width="1.3" opacity="0.25"/>';
    }
    var core = '<path d="M50 22 L82 82 L18 82 Z" fill="' + ICON_RED + '" stroke="' + ICON_RED + '" stroke-width="2" stroke-linejoin="round"/>';
    return '<svg class="anom-ico" viewBox="8 8 84 84" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' + rings + core + '</svg>';
  }
  function icoShield() {
    return '<svg class="anom-ico" viewBox="0 0 24 24" fill="none" stroke="' + ICON_BLUE + '" stroke-width="2" stroke-linejoin="round"><path d="M12 3 L20 6 v6 c0 5 -3.5 8 -8 9 c-4.5 -1 -8 -4 -8 -9 V6 Z"/></svg>';
  }

  var ARR_KEY = { anom: 'anoms', real: 'reals', item: 'items' };
  var RENDER = {}; /* type → 渲染函数 */

  /* --- 异常能力.exe --- */
  function renderAnomWin() {
    var el = document.getElementById('winAnomBody');
    var card = activeData();
    if (!card) { el.innerHTML = winEmpty('未选择角色'); return; }
    var anoms = card.anoms || [];
    if (!anoms.length) { el.innerHTML = winEmpty('角色卡中暂无异常能力'); return; }
    el.innerHTML = anoms.map(function (a, idx) {
      var h = '<div class="acard">' + cardActs('anom', idx);
      h += '<div class="ac-head"><span class="ac-name">' + esc(a.name || '未命名') + '</span>';
      /* sheet 语义：trig 字段显示为「★资质」，qual 字段显示为「触发」 */
      if (a.trig) h += '<span class="ac-tag"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.5 l2.6 6.4 6.9 .5 -5.3 4.4 1.7 6.7 -5.9 -3.8 -5.9 3.8 1.7 -6.7 -5.3 -4.4 6.9 -.5 Z"/></svg>' + esc(a.trig) + '</span>';
      h += '</div>';
      if (a.qual) h += '<div class="ac-trig"><b>触发</b>' + esc(a.qual) + '</div>';
      var sub = (a.subOn && a.sub) ? a.sub : '';
      var hasList = a.listOn && !!(a.listName || (a.list || []).length);
      var list = a.list || [];
      var tl = function () {
        var single = list.length === 1;
        return '<div class="ac-tl' + (single ? ' single' : '') + '">'
          + list.map(function (r) {
              return single
                ? '<div class="ac-tl-row"><span class="ac-tl-text">' + esc(r) + '</span></div>'
                : '<div class="ac-tl-row"><span class="ac-tl-node"></span><span class="ac-tl-text">' + esc(r) + '</span></div>';
            }).join('')
          + '</div>';
      };
      if (a.passive) {
        h += '<div class="ac-grid single"><div class="ac-box c1"><div class="ac-box-label">' + icoShield() + '<span>描述</span></div>' + (a.succ || '<span class="ac-none">无</span>') + '</div></div>';
      } else {
        h += '<div class="ac-grid' + (sub ? '' : ' no-sub') + '">'
          + '<div class="ac-box c1"><div class="ac-box-label">' + icoCheck() + '<span>成功时</span></div>' + (a.succ || '<span class="ac-none">无</span>') + '</div>'
          + (sub ? '<div class="ac-box c2"><div class="ac-box-label sub-lbl">' + icoWave() + '<span>三重升华时</span></div>' + sub + '</div>' : '')
          + (hasList ? '<div class="ac-box list c3"><div class="ac-box-label">' + icoStar() + '<span>' + esc(a.listName || '列表') + '</span></div>' + tl() + '</div>' : '')
          + '<div class="ac-box fail c4"><div class="ac-box-label">' + icoX() + '<span>失败时</span></div>' + (a.fail || '<span class="ac-none">无</span>') + '</div>'
          + '</div>';
      }
      var q = '';
      if (a.chk) q += '<span class="ac-q-tag">已训练</span>';
      if (a.tdesc) q += '<b>' + esc(a.tdesc) + '</b>';
      [['t1', 't1v', 'p1'], ['t2', 't2v', 'p2'], ['t3', 't3v', 'p3']].forEach(function (t) {
        if (!a[t[0]]) return;
        var dots = '<span class="ac-dots">';
        for (var i = 0; i < 3; i++) dots += '<i class="' + ((a[t[2]] || [])[i] ? 'on' : '') + '"></i>';
        dots += '</span>';
        q += '<div class="ac-q-row"><span>› ' + esc(a[t[0]]) + '</span>' + (a[t[1]] ? '<code class="ac-q-code">' + esc(a[t[1]]) + '</code>' : '') + dots + '</div>';
      });
      if (q) h += '<div class="ac-q">' + q + '</div>';
      return h + '</div>';
    }).join('');
  }

  /* --- 联络（关系网） --- */
  function renderRealWin() {
    var el = document.getElementById('winRealBody');
    var card = activeData();
    if (!card) { document.getElementById('realCount').textContent = ''; el.innerHTML = winEmpty('未选择角色'); return; }
    var reals = card.reals || [];
    document.getElementById('realCount').textContent = '(' + reals.length + '/' + (card.realSlots || 10) + ')';
    if (!reals.length) { el.innerHTML = winEmpty('关系网还是空的'); return; }
    el.innerHTML = reals.map(function (r, idx) {
      var h = '<div class="rcard">' + cardActs('real', idx);
      h += '<div class="rc-name">' + (r.name ? '<span class="lbl">姓名：</span>' + esc(r.name) : '<span class="empty">未命名</span>')
        + (r.actor ? '<span class="rc-actor">｜ ' + esc(r.actor) + '</span>' : '') + '</div>';
      if (r.desc) h += '<div class="rc-desc">' + r.desc + '</div>';
      var dots = '<span class="rc-dots">';
      for (var i = 1; i <= 9; i++) dots += '<i class="' + (i <= (r.lvl || 0) ? 'on' : '') + '"></i>';
      dots += '</span>';
      h += '<div class="rc-conn"><span class="lbl"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M10 13.5 a4 4 0 0 0 6 .4 l3 -3 a4 4 0 0 0 -5.6 -5.6 l-1.6 1.5"/><path d="M14 10.5 a4 4 0 0 0 -6 -.4 l-3 3 a4 4 0 0 0 5.6 5.6 l1.6 -1.5"/></svg> 连结</span>' + dots + '</div>';
      if (r.conn) h += '<div class="rc-bonus">' + r.conn + '</div>';
      return h + '</div>';
    }).join('');
  }

  /* --- 物品 --- */
  function renderItemWin() {
    var el = document.getElementById('winItemBody');
    var card = activeData();
    if (!card) { el.innerHTML = winEmpty('未选择角色'); return; }
    var items = card.items || [];
    if (!items.length) { el.innerHTML = winEmpty('随身物品为空'); return; }
    el.innerHTML = items.map(function (it, idx) {
      var h = '<div class="icard">' + cardActs('item', idx);
      h += '<div class="ic-head">';
      h += '<span class="ic-name"><span class="lbl">申领物：</span>' + (it.item ? esc(it.item) : '<span class="empty">未命名</span>') + '</span>';
      if (it.once) h += '<span class="ic-tag">一次性</span>';
      if (it.pd) h += '<span class="ic-pd">PD：' + esc(it.pd) + '</span>';
      h += '</div>';
      if (it.eff) h += '<div class="ic-eff">' + it.eff + '</div>';
      return h + '</div>';
    }).join('');
  }
  RENDER.anom = renderAnomWin; RENDER.real = renderRealWin; RENDER.item = renderItemWin;

  /* --- 卡片悬停操作钮（编辑/删除） --- */
  function cardActs(type, idx) {
    return '<div class="card-acts">'
      + '<button class="card-act" data-act="edit" data-type="' + type + '" data-i="' + idx + '" title="编辑"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20 h4.5 L20 8.5 a2.1 2.1 0 0 0 -4.5 -4.5 L4 15.5 Z"/><path d="M13.5 5.5 L18.5 10.5"/></svg></button>'
      + '<button class="card-act del" data-act="del" data-type="' + type + '" data-i="' + idx + '" title="删除"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6 L18 18 M18 6 L6 18"/></svg></button>'
      + '</div>';
  }

  /* --- 保存到角色卡（整包 PUT） --- */
  function saveActiveData(card) {
    var c = curChar();
    return fetch('/api/character/' + c.id, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify(card)
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (!d.success) throw new Error('save failed');
      c.data = JSON.stringify(card);
    });
  }

  function delEntry(type, idx) {
    if (!confirm('确定删除这一条吗？')) return;
    var card = activeData();
    var arr = card[ARR_KEY[type]] = card[ARR_KEY[type]] || [];
    arr.splice(idx, 1);
    saveActiveData(card).then(function () { RENDER[type](); }).catch(function () { alert('删除失败，请重试'); });
  }

  /* --- 编辑弹窗 --- */
  var editMask = document.getElementById('editMask');
  var emBody = document.getElementById('emBody');
  var editing = null; /* { type, idx, card, isNew } */

  function openEditor(type, idx) {
    var card = activeData();
    if (!card) { alert('请先创建并激活角色'); return; }
    var isNew = (idx === null || idx === undefined);
    var arr = card[ARR_KEY[type]] = card[ARR_KEY[type]] || [];
    var o = isNew ? {} : arr[idx];
    editing = { type: type, idx: isNew ? null : idx, card: card, isNew: isNew };

    var titles = { anom: '异常能力', real: '关系', item: '物品' };
    document.getElementById('emTitle').textContent = (isNew ? '新建' : '编辑') + titles[type];
    /* 「⤓ 导入」仅在异常能力编辑时显示：预设库只有异常能力，关系/物品用不到 */
    document.getElementById('emImportBtn').style.display = type === 'anom' ? '' : 'none';

    if (type === 'anom') {
      emBody.innerHTML =
        field('名称', '<input class="em-input" id="em-name" value="' + esc(o.name || '') + '">')
        + '<div class="em-row2">' + field('资质', '<input class="em-input" id="em-trig" value="' + esc(o.trig || '') + '">')
        + field('触发器', '<input class="em-input" id="em-qual" value="' + esc(o.qual || '') + '">') + '</div>'
        + check('em-passive', '被动（成功区变“描述”，隐藏失败时）', o.passive)
        + field('成功时', '<textarea class="em-input" id="em-succ">' + esc(htmlToText(o.succ)) + '</textarea>')
        + field('失败时', '<textarea class="em-input" id="em-fail">' + esc(htmlToText(o.fail)) + '</textarea>')
        + '<hr class="em-hr">'
        + subSec(check('em-subon', '启用三重升华', o.subOn) + field('三重升华内容', '<textarea class="em-input" id="em-sub">' + esc(htmlToText(o.sub)) + '</textarea>'))
        + subSec(check('em-liston', '启用列表', o.listOn)
          + field('列表名称', '<input class="em-input" id="em-listname" value="' + esc(o.listName || '') + '">')
          + '<div class="em-field"><label>列表条目</label><div class="em-list-rows" id="em-listrows"></div>'
          + '<button class="em-list-add" id="em-listadd" type="button">＋ 添加一行</button></div>')
        + subSec(check('em-chk', '已训练', o.chk)
          + field('问答标题', '<input class="em-input" id="em-tdesc" value="' + esc(o.tdesc || '') + '">')
          + qrow('行1', 'em-t1', 'em-t1v', 'em-p1', o.p1, o.t1, o.t1v)
          + qrow('行2', 'em-t2', 'em-t2v', 'em-p2', o.p2, o.t2, o.t2v)
          + qrow('行3', 'em-t3', 'em-t3v', 'em-p3', o.p3, o.t3, o.t3v));
      renderListRows(o.list || []);
      wireQDots();
      document.getElementById('em-listadd').addEventListener('click', function () { addListRow(''); });
    } else if (type === 'real') {
      emBody.innerHTML =
        '<div class="em-row2">' + field('姓名', '<input class="em-input" id="em-name" value="' + esc(o.name || '') + '">')
        + field('扮演者', '<input class="em-input" id="em-actor" value="' + esc(o.actor || '') + '">') + '</div>'
        + field('描述', '<textarea class="em-input" id="em-desc">' + esc(htmlToText(o.desc)) + '</textarea>')
        + subSec('<div class="em-field"><label>连结等级（点击圆点设置）</label><span class="rc-dots" id="em-lvl">' + lvlDots(o.lvl || 0) + '</span></div>')
        + field('连结加成预设', '<select class="em-input" id="em-conn-sel"></select>')
        + field('连结加成（选择预设或手动输入）', '<textarea class="em-input" id="em-conn" placeholder="选择预设或输入加成效果...">' + esc(htmlToText(o.conn)) + '</textarea>');
      wireLvlDots(o.lvl || 0);
      fillBonusSel(htmlToText(o.conn));
    } else {
      emBody.innerHTML =
        '<div class="em-row2">' + field('物品名称', '<input class="em-input" id="em-item" value="' + esc(o.item || '') + '">')
        + field('PD', '<input class="em-input" id="em-pd" value="' + esc(o.pd || '') + '">') + '</div>'
        + check('em-once', '一次性物品', o.once)
        + field('效果', '<textarea class="em-input" id="em-eff">' + esc(htmlToText(o.eff)) + '</textarea>');
    }

    $('emImportPanel').classList.remove('on');
    editMask.classList.add('show');
  }

  function field(lbl, inputHtml) { return '<div class="em-field"><label>' + lbl + '</label>' + inputHtml + '</div>'; }
  function check(id, lbl, on) { return '<label class="em-check"><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '> ' + lbl + '</label>'; }
  function subSec(inner) { return '<div class="em-sub-sec">' + inner + '</div>'; }
  function lvlDots(lvl) {
    var h = '';
    for (var i = 1; i <= 9; i++) h += '<i class="clickable' + (i <= lvl ? ' on' : '') + '" data-l="' + i + '"></i>';
    return h;
  }
  function wireLvlDots(initial) {
    var dots = emBody.querySelectorAll('#em-lvl i');
    dots.forEach(function (d) {
      d.addEventListener('click', function () {
        var l = parseInt(d.dataset.l, 10);
        dots.forEach(function (x) { x.classList.toggle('on', parseInt(x.dataset.l, 10) <= l); });
        emBody.dataset.lvl = String(l);
      });
    });
    emBody.dataset.lvl = String(initial);
  }
  function fillBonusSel(current) {
    var sel = $('em-conn-sel');
    if (!sel) return;
    loadBonuses(function (bonuses) {
      var h = '<option value="" disabled>-- 选择连结加成 --</option>';
      bonuses.forEach(function (b) {
        var val = typeof b === 'string' ? b : (b.content || b.name);
        var name = typeof b === 'string' ? b : b.name;
        var disp = name.length > 20 ? name.substring(0, 20) + '...' : name;
        h += '<option value="' + esc(val).replace(/"/g, '&quot;') + '">' + esc(disp) + '</option>';
      });
      h += '<option value="__CUSTOM__">自定义 / 手动输入...</option>';
      sel.innerHTML = h;
      var match = false;
      Array.prototype.forEach.call(sel.options, function (o) {
        if (o.value && o.value !== '__CUSTOM__' && o.value === current) match = true;
      });
      sel.value = match ? current : '__CUSTOM__';
      sel.onchange = function () {
        if (sel.value !== '__CUSTOM__') $('em-conn').value = sel.value;
      };
    });
  };
  var cfgBonuses = null;
  function loadBonuses(cb) {
    if (cfgBonuses) return cb(cfgBonuses);
    fetch('/api/options', { headers: authH() })
      .then(function (r) { return r.ok ? r.json() : { bonuses: [] }; })
      .then(function (d) { cfgBonuses = (d && d.bonuses) || []; cb(cfgBonuses); })
      .catch(function () { cfgBonuses = []; cb(cfgBonuses); });
  }
  function addListRow(val) {
    var row = document.createElement('div');
    row.className = 'em-list-row';
    row.innerHTML = '<span class="ac-tl-node"></span><input class="em-input" value="' + esc(val || '') + '"><button class="em-del-row" type="button" title="删除此行">×</button>';
    row.querySelector('.em-del-row').addEventListener('click', function () { row.remove(); });
    document.getElementById('em-listrows').appendChild(row);
  }
  function renderListRows(list) {
    var box = document.getElementById('em-listrows');
    box.innerHTML = '';
    (list || []).forEach(function (r) { addListRow(r); });
    if (!list || !list.length) addListRow('');
  }

  function qrow(lbl, tId, vId, pId, pArr, tVal, vVal) {
    var dots = '<span class="em-qdots" id="' + pId + '">';
    for (var i = 0; i < 3; i++) dots += '<i class="' + ((pArr || [])[i] ? 'on' : '') + '"></i>';
    dots += '</span>';
    return '<div class="em-qrow"><input class="em-input" id="' + tId + '" value="' + esc(tVal || '') + '" placeholder="' + lbl + '">'
      + '<input class="em-input" id="' + vId + '" value="' + esc(vVal || '') + '" placeholder="掷码" style="max-width:64px;flex:none;">'
      + dots + '</div>';
  }
  /* 进度点：左键切换 / 右键涂抹与恢复（复刻 sheet smearNext 规则） */
  function bindQDot(span, d, i) {
    d.addEventListener('click', function () {
      if (d.classList.contains('smeared')) return;
      d.classList.toggle('on');
    });
    d.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      var cur = parseInt(span.dataset.n) || 3;
      var idx = i + 1;
      var next = idx <= cur ? Math.max(1, idx - 1) : Math.min(3, idx);
      span.dataset.n = String(next);
      rebuildQDots(span, next);
    });
  }
  function rebuildQDots(span, n) {
    var had = Array.prototype.map.call(span.querySelectorAll('i'), function (d) { return d.classList.contains('on'); });
    var h = '';
    for (var i = 0; i < 3; i++) h += '<i class="' + (i >= n ? 'smeared ' : '') + (had[i] ? 'on' : '') + '"></i>';
    span.innerHTML = h;
    Array.prototype.forEach.call(span.querySelectorAll('i'), function (d, i) { bindQDot(span, d, i); });
  }
  function wireQDots() {
    ['em-p1', 'em-p2', 'em-p3'].forEach(function (id) {
      var span = $(id);
      if (!span) return;
      span.dataset.n = '3';
      Array.prototype.forEach.call(span.querySelectorAll('i'), function (d, i) { bindQDot(span, d, i); });
    });
  }
  function dotState(id) {
    var span = $(id);
    if (!span) return [false, false, false];
    return Array.prototype.map.call(span.querySelectorAll('i'), function (d) { return d.classList.contains('on'); });
  }

  /* 保存 */
  document.getElementById('emSave').addEventListener('click', function () {
    if (!editing) return;
    var t = editing.type, o;
    var card = editing.card;
    var arr = card[ARR_KEY[t]] = card[ARR_KEY[t]] || [];
    var g = function (id) { var el = emBody.querySelector(id); return el ? el.value.trim() : ''; };
    var c = function (id) { var el = emBody.querySelector(id); return el ? el.checked : false; };
    if (t === 'anom') {
      o = editing.isNew ? { p1: [false, false, false], p2: [false, false, false], p3: [false, false, false] } : arr[editing.idx];
      o.name = g('#em-name'); o.qual = g('#em-qual'); o.trig = g('#em-trig');
      o.passive = c('#em-passive');
      o.succ = textToHtml(g('#em-succ'));
      o.fail = textToHtml(g('#em-fail'));
      o.subOn = c('#em-subon'); o.sub = textToHtml(g('#em-sub'));
      o.listOn = c('#em-liston'); o.listName = g('#em-listname');
      o.list = Array.prototype.map.call(emBody.querySelectorAll('#em-listrows input'), function (i) { return i.value.trim(); }).filter(function (v) { return v; });
      o.chk = c('#em-chk');
      o.tdesc = g('#em-tdesc');
      o.t1 = g('#em-t1'); o.t1v = g('#em-t1v');
      o.t2 = g('#em-t2'); o.t2v = g('#em-t2v');
      o.t3 = g('#em-t3'); o.t3v = g('#em-t3v');
      o.p1 = dotState('em-p1'); o.p2 = dotState('em-p2'); o.p3 = dotState('em-p3');
    } else if (t === 'real') {
      o = editing.isNew ? {} : arr[editing.idx];
      o.name = g('#em-name'); o.actor = g('#em-actor');
      o.desc = textToHtml(g('#em-desc'));
      o.lvl = parseInt(emBody.dataset.lvl || '0', 10) || 0;
      o.conn = textToHtml(g('#em-conn'));
    } else {
      o = editing.isNew ? {} : arr[editing.idx];
      o.item = g('#em-item'); o.pd = g('#em-pd');
      o.once = c('#em-once');
      o.eff = textToHtml(g('#em-eff'));
    }
    if (editing.isNew) arr.push(o);
    saveActiveData(card).then(function () {
      RENDER[t]();
      closeEditor();
    }).catch(function () { alert('保存失败，请重试'); });
  });

  /* ========== 异常能力导入（预设库 /api/options） ========== */
  var $ = function (id) { return document.getElementById(id); };
  function authH() { return { "Authorization": "Bearer " + window.DESKTOP.getToken() }; }
  var cfgGroups = null; /* 预设分组缓存 */
  function loadCfg(cb) {
    if (cfgGroups) return cb(cfgGroups);
    fetch('/api/options', { headers: authH() })
      .then(function (r) { return r.ok ? r.json() : { anoms: [] }; })
      .then(function (d) { cfgGroups = (d && d.anoms) || []; cb(cfgGroups); })
      .catch(function () { cfgGroups = []; cb(cfgGroups); });
  }
  function openImport() {
    var panel = $('emImportPanel');
    if (panel.classList.contains('on')) { panel.classList.remove('on'); return; }
    panel.classList.add('on');
    var search = $('emImportSearch');
    search.value = '';
    loadCfg(function (groups) { renderImportList(''); });
    search.oninput = function () { renderImportList(search.value); };
  }
  function renderImportList(kw) {
    var list = $('emImportList');
    if (!cfgGroups) { list.innerHTML = '<div class="pane-empty">加载中…</div>'; return; }
    var key = (kw || '').trim().toLowerCase();
    var flat = [];
    var html = '';
    cfgGroups.forEach(function (g) {
      var abis = (g.abilities || []).filter(function (a) { return !key || (a.name || '').toLowerCase().indexOf(key) >= 0; });
      if (!abis.length) return;
      html += '<div class="em-import-group">' + esc(g.name || '') + '</div>';
      abis.forEach(function (a) {
        var idx = flat.length; flat.push(a);
        html += '<div class="em-import-item" data-i="' + idx + '"><span>' + esc(a.name || '') + '</span>'
          + (a.trig ? '<span class="anom-import-trig">' + esc(a.trig) + '</span>' : '') + '</div>';
      });
    });
    list.innerHTML = html || '<div class="pane-empty">未找到匹配的能力</div>';
    Array.prototype.forEach.call(list.querySelectorAll('.em-import-item'), function (el) {
      el.addEventListener('click', function () { applyImport(flat[+el.dataset.i]); });
    });
  }
  function applyImport(a) {
    if (!a) return;
    var g = function (id) { var e = $(id); return e ? e.value : ''; };
    var set = function (id, v) { var e = $(id); if (e) e.value = v == null ? '' : v; };
    set('em-name', a.name);
    set('em-trig', a.trig);   /* 资质 */
    set('em-qual', a.qual);   /* 触发器 */
    set('em-succ', htmlToText(a.succ));
    set('em-fail', htmlToText(a.fail));
    var p = $('em-passive'); if (p) p.checked = !!a.passive;
    var so = $('em-subon'); if (so) so.checked = !!a.subOn;
    set('em-sub', htmlToText(a.sub));
    var lo = $('em-liston'); if (lo) lo.checked = !!a.listOn;
    set('em-listname', a.listName);
    var rows = $('em-listrows');
    if (rows) {
      rows.innerHTML = '';
      (Array.isArray(a.list) ? a.list : []).forEach(function (r) { addListRow(r); });
      if (!a.list || !a.list.length) addListRow('');
    }
    var ck = $('em-chk'); if (ck) ck.checked = !!a.chk;
    set('em-tdesc', a.tdesc);
    set('em-t1', a.t1); set('em-t1v', a.t1v);
    set('em-t2', a.t2); set('em-t2v', a.t2v);
    set('em-t3', a.t3); set('em-t3v', a.t3v);
    closeImport();
    showToast('已导入预设：' + (a.name || ''));
  }
  function closeImport() { $('emImportPanel').classList.remove('on'); }
  $('emImportBtn').addEventListener('click', function (e) { e.stopPropagation(); openImport(); });

  function closeEditor() {
    editMask.classList.remove('show');
    editing = null;
  }
  document.getElementById('emClose').addEventListener('click', closeEditor);
  /* 编辑异常/关系/物品：点击遮罩空白不关闭（与档案编辑弹窗一致，防止误触丢内容），仅 × 或 Esc 关闭 */

  /* 头部 ＋ 新建 */
  document.getElementById('anomAdd').addEventListener('click', function (e) { e.stopPropagation(); openEditor('anom', null); });
  document.getElementById('realAdd').addEventListener('click', function (e) { e.stopPropagation(); openEditor('real', null); });
  document.getElementById('itemAdd').addEventListener('click', function (e) { e.stopPropagation(); openEditor('item', null); });

  /* 卡片操作（编辑/删除）事件委托 */
  [['winAnomBody', 'anom'], ['winRealBody', 'real'], ['winItemBody', 'item']].forEach(function (p) {
    document.getElementById(p[0]).addEventListener('click', function (e) {
      var b = e.target.closest('.card-act');
      if (!b) return;
      var i = parseInt(b.dataset.i, 10);
      if (b.dataset.act === 'del') delEntry(p[1], i);
      else openEditor(p[1], i);
    });
  });

  /* 供应用窗口模块读取当前激活角色 */
  window.DESKTOP = { getActiveCharId: function () { return activeCharId; }, getCardData: function () { return activeData(); }, authHeaders: function () { return authHeaders; }, getToken: function () { return token; }, bringToFront: function (win) { bringToFrontEl(win); }, registerWin: function (win) { if (win && winOrder.indexOf(win) < 0) winOrder.push(win); }, makeDraggable: function (win, onlyWindowed) { makeDraggable(win, onlyWindowed); }, onCardReady: function (cb) { if (charsLoaded) cb(); else cardCbs.push(cb); }, refreshChar: function () { loadProfile(); }, getCurChar: function () { return curChar(); }, setBranch: function (id) { saveBranch(id); }, loadBranches: function () { loadBranches(); } };
  /* 管理台模块自动选定分部后回调：刷新开始菜单选择器并按分部重拉角色 */
  window.DESKTOP.onBranchChanged = function () { renderBranchSels(); loadProfile(); };
  /* 登录层登录成功后：刷新会话引用并首次加载用户数据（同页融合，无跳转） */
  window.DESKTOP.onLoginOK = function () {
    uid = localStorage.getItem('ta_uid');
    token = localStorage.getItem('ta_token') || '';
    authHeaders = { 'Authorization': 'Bearer ' + token, 'Cache-Control': 'no-cache' };
    activeCharId = localStorage.getItem(CHAR_KEY) || null;
    /* 换号登录：按新角色重算管理台窗口/图标（清掉上个账号残留） */
    if (window.DESKTOP.resetPrivilegedUi) window.DESKTOP.resetPrivilegedUi();
    if (uid && token) {
      loadBranches();
      loadScatter();
      loadProfile();
      if (window.DA && window.DA.mail && window.DA.mail.refreshBadge) window.DA.mail.refreshBadge();
    }
  };

  /* --- 浮窗拖动 + 点击置顶 --- */
  var winOrder = [];   /* 所有可层叠窗口，末位 = 最顶层 */
  function bringToFrontEl(win) {
    winOrder = winOrder.filter(function (w) { return w !== win; });
    winOrder.push(win);
    winOrder.forEach(function (w, i) { w.style.zIndex = String(40 + i); });
  }
  function makeDraggable(win, onlyWindowed) {
    /* 按下即置顶（顺序表重排，保持在遮罩层 z=50 之下） */
    win.addEventListener('mousedown', function () { bringToFrontEl(win); });
    var head = win.querySelector('.dwin-head');
    head.addEventListener('mousedown', function (e) {
      if (onlyWindowed && !win.classList.contains('windowed')) return;
      if (e.target.closest('.dwin-btn') || e.button !== 0) return;
      var rect = win.getBoundingClientRect();
      var dx = e.clientX - rect.left, dy = e.clientY - rect.top;
      win.style.left = rect.left + 'px';
      win.style.top = rect.top + 'px';
      win.style.right = 'auto';
      win.style.bottom = 'auto';
      win.style.marginLeft = '0';
      function move(ev) {
        var x = Math.min(Math.max(ev.clientX - dx, 8 - rect.width + 60), window.innerWidth - 60);
        var y = Math.min(Math.max(ev.clientY - dy, 0), window.innerHeight - 90);
        win.style.left = x + 'px';
        win.style.top = y + 'px';
        ev.preventDefault();
      }
      function up() {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
      }
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
      e.preventDefault();
    });
  }
  makeDraggable(document.getElementById('winAnom'));
  makeDraggable(document.getElementById('winReal'));
  makeDraggable(document.getElementById('winItem'));

  /* --- 窗口开关 --- */
  function bindWin(winId, btnId, renderFn) {
    var win = document.getElementById(winId);
    var btn = document.getElementById(btnId);
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = win.classList.contains('show');
      if (isOpen) { win.classList.remove('show'); btn.classList.remove('open'); }
      else { renderFn(); win.classList.add('show'); btn.classList.add('open'); bringToFrontEl(win); }
    });
    Array.prototype.forEach.call(win.querySelectorAll('[data-close]'), function (b) {
      b.addEventListener('click', function () { win.classList.remove('show'); btn.classList.remove('open'); });
    });
  }
  bindWin('winAnom', 'tbAnom', renderAnomWin);
  bindWin('winReal', 'tbReal', renderRealWin);
  bindWin('winItem', 'tbItem', renderItemWin);

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    ['winAnom', 'winReal', 'winItem', 'winMail'].forEach(function (id) {
      var win = document.getElementById(id);
      if (win.classList.contains('show')) {
        win.classList.remove('show');
        var btnId = id === 'winAnom' ? 'tbAnom' : (id === 'winReal' ? 'tbReal' : (id === 'winItem' ? 'tbItem' : 'tbMail'));
        document.getElementById(btnId).classList.remove('open');
      }
    });
    if ($('emImportPanel').classList.contains('on')) { closeImport(); return; }
    if (editMask.classList.contains('show')) closeEditor();
    closeCharModal();
  });
})();
