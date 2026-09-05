/* 邮箱：MailApp（收件/已发送/写信）+ 邮箱浮窗开关 + 邮件阅读弹窗 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid, ICO = DA.ICO;
  var mailCtl = null;

  /* ========== 邮箱 ========== */
  function MailApp() {
    var self = this;
    this.tab = 'inbox';
    this.data = { inbox: [], sent: [] };
    this.open = function () {
      this.tab = 'inbox';
      this.a1 = false;
      Array.prototype.forEach.call(document.querySelectorAll('.mail-tab'), function (b) {
        b.classList.toggle('active', b.dataset.mtab === 'inbox');
        b.onclick = function () { self.switchTab(b.dataset.mtab); };
      });
      $('mailList').style.display = 'block';
      $('mailCompose').classList.remove('active');
      this.load();
      fetch('/api/character/' + cid() + '/check-a1', { headers: authH() })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { self.a1 = !!(d && d.unlocked); })
        .catch(function () {});
    };
    this.switchTab = function (t) {
      this.tab = t;
      Array.prototype.forEach.call(document.querySelectorAll('.mail-tab'), function (x) {
        x.classList.toggle('active', x.dataset.mtab === t);
      });
      $('mailList').style.display = t === 'compose' ? 'none' : 'block';
      $('mailCompose').classList.toggle('active', t === 'compose');
      if (t === 'compose') self.renderCompose(); else self.renderList();
    };
    this.load = function () {
      var self = this;
      $('mailList').innerHTML = '<div class="pane-empty">加载中…</div>';
      Promise.all([
        fetch('/api/character/' + cid() + '/messages', { headers: authH() }).then(function (r) { return r.json(); }),
        fetch('/api/character/' + cid() + '/sent-messages', { headers: authH() }).then(function (r) { return r.json(); })
      ]).then(function (rs) {
        self.data.inbox = Array.isArray(rs[0]) ? rs[0] : ((rs[0] && rs[0].messages) || []);
        self.data.sent = Array.isArray(rs[1]) ? rs[1] : ((rs[1] && rs[1].messages) || []);
        refreshMailBadge(self.data.inbox);
        self.renderList();
      }).catch(function () { $('mailList').innerHTML = '<div class="pane-empty">加载失败</div>'; });
    };
    this.renderList = function () {
      var list = $('mailList');
      var self = this;
      if (this.tab === 'inbox') {
        var inbox = (this.data.inbox || []).slice().sort(function (a, b) { return (b.createdAt || 0) - (a.createdAt || 0); });
        if (!inbox.length) { list.innerHTML = '<div class="pane-empty">收件箱为空</div>'; return; }
        list.innerHTML = inbox.map(function (m, i) {
          var date = m.createdAt ? new Date(m.createdAt).toLocaleDateString('zh-CN') : '';
          var unread = m.read === 0 || m.read === false;
          return '<div class="mail-item' + (unread ? ' unread' : '') + '" data-i="' + i + '">'
            + '<button class="m-del" data-del="' + i + '" title="删除">×</button>'
            + '<div class="m-sender">' + esc(m.senderName || m.sender || '机构') + '</div>'
            + '<div class="m-subject">' + esc(m.subject || '（无主题）') + '</div>'
            + '<div class="m-preview">' + esc((m.content || '').substring(0, 50)) + '</div>'
            + '<div class="m-time">' + date + '</div></div>';
        }).join('');
        Array.prototype.forEach.call(list.querySelectorAll('.mail-item'), function (it) {
          it.addEventListener('click', function () { self.read(inbox[+it.dataset.i]); });
        });
        Array.prototype.forEach.call(list.querySelectorAll('[data-del]'), function (b) {
          b.addEventListener('click', function (e) {
            e.stopPropagation();
            var m = inbox[+b.dataset.del];
            if (!confirm('删除「' + (m.subject || '无主题') + '」？')) return;
            fetch('/api/character/' + cid() + '/message/' + m.id, { method: 'DELETE', headers: authH() })
              .then(function () { self.load(); });
          });
        });
      } else {
        var sent = this.data.sent || [];
        if (!sent.length) { list.innerHTML = '<div class="pane-empty">暂无已发记录</div>'; return; }
        list.innerHTML = sent.map(function (m, i) {
          var d = m.createdAt ? new Date(m.createdAt) : null;
          var timeStr = d ? (d.getMonth() + 1) + '月' + d.getDate() + '日 ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') : '';
          var statusMap = { submitted: '待评审', reviewed: '已评审', sent: '已完成' };
          var badge = m.type === 'report' && m.status ? '<span style="font-size:10px;color:#e67e22;">' + (statusMap[m.status] || '') + '</span>' : '';
          var info = m.missionName ? '任务：' + esc(m.missionName) : '已发送';
          return '<div class="mail-item" data-i="' + i + '">'
            + '<div class="m-sender">' + info + ' ' + badge + '</div>'
            + '<div class="m-subject">' + esc(m.subject || '（无主题）') + '</div>'
            + '<div class="m-time">' + timeStr + '</div></div>';
        }).join('');
        Array.prototype.forEach.call(list.querySelectorAll('.mail-item'), function (it) {
          it.addEventListener('click', function () { self.read(sent[+it.dataset.i]); });
        });
      }
    };
    this.renderCompose = function () {
      var box = $('mailCompose');
      var reportOpt = this.a1
        ? '<div class="oc-opt" data-oc="report"><span class="oc-ico">' + ICO.file + '</span><div><b>提交任务报告</b><p>填写并提交任务报告</p></div></div>'
        : '';
      box.innerHTML = '<div class="oc-options">'
        + '<div class="oc-opt" data-oc="containment"><span class="oc-ico">' + ICO.box + '</span><div><b>寄送收容物</b><p>向经理发送收容物品</p></div></div>'
        + reportOpt
        + '</div>';
      Array.prototype.forEach.call(box.querySelectorAll('.oc-opt'), function (o) {
        o.addEventListener('click', function () { self.openForm(o.dataset.oc); });
      });
    };
    /* 表单弹窗：点击遮罩不关闭，防误触 */
    this.openForm = function (type) {
      var body = $('ocBody');
      if (type === 'containment') {
        $('ocTitle').textContent = '寄送收容物';
        body.innerHTML = '<div class="oc-form on">'
          + '<label>选择任务 *</label><select class="em-input" id="oc-mission"><option value="">-- 请选择任务 --</option></select>'
          + '<div class="oc-hint">每个任务只能寄送一次收容物</div>'
          + '<label>收容物名称 *</label><input class="em-input" id="oc-name" placeholder="输入收容物名称">'
          + '<label>收容物描述</label><textarea class="em-input" id="oc-desc" placeholder="描述收容物的特征、来源等信息..."></textarea>'
          + '<button class="oc-send" id="oc-send"><span class="oc-send-ico">' + ICO.plane + '</span><span> 寄送</span></button>'
          + '</div>';
        $('oc-send').addEventListener('click', function () { self.sendContainment(); });
        this.loadMissions('containment');
      } else {
        $('ocTitle').textContent = '任务报告';
        body.innerHTML = '<div class="oc-form on">'
          + '<label>选择任务 *</label><select class="em-input" id="oc-rpt-mission"><option value="">-- 请选择任务 --</option></select>'
          + '<div class="oc-hint">只能为进行中的任务提交报告，且每个任务只能提交一次</div>'
          + '<label>异常状态</label>'
          + '<div class="oc-checks">'
          + '<label><input type="checkbox" id="oc-neutralized"> 已中和</label>'
          + '<label><input type="checkbox" id="oc-captured"> 已捕获 +3嘉奖</label>'
          + '<label><input type="checkbox" id="oc-escaped"> 已逃脱 +3申诫</label>'
          + '<label><input type="checkbox" id="oc-other"> 其他</label>'
          + '<input class="em-input" id="oc-other-text" placeholder="说明" style="display:none;flex:1;min-width:60px;">'
          + '</div>'
          + '<label>异常分析</label>'
          + '<div class="em-row2"><input class="em-input" id="oc-codename" placeholder="代号"><input class="em-input" id="oc-behavior" placeholder="行为"></div>'
          + '<div class="em-row2"><input class="em-input" id="oc-focus" placeholder="焦点"><input class="em-input" id="oc-domain" placeholder="领域"></div>'
          + '<label>散逸端</label>'
          + '<table class="oc-table"><thead><tr><th>姓名</th><th>数量</th><th>备注</th><th></th></tr></thead><tbody id="oc-scat"></tbody></table>'
          + '<button class="em-list-add" id="oc-scat-add" type="button" style="color:#2E5EA8;">＋ 添加散逸端</button>'
          + '<label>评优信息</label>'
          + '<div class="em-row2"><input class="em-input" id="oc-rating" placeholder="最终评级（仅供GM）"><input class="em-input" id="oc-chaos" placeholder="混沌池"></div>'
          + '<div class="em-row2"><input class="em-input" id="oc-mvp" placeholder="MVP"><input class="em-input" id="oc-probation" placeholder="察看期"></div>'
          + '<label>参与者</label><textarea class="em-input" id="oc-participants" placeholder="填写参与任务的特工..."></textarea>'
          + '<label>可选目标</label>'
          + '<table class="oc-table"><thead><tr><th>目标</th><th>奖励</th><th>按特工</th><th></th></tr></thead><tbody id="oc-obj"></tbody></table>'
          + '<button class="em-list-add" id="oc-obj-add" type="button" style="color:#2E5EA8;">＋ 添加目标</button>'
          + '<button class="oc-send" id="oc-rpt-send"><span class="oc-send-ico">' + ICO.plane + '</span><span> 提交报告</span></button>'
          + '</div>';
        $('oc-rpt-send').addEventListener('click', function () { self.sendReport(); });
        $('oc-scat-add').addEventListener('click', function () { self.addRow('oc-scat', ['scat-name', '姓名'], ['scat-qty', '数量'], ['scat-note', '备注']); });
        $('oc-obj-add').addEventListener('click', function () { self.addRow('oc-obj', ['obj-target', '目标'], ['obj-reward', '奖励'], ['obj-agent', '按特工']); });
        $('oc-other').addEventListener('change', function () {
          $('oc-other-text').style.display = $('oc-other').checked ? 'block' : 'none';
        });
        this.addRow('oc-scat', ['scat-name', '姓名'], ['scat-qty', '数量'], ['scat-note', '备注']);
        this.addRow('oc-obj', ['obj-target', '目标'], ['obj-reward', '奖励'], ['obj-agent', '按特工']);
        this.loadMissions('report');
      }
        $('ocMask').classList.add('show');
    };
    this.addRow = function (tbodyId) {
      var classes = Array.prototype.slice.call(arguments, 1);
      var tr = document.createElement('tr');
      var h = classes.map(function (c) { return '<td><input class="em-input ' + c[0] + '" placeholder="' + (c[1] || '') + '"></td>'; }).join('');
      tr.innerHTML = h + '<td><button class="oc-delrow" type="button" title="删除此行">×</button></td>';
      tr.querySelector('.oc-delrow').addEventListener('click', function () { tr.remove(); });
      $(tbodyId).appendChild(tr);
    };
    this.selectOutbox = function (type) {
      Array.prototype.forEach.call($('mailCompose').querySelectorAll('.oc-opt'), function (o) { o.classList.toggle('on', o.dataset.oc === type); });
      $('ocContainment').classList.toggle('on', type === 'containment');
      $('ocReport').classList.toggle('on', type === 'report');
      if (type === 'report') this.loadMissions('report');
      else this.loadMissions('containment');
    };
    this.loadMissions = function (kind) {
      var sel = kind === 'report' ? $('oc-rpt-mission') : $('oc-mission');
      if (!sel) return;
      sel.innerHTML = '<option value="">加载中…</option>';
      var url = kind === 'report' ? '/available-missions' : '/available-missions-containment';
      fetch('/api/character/' + cid() + url, { headers: authH() })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (list) {
          sel.innerHTML = '';
          if (!list || !list.length) {
            var o = document.createElement('option');
            o.value = '';
            o.textContent = kind === 'report' ? '暂无可提交报告的任务' : '暂无可寄送收容物的任务';
            sel.appendChild(o); return;
          }
          list.forEach(function (m) {
            var o = document.createElement('option');
            o.value = m.id;
            var done = kind === 'report' ? m.hasSubmitted : m.hasSentContainment;
            if (done) { o.disabled = true; o.style.color = '#b3a8a8'; o.textContent = m.name + ' 【已' + (kind === 'report' ? '提交' : '寄送') + '】'; }
            else o.textContent = m.name;
            sel.appendChild(o);
          });
        }).catch(function () { sel.innerHTML = '<option value="">加载失败</option>'; });
    };
    this.sendContainment = function () {
      var missionId = $('oc-mission').value;
      if (!missionId) { showToast('请先选择要寄送收容物的任务'); return; }
      var name = $('oc-name').value.trim();
      if (!name) { showToast('请输入收容物名称'); return; }
      var desc = $('oc-desc').value.trim();
      var btn = $('oc-send');
      btn.disabled = true; btn.textContent = '发送中…';
      fetch('/api/character/' + cid() + '/send-containment', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify({ missionId: missionId, name: name, description: desc })
      }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); }).then(function (res) {
        if (!res.ok) { showToast(res.d.message || '发送失败'); }
        else {
          showToast('收容物已寄送');
          $('oc-name').value = ''; $('oc-desc').value = '';
          self.loadMissions('containment');
          self.load();
        }
      }).catch(function () { showToast('发送失败，请重试'); })
        .finally(function () { btn.disabled = false; btn.innerHTML = '<span class="oc-send-ico">' + ICO.plane + '</span><span> 寄送</span>'; });
    };
    this.sendReport = function () {
      var missionId = $('oc-rpt-mission').value;
      if (!missionId) { showToast('请先选择要提交报告的任务'); return; }
      var g = function (id) { var e = $(id); return e ? e.value.trim() : ''; };
      var c = function (id) { var e = $(id); return e ? e.checked : false; };
      var scattering = Array.prototype.map.call(document.querySelectorAll('#oc-scat tr'), function (row) {
        return { name: row.querySelector('.scat-name').value.trim(), qty: row.querySelector('.scat-qty').value.trim(), note: row.querySelector('.scat-note').value.trim() };
      }).filter(function (s) { return s.name; });
      var objectives = Array.prototype.map.call(document.querySelectorAll('#oc-obj tr'), function (row) {
        return { target: row.querySelector('.obj-target').value.trim(), reward: row.querySelector('.obj-reward').value.trim(), agent: row.querySelector('.obj-agent').value.trim() };
      }).filter(function (o) { return o.target; });
      var reportData = {
        missionId: missionId,
        status: { neutralized: c('oc-neutralized'), captured: c('oc-captured'), escaped: c('oc-escaped'), other: c('oc-other') ? g('oc-other-text') : null },
        analysis: { codename: g('oc-codename'), behavior: g('oc-behavior'), focus: g('oc-focus'), domain: g('oc-domain') },
        scattering: scattering,
        evaluation: { rating: g('oc-rating'), chaosPool: g('oc-chaos'), mvp: g('oc-mvp'), probation: g('oc-probation'), participants: g('oc-participants') },
        objectives: objectives
      };
      var btn = $('oc-rpt-send');
      btn.disabled = true; btn.textContent = '提交中…';
      fetch('/api/character/' + cid() + '/send-report', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify({ reportData: reportData })
      }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); }).then(function (res) {
        if (!res.ok) { showToast(res.d.message || '提交失败'); }
        else {
          showToast('任务报告已提交');
          self.loadMissions('report');
          self.load();
        }
      }).catch(function () { showToast('提交失败，请重试'); })
        .finally(function () { btn.disabled = false; btn.innerHTML = '<span class="oc-send-ico">' + ICO.plane + '</span><span> 提交报告</span>'; });
    };
    this.read = function (m) {
      if (!m) return;
      openMailView(m);
      var unread = m.read === 0 || m.read === false;
      if (unread && cid()) {
        fetch('/api/character/' + cid() + '/message/' + m.id + '/read', {
          method: 'PUT', headers: authH()
        }).then(function (r) { return r.json(); }).catch(function () {});
        m.read = 1;
        var idx = (self.data.inbox || []).indexOf(m);
        if (idx >= 0) self.data.inbox[idx].read = 1;
        refreshMailBadge(self.data.inbox);
        self.renderList();
      }
    };
  }
  /* ========== 邮箱浮窗（与异常/关系/物品同层的浮窗） ========== */
  var mailFloat = $('winMail');
  function setMailBtn(on) { var b = $('tbMail'); if (b) b.classList.toggle('open', !!on); }
  function openMailFloat() {
    ensureMailSock();
    mailCtl = mailCtl || new MailApp();
    mailCtl.open();
    mailFloat.classList.add('show');
    window.DESKTOP.bringToFront(mailFloat);
    setMailBtn(true);
  }
  function closeMailFloat() {
    mailFloat.classList.remove('show');
    setMailBtn(false);
  }
  $('tbMail').addEventListener('click', function (e) {
    e.stopPropagation();
    if (mailFloat.classList.contains('show')) closeMailFloat();
    else openMailFloat();
  });
  Array.prototype.forEach.call(mailFloat.querySelectorAll('[data-close]'), function (b) {
    b.addEventListener('click', closeMailFloat);
  });
  mailFloat.addEventListener('mousedown', function () { window.DESKTOP.bringToFront(mailFloat); });
  window.DESKTOP.makeDraggable(mailFloat);
  /* ========== 邮件阅读弹窗 ========== */
  var mailViewMask = $('mailViewMask');
  function openMailView(m) {
    $('mvSubject').textContent = m.subject || '（无主题）';
    $('mvMeta').textContent = (m.senderName || m.sender || '') + (m.createdAt ? ' · ' + new Date(m.createdAt).toLocaleString('zh-CN') : '');
    var c = $('mvContent');
    if (m.html) { c.innerHTML = m.html; c.style.whiteSpace = 'normal'; }
    else { c.textContent = m.content || ''; c.style.whiteSpace = 'pre-wrap'; }
    mailViewMask.classList.add('show');
  }
  function closeMailView() { mailViewMask.classList.remove('show'); }
  $('mvClose').addEventListener('click', closeMailView);
  mailViewMask.addEventListener('click', function (e) { if (e.target === mailViewMask) closeMailView(); });
  var ocMask = $('ocMask');
  $('ocClose').addEventListener('click', function () { ocMask.classList.remove('show'); });
  /* 注意：点击遮罩不关闭，防止误触丢失已填内容 */
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && mailViewMask.classList.contains('show')) { closeMailView(); return; }
  });

  /* ========== 邮箱 Socket 实时刷新 + 任务栏未读徽章 ========== */
  var mailSock = null;
  function ensureMailSock() {
    if (mailSock) return mailSock;
    mailSock = io({ auth: { token: window.DESKTOP.getToken() } });
    if (!mailSock.__mailBound) {
      mailSock.__mailBound = true;
      mailSock.on('mail:new', function () {
        setTimeout(function () {
          refreshMailBadge();
          if (mailFloat.classList.contains('show') && mailCtl) mailCtl.load();
        }, 400);
      });
    }
    return mailSock;
  }
  function refreshMailBadge(inbox) {
    var badge = document.getElementById('tbMailBadge');
    if (!badge) return;
    function apply(n) {
      badge.textContent = n > 99 ? '99+' : n;
      badge.style.display = n > 0 ? '' : 'none';
    }
    if (inbox) { apply(inbox.filter(function (x) { return x.read === 0 || x.read === false; }).length); return; }
    if (!cid()) { apply(0); return; }
    fetch('/api/character/' + cid() + '/messages', { headers: authH() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var list = Array.isArray(d) ? d : ((d && d.messages) || []);
        apply(list.filter(function (x) { return x.read === 0 || x.read === false; }).length);
      })
      .catch(function () {});
  }

  DA.mail = { openMailView: openMailView, closeFloat: closeMailFloat, refreshBadge: refreshMailBadge };
  ensureMailSock();
  refreshMailBadge();
})();
