/* 高墙文件：文件列表/阅读 + 顶部编号直查 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid, ICO = DA.ICO;

  /* ========== 搜索框：高墙文件编号查找 ========== */
  var hwInput = $('hwSearch');
  function openHighwallByCode(code) {
    code = (code || '').trim().toUpperCase();
    if (!code) return;
    fetch('/api/documents/read/' + encodeURIComponent(code) + '.md', { headers: authH() })
      .then(function (r) {
        if (r.status === 403) { showToast('无权限查看该高墙文件'); return null; }
        if (r.status === 404) { showToast('未找到该编号的高墙文件'); return null; }
        return r.json();
      })
      .then(function (d) {
        if (!d) return;
        var md = window.marked;
        var html = md ? (typeof md.parse === 'function' ? md.parse(d.content) : md(d.content)) : '<pre style="white-space:pre-wrap;">' + esc(d.content) + '</pre>';
        DA.mail.openMailView({ subject: code + ' 高墙文件', senderName: '高墙档案库 · 已解锁', html: html });
        hwInput.value = '';
      }).catch(function () { showToast('读取失败，请重试'); });
  }
  function submitHwSearch() { openHighwallByCode(hwInput.value); hwInput.blur(); }
  hwInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') submitHwSearch();
  });
  $('hwSearchGo').addEventListener('click', submitHwSearch);
  /* ========== 高墙文件 ========== */
  var hwCtl = null;
  function HighwallApp() {
    var self = this;
    this.open = function () { this.load(); };
    this.load = function () {
      var list = $('hwList');
      list.innerHTML = '<div class="pane-empty">加载中…</div>';
      var q = cid() ? '?charId=' + encodeURIComponent(cid()) : '';
      fetch('/api/documents/list' + q, { headers: authH() })
        .then(function (r) { return r.json(); })
        .then(function (files) {
          self.files = files || [];
          if (!self.files.length) { list.innerHTML = '<div class="pane-empty">暂无文件权限</div>'; return; }
          list.innerHTML = self.files.map(function (f, i) {
            return '<div class="hw-item' + (f.allowed ? '' : ' locked') + '" data-i="' + i + '">'
              + '<span class="hw-ico">' + (f.allowed ? ICO.file : ICO.lock) + '</span>'
              + '<span class="hw-title">' + esc(f.title) + '</span></div>';
          }).join('');
          Array.prototype.forEach.call(list.querySelectorAll('.hw-item'), function (it) {
            it.addEventListener('click', function () {
              var f = self.files[+it.dataset.i];
              if (!f.allowed) { showToast('无权限查看该文件'); return; }
              self.read(f, it);
            });
          });
        }).catch(function () { list.innerHTML = '<div class="pane-empty">加载失败</div>'; });
    };
    this.read = function (f, it) {
      Array.prototype.forEach.call($('hwList').querySelectorAll('.hw-item'), function (x) { x.classList.remove('active'); });
      if (it) it.classList.add('active');
      var prev = $('hwPreview');
      prev.innerHTML = '<div class="pane-empty">正在解密…</div>';
      fetch('/api/documents/read/' + encodeURIComponent(f.filename), { headers: authH() })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var md = window.marked;
          var html = md ? (typeof md.parse === 'function' ? md.parse(d.content) : md(d.content)) : '<pre style="white-space:pre-wrap;">' + esc(d.content) + '</pre>';
          prev.innerHTML = '<div class="hw-doc">' + html + '</div>';
        }).catch(function () { prev.innerHTML = '<div class="pane-empty">读取失败</div>'; });
    };
  }

  var hwCtl = null;
  DA.feats.highwall = { start: function () { hwCtl = new HighwallApp(); hwCtl.open(); } };
})();
