/* 出勤记录：参与过的任务列表 + 本人提交的任务报告/收容物查看（卡片式档案版式） */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid;
  var RPT_STATUS = { submitted: '待评审', reviewed: '已评审', sent: '已完成' };
  /* 报告状态 → 状态横幅（标题/副标题/图标/胶囊配色） */
  var BANNER = {
    sent:      { pill: '任务已完成', pillCls: 'sent', ico: 'fa-check', title: '任务完成', sub: '本次任务已顺利完成，报告已完成评级归档。' },
    reviewed:  { pill: '已评审',    pillCls: 'reviewed', ico: 'fa-pen-nib', title: '报告已评审', sub: '经理已完成评审，评级结果待发送。' },
    submitted: { pill: '待评审',    pillCls: 'submitted', ico: 'fa-clock', title: '报告待评审', sub: '报告已提交，等待经理评审。' },
    none:      { pill: '未提交报告', pillCls: 'none', ico: 'fa-file-alt', title: '未提交报告', sub: '本次任务没有提交任务报告。' }
  };

  function fmtDate(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    return d.getFullYear() + '/' + (d.getMonth() + 1) + '/' + d.getDate();
  }
  function fmtTime(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    return fmtDate(ts) + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }
  /* 收容物消息正文是「收容物名称: x\n\n描述: y」，名称已在卡片标题展示，这里只留描述 */
  function parseContainmentDesc(content) {
    if (!content) return '';
    var t = String(content)
      .replace(/^\s*收容物名称\s*[:：][^\n]*\n?/, '')
      .replace(/^\s*描述\s*[:：]\s*/, '');
    return t.trim() || String(content);
  }
  /* 卡片标题行：竖条 + 图标 + 标题 + 右侧英文小字（+附加内容） */
  function cardHead(ico, title, eng, extra) {
    return '<div class="his-card-h">'
      + '<span class="his-card-bar"></span>'
      + (ico ? '<i class="fas ' + ico + ' his-card-ico"></i>' : '')
      + '<b>' + esc(title) + '</b>' + (extra || '')
      + '<span class="his-card-eng">' + esc(eng) + '</span>'
      + '</div>';
  }
  function cell(label, val) {
    if (!val) return '';
    return '<div class="his-tcell"><span>' + esc(label) + '</span><i>' + esc(val) + '</i></div>';
  }
  function kvRow(label, val, cls) {
    if (!val && val !== 0) return '';
    return '<div class="his-kvrow"><span>' + esc(label) + '</span><i' + (cls ? ' class="' + cls + '"' : '') + '>' + esc(val) + '</i></div>';
  }

  function HistoryApp() {
    var self = this;
    this.data = [];
    this.selId = null;

    this.load = function () {
      var charId = cid();
      if (!charId) {
        this.data = [];
        this.renderList();
        return;
      }
      $('hisList').innerHTML = '<div class="pane-empty">加载中…</div>';
      fetch('/api/character/' + charId + '/mission-history', { headers: authH() })
        .then(function (r) {
          if (!r.ok) throw new Error(r.status);
          return r.json();
        })
        .then(function (list) {
          self.data = Array.isArray(list) ? list : [];
          self.renderList();
        })
        .catch(function () {
          $('hisList').innerHTML = '<div class="pane-empty">加载失败</div>';
        });
    };

    this.renderList = function () {
      var list = $('hisList');
      $('hisCount').textContent = this.data.length ? '共 ' + this.data.length + ' 次任务' : '';
      if (!this.data.length) {
        list.innerHTML = '<div class="pane-empty">暂无任务记录</div>';
        this.renderDetail();
        return;
      }
      var selId = this.selId;
      if (!this.data.some(function (m) { return m.id === selId; })) selId = this.data[0].id;
      list.innerHTML = this.data.map(function (m) {
        var flags = '';
        if (m.myReport) flags += '<i class="fas fa-file-alt his-flag his-flag-rpt" title="已提交报告"></i>';
        if (m.myContainment) flags += '<i class="fas fa-cube his-flag his-flag-box" title="已寄送收容物"></i>';
        return '<div class="his-item' + (m.id === selId ? ' active' : '') + '" data-id="' + esc(m.id) + '">'
          + '<div class="his-item-top"><span class="his-item-name">' + esc(m.name) + '</span>'
          + '<span class="his-badge ' + (m.status === 'archived' ? 'his-badge-arc' : 'his-badge-act') + '">' + (m.status === 'archived' ? '已归档' : '进行中') + '</span></div>'
          + '<div class="his-item-sub"><span class="his-badge his-badge-type">' + (m.missionType === 'sweep' ? '清扫' : '收容') + '</span>'
          + '<span class="his-item-date">' + fmtDate(m.joinedAt) + '</span>'
          + '<span class="his-item-flags">' + flags + '</span></div>'
          + '</div>';
      }).join('');
      this.selId = selId;
      Array.prototype.forEach.call(list.querySelectorAll('.his-item'), function (it) {
        it.addEventListener('click', function () {
          self.selId = it.dataset.id;
          Array.prototype.forEach.call(list.querySelectorAll('.his-item'), function (x) { x.classList.toggle('active', x === it); });
          self.renderDetail();
          /* 手机端：点击任务进入详情二级界面 */
          if (window.innerWidth <= 860) document.querySelector('#winHistory .his-body').classList.add('in-detail');
        });
      });
      this.renderDetail();
    };

    this.renderDetail = function () {
      var box = $('hisDetail');
      var m = this.data.find(function (x) { return x.id === self.selId; });
      if (!m) {
        box.innerHTML = '<div class="pane-empty">' + (this.data.length ? '← 选择任务查看详情' : '参与任务后，任务报告与收容物会记录在这里') + '</div>';
        return;
      }

      var r = m.myReport;
      var rd = r ? (r.reportData || {}) : {};
      var bn = BANNER[r ? r.status : 'none'] || BANNER.none;
      var h = '<button type="button" class="his-mback" id="hisMBack"><i class="fas fa-arrow-left"></i> 返回列表</button>';
      h += '<div class="his-doc">';

      /* ===== 任务头部：标题+徽章 / 状态胶囊+时间 ===== */
      h += '<div class="his-head">'
        + '<div class="his-head-l">'
        + '<div class="his-head-row"><span class="his-title">' + esc(m.name) + '</span>'
        + '<span class="his-badge ' + (m.status === 'archived' ? 'his-badge-arc' : 'his-badge-act') + '">' + (m.status === 'archived' ? '已归档' : '进行中') + '</span>'
        + '<span class="his-badge his-badge-type">' + (m.missionType === 'sweep' ? '清扫' : '收容') + '</span></div>'
        + '<div class="his-meta">'
        + (m.joinedAt ? '<span><i class="fas fa-calendar-day"></i> 出勤 ' + fmtDate(m.joinedAt) + '</span><i class="his-msep"></i>' : '')
        + '<span><i class="fas fa-file-alt"></i> 报告 ' + (r ? (RPT_STATUS[r.status] || '') : '未提交') + '</span><i class="his-msep"></i>'
        + '<span><i class="fas fa-cube"></i> 收容物' + (m.myContainment ? ' 已寄送' : ' 未寄送') + '</span>'
        + '</div></div>'
        + '<div class="his-head-r">'
        + '<span class="his-pill his-pill-' + bn.pillCls + '"><i class="fas ' + bn.ico + '"></i> ' + esc(bn.pill) + '</span>'
        + (r ? '<span class="his-head-time">提交于 ' + fmtTime(r.submittedAt) + '</span>' : '')
        + '</div></div>';

      /* ===== 任务简报（有描述时） ===== */
      if (m.description) {
        h += '<div class="his-card his-sec-gap">' + cardHead('fa-book', '任务简报', 'MISSION BRIEF')
          + '<p class="his-brief">' + esc(m.description) + '</p></div>';
      }

      /* ===== 状态横幅 ===== */
      h += '<div class="his-banner his-banner-' + bn.pillCls + ' his-sec-gap">'
        + '<span class="his-banner-ico"><i class="fas ' + bn.ico + '"></i></span>'
        + '<span class="his-banner-txt"><em class="his-banner-tag">TASK STATUS</em>'
        + '<b>' + esc(bn.title) + '</b>'
        + '<p>' + esc(bn.sub) + '</p></span>'
        + '</div>';

      /* ===== 经理批注 ===== */
      if (r && r.annotations && r.annotations.length) {
        h += '<div class="his-ann his-sec-gap"><span class="his-ann-ico"><i class="fas fa-pen-nib"></i></span>'
          + '<span class="his-ann-txt"><b>经理批注</b>';
        r.annotations.forEach(function (a) { h += '<p>• ' + esc(a) + '</p>'; });
        h += '</span></div>';
      }

      /* ===== 报告内容卡（有报告时） ===== */
      if (r) {
        h += '<div class="his-sec-cards" id="hisCards">';
        /* 威胁分析 */
        if (rd.analysis) {
          var an = rd.analysis;
          var cells = cell('代号', an.codename) + cell('行为', an.behavior) + cell('专注', an.focus) + cell('区域', an.domain);
          if (cells) h += '<div class="his-card his-sec-gap">' + cardHead('fa-search', '威胁分析', 'THREAT ANALYSIS')
            + '<div class="his-tcells">' + cells + '</div></div>';
        }
        /* 散逸端记录 + 任务评估 双栏 */
        var scatTable = '';
        if (rd.scattering && rd.scattering.length) {
          var rows = rd.scattering.map(function (s) {
            if (typeof s === 'string') return '<tr><td colspan="3">' + esc(s) + '</td></tr>';
            return '<tr><td>' + esc(s.name || '') + '</td><td>' + esc(s.qty || '') + '</td><td>' + esc(s.note || '') + '</td></tr>';
          }).join('');
          scatTable = '<table class="his-table"><thead><tr><th>姓名</th><th style="width:58px;">数量</th><th>备注</th></tr></thead><tbody>' + rows + '</tbody></table>';
        }
        var kv = kvRow('评级', r.rating || '', 'his-kv-rating') + kvRow('散逸端', (r.scatterValue != null && r.scatterValue !== '') ? r.scatterValue : '', 'his-kv-scatter')
          + kvRow('威胁等级', rd.evaluation && rd.evaluation.rating)
          + kvRow('混沌池', rd.evaluation && rd.evaluation.chaosPool)
          + kvRow('MVP', rd.evaluation && rd.evaluation.mvp)
          + kvRow('察看期', rd.evaluation && rd.evaluation.probation)
          + kvRow('参与者', rd.evaluation && rd.evaluation.participants);
        if (scatTable || kv) {
          h += '<div class="his-row2 his-sec-gap">'
            + '<div class="his-card">' + cardHead('fa-list-alt', '散逸端记录', 'SCATTER')
            + (scatTable || '<div class="his-card-empty">无散逸端记录</div>') + '</div>'
            + '<div class="his-card">' + cardHead('fa-chart-bar', '任务评估', 'EVALUATION')
            + (kv ? '<div class="his-kvlist">' + kv + '</div>' : '<div class="his-card-empty">暂无评估数据</div>') + '</div>'
            + '</div>';
        }
        /* 任务目标 */
        if (rd.objectives && rd.objectives.length) {
          var orows = rd.objectives.map(function (o) {
            if (typeof o === 'string') return '<tr><td colspan="3">' + esc(o) + '</td></tr>';
            return '<tr><td>' + esc(o.target || '') + '</td><td>' + esc(o.reward || '') + '</td><td>' + esc(o.agent || '') + '</td></tr>';
          }).join('');
          h += '<div class="his-card his-sec-gap">' + cardHead('fa-bullseye', '任务目标', 'OBJECTIVE')
            + '<table class="his-table"><thead><tr><th>目标</th><th>奖励</th><th style="width:96px;">按特工</th></tr></thead><tbody>' + orows + '</tbody></table></div>';
        }
        h += '</div>';
      }

      /* ===== 收容物 ===== */
      h += '<div class="his-card his-sec-gap">' + cardHead('fa-cube', '收容物', 'CONTAINMENT',
        m.myContainment ? '<span class="his-badge his-badge-box">已寄送</span>' : '')
      ;
      if (m.myContainment) {
        h += '<div class="his-box">'
          + '<div class="his-box-name"><i class="fas fa-cube"></i>' + esc(m.myContainment.name) + '</div>'
          + '<div class="his-box-meta">寄送于 ' + fmtTime(m.myContainment.createdAt) + '</div>'
          + '<div class="his-box-desc">' + esc(parseContainmentDesc(m.myContainment.content)) + '</div>'
          + '</div>';
      } else {
        h += '<div class="his-card-empty">该任务未寄送收容物</div>';
      }
      h += '</div>';

      h += '</div>';
      box.innerHTML = h;
      /* 手机端返回按钮：回列表 */
      var back = $('hisMBack');
      if (back) back.addEventListener('click', function () {
        document.querySelector('#winHistory .his-body').classList.remove('in-detail');
      });
    };
  }

  var ctl = null;
  function start() {
    window.DESKTOP.onCardReady(function () {
      ctl = ctl || new HistoryApp();
      ctl.load();
    });
  }
  function reload() {
    if (ctl) ctl.load();
    else start();
  }

  DA.feats.history = { start: start, close: function () {}, reload: reload };
})();
