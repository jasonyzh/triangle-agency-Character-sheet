/* 我的文档窗口：档案页 + 编辑角色卡弹窗 + 头像上传裁剪 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cardData = DA.cardData;

  /* ========== 我的文档 ========== */
  var DOC_QS = [
    '1. 你是如何与你的异常接触的？',
    '2. 机构是如何找到你的？',
    '3. 你的能力有独特的外在视觉表现吗？',
    '4. 你喝咖啡有什么偏好？',
    '5. 请描述你过往的工作经历',
    '6. 你对Adobe、Excel和Google套件的熟悉程度如何？',
    '7. 在协作工作环境中，你能做出什么贡献？'
  ];

  function renderDocs() {
    var el = $('docsBody');
    var c = cardData();
    if (!c) { el.innerHTML = '<div class="pane-empty">未选择角色，请先在个人面板中激活角色</div>'; return; }

    var sum = function (arr) { return (arr || []).reduce(function (s, r) { return s + (r.count || 1); }, 0); };

    /* 资质保证环（保证上限 v，最高 9 点） */
    var attrs = c.attrs || {};
    var attrKeys = Object.keys(attrs);
    var rings = attrKeys.map(function (k) {
      var a = attrs[k] || {};
      var n = parseInt(a.v) || 0;
      var pct = Math.min(n / 9, 1);
      var C = 2 * Math.PI * 26;
      return '<div class="docx-ring"><div class="docx-ringfig">'
        + '<svg viewBox="0 0 64 64"><circle class="tr" cx="32" cy="32" r="26"/>'
        + '<circle class="pr" cx="32" cy="32" r="26" stroke-dasharray="' + C.toFixed(1) + '" stroke-dashoffset="' + (C * (1 - pct)).toFixed(1) + '"/></svg>'
        + '<b>' + n + '/9</b></div><span>' + esc(k) + '</span></div>';
    }).join('');
    if (!rings) rings = '<div class="pane-empty">暂无资质数据</div>';

    /* 欢迎你，特工 7 问（问上答下） */
    var qs = c.qs || [];
    var qsHtml = DOC_QS.map(function (lbl, i) {
      var ans = qs[i] || '';
      var q = lbl.replace(/^\d+\.\s*/, '');
      var ansHtml = /^[^<>]*$/.test(ans) ? esc(ans) : ans;   /* 纯文本转义，富文本原样 */
      return '<div class="docx-q"><div class="docx-q-head"><i>' + (i + 1) + '</i><span class="t">' + esc(q) + '</span></div>'
        + '<div class="a' + (ans ? '' : ' empty') + '">' + (ans ? ansHtml : '未填写') + '</div></div>';
    }).join('');

    /* 基础信息 */
    var ava = c.pAvatar
      ? '<div class="docx-ava"><img src="' + (c.pAvatar.indexOf('http') === 0 ? DA.avaSrc(c.pAvatar) : '/' + DA.avaSrc(c.pAvatar)) + '" alt=""></div>'
      : '<div class="docx-ava"><span>' + esc((c.pName || '？').charAt(0)) + '</span></div>';
    var types = [['异常', c.pAnom], ['现实', c.pReal], ['职能', c.pFunc]]
      .filter(function (r) { return r[1]; })
      .map(function (r) { return '<span class="docx-tag">' + r[0] + ' · ' + esc(r[1]) + '</span>'; }).join('');

    function row(lbl, val, blockable) {
      if (val === undefined || val === null || val === '') return '';
      var s = String(val);
      var rich = /[<>]/.test(s);
      if (rich || (blockable && s.replace(/<[^>]+>/g, '').length > 46)) {
        return '<div class="docx-row block"><span class="lbl">' + lbl + '</span><div class="val' + (rich ? ' rich' : '') + '">' + val + '</div></div>';
      }
      return '<div class="docx-row"><span class="lbl">' + lbl + '</span><span class="val">' + esc(s) + '</span></div>';
    }

    var deriv = c.derivativeProgress || [];
    var derivHtml = '<span class="docx-dots">' + [1, 2, 3, 4].map(function (n) {
      return '<span class="docx-dot' + (deriv.indexOf(n) >= 0 ? ' on' : '') + '">' + n + '</span>';
    }).join('') + '</span>';
    var perms = [c.perm1, c.perm2, c.perm3].filter(Boolean)
      .map(function (p) { return '<span class="docx-perm">' + esc(p) + '</span>'; }).join('');

    el.innerHTML =
      '<div class="docx">'
      + '<div class="docx-head"><span class="docx-head-ico"></span><div><b>基础档案</b><small>查看角色的完整信息与评估记录</small></div><button class="docx-edit" id="docxEdit">编辑角色卡</button></div>'
      + '<div class="docx-grid">'
      + '<div class="docx-card docx-basic"><div class="docx-card-h"><b>基础信息</b><span>核心信息</span></div>'
      + '<div class="docx-id">' + ava + '<div class="docx-idinfo"><label>姓名</label><b>' + esc(c.pName || '—') + '</b>'
      + (types ? '<div class="docx-tags">' + types + '</div>' : '') + '</div></div>'
      + row('过载解除', c.pTrig1, true)
      + row('现实触发器', c.pTrig2, true)
      + row('首要指令', c.pTrig3, true)
      + '<div class="docx-stats">'
      + '<div class="docx-stat"><b>' + sum(c.mvpRecords) + '</b><span>MVP</span></div>'
      + '<div class="docx-stat"><b>' + sum(c.watchRecords) + '</b><span>察看期</span></div>'
      + '<div class="docx-stat"><b>' + sum(c.rewards) + '</b><span>嘉奖</span></div>'
      + '<div class="docx-stat"><b>' + sum(c.reprimands) + '</b><span>申诫</span></div>'
      + '</div>'
      + '<div class="docx-row"><span class="lbl">现实计数</span>' + derivHtml + '</div>'
      + (perms ? '<div class="docx-sub"><label>许可行为</label><div class="docx-perms">' + perms + '</div></div>' : '')
      + '</div>'
      + '<div class="docx-card docx-attrs"><div class="docx-card-h"><b>资质保证</b><span>' + attrKeys.length + ' 项能力评估</span></div>'
      + '<div class="docx-rings">' + rings + '</div></div>'
      + '<div class="docx-card docx-qs"><div class="docx-card-h"><b>欢迎你，特工！</b><span>完成以下问题，帮助我们更好地了解你</span></div>'
      + qsHtml + '</div>'
      + '</div>'
      + '</div>';

    var editBtn = document.getElementById('docxEdit');
    if (editBtn) editBtn.addEventListener('click', openDocEditor);
  }
  /* ========== 我的文档：编辑角色卡弹窗（当前页直接编辑，PUT /api/character/:id） ========== */
  var docOpts = null;        /* 预设缓存（/api/options 的 anoms/realities/functions） */
  var uploadedAvatar = null; /* 本次弹窗内新上传的头像 */
  function loadDocOpts(cb) {
    if (docOpts) return cb(docOpts);
    fetch('/api/options', { headers: authH() })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .then(function (d) { docOpts = d || {}; cb(docOpts); })
      .catch(function () { docOpts = {}; cb(docOpts); });
  }

  /* hybrid 三件套（复刻 sheet：下拉预设 + 自定义输入，载入时按已有数据自动选择） */
  function deFillSelect(sel, items) {
    sel.innerHTML = '<option value="" disabled selected>-- 请选择 --</option>';
    (items || []).forEach(function (item) {
      var val = typeof item === 'string' ? item : item.name;
      var o = document.createElement('option');
      o.value = val; o.textContent = val;
      sel.appendChild(o);
    });
    var c = document.createElement('option');
    c.value = '__CUSTOM__'; c.textContent = '➤ 自定义 / 手动输入...';
    sel.appendChild(c);
  }
  function deSetHybrid(field, value) {
    var sel = $('de-sel-' + field), wrap = $('de-grp-' + field), input = $('de-' + field);
    var isPreset = false;
    Array.prototype.forEach.call(sel.options, function (o) { if (o.value === value) isPreset = true; });
    input.value = value || '';
    if (isPreset) { wrap.classList.remove('show-input'); sel.value = value; }
    else if (value && value.trim() !== '') { wrap.classList.add('show-input'); sel.value = '__CUSTOM__'; }
    else { wrap.classList.remove('show-input'); sel.value = ''; }
  }
  /* 选预设的级联：现实→触发器；职能→首要指令+许可行为+评估问答；异常→预设能力组写入角色（同 sheet applyCascadingLogic） */
  function deCascade(field, value) {
    if (field === 'pReal') {
      var r = (docOpts.realities || []).filter(function (x) { return x.name === value; })[0];
      if (r) {
        $('deTrig1').innerHTML = r.trigger || '';
        $('deTrig2').innerHTML = r.overload || '';
        showToast('已按预设填入过载解除与现实触发器');
      }
    } else if (field === 'pAnom') {
      /* 复刻 sheet：选择异常预设后，把该组的异常能力整组写入角色卡的 anoms（同名不重复，原有自定义能力保留在后面） */
      var g = (docOpts.anoms || []).filter(function (x) { return x.name === value; })[0];
      if (g && (g.abilities || []).length) {
        var presets = g.abilities.map(function (a) {
          var o = {};
          for (var k in a) o[k] = a[k];
          o.passive = !!o.passive; o.subOn = !!o.subOn; o.listOn = !!o.listOn; o.chk = !!o.chk;
          o.list = o.list || [];
          o.p1 = o.p1 || [false, false, false];
          o.p2 = o.p2 || [false, false, false];
          o.p3 = o.p3 || [false, false, false];
          return o;
        });
        var names = presets.map(function (p) { return p.name; });
        var ch = window.DESKTOP.getCurChar();
        if (ch) {
          var cd = {};
          try { cd = JSON.parse(ch.data || '{}'); } catch (e) { cd = {}; }
          var kept = (cd.anoms || []).filter(function (a) { return names.indexOf(a.name) < 0; });
          cd.anoms = presets.concat(kept);
          ch.data = JSON.stringify(cd);   /* 写回存储串，点「保存」时随整卡 PUT */
          showToast('已按预设写入 ' + presets.length + ' 项异常能力，保存后生效');
        }
      }
    } else if (field === 'pFunc') {
      var f = (docOpts.functions || []).filter(function (x) { return x.name === value; })[0];
      if (f) {
        $('deTrig3').innerHTML = f.directive || '';
        if (f.perms && f.perms.length === 3) {
          $('dePerm1').value = f.perms[0];
          $('dePerm2').value = f.perms[1];
          $('dePerm3').value = f.perms[2];
        }
        showToast('已按预设填入首要指令与许可行为');
        /* 复刻 sheet：选择职能预设后弹出该职能的入职自我评估问答（提交后资质清零自动分配） */
        if (f.Assessment && f.Assessment.length) openAssessment(f.Assessment);
      }
    }
  }

  /* ========== 职能自我评估问答（复刻 sheet assessment.js：每题二选一，提交后九项资质清零、按所选答案自动分配） ========== */
  function openAssessment(list) {
    var body = $('deAssessBody');
    var qs = list || [];
    window.__deAssessData = qs;
    /* 选项文本里已带 "(+3 气场)" 之类后缀，徽章单独展示，故文本去掉尾部括号避免重复 */
    function optText(t) { return String(t).replace(/[（(]\s*\+\d+[^）)]*[）)]\s*$/, ''); }
    body.innerHTML = qs.map(function (qa, index) {
      function opt(key) {
        var a = qa[key] || [];
        return '<label class="de-assess-opt" data-q="' + index + '" data-opt="' + key + '">'
          + '<span class="de-assess-text">' + esc(optText(a[0])) + '</span>'
          + '<span class="de-assess-badge">' + esc(a[1]) + ' +' + esc(a[2]) + '</span></label>';
      }
      return '<div class="de-assess-q"><div class="de-assess-qtext">' + (index + 1) + '. ' + esc(qa.q) + '</div>'
        + opt('a1') + opt('a2') + '</div>';
    }).join('');
    Array.prototype.forEach.call(body.querySelectorAll('.de-assess-opt'), function (el) {
      el.addEventListener('click', function () {
        Array.prototype.forEach.call(body.querySelectorAll('.de-assess-opt[data-q="' + el.dataset.q + '"]'), function (o) {
          o.classList.remove('selected');
        });
        el.classList.add('selected');
      });
    });
    body.scrollTop = 0;
    $('deAssessMask').classList.add('show');
  }
  function closeAssessment() {
    $('deAssessMask').classList.remove('show');
    window.__deAssessData = null;
  }
  function submitAssessment() {
    var qs = window.__deAssessData || [];
    var answered = document.querySelectorAll('#deAssessBody .de-assess-opt.selected').length;
    if (answered < qs.length) { showToast('请回答所有问题后再提交'); return; }
    /* 同 sheet：九项资质先清零，再按所选答案累加属性值自动分配 */
    var mods = {};
    qs.forEach(function (qa, index) {
      var sel = document.querySelector('#deAssessBody .de-assess-opt.selected[data-q="' + index + '"]');
      if (!sel) return;
      var a = qa[sel.dataset.opt];
      if (!a) return;
      var val = parseInt(a[2]) || 0;
      mods[a[1]] = (mods[a[1]] || 0) + val;
    });
    Array.prototype.forEach.call(document.querySelectorAll('#docEditBody .de-attr-val'), function (inp) {
      inp.value = mods[inp.dataset.k] !== undefined ? mods[inp.dataset.k] : 0;
    });
    closeAssessment();
    var summary = Object.keys(mods).map(function (k) { return k + ' +' + mods[k]; }).join('，');
    showToast(summary ? '评估完成！' + summary : '评估完成，资质已重置');
  }

  function uploadDocAvatarBlob(blob) {
    var cid = window.DESKTOP.getActiveCharId();
    if (!cid || !blob) return;
    showToast('头像上传中…');
    var fd = new FormData();
    fd.append('avatar', blob, 'avatar.jpg');
    fetch('/api/character/' + cid + '/avatar', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
      body: fd
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) {
        uploadedAvatar = d.avatar;
        DA.bumpAvaVer(d.avatar);
        var ava = $('deAva');
        var img = ava.querySelector('img');
        if (!img) { ava.innerHTML = '<img alt="">'; img = ava.querySelector('img'); }
        img.src = DA.avaSrc(d.avatar);
        /* 上传接口已直接写库，本地卡数据同步，避免后续保存用旧 pAvatar 覆盖 */
        var ch = window.DESKTOP.getCurChar();
        if (ch) { try { var cd = JSON.parse(ch.data || '{}'); cd.pAvatar = d.avatar; ch.data = JSON.stringify(cd); } catch (e) {} }
        showToast('头像已更新，记得保存');
      } else showToast(d.message || '头像上传失败');
    })
    .catch(function () { showToast('头像上传失败'); });
  }

  /* 裁剪窗（Cropper.js，正方形 1:1，确认后转 JPEG 上传） */
  var docCropper = null;
  function openDocAvaCrop(dataUrl) {
    var img = $('docCropImg');
    $('docAvaCropMask').classList.add('show');
    if (docCropper) { docCropper.destroy(); docCropper = null; }
    /* 必须等图片真正加载解码完成再初始化 Cropper，否则按错误尺寸计算会导致蒙版错位 */
    img.onload = function () {
      img.onload = null;
      setTimeout(function () {
        docCropper = new Cropper(img, {
          aspectRatio: 1, viewMode: 1, autoCropArea: 0.9,
          movable: true, zoomable: true, rotatable: false, scalable: false,
          background: false
        });
      }, 50);
    };
    img.src = dataUrl;
    if (img.complete && img.naturalWidth) img.onload();   /* 缓存图立即触发 */
  }
  function closeDocAvaCrop() {
    $('docAvaCropMask').classList.remove('show');
    if (docCropper) { docCropper.destroy(); docCropper = null; }
  }
  function confirmDocAvaCrop() {
    if (!docCropper) return;
    var canvas = docCropper.getCroppedCanvas({ width: 256, height: 256, imageSmoothingQuality: 'high' });
    if (!canvas) { showToast('裁剪失败'); return; }
    canvas.toBlob(function (blob) {
      if (!blob) { showToast('生成图片失败'); return; }
      uploadDocAvatarBlob(blob);   /* blob 为 image/jpeg */
      closeDocAvaCrop();
    }, 'image/jpeg', 0.9);
  }

  /* 资质固定按 sheet 的九项展示（新角色也能被评估问答分配到任意属性），卡里额外的键附在后面 */
  var SHEET_ATTRS = ['专注', '欺瞒', '活力', '共情', '主动', '坚毅', '气场', '专业', '诡秘'];

  function openDocEditor() {
    var c = cardData();
    if (!c) { showToast('未选择角色'); return; }
    var body = $('docEditBody');
    uploadedAvatar = null;

    var avaHtml = c.pAvatar
      ? '<img src="' + (c.pAvatar.indexOf('http') === 0 ? DA.avaSrc(c.pAvatar) : '/' + DA.avaSrc(c.pAvatar)) + '" alt="">'
      : '<span>' + esc((c.pName || '？').charAt(0)) + '</span>';

    var attrKeys = SHEET_ATTRS.slice();
    Object.keys(c.attrs || {}).forEach(function (k) { if (attrKeys.indexOf(k) < 0) attrKeys.push(k); });
    var attrRows = attrKeys.map(function (k) {
      var v = parseInt(((c.attrs || {})[k] || {}).v) || 0;
      return '<div class="de-attr-row"><span>' + esc(k) + '</span><input type="number" class="de-input de-attr-val" data-k="' + esc(k) + '" min="0" max="9" value="' + v + '"></div>';
    }).join('');
    var deriv = c.derivativeProgress || [];
    var dots = [1, 2, 3, 4].map(function (n) {
      return '<span class="docx-dot de-dot' + (deriv.indexOf(n) >= 0 ? ' on' : '') + '" data-n="' + n + '">' + n + '</span>';
    }).join('');
    var qsEd = DOC_QS.map(function (lbl, i) {
      var ans = (c.qs || [])[i] || '';
      return '<div class="de-field"><label>' + esc(lbl.replace(/^\d+\.\s*/, '')) + '</label>'
        + '<div class="de-editor" contenteditable="true" data-q="' + i + '" data-ph="未填写">' + (ans || '') + '</div></div>';
    }).join('');

    body.innerHTML =
      '<div class="de-sec"><label class="de-sec-t">基础信息</label>'
      + '<div class="de-ava-wrap"><div class="docx-ava" id="deAva" title="点击更换头像">' + avaHtml
      + '</div></div>'
      + '<div class="de-field"><label>姓名</label><input class="de-input" id="deName" value="' + esc(c.pName || '') + '"></div>'
      + '<div class="de-grid">'
      + '<div class="de-field"><label>异常能力</label><div class="de-hybrid" id="de-grp-pAnom"><select class="de-input de-sel" id="de-sel-pAnom"></select><input class="de-input de-txt" id="de-pAnom" placeholder="输入异常能力"><button type="button" class="de-back" id="deBack-pAnom" title="返回选择预设">⟲</button></div></div>'
      + '<div class="de-field"><label>现实身份</label><div class="de-hybrid" id="de-grp-pReal"><select class="de-input de-sel" id="de-sel-pReal"></select><input class="de-input de-txt" id="de-pReal" placeholder="输入现实身份"><button type="button" class="de-back" id="deBack-pReal" title="返回选择预设">⟲</button></div></div>'
      + '<div class="de-field"><label>机构职能</label><div class="de-hybrid" id="de-grp-pFunc"><select class="de-input de-sel" id="de-sel-pFunc"></select><input class="de-input de-txt" id="de-pFunc" placeholder="输入机构职能"><button type="button" class="de-back" id="deBack-pFunc" title="返回选择预设">⟲</button></div></div>'
      + '</div></div>'
      + '<div class="de-sec"><label class="de-sec-t">触发器</label>'
      + '<div class="de-field"><label>过载解除</label><div class="de-editor" contenteditable="true" id="deTrig1" data-ph="过载解除的效果…">' + (c.pTrig1 || '') + '</div></div>'
      + '<div class="de-field"><label>现实触发器</label><div class="de-editor" contenteditable="true" id="deTrig2" data-ph="现实触发器的效果…">' + (c.pTrig2 || '') + '</div></div>'
      + '<div class="de-field"><label>首要指令</label><div class="de-editor" contenteditable="true" id="deTrig3" data-ph="首要指令的内容…">' + (c.pTrig3 || '') + '</div></div>'
      + '</div>'
      + '<div class="de-sec"><label class="de-sec-t">资质保证</label><div class="de-grid">' + attrRows + '</div><small class="de-tip">资质保证上限，最高 9 点</small></div>'
      + '<div class="de-sec"><label class="de-sec-t">现实计数</label><div class="de-dots">' + dots + '</div></div>'
      + '<div class="de-sec"><label class="de-sec-t">许可行为</label><div class="de-grid">'
      + '<div class="de-field"><label>许可行为 1</label><input class="de-input" id="dePerm1" value="' + esc(c.perm1 || '') + '"></div>'
      + '<div class="de-field"><label>许可行为 2</label><input class="de-input" id="dePerm2" value="' + esc(c.perm2 || '') + '"></div>'
      + '<div class="de-field"><label>许可行为 3</label><input class="de-input" id="dePerm3" value="' + esc(c.perm3 || '') + '"></div>'
      + '</div></div>'
      + '<div class="de-sec"><label class="de-sec-t">欢迎你，特工！</label>' + qsEd + '</div>';

    /* 现实计数点选 */
    Array.prototype.forEach.call(body.querySelectorAll('.de-dot'), function (d) {
      d.addEventListener('click', function () { d.classList.toggle('on'); });
    });

    /* 头像上传：选图 → 打开裁剪窗 */
    $('deAva').addEventListener('click', function () { $('deAvaFile').click(); });
    $('deAvaFile').addEventListener('change', function () {
      var file = this.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function (ev) { openDocAvaCrop(ev.target.result); };
      reader.readAsDataURL(file);
      this.value = '';   /* 允许重复选同一文件 */
    });

    /* 异常/现实/职能 hybrid：异步拉预设后按已有数据自动选择 */
    loadDocOpts(function (opts) {
      [['pAnom', 'anoms'], ['pReal', 'realities'], ['pFunc', 'functions']].forEach(function (pair) {
        var f = pair[0];
        var sel = $('de-sel-' + f);
        if (!sel) return;
        deFillSelect(sel, opts[pair[1]]);
        deSetHybrid(f, c[f] || '');
        sel.addEventListener('change', function () {
          if (sel.value === '__CUSTOM__') {
            $('de-grp-' + f).classList.add('show-input');
            var inp = $('de-' + f); inp.value = ''; inp.focus();
          } else {
            $('de-' + f).value = sel.value;
            deCascade(f, sel.value);
          }
        });
        $('deBack-' + f).addEventListener('click', function () {
          $('de-grp-' + f).classList.remove('show-input');
          sel.value = ''; $('de-' + f).value = '';
        });
      });
    });

    $('docEditMask').classList.add('show');
    body.scrollTop = 0;
  }

  function saveDocEdit() {
    var card = cardData();
    var cid = window.DESKTOP.getActiveCharId();
    if (!card || !cid) { showToast('未选择角色'); return; }
    var g = function (id) { var el = $(id); return el ? el.value : undefined; };
    card.pName = g('deName');
    /* hybrid：无论处于下拉还是自定义模式，值始终在 input 里 */
    card.pAnom = g('de-pAnom'); card.pReal = g('de-pReal'); card.pFunc = g('de-pFunc');
    card.pTrig1 = $('deTrig1').innerHTML; card.pTrig2 = $('deTrig2').innerHTML; card.pTrig3 = $('deTrig3').innerHTML;
    if (!card.attrs) card.attrs = {};
    Array.prototype.forEach.call(document.querySelectorAll('#docEditBody .de-attr-val'), function (inp) {
      if (!card.attrs[inp.dataset.k]) card.attrs[inp.dataset.k] = { v: '0', m: [] };
      card.attrs[inp.dataset.k].v = inp.value;
    });
    card.derivativeProgress = Array.prototype.map.call(
      document.querySelectorAll('#docEditBody .de-dot.on'),
      function (d) { return parseInt(d.dataset.n, 10); }
    );
    card.perm1 = g('dePerm1'); card.perm2 = g('dePerm2'); card.perm3 = g('dePerm3');
    card.qs = Array.prototype.map.call(
      document.querySelectorAll('#docEditBody .de-editor[data-q]'),
      function (e) { return e.innerHTML; }
    );
    if (uploadedAvatar) card.pAvatar = uploadedAvatar;

    var btn = $('docEditSave');
    btn.disabled = true;
    var old = btn.textContent;
    btn.textContent = '保存中…';
    fetch('/api/character/' + cid, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
      body: JSON.stringify(card)
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      btn.disabled = false; btn.textContent = old;
      if (!d.success) throw new Error(d.message || '保存失败');
      /* 同步本地卡数据并重渲染，再异步重拉 */
      var ch = window.DESKTOP.getCurChar();
      if (ch) ch.data = JSON.stringify(card);
      $('docEditMask').classList.remove('show');
      showToast('角色卡已保存');
      renderDocs();
      window.DESKTOP.refreshChar();
    })
    .catch(function () {
      btn.disabled = false; btn.textContent = old;
      showToast('保存失败，请重试');
    });
  }

  /* 编辑弹窗事件（静态元素，只绑一次）。注意：点击遮罩不关闭，避免丢失已填内容 */
  $('docEditClose').addEventListener('click', function () {
    $('docEditMask').classList.remove('show');
    uploadedAvatar = null;
  });
  $('docEditSave').addEventListener('click', saveDocEdit);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && $('docEditMask').classList.contains('show')) {
      $('docEditMask').classList.remove('show');
      uploadedAvatar = null;
    }
    if (e.key === 'Escape' && $('docAvaCropMask').classList.contains('show')) closeDocAvaCrop();
  });
  /* 裁剪窗事件 */
  $('docCropClose').addEventListener('click', closeDocAvaCrop);
  $('docCropCancel').addEventListener('click', closeDocAvaCrop);
  $('docCropConfirm').addEventListener('click', confirmDocAvaCrop);

  /* 评估问答弹窗事件（静态元素，只绑一次） */
  $('deAssessClose').addEventListener('click', closeAssessment);
  $('deAssessCancel').addEventListener('click', closeAssessment);
  $('deAssessSubmit').addEventListener('click', submitAssessment);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && $('deAssessMask').classList.contains('show')) closeAssessment();
  });

  /* 注册到桌面 shell：打开“我的文档”时渲染档案页；rerender 供 desktop.js 在角色数据到达后刷新 */
  DA.feats.docs = {
    start: function () { window.DESKTOP.onCardReady(renderDocs); },
    rerender: function () { renderDocs(); }
  };
})();
