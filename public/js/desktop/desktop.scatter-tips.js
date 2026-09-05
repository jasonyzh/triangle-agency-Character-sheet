/* 散逸端「窃窃私语」气泡：当前分部散逸端 ≥ 11 时，壁纸层（z=背景+1）随机浮现低语文案。
   规则：同屏最多 3 个；10s 淡入 → 停 2s → 10s 淡出；随机 9~16s 间隔连续出现；
   槽位互不重叠；层 pointer-events:none，纯背景低语，不挡任何内容与点击。
   数据入口：desktop.js loadScatter() 拿到分部散逸端后调 DA.feats.scatterTips.update(num) */
(function () {
  'use strict';

  var TIPS = [
    '请记得，凡俗心智的认知会增强异常。妥善移除散逸端，是保护现实的关键。',
    '每一次成功的说服或信息管控，都是在为下一次任务降低风险。',
    '散逸端的危险在于传播。评估他们的影响力，比单纯计数更重要。',
    '我们的职责是守护秩序。让凡人远离危险的认知，本身就是一种保护。',
    '未处理的散逸端会转化为异常体的力量。谨慎行事，是对队友和自己负责。',
    '优先尝试说服；若无法达成共识，请务必阻断其可信的传播途径。',
    '减少散逸端不是额外要求，而是维系宇宙存续的核心工作。',
    '你的专业处置，能让凡俗心智免于接触无法承受之重。',
    '每消除一个散逸端，都是在为现实的稳定添一份保障。',
    '这份工作的意义，藏在那些被妥善安抚、未被惊扰的平凡生活里。'
  ];
  var THRESHOLD = 11;
  var MAX_ONSCREEN = 3;
  var FADE_IN_MS = 10000;                          /* 淡入时长 */
  var HOLD_MS = 2000;                              /* 完全显现后停留 */
  var FADE_OUT_MS = 10000;                         /* 淡出时长 */
  var INTERVAL_MIN = 9000, INTERVAL_MAX = 16000;   /* 随机产生间隔 */

  var layer = null;
  var timer = null;
  var lastIdx = -1;

  function isMobile() { return window.matchMedia && window.matchMedia('(max-width: 860px)').matches; }

  function ensureLayer() {
    if (!layer || !document.body.contains(layer)) {
      layer = document.createElement('div');
      layer.id = 'scatterTips';
      document.body.appendChild(layer);
    }
    return layer;
  }

  /* 挑一个未被在屏气泡占用的槽位（0/1/2），保证三个同屏不重叠 */
  function freeSlot(box) {
    var used = {};
    box.querySelectorAll('.stip').forEach(function (b) { used[b.dataset.slot] = true; });
    for (var s = 0; s < MAX_ONSCREEN; s++) if (!used[s]) return s;
    return -1;
  }

  /* 优先用当前激活角色「关系网」里的人名作低语前缀（如「安妮：请记得…」）；关系为空则维持无前缀 */
  function relNames() {
    try {
      var ch = window.DESKTOP && window.DESKTOP.getCurChar ? window.DESKTOP.getCurChar() : null;
      if (!ch) return [];
      var card = {};
      try { card = JSON.parse(ch.data || '{}'); } catch (e) { card = {}; }
      return (card.reals || []).map(function (r) { return String((r && r.name) || '').trim(); }).filter(Boolean);
    } catch (e) { return []; }
  }

  function spawn() {
    var box = ensureLayer();
    var slot = freeSlot(box);
    if (slot < 0) return;   /* 同屏已满 3 个，本轮跳过 */

    var i = lastIdx;
    while (i === lastIdx) i = Math.floor(Math.random() * TIPS.length);   /* 避免连续重复同一条 */
    lastIdx = i;

    var names = relNames();
    var prefix = names.length ? names[Math.floor(Math.random() * names.length)] + '：' : '';

    var b = document.createElement('div');
    b.className = 'stip s' + slot;
    b.dataset.slot = slot;
    b.textContent = '“' + prefix + TIPS[i] + '”';
    /* 电脑端在右侧白墙区域随机浮现；手机端位置交给 CSS（Dock 上方近全宽） */
    if (!isMobile()) b.style.left = (42 + Math.random() * 26) + '%';
    box.appendChild(b);
    /* 下一帧再加 show，触发 10s 淡入；到时后移除 show，10s 淡出后移除节点 */
    requestAnimationFrame(function () { requestAnimationFrame(function () { b.classList.add('show'); }); });
    setTimeout(function () { b.classList.remove('show'); }, FADE_IN_MS + HOLD_MS);
    setTimeout(function () { if (b.parentNode) b.parentNode.removeChild(b); }, FADE_IN_MS + HOLD_MS + FADE_OUT_MS + 400);
  }

  function loop() {
    spawn();
    timer = setTimeout(loop, INTERVAL_MIN + Math.random() * (INTERVAL_MAX - INTERVAL_MIN));
  }
  function start() { if (!timer) loop(); }
  function stop() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (layer) layer.innerHTML = '';   /* 立即清掉在屏气泡 */
  }

  /* 散逸端数值变化入口：≥阈值开启轮播，<阈值停止并清屏 */
  function update(v) {
    var on = (parseInt(v, 10) || 0) >= THRESHOLD;
    if (on && !timer) start();
    else if (!on && timer) stop();
  }

  DA.feats.scatterTips = { update: update };

  /* 兜底：desktop.js loadScatter 的回调可能先于本文件加载执行（守卫跳过 update），初始化时补读最新值 */
  if (typeof window.__taScatter !== 'undefined') update(window.__taScatter);
})();
