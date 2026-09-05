/* 桌面天气卡：按任务分页的滑块（左右拖动/触摸翻页，底部圆点指示当前页） */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, authH = DA.authH, cid = DA.cid;

  var tianqiCache = null;
  var weatherByMission = {};   /* missionId → 已选天气卡数组 */
  var weatherNames = {};       /* missionId → 任务名 */
  var wsIndex = 0;             /* 当前页 */

  function loadTianqi(cb) {
    if (tianqiCache) return cb(tianqiCache);
    fetch('/api/options').then(function (r) { return r.ok ? r.json() : { tianqi: [] }; }).then(function (d) {
      tianqiCache = (d && d.tianqi) || [];
      cb(tianqiCache);
    }).catch(function () { cb([]); });
  }

  function refreshWeather() {
    loadTianqi(function (tq) {
      fetch('/api/character/' + cid() + '/available-missions', { headers: authH() })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (missions) {
          var ids = (missions || []).map(function (m) { return m.id; });
          return Promise.all(ids.map(function (id) {
            var m = (missions || []).find(function (x) { return x.id === id; }) || {};
            return fetch('/api/board/' + id, { headers: authH() })
              .then(function (r) { return r.ok ? r.json() : null; })
              .then(function (d) { return { missionId: id, name: m.name || '任务', cards: parseWeatherIds(d && d.weather) }; });
          }));
        })
        .then(function (list) {
          weatherByMission = {};
          weatherNames = {};
          (list || []).forEach(function (m) {
            var cards = m.cards.map(function (id) {
              var opt = tq.find(function (c) { return c.id === id; });
              return opt || { id: id, title: id, text: '' };
            }).filter(Boolean);
            if (cards.length) { weatherByMission[m.missionId] = cards; weatherNames[m.missionId] = m.name; }
          });
          if (wsIndex >= Object.keys(weatherByMission).length) wsIndex = 0;
          renderWeather();
        }).catch(function () {});
    });
  }
  function parseWeatherIds(jsonStr) {
    try { var a = JSON.parse(jsonStr || ''); return Array.isArray(a) ? a : []; } catch (e) { return []; }
  }

  /* ========== 滑块渲染 ========== */
  var SUN_SVG = '<svg class="weather-sun" viewBox="0 0 64 64"><circle cx="32" cy="32" r="13" fill="#f5b942"/><g stroke="#f5b942" stroke-width="3.5" stroke-linecap="round"><line x1="32" y1="6" x2="32" y2="13"/><line x1="32" y1="51" x2="32" y2="58"/><line x1="6" y1="32" x2="13" y2="32"/><line x1="51" y1="32" x2="58" y2="32"/><line x1="13.5" y1="13.5" x2="18.5" y2="18.5"/><line x1="45.5" y1="45.5" x2="50.5" y2="50.5"/><line x1="13.5" y1="50.5" x2="18.5" y2="45.5"/><line x1="45.5" y1="18.5" x2="50.5" y2="13.5"/></g></svg>';

  function renderWeather() {
    var strip = $('weatherStrip');
    if (!strip) return;
    var pages = Object.keys(weatherByMission).map(function (mid) {
      return { id: mid, name: weatherNames[mid] || '任务', cards: weatherByMission[mid] || [] };
    }).filter(function (p) { return p.cards.length; });

    if (!pages.length) {
      strip.innerHTML = '<div class="weather-empty">' + SUN_SVG + '<div class="weather-empty-txt">万里无云</div></div>';
      return;
    }
    if (wsIndex >= pages.length) wsIndex = 0;

    /* 天气卡标题行：右侧显示当前页任务名 */
    var head = strip.closest('.wcard') ? strip.closest('.wcard').querySelector('.wcard-head') : null;
    if (head) {
      var old = head.querySelector('.ws-warning');
      if (old) old.remove();
      var wname = document.createElement('span');
      wname.className = 'ws-warning';
      wname.textContent = pages[wsIndex] ? pages[wsIndex].name : '';
      head.appendChild(wname);
    }

    strip.innerHTML =
      '<div class="ws-viewport"><div class="ws-track">'
      + pages.map(function (p, i) {
          return '<div class="ws-page' + (i === wsIndex ? ' on' : '') + '" data-p="' + i + '">'
            + p.cards.map(function (c) {
                return '<div class="wrow" data-wid="' + esc(c.id) + '"><span>' + esc(c.title) + '</span></div>';
              }).join('')
            + '</div>';
        }).join('')
      + '</div></div>'
      + (pages.length > 1
        ? '<div class="ws-dots">' + pages.map(function (_, i) {
            return '<i data-p="' + i + '"' + (i === wsIndex ? ' class="on"' : '') + '></i>';
          }).join('') + '</div>'
        : '');

    /* 每行天气 hover 详情 */
    Array.prototype.forEach.call(strip.querySelectorAll('.wrow'), function (row) {
      var pageEl = row.closest('.ws-page');
      var page = pages[parseInt(pageEl.dataset.p, 10)] || { cards: [] };
      var card = page.cards.find(function (x) { return x.id === row.dataset.wid; });
      if (!card) return;
      row.addEventListener('mouseenter', function () { showWeatherTip(card, row); });
      row.addEventListener('mouseleave', hideWeatherTip);
    });

    /* 圆点点击跳页 */
    Array.prototype.forEach.call(strip.querySelectorAll('.ws-dots i'), function (d) {
      d.addEventListener('click', function () { goPage(parseInt(d.dataset.p, 10)); });
    });

    bindSwipe();
    applyPage();
  }

  function applyPage() {
    var strip = $('weatherStrip');
    if (!strip) return;
    var track = strip.querySelector('.ws-track');
    if (!track) return;
    track.style.transform = 'translateX(' + (-wsIndex * 100) + '%)';
    Array.prototype.forEach.call(track.children, function (p, idx) {
      p.classList.toggle('on', idx === wsIndex);
    });
    Array.prototype.forEach.call(strip.querySelectorAll('.ws-dots i'), function (d, idx) {
      d.classList.toggle('on', idx === wsIndex);
    });
    /* 标题行任务名随页同步 */
    var head = strip.closest('.wcard') ? strip.closest('.wcard').querySelector('.wcard-head') : null;
    if (head) {
      var wn = head.querySelector('.ws-warning');
      var pages = Object.keys(weatherByMission).filter(function (k) { return (weatherByMission[k] || []).length; });
      if (wn) wn.textContent = pages[wsIndex] ? (weatherNames[pages[wsIndex]] || '任务') : '';
    }
  }

  function goPage(i) {
    var strip = $('weatherStrip');
    var track = strip && strip.querySelector('.ws-track');
    if (!track) return;
    var max = track.children.length - 1;
    wsIndex = Math.max(0, Math.min(i, max));
    if (track.style.transition === 'none') track.style.transition = '';
    applyPage();
  }

  /* 左右拖动 / 触摸滑动翻页（跟手 + 松手吸附） */
  function bindSwipe() {
    var strip = $('weatherStrip');
    var vp = strip.querySelector('.ws-viewport');
    if (!vp || vp.dataset.swiped) return;
    vp.dataset.swiped = '1';

    var startX = 0, dx = 0, dragging = false;
    function startDrag(x) { startX = x; dx = 0; dragging = true; vp.classList.add('dragging'); }
    function moveDrag(x) {
      if (!dragging) return;
      dx = x - startX;
      var track = strip.querySelector('.ws-track');
      if (track) track.style.transform = 'translateX(calc(' + (-wsIndex * 100) + '% + ' + dx + 'px))';
    }
    function endDrag() {
      if (!dragging) return;
      dragging = false;
      vp.classList.remove('dragging');
      if (dx <= -40) goPage(wsIndex + 1);
      else if (dx >= 40) goPage(wsIndex - 1);
      else goPage(wsIndex);
      dx = 0;
    }

    vp.addEventListener('mousedown', function (e) { startDrag(e.clientX); });
    window.addEventListener('mousemove', function (e) { moveDrag(e.clientX); });
    window.addEventListener('mouseup', endDrag);

    vp.addEventListener('touchstart', function (e) { startDrag(e.touches[0].clientX); }, { passive: true });
    vp.addEventListener('touchmove', function (e) { moveDrag(e.touches[0].clientX); }, { passive: true });
    vp.addEventListener('touchend', endDrag);
  }

  /* ========== hover 天气链详情 ========== */
  var weatherTip = null;
  function ensureWeatherTip() { if (!weatherTip) { weatherTip = document.createElement('div'); weatherTip.className = 'weather-tip'; document.body.appendChild(weatherTip); } return weatherTip; }
  function expandWeatherCards(cards) {
    var list = tianqiCache || [];
    var result = [];
    (cards || []).forEach(function (card) {
      var siblings = list.filter(function (c) { return c.group === card.group; })
        .sort(function (a, b) { return a.id.localeCompare(b.id); });
      var myIdx = siblings.findIndex(function (c) { return c.id === card.id; });
      siblings.slice(0, myIdx + 1).forEach(function (c) {
        if (!result.find(function (r) { return r.id === c.id; })) result.push(c);
      });
    });
    result.sort(function (a, b) {
      if (a.group !== b.group) return a.group - b.group;
      return a.id.localeCompare(b.id);
    });
    return result;
  }
  function showWeatherTip(card, chip) {
    var wt = ensureWeatherTip();
    var chain = expandWeatherCards([card]);
    wt.innerHTML = chain.map(function (c) {
      return '<div class="wt-item"><b>' + esc(c.title || '') + '</b>' + esc(c.text || '') + '</div>';
    }).join('');
    wt.style.display = 'block';
    var r = chip.getBoundingClientRect();
    var top = r.top - 10 - wt.offsetHeight;
    if (top < 8) top = r.bottom + 10;
    wt.style.left = Math.max(8, Math.min(r.left, window.innerWidth - wt.offsetWidth - 8)) + 'px';
    wt.style.top = top + 'px';
  }
  function hideWeatherTip() { if (weatherTip) weatherTip.style.display = 'none'; }
  if (cid()) refreshWeather();

  /* 供外勤OS socket weather:update 刷新调用 */
  DA.weather = { weatherByMission: weatherByMission, renderWeather: renderWeather, refresh: refreshWeather };
  /* 同页登录成功后重拉角色任务天气 */
  window.addEventListener('ta:login-ok', function () { if (cid()) refreshWeather(); });
})();
