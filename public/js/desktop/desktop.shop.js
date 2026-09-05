/* 职员内购：可购买/已购买申领物 */
(function () {
  'use strict';
  var $ = DA.$, esc = DA.esc, showToast = DA.showToast, authH = DA.authH, cid = DA.cid, cardData = DA.cardData, ICO = DA.ICO;

  /* ========== 职员内购 ========== */
  function ShopApp() {
    var self = this;
    this.tab = 'avail';
    this.avail = [];
    this.owned = [];
    this.open = function () {
      this.tab = 'avail';
      Array.prototype.forEach.call(document.querySelectorAll('.shop-tab'), function (b) {
        b.classList.toggle('active', b.dataset.stab === 'avail');
        b.onclick = function () {
          self.tab = b.dataset.stab;
          Array.prototype.forEach.call(document.querySelectorAll('.shop-tab'), function (x) { x.classList.toggle('active', x === b); });
          self.render();
        };
      });
      this.load();
    };
    this.load = function () {
      var self = this;
      $('shopGrid').innerHTML = '<div class="pane-empty">加载中…</div>';
      Promise.all([
        fetch('/api/character/' + cid() + '/requisitions', { headers: authH() }).then(function (r) { return r.json(); }),
        fetch('/api/character/' + cid() + '/purchased-requisitions', { headers: authH() }).then(function (r) { return r.json(); })
      ]).then(function (rs) {
        self.avail = (rs[0] && rs[0].items) || [];
        self.owned = Array.isArray(rs[1]) ? rs[1] : ((rs[1] && rs[1].purchases) || []);
        self.render();
      }).catch(function () { $('shopGrid').innerHTML = '<div class="pane-empty">加载失败</div>'; });
    };
    this.render = function () {
      var grid = $('shopGrid');
      var self = this;
      /* 嘉奖余额（角色卡 rewards 求和） */
      var c = cardData();
      var bonus = 0;
      if (c && c.rewards) bonus = c.rewards.reduce(function (s, r) { return s + (r.count || 0); }, 0);
      $('shopBonus').textContent = '嘉奖 × ' + bonus;
      if (this.tab === 'avail') {
        if (!this.avail.length) { grid.innerHTML = '<div class="pane-empty">暂无可购买申领物</div>'; return; }
        grid.innerHTML = this.avail.map(function (it, i) {
          var typeTag = '<span class="s-tag">' + (it.type === 'permission' ? '权限' : '基础') + '</span>';
          var head = '<div class="s-name">' + esc(it.name) + typeTag + '</div>'
            + (it.pd ? '<div class="s-pd">PD ' + esc(it.pd) + '</div>' : '')
            + '<div class="s-eff">' + (it.effect || '') + '</div>';
          var prices = (it.prices && it.prices.length)
            ? it.prices.map(function (po, idx) {
                var afford = bonus >= (po.price || 0);
                return '<div class="s-price-row">'
                  + '<span class="s-price-desc">' + esc(po.description || '标准') + '</span>'
                  + '<span class="s-price-val">嘉奖 × ' + esc(po.price || 0) + '</span>'
                  + '<button class="s-buy s-buy-sm" data-buy="' + i + '" data-idx="' + idx + '"' + (afford ? '' : ' disabled title="嘉奖不足"') + '>购买</button>'
                  + '</div>';
              }).join('')
            : '<div class="s-price-row"><span class="s-price-val">嘉奖 × ' + esc(it.price || 0) + '</span>'
              + '<button class="s-buy s-buy-sm" data-buy="' + i + '" data-idx=""' + (bonus < (it.price || 0) ? ' disabled title="嘉奖不足"' : '') + '>购买</button></div>';
          return '<div class="shop-card">' + head + prices + '</div>';
        }).join('');
        Array.prototype.forEach.call(grid.querySelectorAll('[data-buy]'), function (b) {
          b.addEventListener('click', function () {
            var it = self.avail[+b.dataset.buy];
            var idx = b.dataset.idx === '' ? null : parseInt(b.dataset.idx, 10);
            self.buy(it, idx);
          });
        });
      } else {
        if (!this.owned.length) { grid.innerHTML = '<div class="pane-empty">还没有购买记录</div>'; return; }
        grid.innerHTML = this.owned.map(function (p) {
          var d = p.purchased_at ? new Date(p.purchased_at).toLocaleString('zh-CN') : '';
          return '<div class="shop-card">'
            + '<div class="s-name">' + esc(p.name || '申领物') + (p.type === 'permission' ? '<span class="s-tag">权限</span>' : '') + '</div>'
            + (p.pd ? '<div class="s-pd">PD ' + esc(p.pd) + '</div>' : '')
            + '<div class="s-eff">' + (p.effect || '') + '</div>'
            + '<div class="s-owned-foot"><span class="shop-owned-tag">' + ICO.check + ' 已购买</span>'
            + '<span class="s-owned-info">' + (d ? d : '') + ' · 消耗嘉奖 × ' + esc(p.price || 0) + '</span></div>'
            + '</div>';
        }).join('');
      }
    };
    this.buy = function (item, priceIndex) {
      if (!item) return;
      var price = priceIndex != null && item.prices && item.prices[priceIndex] ? item.prices[priceIndex].price : (item.price || 0);
      if (!confirm('确定花费 ' + price + ' 个嘉奖购买该申领物「' + item.name + '」吗？')) return;
      var self = this;
      fetch('/api/character/' + cid() + '/purchase-requisition', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify({ requisitionId: item.id, priceIndex: priceIndex })
      }).then(function (r) { return r.json(); }).then(function (d) {
        showToast(d.message || (d.success ? '购买成功' : '购买失败'));
        if (d.success) {
          self.load();
          window.DESKTOP.refreshChar();  /* 同步嘉奖余额与申领物浮窗 */
        }
      }).catch(function () { showToast('购买失败，请重试'); });
    };
  }

  var shopCtl = null;
  DA.feats.shop = { start: function () { shopCtl = new ShopApp(); shopCtl.open(); } };

  /* ========== 虹吸商店（items.html Siphon商店，X2解锁可入） ========== */
  function SiphonShopApp() {
    var self = this;
    this.products = [];
    this.owned = [];
    this.cat = 'avail';
    this.open = function () {
      this.load();
      Array.prototype.forEach.call($('winSiphonShop').querySelectorAll('[data-sscat]'), function (b) {
        b.addEventListener('click', function () {
          self.cat = b.dataset.sscat;
          Array.prototype.forEach.call($('winSiphonShop').querySelectorAll('[data-sscat]'), function (x) { x.classList.toggle('active', x === b); });
          self.render();
        });
      });
    };
    this.load = function () {
      var cidv = cid();
      if (!cidv) { $('ssGrid').innerHTML = '<div class="pane-empty">未选择角色</div>'; return; }
      $('ssGrid').innerHTML = '<div class="pane-empty">加载中…</div>';
      Promise.all([
        fetch('/api/character/' + cidv + '/siphon-products', { headers: authH() }).then(function (r) { return r.ok ? r.json() : {}; }),
        fetch('/api/character/' + cidv + '/siphon-purchased', { headers: authH() }).then(function (r) { return r.ok ? r.json() : {}; })
      ]).then(function (rs) {
        self.products = (rs[0] && rs[0].products) || [];
        self.owned = (rs[1] && rs[1].purchases) || [];
        self.render();
      }).catch(function () { $('ssGrid').innerHTML = '<div class="pane-empty">加载失败</div>'; });
    };
    this.render = function () {
      var grid = $('ssGrid');
      var bonus = curReprimands();
      var b = $('ssBonus');
      if (b) b.textContent = '申诫余额 · ' + bonus;
      if (this.cat === 'owned') {
        if (!this.owned.length) { grid.innerHTML = '<div class="pane-empty">还没有购买记录</div>'; return; }
        grid.innerHTML = this.owned.map(function (p) {
          var d = p.purchased_at ? new Date(p.purchased_at).toLocaleString('zh-CN') : '';
          return '<div class="shop-card"><div class="s-name">' + esc(p.name) + '</div>'
            + '<div class="s-eff">' + (p.description || '') + '</div>'
            + '<div class="s-owned-foot"><span class="shop-owned-tag">' + ICO.check + ' 已购买</span>'
            + '<span class="s-owned-info">' + d + ' · 消耗申诫 × ' + esc(p.price || 0) + '</span></div></div>';
        }).join('');
        return;
      }
      if (!this.products.length) { grid.innerHTML = '<div class="pane-empty">暂无Siphon商品</div>'; return; }
      grid.innerHTML = this.products.map(function (p, i) {
        var afford = bonus >= (p.price || 0);
        return '<div class="shop-card"><div class="s-name">' + esc(p.name) + '<span class="s-tag">Siphon</span></div>'
          + '<div class="s-eff">' + (p.description || '') + '</div>'
          + '<div class="s-price-row"><span class="s-price-desc">申诫</span>'
          + '<span class="s-price-val">申诫 × ' + esc(p.price || 0) + '</span>'
          + '<button class="s-buy s-buy-sm" data-buy="' + i + '"' + (afford ? '' : ' disabled title="申诫不足"') + '>购买</button></div></div>';
      }).join('');
      Array.prototype.forEach.call(grid.querySelectorAll('[data-buy]'), function (b) {
        b.addEventListener('click', function () { self.buy(self.products[+b.dataset.buy]); });
      });
    };
    this.buy = function (p) {
      if (!p) return;
      if (!confirm('确定花费 ' + p.price + ' 点申诫购买「' + p.name + '」吗？')) return;
      fetch('/api/character/' + cid() + '/siphon-purchase', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + window.DESKTOP.getToken() },
        body: JSON.stringify({ productId: p.id })
      }).then(function (r) { return r.json(); }).then(function (d) {
        showToast(d.message || (d.success ? '购买成功' : '购买失败'));
        if (d.success) { self.load(); window.DESKTOP.refreshChar(); }
      }).catch(function () { showToast('购买失败，请重试'); });
    };
  }
  function curReprimands() {
    var c = cardData();
    var arr = (c && c.reprimands) || [];
    return arr.reduce(function (s, r) { return s + (r.count || 1); }, 0);
  }

  var siphonShopCtl = null;
  DA.feats['siphon-shop'] = { start: function () { siphonShopCtl = new SiphonShopApp(); siphonShopCtl.open(); } };
})();
