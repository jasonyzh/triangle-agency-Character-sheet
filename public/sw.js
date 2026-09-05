/* 三角机构 PWA Service Worker
   策略：静态资源缓存优先（文件带 ?v= 版本号，改动即换 URL 自然更新）；
   页面导航网络优先、离线回退桌面壳；/api/ 与 /socket.io/ 永不缓存。
   发版时把 CACHE 版本号 +1，activate 会自动清掉旧缓存。 */
var CACHE = 'ta-pwa-v2';

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE)
      .then(function (c) { return c.addAll(['/desktop.html']); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys()
      .then(function (keys) { return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); })); })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url = new URL(req.url);
  if (url.origin !== location.origin) return;                      /* 跨域（COS 图床等）直接走网络 */
  if (url.pathname.indexOf('/api/') === 0) return;                 /* 接口永不缓存 */
  if (url.pathname.indexOf('/socket.io/') === 0) return;           /* Socket 轮询不缓存 */

  /* 页面导航：网络优先，离线回退桌面壳 */
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).catch(function () { return caches.match('/desktop.html'); }));
    return;
  }

  /* 静态资源：缓存优先，未命中时拉取并写入缓存 */
  e.respondWith(
    caches.match(req, { ignoreSearch: false }).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) {
        if (res.ok) {
          var clone = res.clone();
          caches.open(CACHE).then(function (c) { c.put(req, clone); });
        }
        return res;
      });
    })
  );
});
