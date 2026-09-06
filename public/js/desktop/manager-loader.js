/* 管理台模块加载器：仅经理(role>=1)/超级管理员(role>=2)加载 manager-main.js
   玩家不加载，避免 manager/state.js 的权限重定向影响桌面页 */
(function () {
  'use strict';
  var token = localStorage.getItem('ta_token');
  var role = parseInt(localStorage.getItem('ta_role') || '0', 10);
  if (!token || role < 1) return;
  import('./manager-main.js?v=4').catch(function (e) {
    console.error('[管理台] 模块加载失败:', e);
  });
  /* 同页登录成功后再按角色加载（未登录时上方已 return） */
  window.addEventListener('ta:login-ok', function () {
    var tk = localStorage.getItem('ta_token');
    var r2 = parseInt(localStorage.getItem('ta_role') || '0', 10);
    if (!tk || r2 < 1) return;
    import('./manager-main.js?v=4').catch(function (e) {
      console.error('[管理台] 模块加载失败:', e);
    });
  });
})();
