/* 共享底座：桌面功能文件的 $/esc/showToast/authH/cid/cardData/ICO 与功能注册表
   （从 desktop.js 原 IIFE2 头部拆出，window.DESKTOP 桥见 desktop.js） */
window.DA = (function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  function esc(s) { return s == null ? '' : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function authH() { return window.DESKTOP.authHeaders(); }
  function cid() { return window.DESKTOP.getActiveCharId(); }
  function cardData() { return window.DESKTOP.getCardData(); }

  var ICO = {
    box: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 L20 7 v10 l-8 4 -8 -4 V7 Z"/><path d="M4 7 l8 4 8 -4 M12 11 v10"/></svg>',
    file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3 h8 l4 4 v14 H6 Z"/><path d="M14 3 v4 h4"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11 V8 a4 4 0 0 1 8 0 v3"/></svg>',
    plane: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 3 L3 10.5 l7 2.5 2.5 7 Z"/><path d="M10 13 L21 3"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12.5 L10 18 L20 6"/></svg>'
  };
  var toast = $('deskToast');
  var toastT;
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastT);
    toastT = setTimeout(function () { toast.classList.remove('show'); }, 2200);
  }

  /* 头像地址缓存穿透：上传会覆盖同一 URL（pcimg/{id}.jpg），展示时按版本戳追加 t 参数强制刷新 */
  function avaSrc(url) {
    if (!url) return url;
    var t = null;
    try { t = (JSON.parse(localStorage.getItem('ta_ava_ver') || '{}'))[url]; } catch (e) {}
    return t ? url + (url.indexOf('?') >= 0 ? '&' : '?') + 't=' + t : url;
  }
  function bumpAvaVer(url) {
    if (!url) return;
    var m = {};
    try { m = JSON.parse(localStorage.getItem('ta_ava_ver') || '{}'); } catch (e) {}
    m[url] = Date.now();
    try { localStorage.setItem('ta_ava_ver', JSON.stringify(m)); } catch (e) {}
  }

  /* 功能注册表：各应用模块（desktop.*.js）自行挂载 DA.feats.<key> = {start, close} */
  var feats = {};
  return { $: $, esc: esc, showToast: showToast, authH: authH, cid: cid, cardData: cardData, ICO: ICO, avaSrc: avaSrc, bumpAvaVer: bumpAvaVer, feats: feats };
})();
