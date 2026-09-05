/* 系统设置面板（admin.html → desktop.html 迁移）
   仅超级管理员可用；复刻 admin.html 全部功能：
   人员管理（创建/过滤/搜索/重置密码/改角色/删除）、分部管理（创建/编辑/成员/删除）、系统设置（注册/SMTP/COS） */
import { S } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtml } from './ui.js';

var ROLE_NAMES = ['玩家', '经理', '超管'];
var ROLE_CLASSES = ['adm-role-0', 'adm-role-1', 'adm-role-2'];
var allUsersData = [];
var currentFilter = 'all';
var editingUserId = null;
var passwordEditingUserId = null;
var editingBranchId = null;
var branchAllUsers = [];
var currentTab = 'users';

/* ================= Tab 切换 ================= */
function switchAdminTab(tab) {
  currentTab = tab;
  Array.prototype.forEach.call(document.querySelectorAll('#winMAdmin .adm-nav-btn'), function (b) {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  Array.prototype.forEach.call(document.querySelectorAll('#winMAdmin .adm-pane'), function (p) {
    p.classList.toggle('active', p.dataset.pane === tab);
  });
  if (tab === 'config') loadConfig();
  if (tab === 'branches') loadBranches();
  if (tab === 'users') loadUsers();
}

/* ================= 人员管理 ================= */
function loadUsers() {
  return fetch('/api/users', { headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (list) {
      allUsersData = list || [];
      applyFilters();
    })
    .catch(function () { showToast('加载用户列表失败'); });
}

function roleOf(u) { return u.role !== undefined ? u.role : (u.isAdmin ? 2 : 0); }

function renderUserList(users) {
  var container = document.getElementById('admUserList');
  if (!container) return;
  if (!users.length) { container.innerHTML = '<div class="adm-empty">NO MATCHING RECORDS FOUND</div>'; return; }
  container.innerHTML = users.map(function (u) {
    var role = roleOf(u);
    var delBtn = role >= 2
      ? '<span class="adm-sys-tag">SYSTEM</span>'
      : '<button class="adm-btn adm-btn-danger" data-act="del" data-id="' + u.id + '" data-name="' + escapeHtml(u.name || '') + '">删除</button>';
    return '<div class="adm-user-card">'
      + '<div class="adm-u-info"><div class="adm-u-name">' + escapeHtml(u.name || '') + ' <span class="adm-role ' + ROLE_CLASSES[role] + '">' + (ROLE_NAMES[role] || '?') + '</span></div>'
      + '<div class="adm-u-meta">ID: ' + escapeHtml(u.username || '') + ' · 档案 ' + (u.charCount || 0) + (u.email ? ' · ' + escapeHtml(u.email) : '') + '</div></div>'
      + '<div class="adm-u-actions">'
      + '<button class="adm-btn" data-act="pwd" data-id="' + u.id + '" data-username="' + escapeHtml(u.username || '') + '">重置密码</button>'
      + '<button class="adm-btn" data-act="role" data-id="' + u.id + '" data-name="' + escapeHtml(u.name || '') + '" data-role="' + role + '">角色</button>'
      + delBtn
      + '</div></div>';
  }).join('');
}

function applyFilters() {
  var input = document.getElementById('admUserSearch');
  var term = input ? input.value.toLowerCase().trim() : '';
  var filtered = allUsersData;
  if (currentFilter !== 'all') filtered = filtered.filter(function (u) { return roleOf(u) === currentFilter; });
  if (term) filtered = filtered.filter(function (u) {
    return (u.name && u.name.toLowerCase().indexOf(term) >= 0) || (u.username && u.username.toLowerCase().indexOf(term) >= 0);
  });
  renderUserList(filtered);
}

function addUser() {
  var name = document.getElementById('admNewName').value;
  var user = document.getElementById('admNewUser').value;
  var pass = document.getElementById('admNewPass').value;
  var role = parseInt(document.getElementById('admNewRole').value, 10);
  if (!user || !pass) { showToast('账号和密码必填'); return; }
  fetch('/api/users', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ username: user, password: pass, name: name, role: role }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) {
        document.getElementById('admNewName').value = '';
        document.getElementById('admNewUser').value = '';
        document.getElementById('admNewPass').value = '';
        document.getElementById('admNewRole').value = '0';
        showToast('用户已创建', 'success');
        loadUsers();
      } else showToast(data.message || '创建失败');
    })
    .catch(function () { showToast('创建失败'); });
}

function delUser(id, name) {
  if (!confirm('警告：删除用户 [' + name + '] 将会同时销毁该用户下的所有角色档案！\n\n确定继续吗？')) return;
  fetch('/api/users/' + id, { method: 'DELETE', headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('用户已删除', 'success'); loadUsers(); }
      else showToast(data.message || '删除失败');
    });
}

function openRoleModal(userId, userName, currentRole) {
  editingUserId = userId;
  document.getElementById('admRoleUserName').textContent = userName;
  document.getElementById('admRoleSelect').value = currentRole;
  document.getElementById('admRoleModal').classList.add('show');
}
function closeRoleModal() { document.getElementById('admRoleModal').classList.remove('show'); editingUserId = null; }
function confirmRoleChange() {
  if (!editingUserId) return;
  var newRole = parseInt(document.getElementById('admRoleSelect').value, 10);
  fetch('/api/admin/users/' + editingUserId + '/role', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ role: newRole }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('角色已更新', 'success'); closeRoleModal(); loadUsers(); }
      else showToast(data.message || '更新失败');
    });
}

function changePass(id, username) {
  passwordEditingUserId = id;
  document.getElementById('admPwdUserName').textContent = username;
  document.getElementById('admNewPassword').value = '';
  document.getElementById('admConfirmPassword').value = '';
  document.getElementById('admPasswordModal').classList.add('show');
  document.getElementById('admNewPassword').focus();
}
function closePasswordModal() { document.getElementById('admPasswordModal').classList.remove('show'); passwordEditingUserId = null; }
function confirmPasswordChange() {
  if (!passwordEditingUserId) return;
  var newPass = document.getElementById('admNewPassword').value;
  if (!newPass || newPass.trim() === '') { showToast('请输入新密码'); return; }
  if (newPass !== document.getElementById('admConfirmPassword').value) { showToast('两次输入的密码不一致'); return; }
  fetch('/api/users/' + passwordEditingUserId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ password: newPass }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('密码已重置', 'success'); closePasswordModal(); loadUsers(); }
      else showToast(data.message || '重置失败');
    });
}

/* ================= 分部管理 ================= */
function loadBranches() {
  return fetch('/api/admin/branches', { headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data.success) return;
      var container = document.getElementById('admBranchList');
      if (!container) return;
      if (!data.branches.length) { container.innerHTML = '<div class="adm-empty">暂无分部</div>'; return; }
      container.innerHTML = data.branches.map(function (b) {
        return '<div class="adm-user-card">'
          + '<div class="adm-u-info"><div class="adm-u-name">' + escapeHtml(b.name) + '</div>'
          + '<div class="adm-u-meta">成员 ' + (b.user_count || 0) + ' · 角色 ' + (b.character_count || 0) + ' · 散逸端 ' + (b.total_scatter || 0) + (b.description ? ' · ' + escapeHtml(b.description) : '') + '</div></div>'
          + '<div class="adm-u-actions">'
          + '<button class="adm-btn" data-act="bman" data-id="' + b.id + '">管理</button>'
          + '<button class="adm-btn adm-btn-danger" data-act="bdel" data-id="' + b.id + '" data-name="' + escapeHtml(b.name) + '">删除</button>'
          + '</div></div>';
      }).join('');
    })
    .catch(function () { showToast('加载分部失败'); });
}

function addBranch() {
  var name = document.getElementById('admNewBranchName').value.trim();
  var desc = document.getElementById('admNewBranchDesc').value.trim();
  if (!name) { showToast('分部名称不能为空'); return; }
  fetch('/api/admin/branch', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ name: name, description: desc }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) {
        document.getElementById('admNewBranchName').value = '';
        document.getElementById('admNewBranchDesc').value = '';
        showToast('分部已创建', 'success');
        loadBranches();
      } else showToast(data.message || '创建失败');
    });
}

function delBranch(id, name) {
  if (!confirm('确定删除分部 [' + name + ']？此操作不可逆。')) return;
  fetch('/api/admin/branch/' + id, { method: 'DELETE', headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('分部已删除', 'success'); loadBranches(); }
      else showToast(data.message || '删除失败');
    });
}

function openBranchModal(id) {
  editingBranchId = id;
  fetch('/api/admin/branch/' + id, { headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data.success) { showToast('加载失败'); return; }
      document.getElementById('admBranchEditName').value = data.branch.name || '';
      document.getElementById('admBranchEditDesc').value = data.branch.description || '';
      renderBranchMembers(data.branch.users || []);
      return fetch('/api/users', { headers: getAuthHeaders() }).then(function (r) { return r.json(); }).then(function (all) {
        branchAllUsers = all || [];
        var memberIds = (data.branch.users || []).map(function (m) { return m.id; });
        var select = document.getElementById('admBranchAddUser');
        select.innerHTML = '<option value="">选择用户添加...</option>';
        branchAllUsers.forEach(function (u) {
          if (memberIds.indexOf(u.id) === -1) {
            var opt = document.createElement('option');
            opt.value = u.id;
            opt.textContent = (u.name || '') + ' (' + (u.username || '') + ')';
            select.appendChild(opt);
          }
        });
      });
    })
    .then(function () { document.getElementById('admBranchModal').classList.add('show'); })
    .catch(function () { showToast('加载失败'); });
}

function renderBranchMembers(members) {
  var memberList = document.getElementById('admBranchMemberList');
  memberList.innerHTML = members.length ? members.map(function (u) {
    var role = u.role !== undefined ? u.role : 0;
    return '<div class="adm-member-row"><span>' + escapeHtml(u.name || '') + ' <small>(' + escapeHtml(u.username || '') + ' · ' + (ROLE_NAMES[role] || '?') + ')</small></span>'
      + '<button class="adm-btn adm-btn-danger" data-act="rmember" data-id="' + u.id + '">移除</button></div>';
  }).join('') : '<div class="adm-empty" style="padding:14px 0;">暂无成员</div>';
}

function closeBranchModal() {
  document.getElementById('admBranchModal').classList.remove('show');
  editingBranchId = null;
}

function saveBranchEdit() {
  if (!editingBranchId) return;
  var name = document.getElementById('admBranchEditName').value.trim();
  var desc = document.getElementById('admBranchEditDesc').value.trim();
  if (!name) { showToast('名称不能为空'); return; }
  fetch('/api/admin/branch/' + editingBranchId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ name: name, description: desc }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('已保存', 'success'); closeBranchModal(); loadBranches(); }
      else showToast(data.message || '保存失败');
    });
}

function addUserToBranch() {
  if (!editingBranchId) return;
  var userId = document.getElementById('admBranchAddUser').value;
  if (!userId) { showToast('请选择用户'); return; }
  fetch('/api/admin/branch/' + editingBranchId + '/user', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ userId: userId }) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('已添加', 'success'); openBranchModal(editingBranchId); }
      else showToast(data.message || '添加失败');
    });
}

function removeUserFromBranch(userId) {
  if (!editingBranchId) return;
  fetch('/api/admin/branch/' + editingBranchId + '/user/' + userId, { method: 'DELETE', headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) { showToast('已移除', 'success'); openBranchModal(editingBranchId); }
      else showToast(data.message || '移除失败');
    });
}

/* ================= 系统设置 ================= */
function loadConfig() {
  fetch('/api/admin/config', { headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (config) {
      var set = function (id, v) { var el = document.getElementById(id); if (el) el.value = v; };
      var chk = function (id, v) { var el = document.getElementById(id); if (el) el.checked = v === true || v === 'true'; };
      chk('admCfg_reg_enabled', config.registration_enabled);
      chk('admCfg_email_enabled', config.email_registration_enabled);
      set('admCfg_smtp_host', config.smtp_host || '');
      set('admCfg_smtp_port', config.smtp_port || '587');
      set('admCfg_smtp_user', config.smtp_user || '');
      set('admCfg_smtp_pass', config.smtp_pass || '');
      set('admCfg_smtp_from', config.smtp_from || '');
      chk('admCfg_smtp_secure', config.smtp_secure);
      chk('admCfg_cos_enabled', config.cos_enabled);
      set('admCfg_cos_secret_id', config.cos_secret_id || '');
      set('admCfg_cos_secret_key', config.cos_secret_key || '');
      set('admCfg_cos_bucket', config.cos_bucket || '');
      set('admCfg_cos_region', config.cos_region || '');
      set('admCfg_cos_domain', config.cos_domain || '');
    })
    .catch(function () { showToast('加载配置失败'); });
}

function saveConfig() {
  var val = function (id) { var el = document.getElementById(id); return el ? el.value : ''; };
  var chk = function (id) { var el = document.getElementById(id); return el && el.checked ? 'true' : 'false'; };
  var config = {
    registration_enabled: chk('admCfg_reg_enabled'),
    email_registration_enabled: chk('admCfg_email_enabled'),
    smtp_host: val('admCfg_smtp_host'),
    smtp_port: val('admCfg_smtp_port'),
    smtp_user: val('admCfg_smtp_user'),
    smtp_pass: val('admCfg_smtp_pass'),
    smtp_from: val('admCfg_smtp_from'),
    smtp_secure: chk('admCfg_smtp_secure'),
    cos_enabled: chk('admCfg_cos_enabled'),
    cos_secret_id: val('admCfg_cos_secret_id'),
    cos_secret_key: val('admCfg_cos_secret_key'),
    cos_bucket: val('admCfg_cos_bucket'),
    cos_region: val('admCfg_cos_region'),
    cos_domain: val('admCfg_cos_domain')
  };
  fetch('/api/admin/config', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify(config) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) showToast('配置已保存', 'success');
      else showToast(data.message || '保存失败');
    })
    .catch(function () { showToast('保存失败'); });
}

function testSmtp() {
  showToast('正在测试 SMTP 连接…');
  fetch('/api/admin/test-smtp', { method: 'POST', headers: getAuthHeaders() })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.success) showToast('SMTP连接成功', 'success');
      else showToast(data.message || 'SMTP连接失败');
    })
    .catch(function () { showToast('测试失败'); });
}

/* ================= 事件委托绑定（一次绑定） ================= */
function bindEvents() {
  var win = document.getElementById('winMAdmin');
  if (!win || win.dataset.bound) return;
  win.dataset.bound = '1';

  /* 左侧导航 */
  Array.prototype.forEach.call(win.querySelectorAll('.adm-nav-btn'), function (b) {
    b.addEventListener('click', function () { switchAdminTab(b.dataset.tab); });
  });

  /* 人员 */
  document.getElementById('admAddUser').addEventListener('click', addUser);
  Array.prototype.forEach.call(win.querySelectorAll('.adm-filter-btn'), function (b) {
    b.addEventListener('click', function () {
      currentFilter = b.dataset.role === 'all' ? 'all' : parseInt(b.dataset.role, 10);
      Array.prototype.forEach.call(win.querySelectorAll('.adm-filter-btn'), function (x) { x.classList.remove('active'); });
      b.classList.add('active');
      applyFilters();
    });
  });
  document.getElementById('admUserSearch').addEventListener('input', applyFilters);
  document.getElementById('admUserList').addEventListener('click', function (e) {
    var btn = e.target.closest('[data-act]');
    if (!btn) return;
    var act = btn.dataset.act;
    if (act === 'pwd') changePass(btn.dataset.id, btn.dataset.username);
    else if (act === 'role') openRoleModal(btn.dataset.id, btn.dataset.name, parseInt(btn.dataset.role, 10));
    else if (act === 'del') delUser(btn.dataset.id, btn.dataset.name);
  });

  /* 分部 */
  document.getElementById('admAddBranch').addEventListener('click', addBranch);
  document.getElementById('admBranchList').addEventListener('click', function (e) {
    var btn = e.target.closest('[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'bman') openBranchModal(btn.dataset.id);
    else if (btn.dataset.act === 'bdel') delBranch(btn.dataset.id, btn.dataset.name);
  });
  document.getElementById('admBranchAddUser').addEventListener('click', function () {});
  document.getElementById('admAddBranchUser').addEventListener('click', addUserToBranch);
  document.getElementById('admBranchMemberList').addEventListener('click', function (e) {
    var btn = e.target.closest('[data-act="rmember"]');
    if (btn) removeUserFromBranch(btn.dataset.id);
  });

  /* 设置 */
  document.getElementById('admTestSmtp').addEventListener('click', testSmtp);
  Array.prototype.forEach.call(win.querySelectorAll('.admSaveCfg'), function (b) {
    b.addEventListener('click', saveConfig);
  });

  /* 弹窗 */
  document.getElementById('admRoleCancel').addEventListener('click', closeRoleModal);
  document.getElementById('admRoleConfirm').addEventListener('click', confirmRoleChange);
  document.getElementById('admPwdCancel').addEventListener('click', closePasswordModal);
  document.getElementById('admPwdConfirm').addEventListener('click', confirmPasswordChange);
  document.getElementById('admBranchCancel').addEventListener('click', closeBranchModal);
  document.getElementById('admBranchSave').addEventListener('click', saveBranchEdit);

  /* 弹窗点遮罩关闭 */
  ['admRoleModal', 'admPasswordModal', 'admBranchModal'].forEach(function (id) {
    var m = document.getElementById(id);
    m.addEventListener('click', function (e) { if (e.target === m) m.classList.remove('show'); });
  });
}

/* ================= 打开入口（desktop.js startApp 调用） ================= */
function loadAdmin() {
  bindEvents();
  loadUsers();
}

export {
  switchAdminTab, loadAdmin, loadUsers, loadBranches, loadConfig,
  closeRoleModal, closePasswordModal, closeBranchModal
};
