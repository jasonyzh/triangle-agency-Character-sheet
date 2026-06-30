var token = localStorage.getItem('ta_token');
var isAdmin = localStorage.getItem('ta_is_admin');
if (isAdmin !== 'true' || !token) { window.location.href = 'login.html'; }

var ROLE_NAMES = ['玩家', '经理', '超管'];
var ROLE_CLASSES = ['role-player', 'role-manager', 'role-admin'];
var allUsersData = [];
var currentFilter = 'all';
var editingUserId = null;

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
    document.querySelector('[onclick="switchTab(\'' + tab + '\')"]').classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
    if (tab === 'config') loadConfig();
    if (tab === 'branches') loadBranches();
}

async function loadConfig() {
    try {
        var res = await fetch('/api/admin/config', { headers: getAuthHeaders() });
        var config = await res.json();
        document.getElementById('cfg_reg_enabled').checked = config.registration_enabled === 'true';
        document.getElementById('cfg_email_enabled').checked = config.email_registration_enabled === 'true';
        document.getElementById('cfg_smtp_host').value = config.smtp_host || '';
        document.getElementById('cfg_smtp_port').value = config.smtp_port || '587';
        document.getElementById('cfg_smtp_user').value = config.smtp_user || '';
        document.getElementById('cfg_smtp_pass').value = config.smtp_pass || '';
        document.getElementById('cfg_smtp_from').value = config.smtp_from || '';
        document.getElementById('cfg_smtp_secure').checked = config.smtp_secure === 'true';
        document.getElementById('cfg_cos_enabled').checked = config.cos_enabled === 'true';
        document.getElementById('cfg_cos_secret_id').value = config.cos_secret_id || '';
        document.getElementById('cfg_cos_secret_key').value = config.cos_secret_key || '';
        document.getElementById('cfg_cos_bucket').value = config.cos_bucket || '';
        document.getElementById('cfg_cos_region').value = config.cos_region || '';
        document.getElementById('cfg_cos_domain').value = config.cos_domain || '';
    } catch (e) { showToast('加载配置失败'); }
}

async function saveConfig() {
    try {
        var config = {
            registration_enabled: document.getElementById('cfg_reg_enabled').checked ? 'true' : 'false',
            email_registration_enabled: document.getElementById('cfg_email_enabled').checked ? 'true' : 'false',
            smtp_host: document.getElementById('cfg_smtp_host').value,
            smtp_port: document.getElementById('cfg_smtp_port').value,
            smtp_user: document.getElementById('cfg_smtp_user').value,
            smtp_pass: document.getElementById('cfg_smtp_pass').value,
            smtp_from: document.getElementById('cfg_smtp_from').value,
            smtp_secure: document.getElementById('cfg_smtp_secure').checked ? 'true' : 'false',
            cos_enabled: document.getElementById('cfg_cos_enabled').checked ? 'true' : 'false',
            cos_secret_id: document.getElementById('cfg_cos_secret_id').value,
            cos_secret_key: document.getElementById('cfg_cos_secret_key').value,
            cos_bucket: document.getElementById('cfg_cos_bucket').value,
            cos_region: document.getElementById('cfg_cos_region').value,
            cos_domain: document.getElementById('cfg_cos_domain').value
        };
        var res = await fetch('/api/admin/config', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify(config) });
        var data = await res.json();
        if (data.success) showToast('配置已保存', 'success');
        else showToast(data.message || '保存失败');
    } catch (e) { showToast('保存失败'); }
}

async function testSmtp() {
    try {
        var res = await fetch('/api/admin/test-smtp', { method: 'POST', headers: getAuthHeaders() });
        var data = await res.json();
        if (data.success) showToast('SMTP连接成功', 'success');
        else showToast(data.message || 'SMTP连接失败');
    } catch (e) { showToast('测试失败'); }
}

async function loadUsers() {
    try {
        var res = await fetch('/api/users', { headers: getAuthHeaders() });
        allUsersData = await res.json();
        renderList(allUsersData);
    } catch (e) { console.error(e); showToast('加载用户列表失败'); }
}

function renderList(users) {
    var container = document.getElementById('list');
    container.innerHTML = '';
    if (users.length === 0) { container.innerHTML = '<div class="no-result">NO MATCHING RECORDS FOUND</div>'; return; }
    users.forEach(function(u) {
        var el = document.createElement('div');
        el.className = 'user-card';
        var role = u.role !== undefined ? u.role : (u.isAdmin ? 2 : 0);
        var roleTag = '<span class="role-tag ' + ROLE_CLASSES[role] + '">' + ROLE_NAMES[role] + '</span>';
        var delBtn = role >= 2
            ? '<span style="font-size:10px;color:#aaa;padding:0 10px;">SYSTEM</span>'
            : '<button class="btn-base btn-del" onclick="delUser(' + u.id + ', \'' + u.name + '\')">删除</button>';
        el.innerHTML = '<div class="u-info"><span class="u-name">' + u.name + ' ' + roleTag + '</span><div class="u-meta">ID: ' + u.username + ' | DOCS: ' + (u.charCount || 0) + (u.email ? ' | EMAIL: ' + u.email : '') + '</div></div><div class="action-btns"><button class="btn-base btn-edit" onclick="changePass(' + u.id + ', \'' + u.username + '\')"><i class="fas fa-key"></i> 重置密码</button><button class="btn-base btn-role" onclick="openRoleModal(' + u.id + ', \'' + u.name + '\', ' + role + ')">角色</button>' + delBtn + '</div>';
        container.appendChild(el);
    });
}

var touchStartX = 0, touchStartY = 0;
var swipeThreshold = 80, edgeThreshold = 60;
document.addEventListener('touchstart', function(e) { touchStartX = e.changedTouches[0].screenX; touchStartY = e.changedTouches[0].screenY; }, {passive: true});
document.addEventListener('touchend', function(e) { handleSwipe(touchStartX, touchStartY, e.changedTouches[0].screenX, e.changedTouches[0].screenY); }, {passive: true});
function handleSwipe(startX, startY, endX, endY) {
    var xDiff = endX - startX, yDiff = endY - startY;
    var menu = document.getElementById('sideMenu');
    var isOpen = menu.classList.contains('show');
    var screenWidth = window.innerWidth;
    if (Math.abs(yDiff) > Math.abs(xDiff)) return;
    if (!isOpen && xDiff < -swipeThreshold && startX > (screenWidth - edgeThreshold)) toggleSideMenu();
    if (isOpen && xDiff > swipeThreshold) closeSideMenu();
}

function filterByRole(role, btn) {
    currentFilter = role;
    document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    applyFilters();
}

document.getElementById('searchInput').addEventListener('input', applyFilters);

function applyFilters() {
    var term = document.getElementById('searchInput').value.toLowerCase().trim();
    var filtered = allUsersData;
    if (currentFilter !== 'all') { filtered = filtered.filter(function(u) { var role = u.role !== undefined ? u.role : (u.isAdmin ? 2 : 0); return role === currentFilter; }); }
    if (term) { filtered = filtered.filter(function(u) { return (u.name && u.name.toLowerCase().includes(term)) || (u.username && u.username.toLowerCase().includes(term)); }); }
    renderList(filtered);
}

var passwordEditingUserId = null;
function changePass(id, username) {
    passwordEditingUserId = id;
    document.getElementById('pwdModalUserName').textContent = username;
    document.getElementById('newPasswordInput').value = '';
    document.getElementById('confirmPasswordInput').value = '';
    document.getElementById('passwordModal').classList.add('show');
    document.getElementById('newPasswordInput').focus();
}
function closePasswordModal() { document.getElementById('passwordModal').classList.remove('show'); passwordEditingUserId = null; }
async function confirmPasswordChange() {
    if (!passwordEditingUserId) return;
    var newPass = document.getElementById('newPasswordInput').value;
    var confirmPass = document.getElementById('confirmPasswordInput').value;
    if (!newPass || newPass.trim() === '') { showToast('请输入新密码'); return; }
    if (newPass !== confirmPass) { showToast('两次输入的密码不一致'); return; }
    var res = await fetch('/api/users/' + passwordEditingUserId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ password: newPass }) });
    var data = await res.json();
    if (data.success) { showToast('密码已重置', 'success'); closePasswordModal(); loadUsers(); }
    else showToast(data.message || '重置失败');
}

async function addUser() {
    var name = document.getElementById('newName').value;
    var user = document.getElementById('newUser').value;
    var pass = document.getElementById('newPass').value;
    var role = parseInt(document.getElementById('newRole').value);
    if (!user || !pass) return showToast('账号和密码必填');
    var res = await fetch('/api/users', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ username: user, password: pass, name: name, role: role }) });
    var data = await res.json();
    if (data.success) {
        document.getElementById('newName').value = '';
        document.getElementById('newUser').value = '';
        document.getElementById('newPass').value = '';
        document.getElementById('newRole').value = '0';
        showToast('用户已创建', 'success');
        loadUsers();
    } else showToast(data.message || '创建失败');
}

var editingBranchId = null;
var branchAllUsers = [];

async function loadBranches() {
    try {
        var res = await fetch('/api/admin/branches', { headers: getAuthHeaders() });
        var data = await res.json();
        if (!data.success) return;
        var container = document.getElementById('branchList');
        container.innerHTML = '';
        if (data.branches.length === 0) {
            container.innerHTML = '<div class="no-result">暂无分部</div>';
            return;
        }
        data.branches.forEach(function(b) {
            var el = document.createElement('div');
            el.className = 'user-card';
            el.innerHTML =
                '<div class="u-info">' +
                    '<span class="u-name">' + b.name + '</span>' +
                    '<div class="u-meta">成员: ' + b.user_count + ' | 角色: ' + b.character_count + ' | 散射: ' + (b.total_scatter || 0) + (b.description ? ' | ' + b.description : '') + '</div>' +
                '</div>' +
                '<div class="action-btns">' +
                    '<button class="btn-base btn-edit" onclick="openBranchModal(\'' + b.id + '\')"><i class="fas fa-building"></i> 管理</button>' +
                    '<button class="btn-base btn-del" onclick="delBranch(\'' + b.id + '\', \'' + b.name + '\')">删除</button>' +
                '</div>';
            container.appendChild(el);
        });
    } catch(e) { console.error(e); showToast('加载分部失败'); }
}

async function addBranch() {
    var name = document.getElementById('newBranchName').value.trim();
    var desc = document.getElementById('newBranchDesc').value.trim();
    if (!name) return showToast('分部名称不能为空');
    var res = await fetch('/api/admin/branch', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ name: name, description: desc })
    });
    var data = await res.json();
    if (data.success) {
        document.getElementById('newBranchName').value = '';
        document.getElementById('newBranchDesc').value = '';
        showToast('分部已创建', 'success');
        loadBranches();
    } else showToast(data.message || '创建失败');
}

async function delBranch(id, name) {
    if (!confirm('确定删除分部 [' + name + ']？此操作不可逆。')) return;
    var res = await fetch('/api/admin/branch/' + id, { method: 'DELETE', headers: getAuthHeaders() });
    var data = await res.json();
    if (data.success) { showToast('分部已删除', 'success'); loadBranches(); }
    else showToast(data.message || '删除失败');
}

async function openBranchModal(id) {
    editingBranchId = id;
    var res = await fetch('/api/admin/branch/' + id, { headers: getAuthHeaders() });
    var data = await res.json();
    if (!data.success) return showToast('加载失败');
    document.getElementById('branchEditName').value = data.branch.name || '';
    document.getElementById('branchEditDesc').value = data.branch.description || '';

    var members = data.branch.users || [];
    var memberList = document.getElementById('branchMemberList');
    memberList.innerHTML = '';
    members.forEach(function(u) {
        var role = u.role !== undefined ? u.role : 0;
        var roleName = ROLE_NAMES[role] || '未知';
        var div = document.createElement('div');
        div.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f0f0f0;';
        div.innerHTML =
            '<span>' + u.name + ' <span style="color:#aaa;font-size:11px;">(' + u.username + ' · ' + roleName + ')</span></span>' +
            '<button class="btn-base btn-del" style="padding:2px 8px;font-size:11px;" onclick="removeUserFromBranch(\'' + u.id + '\')">移除</button>';
        memberList.appendChild(div);
    });

    var allRes = await fetch('/api/users', { headers: getAuthHeaders() });
    branchAllUsers = await allRes.json();
    var select = document.getElementById('branchAddUser');
    select.innerHTML = '<option value="">选择用户添加...</option>';
    var memberIds = members.map(function(m) { return m.id; });
    branchAllUsers.forEach(function(u) {
        if (memberIds.indexOf(u.id) === -1) {
            var opt = document.createElement('option');
            opt.value = u.id;
            opt.textContent = u.name + ' (' + u.username + ')';
            select.appendChild(opt);
        }
    });

    document.getElementById('branchModal').classList.add('show');
}

function closeBranchModal() {
    document.getElementById('branchModal').classList.remove('show');
    editingBranchId = null;
}

async function saveBranchEdit() {
    if (!editingBranchId) return;
    var name = document.getElementById('branchEditName').value.trim();
    var desc = document.getElementById('branchEditDesc').value.trim();
    if (!name) return showToast('名称不能为空');
    var res = await fetch('/api/admin/branch/' + editingBranchId, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ name: name, description: desc })
    });
    var data = await res.json();
    if (data.success) { showToast('已保存', 'success'); closeBranchModal(); loadBranches(); }
    else showToast(data.message || '保存失败');
}

async function addUserToBranch() {
    if (!editingBranchId) return;
    var userId = document.getElementById('branchAddUser').value;
    if (!userId) return showToast('请选择用户');
    var res = await fetch('/api/admin/branch/' + editingBranchId + '/user', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ userId: userId })
    });
    var data = await res.json();
    if (data.success) { showToast('已添加', 'success'); openBranchModal(editingBranchId); }
    else showToast(data.message || '添加失败');
}

async function removeUserFromBranch(userId) {
    if (!editingBranchId) return;
    var res = await fetch('/api/admin/branch/' + editingBranchId + '/user/' + userId, {
        method: 'DELETE',
        headers: getAuthHeaders()
    });
    var data = await res.json();
    if (data.success) { showToast('已移除', 'success'); openBranchModal(editingBranchId); }
    else showToast(data.message || '移除失败');
}

async function delUser(id, name) {
    if (!confirm('警告：删除用户 [' + name + '] 将会同时销毁该用户下的所有角色档案！\n\n确定继续吗？')) return;
    var res = await fetch('/api/users/' + id, { method: 'DELETE', headers: getAuthHeaders() });
    var data = await res.json();
    if (data.success) { showToast('用户已删除', 'success'); loadUsers(); }
    else showToast(data.message || '删除失败');
}

function openRoleModal(userId, userName, currentRole) {
    editingUserId = userId;
    document.getElementById('modalUserName').textContent = userName;
    document.getElementById('modalRoleSelect').value = currentRole;
    document.getElementById('roleModal').classList.add('show');
}
function closeRoleModal() { document.getElementById('roleModal').classList.remove('show'); editingUserId = null; }
async function confirmRoleChange() {
    if (!editingUserId) return;
    var newRole = parseInt(document.getElementById('modalRoleSelect').value);
    var res = await fetch('/api/admin/users/' + editingUserId + '/role', { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ role: newRole }) });
    var data = await res.json();
    if (data.success) { showToast('角色已更新', 'success'); closeRoleModal(); loadUsers(); }
    else showToast(data.message || '更新失败');
}

function goManager() { createTransition('授权认证中', 'manager.html'); }
function goDashboard() { createTransition('档案读取中', 'dashboard.html'); }

(function initNav() {
    var role = parseInt(localStorage.getItem('ta_role') || '0');
    if (role >= 1) {
        var dm = document.getElementById('deskBtnManager');
        var mm = document.getElementById('mobBtnManager');
        if (dm) dm.style.display = 'inline-flex';
        if (mm) mm.style.display = 'flex';
    }
})();

loadUsers();
