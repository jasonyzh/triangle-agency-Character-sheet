var uid = localStorage.getItem('ta_uid');
var token = localStorage.getItem('ta_token');
var userRole = parseInt(localStorage.getItem('ta_role') || '0');
var myBranches = [];
var currentBranchId = localStorage.getItem('ta_plaza_branch');
var allCharacters = [];
var renderedCount = 0;
var batchSize = 30;
var sortMode = localStorage.getItem('ta_plaza_sort') || 'mvp';
if (!uid) window.location.href = 'login.html';

function goBack() {
    createTransition('返回终端', 'dashboard.html');
}

function setSortMode(mode) {
    sortMode = mode;
    localStorage.setItem('ta_plaza_sort', mode);
    var btns = document.querySelectorAll('.sort-btn');
    btns.forEach(function (b) { b.classList.remove('active'); });
    var active = document.querySelector('.sort-' + mode);
    if (active) active.classList.add('active');
    if (allCharacters.length > 0) {
        applySort();
        rerender();
    }
}

function applySort() {
    allCharacters.sort(function (a, b) {
        if (sortMode === 'mvp') return (b.mvpCount || 0) - (a.mvpCount || 0);
        if (sortMode === 'mission') return ((b.missions ? b.missions.length : 0) - (a.missions ? a.missions.length : 0)) || ((b.mvpCount || 0) - (a.mvpCount || 0));
        if (sortMode === 'watch') return (b.watchCount || 0) - (a.watchCount || 0);
        return 0;
    });
}

function initSortButtons() {
    var btns = document.querySelectorAll('.sort-btn');
    btns.forEach(function (b) { b.classList.remove('active'); });
    var active = document.querySelector('.sort-' + sortMode);
    if (active) active.classList.add('active');
}

async function loadMyBranches() {
    try {
        var res;
        if (userRole >= 2) {
            res = await fetch('/api/admin/branches', { headers: { 'Authorization': 'Bearer ' + token } });
        } else {
            res = await fetch('/api/user/my-branches', { headers: { 'Authorization': 'Bearer ' + token } });
        }
        if (res.ok) {
            var data = await res.json();
            myBranches = data.branches || [];
            if (myBranches.length > 0) {
                if (currentBranchId && !myBranches.some(function (b) { return b.id === currentBranchId; })) {
                    currentBranchId = null;
                }
                if (!currentBranchId) {
                    currentBranchId = myBranches[0].id;
                }
                localStorage.setItem('ta_plaza_branch', currentBranchId);
                renderBranchSelector();
                initSortButtons();
                loadPlazaCharacters();
            } else {
                document.getElementById('plazaList').innerHTML = '<div class="empty-state">你还没有加入任何分部</div>';
            }
        }
    } catch (e) { console.error('加载分部失败:', e); }
}

function renderBranchSelector() {
    var container = document.getElementById('branchSelector');
    container.innerHTML = '';

    var currentBranch = myBranches.find(function (b) { return b.id === currentBranchId; });

    var input = document.createElement('input');
    input.type = 'text';
    input.placeholder = '选择分部...';
    input.value = currentBranch ? currentBranch.name : '';
    input.readOnly = true;
    input.style.cursor = 'pointer';
    container.appendChild(input);

    var arrow = document.createElement('i');
    arrow.className = 'fas fa-chevron-down selector-arrow';
    container.appendChild(arrow);

    var dropdown = document.createElement('div');
    dropdown.className = 'selector-dropdown';
    container.appendChild(dropdown);

    function renderOptions() {
        dropdown.innerHTML = '';
        myBranches.forEach(function (b) {
            var item = document.createElement('div');
            item.className = 'dropdown-item' + (b.id === currentBranchId ? ' active' : '');
            item.textContent = b.name;
            item.onmousedown = function (e) {
                e.preventDefault();
                currentBranchId = b.id;
                input.value = b.name;
                dropdown.style.display = 'none';
                localStorage.setItem('ta_plaza_branch', b.id);
                loadPlazaCharacters();
            };
            dropdown.appendChild(item);
        });
    }

    input.onfocus = function () {
        renderOptions();
        dropdown.style.display = 'block';
    };
    input.onblur = function () {
        setTimeout(function () { dropdown.style.display = 'none'; }, 150);
    };
}

async function loadPlazaCharacters() {
    if (!currentBranchId) return;
    var container = document.getElementById('plazaList');
    container.innerHTML = '<div class="empty-state"><i class="fas fa-circle-notch fa-spin" style="font-size:24px;margin-bottom:12px;"></i><br>加载中...</div>';
    allCharacters = [];
    renderedCount = 0;

    try {
        var res = await fetch('/api/plaza/characters?branchId=' + currentBranchId, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        if (res.status === 401 || res.status === 403) { goBack(); return; }
        allCharacters = await res.json();

        if (!allCharacters.length) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-user-slash" style="font-size:28px;margin-bottom:12px;opacity:0.4;"></i><br>该分部暂无公开展示的角色</div>';
            return;
        }

        container.innerHTML = '';
        applySort();
        renderBatch();
    } catch (e) {
        console.error('加载广场失败:', e);
        container.innerHTML = '<div class="empty-state">加载失败</div>';
    }
}

function renderBatch() {
    var container = document.getElementById('plazaList');
    var end = Math.min(renderedCount + batchSize, allCharacters.length);

    for (var i = renderedCount; i < end; i++) {
        var c = allCharacters[i];
        var el = document.createElement('div');
        el.className = 'plaza-card';

        var missionsHtml = '';
        if (c.missions && c.missions.length > 0) {
            missionsHtml = '<div class="plaza-card-missions">' +
                c.missions.map(function (m) {
                    return '<span class="plaza-mission-tag">' + escapeHtml(m) + '</span>';
                }).join('') +
                '</div>';
        }

        var archiveTag = '';
        if (c.isArchived) {
            var tp = c.trackProgress || { func: 0, real: 0, anom: 0 };
            if (tp.func >= tp.real && tp.func >= tp.anom) {
                archiveTag = '<span class="plaza-archive-tag tag-func">升迁总部</span>';
            } else if (tp.real >= tp.func && tp.real >= tp.anom) {
                archiveTag = '<span class="plaza-archive-tag tag-real">头号玩家</span>';
            } else {
                archiveTag = '<span class="plaza-archive-tag tag-anom">无拘无束</span>';
            }
        }

        el.innerHTML =
            '<div class="plaza-card-name">' + escapeHtml(c.name) + archiveTag + '</div>' +
            '<div class="plaza-card-attrs">' +
                '<div class="plaza-attr plaza-attr-anom">' +
                    '<i class="fas fa-bolt"></i>' +
                    '<span class="plaza-attr-label">异常</span>' +
                    '<span class="plaza-attr-value">' + escapeHtml(c.anom) + '</span>' +
                '</div>' +
                '<div class="plaza-attr plaza-attr-real">' +
                    '<i class="fas fa-fingerprint"></i>' +
                    '<span class="plaza-attr-label">现实</span>' +
                    '<span class="plaza-attr-value">' + escapeHtml(c.real) + '</span>' +
                '</div>' +
                '<div class="plaza-attr plaza-attr-func">' +
                    '<i class="fas fa-briefcase"></i>' +
                    '<span class="plaza-attr-label">职能</span>' +
                    '<span class="plaza-attr-value">' + escapeHtml(c.func) + '</span>' +
                '</div>' +
            '</div>' +
            '<div class="plaza-card-stats">' +
                '<div class="plaza-stat plaza-stat-mvp"><i class="fas fa-medal"></i> ' + c.mvpCount + '</div>' +
                '<div class="plaza-stat plaza-stat-watch"><i class="fas fa-eye"></i> ' + c.watchCount + '</div>' +
            '</div>' +
            missionsHtml;

        container.appendChild(el);
    }

    renderedCount = end;
}

function rerender() {
    var container = document.getElementById('plazaList');
    container.innerHTML = '';
    renderedCount = 0;
    renderBatch();
}

window.addEventListener('scroll', function () {
    if (renderedCount >= allCharacters.length) return;
    var scrollBottom = window.innerHeight + window.scrollY;
    if (scrollBottom >= document.documentElement.offsetHeight - 300) {
        renderBatch();
    }
});

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

loadMyBranches();
