var uid = localStorage.getItem('ta_uid');
var token = localStorage.getItem('ta_token');
var userRole = parseInt(localStorage.getItem('ta_role') || '0');
var myBranches = [];
var currentBranchId = localStorage.getItem('ta_current_branch');
if(!uid) window.location.href = 'login.html';

async function loadMyBranches() {
    try {
        var res;
        if (userRole >= 2) {
            res = await fetch('/api/admin/branches', { headers: {'Authorization': 'Bearer ' + token} });
        } else {
            res = await fetch('/api/user/my-branches', { headers: {'Authorization': 'Bearer ' + token} });
        }
        if (res.ok) {
            var data = await res.json();
            myBranches = data.branches || [];
            // 验证保存的分部ID是否仍然有效
            if (currentBranchId && !myBranches.some(function(b) { return b.id === currentBranchId; })) {
                currentBranchId = null;
            }
            if (myBranches.length > 0 && !currentBranchId) {
                currentBranchId = myBranches[0].id;
                localStorage.setItem('ta_current_branch', currentBranchId);
            }
            if (myBranches.length >= 1) {
                renderBranchSelector();
            }
            if (myBranches.length === 0) {
                showBranchApplication();
            }
        }
    } catch(e) { console.error('加载分部失败:', e); }
}

function showBranchApplication() {
    var container = document.getElementById('list');
    var backBtn = currentBranchId
        ? '<button onclick="loadList()" style="margin-top:16px;padding:8px 20px;background:rgba(255,255,255,0.1);color:white;border:1px solid rgba(255,255,255,0.2);border-radius:4px;cursor:pointer;font-size:12px;font-weight:bold;"><i class="fas fa-arrow-left"></i> 返回档案库</button>'
        : '';
    container.innerHTML = '<div class="empty-state"><i class="fas fa-building" style="font-size:32px;margin-bottom:12px;opacity:0.5;"></i><h3 style="margin:0 0 8px;font-size:16px;">选择分部</h3><p style="margin:0 0 16px;font-size:13px;color:#aaa;">申请加入一个分部</p><div id="branchApplyList" style="text-align:left;max-width:400px;margin:0 auto;"></div>' + backBtn + '</div>';
    loadBranchesForApply();
}

async function loadBranchesForApply() {
    try {
        var res = await fetch('/api/branches', { headers: {'Authorization': 'Bearer ' + token} });
        var data = await res.json();
        var container = document.getElementById('branchApplyList');
        if (!data.success || !data.branches || data.branches.length === 0) {
            container.innerHTML = '<div style="color:#aaa;text-align:center;">暂无可加入的分部</div>';
            return;
        }
        var joinedIds = myBranches.map(function(b) { return b.id; });
        container.innerHTML = data.branches.map(function(b) {
            var joined = joinedIds.indexOf(b.id) !== -1;
            var btnHtml;
            if (joined) {
                btnHtml = '<button disabled style="padding:6px 14px;background:rgba(255,255,255,0.05);color:rgba(255,255,255,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:4px;font-size:12px;font-weight:bold;cursor:not-allowed;">已加入</button>';
            } else if (b.applied) {
                btnHtml = '<button disabled style="padding:6px 14px;background:#c0392b;color:white;border:none;border-radius:4px;font-size:12px;font-weight:bold;cursor:not-allowed;"><i class="fas fa-clock" style="margin-right:4px;"></i>申请中</button>';
            } else {
                btnHtml = '<button onclick="applyBranch(\'' + b.id + '\')" style="padding:6px 14px;background:white;color:#c0392b;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:bold;">申请加入</button>';
            }
            return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px;margin-bottom:8px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:6px;' + (joined ? 'opacity:0.5;' : '') + '">' +
                '<div><strong>' + b.name + '</strong>' + (b.description ? '<div style="font-size:12px;color:#aaa;margin-top:4px;">' + b.description + '</div>' : '') + '</div>' +
                btnHtml +
            '</div>';
        }).join('');
    } catch(e) {
        console.error('加载分部列表失败:', e);
    }
}

async function applyBranch(branchId) {
    var overlay = document.getElementById('apply-overlay');
    var barFill = overlay ? overlay.querySelector('.apply-bar-fill') : null;
    if (overlay) {
        if (barFill) { barFill.style.animation = 'none'; barFill.offsetHeight; barFill.style.animation = 'applyFill 1.5s ease-in-out forwards'; }
        overlay.classList.add('active');
    }
    try {
        var res = await fetch('/api/branch-application', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ branchId: branchId })
        });
        var data = await res.json();
        if (data.success) {
            showToast('申请已提交，请等待审批', 'success');
        } else {
            showToast(data.message || '申请失败');
        }
    } catch(e) {
        showToast('申请失败');
    }
    setTimeout(function() {
        if (overlay) overlay.classList.remove('active');
        showBranchApplication();
    }, 1600);
}

function renderBranchSelector() {
    var existing = document.getElementById('branchSelector');
    if (existing) existing.remove();
    var existingDrop = document.getElementById('branchDropdown');
    if (existingDrop) existingDrop.remove();

    var header = document.querySelector('header');
    var currentBranch = myBranches.find(b => b.id === currentBranchId);

    var wrapper = document.createElement('div');
    wrapper.id = 'branchSelector';
    wrapper.style.cssText = 'position:relative;display:inline-flex;align-items:center;margin-right:8px;vertical-align:middle;';

    var input = document.createElement('input');
    input.type = 'text';
    input.placeholder = '搜索部门...';
    input.value = currentBranch ? currentBranch.name : '';
    input.style.cssText = 'background:#2c3e50;color:white;border:1px solid rgba(255,255,255,0.2);border-radius:4px;padding:4px 28px 4px 8px;font-size:12px;font-weight:bold;width:140px;outline:none;box-sizing:border-box;';
    wrapper.appendChild(input);

    var arrow = document.createElement('i');
    arrow.className = 'fas fa-chevron-down';
    arrow.style.cssText = 'position:absolute;right:8px;top:50%;transform:translateY(-50%);color:rgba(255,255,255,0.4);font-size:10px;pointer-events:none;transition:opacity 0.15s;';
    wrapper.appendChild(arrow);

    var clearBtn = document.createElement('i');
    clearBtn.className = 'fas fa-times';
    clearBtn.style.cssText = 'position:absolute;right:8px;top:50%;transform:translateY(-50%);color:rgba(255,255,255,0.5);font-size:10px;cursor:pointer;display:none;transition:opacity 0.15s;padding:2px;';
    wrapper.appendChild(clearBtn);

    clearBtn.onmousedown = function(e) {
        e.preventDefault();
        input.value = '';
        input.focus();
        renderOptions('');
        dropdown.style.display = 'block';
    };

    var dropdown = document.createElement('div');
    dropdown.id = 'branchDropdown';
    dropdown.style.cssText = 'display:none;position:absolute;top:100%;left:0;right:0;background:#2c3e50;border:1px solid rgba(255,255,255,0.2);border-radius:4px;margin-top:2px;z-index:9999;max-height:200px;overflow-y:auto;';

    function renderOptions(filter) {
        dropdown.innerHTML = '';
        var keyword = (filter || '').toLowerCase();
        myBranches.forEach(function(b) {
            if (keyword && b.name.toLowerCase().indexOf(keyword) === -1) return;
            var item = document.createElement('div');
            item.textContent = b.name;
            item.style.cssText = 'padding:6px 10px;font-size:12px;color:white;cursor:pointer;white-space:nowrap;';
            if (b.id === currentBranchId) item.style.background = 'rgba(255,255,255,0.1)';
            var branchId = b.id;
            var branchName = b.name;
            item.onmousedown = function(e) {
                e.preventDefault();
                currentBranchId = branchId;
                input.value = branchName;
                dropdown.style.display = 'none';
                localStorage.setItem('ta_current_branch', currentBranchId);
                loadList();
            };
            item.onmouseenter = function() { this.style.background = 'rgba(255,255,255,0.15)'; };
            item.onmouseleave = function() { this.style.background = b.id === currentBranchId ? 'rgba(255,255,255,0.1)' : 'none'; };
            dropdown.appendChild(item);
        });
        if (!dropdown.children.length) {
            var empty = document.createElement('div');
            empty.textContent = '无匹配';
            empty.style.cssText = 'padding:6px 10px;font-size:12px;color:rgba(255,255,255,0.3);';
            dropdown.appendChild(empty);
        }
    }

    input.onfocus = function() {
        renderOptions(input.value);
        dropdown.style.display = 'block';
        arrow.style.display = 'none';
        clearBtn.style.display = 'block';
    };
    input.oninput = function() {
        renderOptions(input.value);
        dropdown.style.display = 'block';
        arrow.style.display = 'none';
        clearBtn.style.display = 'block';
    };
    input.onblur = function() {
        setTimeout(function() { dropdown.style.display = 'none'; }, 150);
        var branch = myBranches.find(b => b.id === currentBranchId);
        input.value = branch ? branch.name : '';
        arrow.style.display = 'block';
        clearBtn.style.display = 'none';
    };

    wrapper.appendChild(dropdown);
    var btnGroup = header.querySelector('.btn-group');
    btnGroup.parentNode.insertBefore(wrapper, btnGroup);
}

(function initConsoleButton() {
    var btnConsole = document.getElementById('btnConsole');
    var btnManager = document.getElementById('btnManager');
    var menuConsole = document.getElementById('menuConsole');
    var menuManager = document.getElementById('menuManager');

    if (userRole >= 2) {
        if (btnManager) btnManager.style.display = 'inline-flex';
        if (btnConsole) btnConsole.style.display = 'inline-flex';
        if (menuManager) { menuManager.style.display = 'flex'; menuManager.classList.add('console'); }
        if (menuConsole) { menuConsole.style.display = 'flex'; menuConsole.classList.add('admin'); }
    } else if (userRole >= 1) {
        if (btnManager) btnManager.style.display = 'inline-flex';
        if (btnConsole) btnConsole.style.display = 'none';
        if (menuManager) { menuManager.style.display = 'flex'; menuManager.classList.add('console'); }
        if (menuConsole) menuConsole.style.display = 'none';
    } else {
        if (btnManager) btnManager.style.display = 'none';
        if (btnConsole) btnConsole.style.display = 'none';
        if (menuManager) menuManager.style.display = 'none';
        if (menuConsole) menuConsole.style.display = 'none';
    }
})();

var touchStartX = 0, touchStartY = 0;
var swipeThreshold = 80, edgeThreshold = 60;

document.addEventListener('touchstart', function(e) {
    touchStartX = e.changedTouches[0].screenX;
    touchStartY = e.changedTouches[0].screenY;
}, {passive: true});

document.addEventListener('touchend', function(e) {
    var touchEndX = e.changedTouches[0].screenX;
    var touchEndY = e.changedTouches[0].screenY;
    handleSwipe(touchStartX, touchStartY, touchEndX, touchEndY);
}, {passive: true});

function handleSwipe(startX, startY, endX, endY) {
    var xDiff = endX - startX;
    var yDiff = endY - startY;
    var menu = document.getElementById('sideMenu');
    var isOpen = menu.classList.contains('show');
    var screenWidth = window.innerWidth;

    if (Math.abs(yDiff) > Math.abs(xDiff)) return;

    if (!isOpen && xDiff < -swipeThreshold && startX > (screenWidth - edgeThreshold)) {
        toggleSideMenu();
    }
    if (isOpen && xDiff > swipeThreshold) {
        closeSideMenu();
    }
}

function enterHighWall() {
    var overlay = document.getElementById('hw-overlay');
    var icon = document.getElementById('hw-icon');
    var text = document.getElementById('hw-text');
    var scanlines = document.getElementById('hw-scanlines');
    var eyeLayer = document.getElementById('hw-eye-layer');
    var eyeIcon = document.getElementById('hw-eye-icon');
    var tentaclesLayer = document.getElementById('hw-tentacles');
    var blackout = document.getElementById('hw-blackout');

    overlay.classList.add('active');

    setTimeout(function() {
        icon.classList.remove('fa-spin');
        icon.style.transform = 'rotate(160deg)';
        setTimeout(function() {
            icon.className = 'fas fa-exclamation-triangle loader-icon';
            icon.style.color = '#ff0000';
            text.style.color = '#ff0000';
            text.style.fontFamily = 'monospace';
            text.innerHTML = 'SYSTEM FAILURE /// 0xFF';
            overlay.classList.add('glitch-mode');
            scanlines.style.display = 'block';
        }, 100);
    }, 1000);

    setTimeout(function() {
        overlay.classList.remove('glitch-mode');
        scanlines.style.display = 'none';
        document.getElementById('hw-content').style.display = 'none';
        eyeLayer.style.opacity = '1';
        setTimeout(function() { eyeIcon.classList.add('eye-open'); }, 100);
    }, 1500);

    setTimeout(function() {
        eyeIcon.classList.add('scared');
        tentaclesLayer.innerHTML = '';
        var count = 20;
        for (var i = 0; i < count; i++) {
            var div = document.createElement('div');
            div.className = 'tendril';
            var deg = i * (360 / count);
            div.style.setProperty('--r', deg + 'deg');
            div.style.animationDelay = (Math.random() * 0.4) + 's';
            tentaclesLayer.appendChild(div);
            (function(d) { requestAnimationFrame(function() { d.classList.add('creeping'); }); })(div);
        }
    }, 1900);

    setTimeout(function() {
        blackout.classList.add('active');
        setTimeout(function() { window.location.href = 'documents.html'; }, 500);
    }, 2500);
}

function goConsole() {
    createTransition('授权认证中', 'admin.html');
}

function goManager() {
    createTransition('授权认证中', 'manager.html');
}

function goItems() {
    createTransition('访问申领物系统', 'items.html');
}

function goPlaza() {
    createTransition('访问广场', 'plaza.html');
}

async function loadList() {
    try {
        var url = '/api/characters?userId=' + uid;
        if (currentBranchId) url += '&branchId=' + currentBranchId;
        var res = await fetch(url, { headers: {'Authorization': 'Bearer ' + token} });
        if (res.status === 401 || res.status === 403) { logout(); return; }
        var list = await res.json();
        var container = document.getElementById('list');
        container.innerHTML = '';

        if (list.length === 0) {
            container.innerHTML = '<div class="empty-state">暂无数据 // 请建立新档案</div>';
            return;
        }

        list.sort(function(a, b) { return (a.isArchived ? 1 : 0) - (b.isArchived ? 1 : 0); });
        list.forEach(function(c) {
            var el = document.createElement('div');
            var archiveClass = '';
            var archiveIcon = '';
            var archiveLabel = '';
            if (c.isArchived) {
                var tp = c.trackProgress || { func: 0, real: 0, anom: 0 };
                if (tp.func >= tp.real && tp.func >= tp.anom) {
                    archiveClass = 'archived archived-func';
                    archiveLabel = '升迁总部';
                    archiveIcon = '<svg viewBox="0 0 80 100" width="72" height="90"><path d="M40 8 L18 26 L18 32 L34 40 L28 92 L40 78 L52 92 L46 40 L62 32 L62 26 Z" fill="#e74c3c"/><path d="M40 14 L24 28 L40 36 L56 28 Z" fill="#fff" opacity="0.3"/></svg>';
                } else if (tp.real >= tp.func && tp.real >= tp.anom) {
                    archiveClass = 'archived archived-real';
                    archiveLabel = '头号玩家';
                    archiveIcon = '<svg viewBox="0 0 80 100" width="72" height="90"><rect x="18" y="6" width="44" height="88" rx="8" fill="#f1c40f"/><rect x="24" y="20" width="32" height="52" rx="2" fill="#1a1a2e"/><rect x="18" y="10" width="44" height="6" rx="2" fill="#d4ac0d"/><circle cx="40" cy="13" r="1.5" fill="#1a1a2e"/><rect x="18" y="84" width="44" height="6" rx="2" fill="#d4ac0d"/><circle cx="40" cy="87" r="3" fill="none" stroke="#1a1a2e" stroke-width="1.5"/></svg>';
                } else {
                    archiveClass = 'archived archived-anom';
                    archiveLabel = '无拘无束';
                    archiveIcon = '<svg viewBox="0 0 120 70" width="100" height="58"><path d="M6 35 Q30 8 60 8 Q90 8 114 35 Q90 62 60 62 Q30 62 6 35Z" fill="#3498db"/><ellipse cx="60" cy="35" rx="18" ry="18" fill="#fff" opacity="0.95"/><circle cx="60" cy="35" r="11" fill="#2c3e50"/><circle cx="60" cy="35" r="6" fill="#3498db"/><circle cx="64" cy="31" r="2.5" fill="#fff" opacity="0.8"/></svg>';
                }
            }
            if (!c.isArchived) {
                var tp = c.trackProgress || { func: 0, real: 0, anom: 0 };
                if (tp.anom > tp.real && tp.anom > tp.func) archiveClass = 'track-anom';
                else if (tp.real > tp.func && tp.real > tp.anom) archiveClass = 'track-real';
                else archiveClass = 'track-func';
            }
            el.className = 'char-card' + (archiveClass ? ' ' + archiveClass : '');
            el.style.setProperty('--r1', Math.random());
            el.style.setProperty('--r2', Math.random());
            el.style.setProperty('--r3', Math.random());

            var deleteButton = '<button class="tool-btn" onclick="delChar(event, \'' + c.id + '\')"><i class="fas fa-trash"></i></button>';
            var plazaBtn = '<button class="tool-btn plaza-toggle ' + (c.plazaVisible ? 'plaza-on' : 'plaza-off') + '" onclick="togglePlaza(event, \'' + c.id + '\', this)" title="' + (c.plazaVisible ? '广场展示中' : '未在广场展示') + '"><i class="fas fa-globe"></i></button>';

            if (c.isArchived) {
                el.innerHTML =
                    '<div class="card-tools">' +
                        plazaBtn +
                    '</div>' +
                    '<div class="archived-content" onclick="openSheet(event, \'' + c.id + '\')">' +
                        '<div class="archived-banner-label">' + archiveLabel + '</div>' +
                        '<div class="archived-name">' + c.name + '</div>' +
                        '<div class="archived-icon">' + archiveIcon + '</div>' +
                    '</div>';
            } else {
                el.innerHTML =
                    '<div class="card-tools">' +
                        deleteButton +
                        plazaBtn +
                    '</div>' +
                    '<div class="card-content-wrapper" onclick="openSheet(event, \'' + c.id + '\')">' +
                        '<div class="card-header"><span class="c-name">' + c.name + '</span></div>' +
                        '<div class="info-group">' +
                            '<div class="info-field if-anom"><span class="field-label"><i class="fas fa-bolt anim-flicker"></i> 异常 // ANOMALY</span><span class="field-val">' + c.anom + '</span></div>' +
                            '<div class="info-field if-real"><span class="field-label"><i class="fas fa-fingerprint anim-breathe"></i> 现实 // REALITY</span><span class="field-val">' + c.real + '</span></div>' +
                            '<div class="info-field if-func"><span class="field-label"><i class="fas fa-briefcase anim-float"></i> 职能 // COMPETENCY</span><span class="field-val">' + c.func + '</span></div>' +
                        '</div>' +
                    '</div>' +
                '</div>';
            }
            container.appendChild(el);
        });
    } catch(e) {
        console.error("加载列表失败:", e);
        showToast("无法连接至服务器");
    }
}

async function createNew() {
    if (!currentBranchId) {
        showToast('请先加入一个分部');
        return;
    }
    var btn = document.querySelector('.btn-icon.accent');
    if (!btn) return;
    var original = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    btn.disabled = true;
    try {
        var res = await fetch('/api/character', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ userId: uid, branchId: currentBranchId })
        });
        if (res.status === 401) { logout(); return; }
        var data = await res.json();
        if (data.success) {
            createTransition('创建新档案', 'sheet.html?id=' + data.id);
        } else {
            btn.innerHTML = original;
            btn.disabled = false;
        }
    } catch(e) {
        btn.innerHTML = original;
        btn.disabled = false;
    }
}

function openSheet(event, id) {
    event.preventDefault();
    var card = event.currentTarget.closest('.char-card');
    if (card) card.classList.add('accessing');
    createTransition('访问终端中', 'sheet.html?id=' + id);
}


async function delChar(e, id) {
    e.stopPropagation();
    if (!confirm('确定销毁档案？此操作不可逆。')) return;
    try {
        var res = await fetch('/api/character/' + id, {
            method: 'DELETE',
            headers: {'Authorization': 'Bearer ' + token}
        });
        if (res.status === 401) { logout(); return; }
        showToast("档案已销毁", 'success');
        loadList();
    } catch(e) {
        showToast("销毁失败");
    }
}

async function togglePlaza(e, id, btn) {
    e.stopPropagation();
    var isOn = btn.classList.contains('plaza-on');
    try {
        var res = await fetch('/api/character/' + id + '/plaza-visibility', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ visible: !isOn })
        });
        if (res.ok) {
            var data = await res.json();
            if (data.plazaVisible) {
                btn.classList.remove('plaza-off');
                btn.classList.add('plaza-on');
                btn.title = '广场展示中';
            } else {
                btn.classList.remove('plaza-on');
                btn.classList.add('plaza-off');
                btn.title = '未在广场展示';
            }
            showToast(data.plazaVisible ? '已在广场展示' : '已关闭广场展示', 'success');
        }
    } catch (err) {
        showToast('操作失败');
    }
}

loadMyBranches().then(function() {
    if (currentBranchId) {
        loadList();
    }
});