import { S } from './state.js';
import { getAuthHeaders } from './auth.js';

function createTransition(text, url) {
    const overlay = document.getElementById('transition-overlay');
    const loaderText = document.getElementById('transition-text');

    if (loaderText) {
        loaderText.innerHTML = `${text}<span class="dots"></span>`;
    }

    if (overlay) {
        overlay.classList.add('active');
    }

    setTimeout(() => {
        window.location.href = url;
    }, 1200);
}

function showToast(msg, type = false) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    const isSuccess = type === true || type === 'success';
    toast.className = 'toast show' + (isSuccess ? ' success' : '');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function renderBranchSelector() {
    var existing = document.getElementById('branchSelector');
    if (existing) existing.remove();
    var existingDrop = document.getElementById('branchDropdown');
    if (existingDrop) existingDrop.remove();

    var header = document.querySelector('header .btn-group');
    var currentBranch = S.myBranches.find(b => b.id === S.currentBranchId);

    var wrapper = document.createElement('div');
    wrapper.id = 'branchSelector';
    wrapper.style.cssText = 'position:relative;display:inline-block;margin-right:8px;';

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
        S.myBranches.forEach(function(b) {
            if (keyword && b.name.toLowerCase().indexOf(keyword) === -1) return;
            var item = document.createElement('div');
            item.textContent = b.name;
            item.style.cssText = 'padding:6px 10px;font-size:12px;color:white;cursor:pointer;white-space:nowrap;';
            if (b.id === S.currentBranchId) item.style.background = 'rgba(255,255,255,0.1)';
            var branchId = b.id;
            var branchName = b.name;
            item.onmousedown = function(e) {
                e.preventDefault();
                S.currentBranchId = branchId;
                input.value = branchName;
                dropdown.style.display = 'none';
                localStorage.setItem('ta_current_branch', S.currentBranchId);
                reloadAllForBranch();
            };
            item.onmouseenter = function() { this.style.background = 'rgba(255,255,255,0.15)'; };
            item.onmouseleave = function() { this.style.background = branchId === S.currentBranchId ? 'rgba(255,255,255,0.1)' : 'none'; };
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
        var branch = S.myBranches.find(b => b.id === S.currentBranchId);
        input.value = branch ? branch.name : '';
        arrow.style.display = 'block';
        clearBtn.style.display = 'none';
    };

    wrapper.appendChild(dropdown);
    header.insertBefore(wrapper, header.firstChild);
}

function toggleSideMenu() {
    document.getElementById('sideMenu').classList.add('show');
    document.getElementById('sideMenuOverlay').classList.add('show');
}

function closeSideMenu() {
    document.getElementById('sideMenu').classList.remove('show');
    document.getElementById('sideMenuOverlay').classList.remove('show');
}

function switchMainTab(tabName) {
    document.querySelectorAll('.main-tab').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    const tabMap = {
        'characters': 'tabCharacters',
        'missions': 'tabMissions',
        'requisitions': 'tabRequisitions',
        'siphon': 'tabSiphon',
        'anomaly': 'tabAnomaly',
        'destruction': 'tabDestruction',
        'applications': 'tabApplications',
        'npc': 'tabNpc'
    };

    const targetTab = document.getElementById(tabMap[tabName]);
    if (targetTab) {
        targetTab.classList.add('active');
    }

    if (tabName === 'missions') {
        loadMissions();
    }

    if (tabName === 'requisitions' && S.lastLoadedTab !== 'requisitions') {
        loadRequisitionItems();
    }

    if (tabName === 'siphon' && S.lastLoadedTab !== 'siphon') {
        loadSiphonProducts();
    }

    if (tabName === 'applications') {
        loadBranchApplications();
    }

    if (tabName === 'anomaly' && S.lastLoadedTab !== 'anomaly') {
        loadAnomalyTemplates();
    }

    if (tabName === 'npc' && S.lastLoadedTab !== 'npc') {
        loadNpcTemplates();
    }

    if (tabName === 'destruction') {
        loadDestructionTrack();
    }

    S.lastLoadedTab = tabName;
}

function reloadAllForBranch() {
    loadCharacters();
    loadMissions();
    if (S.lastLoadedTab === 'requisitions') loadRequisitionItems();
    if (S.lastLoadedTab === 'siphon') loadSiphonProducts();
    if (S.lastLoadedTab === 'destruction') loadDestructionTrack();
    var branch = S.myBranches.find(b => b.id === S.currentBranchId);
    if (branch) { const el = document.getElementById('branchNameDisplay'); if (el) el.textContent = branch.name; }
    loadBranchScatter();
}

async function loadMyBranches() {
    try {
        let res;
        if (S.role >= 2) {
            res = await fetch('/api/admin/branches', { headers: getAuthHeaders() });
        } else {
            res = await fetch('/api/user/my-branches', { headers: getAuthHeaders() });
        }
        if (res.ok) {
            const data = await res.json();
            S.myBranches = data.branches || [];
            if (S.currentBranchId && !S.myBranches.some(b => b.id === S.currentBranchId)) {
                S.currentBranchId = null;
            }
            if (S.myBranches.length > 0 && !S.currentBranchId) {
                S.currentBranchId = S.myBranches[0].id;
                localStorage.setItem('ta_current_branch', S.currentBranchId);
            }
            if (S.myBranches.length >= 1) {
                renderBranchSelector();
            }
            if (S.myBranches.length > 0) {
                const branch = S.myBranches.find(b => b.id === S.currentBranchId) || S.myBranches[0];
                document.getElementById('branchInfo').style.display = 'flex';
            }
        }
    } catch(e) { console.error('加载分部失败:', e); }
}

async function loadBranchScatter() {
    if (!S.currentBranchId) return;
    try {
        var res = await fetch('/api/admin/branch/' + S.currentBranchId, { headers: getAuthHeaders() });
        if (res.ok) {
            var data = await res.json();
            if (data.success && data.branch && data.branch.stats) {
                document.getElementById('branchScatterDisplay').textContent = data.branch.stats.total_scatter || 0;
            }
        }
    } catch(e) { console.error('加载散逸端统计失败:', e); }
}

import { loadCharacters } from './characters.js';
import { loadMissions } from './missions.js';
import { loadRequisitionItems } from './items.js';
import { loadSiphonProducts } from './siphon.js';
import { loadBranchApplications } from './branches.js';
import { loadAnomalyTemplates } from './anomaly-templates.js';
import { loadDestructionTrack } from './destruction.js';

export {
    createTransition,
    showToast,
    escapeHtml,
    renderBranchSelector,
    toggleSideMenu,
    closeSideMenu,
    switchMainTab,
    reloadAllForBranch,
    loadMyBranches,
    loadBranchScatter
};
