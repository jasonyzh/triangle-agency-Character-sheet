    const token = localStorage.getItem('ta_token');
    const role = parseInt(localStorage.getItem('ta_role') || '0');

    if (!token || role < 1) {
        window.location.href = 'login.html';
    }

    let myBranches = [];
    let currentBranchId = localStorage.getItem('ta_current_branch');

    async function loadMyBranches() {
        try {
            let res;
            if (role >= 2) {
                res = await fetch('/api/admin/branches', { headers: getAuthHeaders() });
            } else {
                res = await fetch('/api/user/my-branches', { headers: getAuthHeaders() });
            }
            if (res.ok) {
                const data = await res.json();
                myBranches = data.branches || [];
                if (currentBranchId && !myBranches.some(b => b.id === currentBranchId)) {
                    currentBranchId = null;
                }
                if (myBranches.length > 0 && !currentBranchId) {
                    currentBranchId = myBranches[0].id;
                    localStorage.setItem('ta_current_branch', currentBranchId);
                }
                if (myBranches.length >= 1) {
                    renderBranchSelector();
                }
                if (myBranches.length > 0) {
                    const branch = myBranches.find(b => b.id === currentBranchId) || myBranches[0];
                    document.getElementById('branchInfo').style.display = 'flex';
                }
            }
        } catch(e) { console.error('加载分部失败:', e); }
    }

    function renderBranchSelector() {
        var existing = document.getElementById('branchSelector');
        if (existing) existing.remove();
        var existingDrop = document.getElementById('branchDropdown');
        if (existingDrop) existingDrop.remove();

        var header = document.querySelector('header .btn-group');
        var currentBranch = myBranches.find(b => b.id === currentBranchId);

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
                    reloadAllForBranch();
                };
                item.onmouseenter = function() { this.style.background = 'rgba(255,255,255,0.15)'; };
                item.onmouseleave = function() { this.style.background = branchId === currentBranchId ? 'rgba(255,255,255,0.1)' : 'none'; };
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
        header.insertBefore(wrapper, header.firstChild);
    }

    function reloadAllForBranch() {
        loadCharacters();
        loadMissions();
        if (lastLoadedTab === 'requisitions') loadRequisitionItems();
        if (lastLoadedTab === 'siphon') loadSiphonProducts();
        var branch = myBranches.find(b => b.id === currentBranchId);
        if (branch) document.getElementById('branchNameDisplay').textContent = branch.name;
        loadBranchScatter();
    }

    async function loadBranchScatter() {
        if (!currentBranchId) return;
        try {
            var res = await fetch('/api/admin/branch/' + currentBranchId, { headers: getAuthHeaders() });
            if (res.ok) {
                var data = await res.json();
                if (data.success && data.branch && data.branch.stats) {
                    document.getElementById('branchScatterDisplay').textContent = data.branch.stats.total_scatter || 0;
                }
            }
        } catch(e) { console.error('加载散逸端统计失败:', e); }
    }
// === 页面过渡动画逻辑 ===
    function createTransition(text, url) {
        const overlay = document.getElementById('transition-overlay');
        const loaderText = document.getElementById('transition-text');
        
        // 设置加载文字 + 动态省略号
        if (loaderText) {
            loaderText.innerHTML = `${text}<span class="dots"></span>`;
        }
        
        // 激活遮罩层
        if (overlay) {
            overlay.classList.add('active');
        }
        
        // 延迟跳转 (配合 CSS 动画时间 0.8s + 缓冲)
        setTimeout(() => {
            window.location.href = url;
        }, 1200);
    }

    function goAdmin() {
        createTransition('权限认证中', 'admin.html');
    }

    function goToDashboard() {
        createTransition('档案读取中', 'dashboard.html');
    }
	
    function getAuthHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        };
    }

    // 清理字符串，移除可能导致 JSON 解析问题的字符
    function sanitizeString(str) {
        if (typeof str !== 'string') return str;
        // 移除控制字符（除了换行、制表符和回车）
        return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    }

    // 递归清理对象中的所有字符串
    function sanitizeObject(obj) {
        if (obj === null || obj === undefined) return obj;
        
        if (Array.isArray(obj)) {
            return obj.map(item => sanitizeObject(item));
        }
        
        if (typeof obj === 'object') {
            const cleaned = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    cleaned[key] = sanitizeObject(obj[key]);
                }
            }
            return cleaned;
        }
        
        if (typeof obj === 'string') {
            return sanitizeString(obj);
        }
        
        return obj;
    }

    // 安全的 JSON fetch 包装函数
    async function safeFetch(url, options = {}) {
        try {
            // 如果有 body，尝试解析并验证
            if (options.body) {
                try {
                    // 验证 JSON 是否有效
                    const parsed = JSON.parse(options.body);
                    console.log(`[SafeFetch] 发送到 ${url}:`, parsed);
                } catch (e) {
                    console.error('[SafeFetch] JSON 解析失败:', e);
                    console.error('[SafeFetch] 原始数据:', options.body);
                    console.error('[SafeFetch] 数据前100个字符:', options.body.substring(0, 100));
                    throw new Error('请求数据格式错误: ' + e.message);
                }
            }
            
            const response = await fetch(url, options);
            return response;
        } catch (error) {
            console.error('[SafeFetch] 请求失败:', error);
            throw error;
        }
    }

    function showToast(msg, type = false) {
        const toast = document.getElementById('toast');
        toast.textContent = msg;
        // 支持布尔值和字符串类型
        const isSuccess = type === true || type === 'success';
        toast.className = 'toast show' + (isSuccess ? ' success' : '');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }

    // 加载已授权的角色
    let allCharacters = [];

    async function loadCharacters() {
        console.log('loadCharacters called'); 
        
        try {
            // 添加超时处理
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10秒超时

            var url = '/api/manager/characters';
            if (currentBranchId) url += '?branchId=' + currentBranchId;
            const res = await fetch(url, {
                headers: getAuthHeaders(),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                const container = document.getElementById('charList');
                if (container) {
                    container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h3>加载失败</h3>
                        <p>状态码: ${res.status}</p>
                    </div>`;
                }
                showToast('加载失败');
                return;
            }

            allCharacters = await res.json();
            renderCharacters(allCharacters);

        } catch (e) {
            console.error('loadCharacters error:', e);
            const container = document.getElementById('charList');
            if (container) {
                const errorMsg = e.name === 'AbortError' ? '请求超时，请检查网络连接' : (e.message || '未知错误');
                container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>加载失败</h3>
                    <p>${errorMsg}</p>
                    <button onclick="loadCharacters()" style="margin-top:10px;padding:8px 16px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;">重试</button>
                </div>`;
            }
            showToast('加载失败: ' + (e.message || '未知错误'));
        }
    }

    function handleSearch() {
        const query = document.getElementById('charSearchInput').value.trim().toLowerCase();
        if (!query) {
            renderCharacters(allCharacters);
            return;
        }

        const filtered = allCharacters.filter(c => {
            return (c.name && c.name.toLowerCase().includes(query)) ||
                   (c.ownerName && c.ownerName.toLowerCase().includes(query)) ||
                   (c.func && c.func.toLowerCase().includes(query)) ||
                   (c.anom && c.anom.toLowerCase().includes(query)) ||
                   (c.real && c.real.toLowerCase().includes(query));
        });

        renderCharacters(filtered);
    }

    function renderCharacters(chars) {
        const container = document.getElementById('charList');

        if (!container) return;

        if (!chars || chars.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="grid-column: 1/-1;">
                    <i class="fas fa-folder-open"></i>
                    <h3>未找到匹配角色</h3>
                    <p>尝试更换搜索关键词</p>
                </div>
            `;
            return;
        }

        container.innerHTML = chars.map(c => {
            const safeCharName = c.name.replace(/'/g, "\\'");
            const safeOwnerName = c.ownerName.replace(/'/g, "\\'");

            return `
            <div class="char-card">
                <div class="card-header" onclick="openSheet('${c.id}')">
                    <div class="card-name">${c.name}</div>
                    <div class="card-owner"><i class="fas fa-user"></i> ${c.ownerName}</div>
                </div>
                <div class="card-body" onclick="openSheet('${c.id}')">
                    <div class="card-info">
                        <div class="info-row">
                            <span class="info-label">异常</span>
                            <span class="info-value">${c.anom || '---'}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">职能</span>
                            <span class="info-value">${c.func || '---'}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">现实</span>
                            <span class="info-value">${c.real || '---'}</span>
                        </div>
                    </div>
                </div>
                <div class="card-footer">
                    <button class="btn-card-action btn-records" onclick="event.stopPropagation(); openRecordModal('${c.id}', '${safeCharName}')" title="嘉奖/申诫">
                        <i class="fas fa-medal"></i>
                    </button>
                    ${role >= 2 ? `<button class="btn-card-action btn-requisition-perm" onclick="event.stopPropagation(); openRequisitionPermModal(${c.ownerId})" title="权限物品授权">
                        <i class="fas fa-gift"></i>
                    </button>` : ''}
                    <button class="btn-card-action btn-docs" onclick="event.stopPropagation(); openDocModal('${c.id}', '${safeCharName}')" title="高墙授权">
                        <i class="fas fa-file-shield"></i>
                    </button>
                    <button class="btn-card-action" onclick="event.stopPropagation(); openGrantAnomalyModal('${c.id}', '${safeCharName}')" title="赋予异常能力">
                        <i class="fas fa-bolt"></i>
                    </button>
                    <button class="btn-card-action btn-slots" onclick="event.stopPropagation(); openSlotModal('${c.id}', '${safeCharName}')" title="槽位管理">
                        <i class="fas fa-unlock-alt"></i>
                    </button>
                    <button class="btn-card-action btn-delete" onclick="event.stopPropagation(); deleteCharacter('${c.id}', '${safeCharName}')" title="彻底删除角色">
                        <i class="fas fa-trash-alt"></i>
                    </button>
                    <button class="btn-card-action btn-view" onclick="openSheet('${c.id}')" title="编辑">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </div>
            `
        }).join('');
    }

    async function deleteCharacter(charId, charName) {
        if (!confirm(`【警告】确定要彻底删除角色 "${charName}" 吗？\n此操作不可逆，将删除该角色的所有数据和授权记录。`)) {
            return;
        }

        try {
            const res = await fetch(`/api/character/${charId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });
            const data = await res.json();

            if (data.success) {
                showToast('角色已彻底删除', true);
                loadCharacters();
            } else {
                showToast(data.message || '删除失败');
            }
        } catch (e) {
            console.error('Delete character error:', e);
            showToast('删除失败');
        }
    }
// ==========================================
    // 【修改】手机端手势 - 右侧菜单 (Right Sidebar)
    // ==========================================
// ==========================================
    // 【修改】手机端手势 - 右侧菜单 (Right Sidebar)
    // ==========================================
    let touchStartX = 0;
    let touchStartY = 0;
    const swipeThreshold = 80; // 滑动触发距离
    const edgeThreshold = 60;  // 边缘检测距离 (从屏幕边缘多少像素内开始滑动才有效)

    document.addEventListener('touchstart', e => {
        touchStartX = e.changedTouches[0].screenX;
        touchStartY = e.changedTouches[0].screenY;
    }, {passive: true});

    document.addEventListener('touchend', e => {
        const touchEndX = e.changedTouches[0].screenX;
        const touchEndY = e.changedTouches[0].screenY;
        handleSwipe(touchStartX, touchStartY, touchEndX, touchEndY);
    }, {passive: true});

    function handleSwipe(startX, startY, endX, endY) {
        const xDiff = endX - startX; // 正数=向右滑，负数=向左滑
        const yDiff = endY - startY;
        const menu = document.getElementById('sideMenu');
        const isOpen = menu.classList.contains('show');
        const screenWidth = window.innerWidth;

        // 1. 过滤垂直滚动：如果垂直移动幅度 > 水平移动幅度，视为滚动页面，不触发侧滑
        if (Math.abs(yDiff) > Math.abs(xDiff)) return;

        // 2. 打开菜单逻辑 (Open Menu)
        // 条件：
        // a. 菜单目前是关闭的 (!isOpen)
        // b. 向左滑动 (xDiff < -swipeThreshold)
        // c. 起始点在屏幕右侧边缘 (startX > screenWidth - edgeThreshold)
        if (!isOpen && xDiff < -swipeThreshold && startX > (screenWidth - edgeThreshold)) {
            toggleSideMenu();
        }

        // 3. 关闭菜单逻辑 (Close Menu)
        // 条件：
        // a. 菜单目前是打开的 (isOpen)
        // b. 向右滑动 (xDiff > swipeThreshold)
        if (isOpen && xDiff > swipeThreshold) {
            closeSideMenu();
        }
    }
	
    // ==========================================================
    // MODIFIED: 在跳转时增加 from=manager 参数
    // ==========================================================
    function openSheet(id) {
        window.location.href = `sheet.html?id=${id}&from=manager`;
    }

    function logout() {
        localStorage.removeItem('ta_uid');
        localStorage.removeItem('ta_token');
        localStorage.removeItem('ta_role');
        localStorage.removeItem('ta_is_admin');
        localStorage.removeItem('ta_is_manager');
        window.location.href = 'login.html';
    }

    // 回车提交
    // ==========================================
    // 槽位管理功能
    // ==========================================
    let currentSlotCharId = null;
    let currentSlotData = { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 };

    async function openSlotModal(charId, charName) {
        currentSlotCharId = charId;
        document.getElementById('modalCharName').textContent = charName;

        try {
            const res = await fetch(`/api/character/${charId}/slots`, {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                currentSlotData = await res.json();
            } else {
                currentSlotData = { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 };
            }
        } catch (e) {
            currentSlotData = { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 };
        }

        document.getElementById('anomSlotValue').textContent = currentSlotData.anomSlots;
        document.getElementById('realSlotValue').textContent = currentSlotData.realSlots;
        document.getElementById('anomUsed').textContent = currentSlotData.currentAnoms;
        document.getElementById('realUsed').textContent = currentSlotData.currentReals;

        document.getElementById('slotModal').classList.add('show');
    }

    function closeSlotModal() {
        document.getElementById('slotModal').classList.remove('show');
        currentSlotCharId = null;
    }

    function adjustSlot(type, delta) {
        const valueEl = document.getElementById(type + 'SlotValue');
        const usedEl = document.getElementById(type + 'Used');
        let current = parseInt(valueEl.textContent);
        const used = parseInt(usedEl.textContent);

        current += delta;

        const minValue = Math.max(3, used);
        if (current < minValue) current = minValue;

        // 上限限制已移除

        valueEl.textContent = current;
    }

    async function saveSlots() {
        if (!currentSlotCharId) return;

        const anomSlots = parseInt(document.getElementById('anomSlotValue').textContent);
        const realSlots = parseInt(document.getElementById('realSlotValue').textContent);

        try {
            const res = await fetch(`/api/character/${currentSlotCharId}/slots`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ anomSlots, realSlots })
            });

            const data = await res.json();
            if (data.success) {
                showToast('槽位设置已保存', true);
                closeSlotModal();
            } else {
                showToast(data.message || '保存失败');
            }
        } catch (e) {
            showToast('保存失败');
        }
    }
	
    // --- 侧边栏控制 ---
    function toggleSideMenu() {
        document.getElementById('sideMenu').classList.add('show');
        document.getElementById('sideMenuOverlay').classList.add('show');
    }
    function closeSideMenu() {
        document.getElementById('sideMenu').classList.remove('show');
        document.getElementById('sideMenuOverlay').classList.remove('show');
    }

    // --- 导航显隐逻辑 (Manager页) ---
    (function initNav() {
        const role = parseInt(localStorage.getItem('ta_role') || '0');
        
        // 只有超管 (Role 2) 才能看到"管理台"入口
        // (注：在 Manager 页面不需要显示"经理台"入口)
        if (role >= 2) {
            if(document.getElementById('deskBtnAdmin')) 
                document.getElementById('deskBtnAdmin').style.display = 'inline-flex';
            if(document.getElementById('mobBtnAdmin')) 
                document.getElementById('mobBtnAdmin').style.display = 'flex';
        }
    })();
    // ==========================================
    // 高墙文件授权功能（按角色卡授权）
    // ==========================================
    let currentDocCharId = null;
    let currentGrantAnomalyCharId = null;

    async function openDocModal(charId, charName) {
        currentDocCharId = charId;
        document.getElementById('docAuthCharName').textContent = charName;
        document.getElementById('docSearch').value = '';

        const listContainer = document.getElementById('docAuthList');
        listContainer.innerHTML = '<div style="padding:20px;text-align:center;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
        document.getElementById('docAuthModal').classList.add('show');

        try {
            const res = await fetch(`/api/manager/character/${charId}/permissions`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) throw new Error('无法获取权限列表');
            const files = await res.json();
            renderDocList(files);
        } catch (e) {
            console.error(e);
            listContainer.innerHTML = `<div style="color:red;text-align:center;">${e.message}</div>`;
        }
    }

    function renderDocList(files) {
        const container = document.getElementById('docAuthList');
        if (!files || files.length === 0) {
            container.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">无高墙文件</div>';
            return;
        }

        container.innerHTML = files.map(f => `
            <label class="doc-item">
                <input type="checkbox" value="${f.filename}" ${f.hasPerm ? 'checked' : ''}>
                <span>${f.filename.replace('.md', '')}</span>
            </label>
        `).join('');
    }

    function filterDocs() {
        const term = document.getElementById('docSearch').value.toLowerCase();
        document.querySelectorAll('#docAuthList .doc-item').forEach(item => {
            const text = item.querySelector('span').textContent.toLowerCase();
            item.style.display = text.includes(term) ? 'flex' : 'none';
        });
    }

    function closeDocModal() {
        document.getElementById('docAuthModal').classList.remove('show');
        currentDocCharId = null;
    }
    
    // ==========================================
    // 权限物品授权功能
    // ==========================================
    let currentPermUserId = null;
    
    async function openRequisitionPermModal(userId) {
        currentPermUserId = userId;
        const modal = document.getElementById('requisitionPermModal');
        const listContainer = document.getElementById('requisitionPermList');
        
        listContainer.innerHTML = '<div style="padding:20px;text-align:center;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
        modal.classList.add('show');
        document.getElementById('requisitionPermSearch').value = '';
        
        try {
            // 获取所有权限申领物
            const res1 = await fetch('/api/manager/requisitions' + (currentBranchId ? '?branchId=' + currentBranchId : ''), {
                headers: getAuthHeaders()
            });
            
            if (!res1.ok) throw new Error('获取申领物失败');
            const data1 = await res1.json();
            const allItems = (data1.items || []).filter(item => item.type === 'permission');
            
            // 获取用户已授权的申领物
            const res2 = await fetch(`/api/admin/user/${userId}/requisition-permissions`, {
                headers: getAuthHeaders()
            });
            
            let grantedIds = [];
            if (res2.ok) {
                const data2 = await res2.json();
                grantedIds = data2.permissions || [];
            }
            
            // 渲染列表
            if (allItems.length === 0) {
                listContainer.innerHTML = '<div style="padding:20px;text-align:center;color:#999;">暂无权限申领物</div>';
            } else {
                listContainer.innerHTML = allItems.map(item => `
                    <label class="doc-item" data-pd="${escapeHtml(item.pd || '')}">
                        <input type="checkbox" value="${item.id}" ${grantedIds.includes(item.id) ? 'checked' : ''}>
                        <span>
                            ${escapeHtml(item.name)}
                            ${item.pd ? `<span style="color: #95a5a6; font-size: 11px; margin-left: 8px;">[${escapeHtml(item.pd)}]</span>` : ''}
                            <span style="color: #f1c40f; margin-left: 8px;">
                                <i class="fas fa-award"></i> ${item.price || 0}
                            </span>
                        </span>
                    </label>
                `).join('');
            }
        } catch (e) {
            console.error('加载权限物品失败:', e);
            listContainer.innerHTML = '<div style="padding:20px;text-align:center;color:#e74c3c;">加载失败</div>';
        }
    }
    
    function filterRequisitionPerms() {
        const term = document.getElementById('requisitionPermSearch').value.toLowerCase();
        document.querySelectorAll('#requisitionPermList .doc-item').forEach(item => {
            const text = item.querySelector('span').textContent.toLowerCase();
            const pd = item.getAttribute('data-pd').toLowerCase();
            const matches = text.includes(term) || pd.includes(term);
            item.style.display = matches ? 'flex' : 'none';
        });
    }
    
    function closeRequisitionPermModal() {
        document.getElementById('requisitionPermModal').classList.remove('show');
        currentPermUserId = null;
    }
    
    async function saveRequisitionPerms() {
        if (!currentPermUserId) return;
        
        const selectedIds = Array.from(document.querySelectorAll('#requisitionPermList input:checked')).map(cb => cb.value);
        const btn = document.querySelector('#requisitionPermModal .btn-modal-confirm');
        btn.textContent = '保存中...';
        btn.disabled = true;
        
        try {
            const res = await fetch(`/api/admin/user/${currentPermUserId}/requisition-permissions`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ requisitionIds: selectedIds })
            });
            
            if (!res.ok) throw new Error('保存失败');
            const data = await res.json();
            
            if (!data.success) throw new Error(data.message || '保存失败');
            
            showToast('权限物品授权已更新', 'success');
            closeRequisitionPermModal();
        } catch (e) {
            console.error('保存失败:', e);
            showToast('保存失败: ' + e.message, 'error');
        } finally {
            btn.textContent = '保存';
            btn.disabled = false;
        }
    }

    async function saveDocPermissions() {
        if (!currentDocCharId) return;

        const selectedFiles = Array.from(document.querySelectorAll('#docAuthList input:checked')).map(cb => cb.value);

        const btn = document.querySelector('#docAuthModal .btn-modal-confirm');
        btn.textContent = '保存中...';
        btn.disabled = true;

        try {
            const res = await fetch(`/api/manager/character/${currentDocCharId}/permissions`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ permissions: selectedFiles })
            });

            const data = await res.json();
            if (data.success) {
                showToast('权限已更新', true);
                closeDocModal();
            } else {
                throw new Error(data.message || '更新失败');
            }
        } catch (e) {
            showToast(e.message, false);
        } finally {
            btn.textContent = '保存更改';
            btn.disabled = false;
        }
    }

    // ==========================================
    // 嘉奖/申诫记录功能
    // ==========================================
    let currentRecordCharId = null;
    let currentRecordTab = 'reward'; // 'reward' or 'reprimand'
    let currentRecords = { rewards: [], reprimands: [] };

    async function openRecordModal(charId, charName) {
        currentRecordCharId = charId;
        currentRecordTab = 'reward';
        document.getElementById('recordCharName').textContent = charName;
        document.getElementById('recordReasonInput').value = '';

        // 重置标签状态
        document.getElementById('tabReward').className = 'record-tab active-reward';
        document.getElementById('tabReprimand').className = 'record-tab';
        updateAddButton();

        // 显示弹窗
        document.getElementById('recordModal').classList.add('show');

        // 加载记录
        await loadRecords();
    }

    function closeRecordModal() {
        document.getElementById('recordModal').classList.remove('show');
        currentRecordCharId = null;
    }

    function switchRecordTab(tab) {
        currentRecordTab = tab;

        const tabReward = document.getElementById('tabReward');
        const tabReprimand = document.getElementById('tabReprimand');

        if (tab === 'reward') {
            tabReward.className = 'record-tab active-reward';
            tabReprimand.className = 'record-tab';
        } else {
            tabReward.className = 'record-tab';
            tabReprimand.className = 'record-tab active-reprimand';
        }

        updateAddButton();
        renderRecords();
    }

    function updateAddButton() {
        const btnAdd = document.getElementById('btnAddRecord');
        const btnDeduct = document.getElementById('btnDeductRecord');
        if (currentRecordTab === 'reward') {
            btnAdd.className = 'btn-add-record reward';
            btnAdd.innerHTML = '<i class="fas fa-plus"></i> 添加嘉奖';
            btnDeduct.innerHTML = '<i class="fas fa-minus"></i> 扣除嘉奖';
            btnDeduct.style.background = '#e67e22'; // 橙色
        } else {
            btnAdd.className = 'btn-add-record reprimand';
            btnAdd.innerHTML = '<i class="fas fa-plus"></i> 添加申诫';
            btnDeduct.innerHTML = '<i class="fas fa-minus"></i> 扣除申诫';
            btnDeduct.style.background = '#c0392b'; // 深红色
        }
    }

    async function loadRecords() {
        const listEl = document.getElementById('recordList');
        listEl.innerHTML = '<div style="text-align:center;padding:20px;"><i class="fas fa-circle-notch fa-spin"></i></div>';

        try {
            const res = await fetch(`/api/character/${currentRecordCharId}/records`, {
                headers: getAuthHeaders()
            });

            if (!res.ok) throw new Error('加载失败');

            currentRecords = await res.json();
            renderRecords();
        } catch (e) {
            listEl.innerHTML = '<div class="record-empty" style="color:#e74c3c;">加载失败</div>';
        }
    }

    function renderRecords() {
        const listEl = document.getElementById('recordList');
        const records = currentRecordTab === 'reward' ? currentRecords.rewards : currentRecords.reprimands;

        if (!records || records.length === 0) {
            listEl.innerHTML = `<div class="record-empty">暂无${currentRecordTab === 'reward' ? '嘉奖' : '申诫'}记录</div>`;
            return;
        }

        // 按时间倒序排列
        const sorted = [...records].sort((a, b) => b.date - a.date);

        listEl.innerHTML = sorted.map(r => {
            const date = new Date(r.date).toLocaleString('zh-CN', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            });
            const countBadge = (r.count && Math.abs(r.count) !== 1)
                ? `<span class="record-count-badge ${currentRecordTab === 'reprimand' ? 'reprimand' : ''}">x${r.count}</span>`
                : '';
            return `
                <div class="record-entry ${currentRecordTab === 'reprimand' ? 'reprimand' : ''}">
                    <div class="record-reason">${escapeHtml(r.reason)}${countBadge}</div>
                    <div class="record-meta">
                        <i class="fas fa-clock"></i> ${date}
                        ${r.addedByName ? `&nbsp;&nbsp;<i class="fas fa-user"></i> ${escapeHtml(r.addedByName)}` : ''}
                    </div>
                    <button class="btn-delete-record" onclick="deleteRecord('${r.id}')" title="删除">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `;
        }).join('');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async function addRecord(type = 'add') {
        const reason = document.getElementById('recordReasonInput').value.trim();
        let count = parseInt(document.getElementById('recordCountInput').value) || 1;

        if (!reason) {
            showToast('请输入原因');
            return;
        }

        if (count < 1 || count > 99) {
            showToast('数量必须在1-99之间');
            return;
        }

        // 如果是扣除，将数量变为负数
        if (type === 'deduct') {
            count = -count;
        }

        const endpoint = currentRecordTab === 'reward' ? 'reward' : 'reprimand';
        const btn = type === 'add' ? document.getElementById('btnAddRecord') : document.getElementById('btnDeductRecord');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> 处理中...';
        btn.disabled = true;

        try {
            // 清理数据
            const recordData = sanitizeObject({ reason, count });
            console.log('[添加记录] 发送数据:', recordData);

            const res = await safeFetch(`/api/character/${currentRecordCharId}/${endpoint}`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(recordData)
            });

            const data = await res.json();
            if (data.success) {
                showToast(data.message || '操作成功', true);
                document.getElementById('recordReasonInput').value = '';
                document.getElementById('recordCountInput').value = '1';
                await loadRecords();
            } else {
                throw new Error(data.message || '操作失败');
            }
        } catch (e) {
            showToast(e.message);
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }

    async function deleteRecord(recordId) {
        if (!confirm('确定要删除这条记录吗？')) return;

        try {
            const res = await fetch(`/api/character/${currentRecordCharId}/record/${recordId}?type=${currentRecordTab}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('记录已删除', true);
                await loadRecords();
            } else {
                throw new Error(data.message || '删除失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    // ==========================================
    // 外勤任务管理
    // ==========================================

    let currentMissionTab = 'active';
    let currentMissionId = null;
    let missionsList = [];
    let inboxMessages = [];

	// 加载任务列表
	async function loadMissions() {
		try {
			var url = `/api/manager/missions?status=${currentMissionTab}`;
			if (currentBranchId) url += '&branchId=' + currentBranchId;
			const res = await fetch(url, {
				headers: getAuthHeaders()
			});

			if (!res.ok) throw new Error('加载任务失败');
			missionsList = await res.json();
			renderMissions();
		} catch (e) {
			console.error('加载任务失败:', e);
			document.getElementById('missionList').innerHTML = `<div class="mission-empty">加载失败</div>`;
		}
	}

    function renderMissions() {
        const container = document.getElementById('missionList');
        const filtered = missionsList.filter(m => m.status === currentMissionTab);

        if (filtered.length === 0) {
            container.innerHTML = `<div class="mission-empty"><i class="fas fa-clipboard-list"></i><br>${currentMissionTab === 'active' ? '暂无进行中的任务' : '暂无已归档任务'}</div>`;
            return;
        }

        container.innerHTML = filtered.map(mission => {
            const memberCount = mission.members ? mission.members.length : 0;
            const memberPreview = mission.members && mission.members.length > 0
                ? mission.members.slice(0, 3).map(m => escapeHtml(m.name)).join('、') + (mission.members.length > 3 ? '...' : '')
                : '暂无成员';
            const missionTypeName = mission.mission_type === 'sweep' ? '清扫' : '收容';
            const missionTypeClass = mission.mission_type === 'sweep' ? 'sweep' : 'containment';

            return `
                <div class="mission-card clickable" data-id="${mission.id}" onclick="openMissionDetail('${mission.id}')">
                    <div class="mission-card-header">
                        <div class="mission-info">
                            <h4>${escapeHtml(mission.name)} <span class="mission-type-badge ${missionTypeClass}">${missionTypeName}</span></h4>
                            ${mission.description ? `<p class="mission-desc">${escapeHtml(mission.description)}</p>` : ''}
                        </div>
                        <div class="mission-quick-actions" onclick="event.stopPropagation()">
                            ${mission.status === 'active' ? `
                                <button class="btn-mission-action" onclick="event.stopPropagation();archiveMission('${mission.id}')" title="归档">
                                    <i class="fas fa-archive"></i>
                                </button>
                            ` : `
                                <button class="btn-mission-action" onclick="event.stopPropagation();restoreMission('${mission.id}')" title="恢复">
                                    <i class="fas fa-undo"></i>
                                </button>
                                <button class="btn-mission-action delete" onclick="event.stopPropagation();deleteMission('${mission.id}')" title="删除">
                                    <i class="fas fa-trash"></i>
                                </button>
                            `}
                        </div>
                    </div>
                    <div class="mission-card-footer">
                        <div class="mission-member-count">
                            <i class="fas fa-users"></i>
                            <span>${memberPreview}</span>
                        </div>
                        <div class="mission-enter-hint">
                            <i class="fas fa-chevron-right"></i>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

	// 切换任务标签页 (进行中 / 已归档)
	function switchMissionTab(tab) {
		currentMissionTab = tab; // 更新全局状态变量
		document.querySelectorAll('.mission-tabs button').forEach(btn => btn.classList.remove('active'));
		event.target.classList.add('active');
		
		// 关键：切换后，调用 loadMissions() 重新从服务器获取数据
		loadMissions(); 
	}

    function openMissionModal(editId = null) {
        currentMissionId = editId;
        document.getElementById('missionEditId').value = editId || '';
        document.getElementById('missionModalTitle').textContent = editId ? '编辑任务' : '创建任务';

        if (editId) {
            const mission = missionsList.find(m => m.id === editId);
            if (mission) {
                document.getElementById('missionName').value = mission.name;
                document.getElementById('missionType').value = mission.mission_type || 'containment';
                document.getElementById('missionDesc').value = mission.description || '';
            }
        } else {
            document.getElementById('missionName').value = '';
            document.getElementById('missionType').value = 'containment';
            document.getElementById('missionDesc').value = '';
        }

        document.getElementById('missionModal').classList.add('show');
    }

    function closeMissionModal() {
        document.getElementById('missionModal').classList.remove('show');
        currentMissionId = null;
    }

    function editMission(missionId) {
        openMissionModal(missionId);
    }

    async function saveMission() {
        const name = document.getElementById('missionName').value.trim();
        const missionType = document.getElementById('missionType').value;
        const description = document.getElementById('missionDesc').value.trim();
        const editId = document.getElementById('missionEditId').value;

        if (!name) {
            showToast('请输入任务名称');
            return;
        }

        try {
            const url = editId ? `/api/manager/mission/${editId}` : '/api/manager/mission';
            const method = editId ? 'PUT' : 'POST';

            // 清理数据
            const missionData = sanitizeObject({ name, description, missionType, branchId: currentBranchId });
            console.log('[保存任务] 发送数据:', missionData);

            const res = await safeFetch(url, {
                method,
                headers: getAuthHeaders(),
                body: JSON.stringify(missionData)
            });

            const data = await res.json();
            if (data.success) {
                showToast(editId ? '任务已更新' : '任务已创建', true);
                closeMissionModal();
                await loadMissions();
            } else {
                throw new Error(data.message || '保存失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function archiveMission(missionId) {
        if (!confirm('确定要归档此任务吗？')) return;

        try {
            const res = await fetch(`/api/manager/mission/${missionId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status: 'archived' })
            });

            const data = await res.json();
            if (data.success) {
                showToast('任务已归档', true);
                await loadMissions();
            } else {
                throw new Error(data.message || '归档失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function restoreMission(missionId) {
        try {
            const res = await fetch(`/api/manager/mission/${missionId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status: 'active' })
            });

            const data = await res.json();
            if (data.success) {
                showToast('任务已恢复', true);
                await loadMissions();
            } else {
                throw new Error(data.message || '恢复失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function deleteMission(missionId) {
        if (!confirm('确定要永久删除此任务吗？此操作不可撤销。')) return;

        try {
            const res = await fetch(`/api/manager/mission/${missionId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('任务已删除', true);
                await loadMissions();
            } else {
                throw new Error(data.message || '删除失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    // ==========================================
    // 成员管理
    // ==========================================

    let addMemberMissionId = null;

    let allAvailableCharacters = []; // 用于搜索过滤

    async function openAddMemberModal(missionId) {
        addMemberMissionId = missionId;
        const container = document.getElementById('memberSelectList');
        const searchInput = document.getElementById('memberSearchInput');
        if (searchInput) searchInput.value = '';
        
        container.innerHTML = '<div style="text-align:center;padding:20px;color:#95a5a6;"><i class="fas fa-spinner fa-spin"></i> 加载中...</div>';
        document.getElementById('addMemberModal').classList.add('show');

        try {
            var charUrl = '/api/manager/characters';
            if (currentBranchId) charUrl += '?branchId=' + currentBranchId;
            const res = await fetch(charUrl, {
                headers: getAuthHeaders()
            });
            if (!res.ok) throw new Error('加载角色失败');
            const characters = await res.json();

            // 获取当前任务的成员
            const mission = missionsList.find(m => m.id === missionId);
            const existingIds = mission?.members?.map(m => m.character_id) || [];

            // 过滤掉已在任务中的角色
            allAvailableCharacters = characters.filter(c => !existingIds.includes(c.id));
            renderAvailableMembers(allAvailableCharacters);

        } catch (e) {
            container.innerHTML = `<div style="text-align:center;padding:20px;color:#e74c3c;">加载失败: ${e.message}</div>`;
        }
    }

    function filterAvailableMembers() {
        const query = document.getElementById('memberSearchInput').value.toLowerCase().trim();
        const filtered = allAvailableCharacters.filter(c => 
            c.name.toLowerCase().includes(query)
        );
        renderAvailableMembers(filtered);
    }

    function renderAvailableMembers(characters) {
        const container = document.getElementById('memberSelectList');
        if (characters.length === 0) {
            container.innerHTML = '<div style="text-align:center;padding:20px;color:#95a5a6;">没有匹配的角色</div>';
            return;
        }

        container.innerHTML = characters.map(char => `
            <div class="member-select-item" onclick="addMemberToMission('${char.id}', '${escapeHtml(char.name)}')">
                <i class="fas fa-user-circle" style="font-size:24px;color:#3498db;margin-right:10px;"></i>
                <span>${escapeHtml(char.name)}</span>
            </div>
        `).join('');
    }

    function closeAddMemberModal() {
        document.getElementById('addMemberModal').classList.remove('show');
        addMemberMissionId = null;
    }

    async function addMemberToMission(charId, charName) {
        if (!addMemberMissionId) return;
        try {
            const res = await fetch(`/api/manager/mission/${addMemberMissionId}/member`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ characterId: charId })
            });

            const data = await res.json();
            if (data.success) {
                showToast(`已添加 ${charName}`, true);
                
                // 保存 missionId 用于后续刷新，因为 closeAddMemberModal 会清空它
                const missionIdToRefresh = addMemberMissionId;
                closeAddMemberModal();
                
                await loadMissions();
                // 如果在任务详情页，刷新成员列表
                if (currentMissionDetailId && currentMissionDetailId === missionIdToRefresh) {
                    const mission = missionsList.find(m => m.id === currentMissionDetailId);

                    if (mission) {
                        renderMissionDetailMembers(mission.members || []);
                    }
                }
            } else {
                throw new Error(data.message || '添加失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function removeMember(missionId, charId) {
        if (!confirm('确定要从任务中移除此成员吗？')) return;

        try {
            const res = await fetch(`/api/manager/mission/${missionId}/member/${charId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('成员已移除', true);
                await loadMissions();
            } else {
                throw new Error(data.message || '移除失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }


    // ==========================================
    // 经理收件箱
    // ==========================================

    async function loadInbox() {
        try {
            const res = await fetch('/api/manager/inbox', {
                headers: getAuthHeaders()
            });
            if (!res.ok) throw new Error('加载收件箱失败');
            inboxMessages = await res.json();
            updateInboxBadge();
        } catch (e) {
            console.error('加载收件箱失败:', e);
        }
    }

    function updateInboxBadge() {
        const unread = inboxMessages.filter(m => !m.read).length;
        const badge = document.getElementById('inboxBadge');
        if (!badge) return;
        badge.textContent = unread;
        badge.style.display = unread > 0 ? 'flex' : 'none';
    }

    function openInboxModal() {
        renderInboxList();
        document.getElementById('inboxModal').classList.add('show');
    }

    function closeInboxModal() {
        document.getElementById('inboxModal').classList.remove('show');
    }

    function renderInboxList() {
        const container = document.getElementById('inboxList');

        if (inboxMessages.length === 0) {
            container.innerHTML = '<div class="inbox-empty"><i class="fas fa-envelope-open" style="font-size:32px;margin-bottom:10px;"></i><br>收件箱为空</div>';
            return;
        }

        container.innerHTML = inboxMessages.map(msg => {
            const typeLabel = getMessageTypeLabel(msg.message_type);
            const timeStr = new Date(msg.created_at).toLocaleString('zh-CN');

            return `
                <div class="inbox-item ${msg.read ? '' : 'unread'}" onclick="openMailDetail(${msg.id})">
                    <div class="inbox-item-icon">
                        <i class="fas ${getMessageTypeIcon(msg.message_type)}"></i>
                    </div>
                    <div class="inbox-item-content">
                        <div class="inbox-item-subject">${escapeHtml(msg.subject || '(无主题)')}</div>
                        <div class="inbox-item-meta">
                            <span class="inbox-item-sender">${escapeHtml(msg.sender_name || '未知')}</span>
                            <span class="inbox-item-type">${typeLabel}</span>
                            <span class="inbox-item-time">${timeStr}</span>
                        </div>
                    </div>
                    ${msg.read ? '' : '<div class="inbox-unread-dot"></div>'}
                </div>
            `;
        }).join('');
    }

    function getMessageTypeLabel(type) {
        switch (type) {
            case 'mail': return '信件';
            case 'report': return '任务报告';
            case 'containment': return '收容物';
            default: return '邮件';
        }
    }

    function getMessageTypeIcon(type) {
        switch (type) {
            case 'mail': return 'fa-envelope';
            case 'report': return 'fa-file-alt';
            case 'containment': return 'fa-box';
            default: return 'fa-envelope';
        }
    }

    async function openMailDetail(msgId) {
        const msg = inboxMessages.find(m => m.id === msgId);
        if (!msg) return;

        // 标记已读
        if (!msg.read) {
            await markInboxRead(msgId);
        }

        document.getElementById('mailDetailSubject').textContent = msg.subject || '(无主题)';
        document.getElementById('mailDetailSender').textContent = msg.sender_name || '未知';
        document.getElementById('mailDetailTime').textContent = new Date(msg.created_at).toLocaleString('zh-CN');
        document.getElementById('mailDetailType').textContent = getMessageTypeLabel(msg.message_type);

        const contentEl = document.getElementById('mailDetailContent');
        const reportEl = document.getElementById('mailReportData');

        contentEl.innerHTML = escapeHtml(msg.content || '').replace(/\n/g, '<br>');

        // 如果是任务报告，显示报告数据
        if (msg.message_type === 'report' && msg.report_data) {
            try {
                const reportData = typeof msg.report_data === 'string' ? JSON.parse(msg.report_data) : msg.report_data;
                reportEl.style.display = 'block';
                reportEl.innerHTML = renderReportData(reportData);
            } catch (e) {
                reportEl.style.display = 'none';
            }
        } else {
            reportEl.style.display = 'none';
        }

        closeInboxModal();
        document.getElementById('mailDetailModal').classList.add('show');
    }

    function renderReportData(data) {
        return `
            <div class="report-section">
                <h4>异常状态</h4>
                <div class="report-status">
                    ${data.status?.neutralized ? '✓ 已中和' : ''}
                    ${data.status?.captured ? '✓ 已捕获' : ''}
                    ${data.status?.escaped ? '✓ 已逃脱' : ''}
                    ${data.status?.other ? `✓ 其他: ${escapeHtml(data.status.otherText || '')}` : ''}
                </div>
            </div>
            <div class="report-section">
                <h4>异常分析</h4>
                <table class="report-table">
                    <tr><td>代号</td><td>${escapeHtml(data.analysis?.codename || '-')}</td></tr>
                    <tr><td>行为</td><td>${escapeHtml(data.analysis?.behavior || '-')}</td></tr>
                    <tr><td>焦点</td><td>${escapeHtml(data.analysis?.focus || '-')}</td></tr>
                    <tr><td>领域</td><td>${escapeHtml(data.analysis?.domain || '-')}</td></tr>
                </table>
            </div>
            ${data.散逸端?.length > 0 ? `
            <div class="report-section">
                <h4>散逸端</h4>
                <table class="report-table">
                    <tr><th>姓名</th><th>数量</th><th>备注</th></tr>
                    ${data.散逸端.map(row => `<tr><td>${escapeHtml(row.name || '-')}</td><td>${escapeHtml(row.count || '-')}</td><td>${escapeHtml(row.note || '-')}</td></tr>`).join('')}
                </table>
            </div>
            ` : ''}
            <div class="report-section">
                <h4>评估</h4>
                <div class="report-rating">
                    <span>最终评级: <strong>${escapeHtml(data.rating || '-')}</strong></span>
                    <span>混沌池: <strong>${escapeHtml(data.chaosPool || '-')}</strong></span>
                </div>
            </div>
            ${data.mvp ? `<div class="report-section"><h4>MVP</h4><p>${escapeHtml(data.mvp)}</p></div>` : ''}
            ${data.probation ? `<div class="report-section"><h4>察看期</h4><p>${escapeHtml(data.probation)}</p></div>` : ''}
            ${data.participants ? `<div class="report-section"><h4>参与者</h4><p>${escapeHtml(data.participants)}</p></div>` : ''}
            ${data.可选目标?.length > 0 ? `
            <div class="report-section">
                <h4>可选目标</h4>
                <table class="report-table">
                    <tr><th>目标</th><th>奖励</th><th>按特工</th></tr>
                    ${data.可选目标.map(row => `<tr><td>${escapeHtml(row.target || '-')}</td><td>${escapeHtml(row.reward || '-')}</td><td>${escapeHtml(row.agent || '-')}</td></tr>`).join('')}
                </table>
            </div>
            ` : ''}
        `;
    }

    async function markInboxRead(msgId) {
        try {
            await fetch(`/api/manager/inbox/${msgId}/read`, {
                method: 'PUT',
                headers: getAuthHeaders()
            });
            const msg = inboxMessages.find(m => m.id === msgId);
            if (msg) msg.read = 1;
            updateInboxBadge();
            renderInboxList();
        } catch (e) {
            console.error('标记已读失败:', e);
        }
    }

    function closeMailDetailModal() {
        document.getElementById('mailDetailModal').classList.remove('show');
    }


    // ==========================================
    // 主标签页切换
    // ==========================================

    let lastLoadedTab = null;
    
    function switchMainTab(tabName) {
        // 切换按钮状态
        document.querySelectorAll('.main-tab').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.tab === tabName) {
                btn.classList.add('active');
            }
        });

        // 切换内容区域
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        const tabMap = {
            'characters': 'tabCharacters',
            'missions': 'tabMissions',
            'requisitions': 'tabRequisitions',
            'siphon': 'tabSiphon',
            'anomaly': 'tabAnomaly',
            'applications': 'tabApplications'
        };

        const targetTab = document.getElementById(tabMap[tabName]);
        if (targetTab) {
            targetTab.classList.add('active');
        }

        // 切换到任务页时重新加载任务列表
        if (tabName === 'missions') {
            loadMissions();
        }
        
        // 切换到申领物管理时加载申领物列表
        // 只在第一次切换或从其他标签页切换过来时加载
        if (tabName === 'requisitions' && lastLoadedTab !== 'requisitions') {
            loadRequisitionItems();
        }

        if (tabName === 'siphon' && lastLoadedTab !== 'siphon') {
            loadSiphonProducts();
        }

        if (tabName === 'applications') {
            loadBranchApplications();
        }

        if (tabName === 'anomaly' && lastLoadedTab !== 'anomaly') {
            loadAnomalyTemplates();
        }
        
        lastLoadedTab = tabName;
    }

    // ==========================================
    // 外勤任务详情全屏覆盖层
    // ==========================================

    let currentMissionDetailId = null;
    let currentMissionDetailData = null;

    function openMissionDetail(missionId) {
        currentMissionDetailId = missionId;
        const mission = missionsList.find(m => m.id === missionId);
        if (!mission) {
            showToast('任务不存在');
            return;
        }
        currentMissionDetailData = mission;

        // 填充详情
        document.getElementById('missionDetailName').textContent = mission.name;
        document.getElementById('missionDetailDesc').textContent = mission.description || '暂无描述';

        const statusEl = document.getElementById('missionDetailStatus');
        statusEl.textContent = mission.status === 'active' ? '进行中' : '已归档';
        statusEl.className = 'mission-detail-status' + (mission.status === 'archived' ? ' archived' : '');

        // 更新按钮显示
        const archiveBtn = document.querySelector('.btn-mission-archive');
        if (mission.status === 'archived') {
            archiveBtn.innerHTML = '<i class="fas fa-undo"></i> 恢复';
            archiveBtn.onclick = restoreCurrentMission;
        } else {
            archiveBtn.innerHTML = '<i class="fas fa-archive"></i> 归档';
            archiveBtn.onclick = archiveCurrentMission;
        }

        // 渲染成员列表
        renderMissionDetailMembers(mission.members || []);

        // 填充任务数值
        document.getElementById('missionChaosValue').value = mission.chaos_value || 0;
        document.getElementById('missionScatterValue').value = mission.scatter_value || 0;

        // 加载任务报告
        loadMissionReports(missionId);

        // 加载任务收件箱
        loadMissionInbox(missionId);

        // 显示覆盖层
        document.getElementById('missionDetailOverlay').classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeMissionDetail() {
        document.getElementById('missionDetailOverlay').classList.remove('active');
        document.body.style.overflow = '';
        currentMissionDetailId = null;
        currentMissionDetailData = null;
    }

    function renderMissionDetailMembers(members) {
        const container = document.getElementById('missionDetailMembers');

        if (!members || members.length === 0) {
            container.innerHTML = '<div class="no-members">暂无成员，点击上方"添加特工"按钮添加</div>';
            return;
        }
        container.innerHTML = members.map(member => {
            const safeName = escapeHtml(member.name).replace(/'/g, "\\'");
            return `
                <div class="agent-card clickable" data-char-id="${member.character_id}" onclick="openAgentDetail('${member.character_id}')">
                    <div class="agent-name">${escapeHtml(member.name)}</div>
                    <div class="agent-actions" onclick="event.stopPropagation()">
                        <button class="btn-agent-record" onclick="openRecordModal('${member.character_id}', '${safeName}')" title="嘉奖/申诫">
                            <i class="fas fa-medal"></i>
                        </button>
                        <button class="btn-agent-perm" onclick="openRequisitionPermModal(${member.user_id})" title="权限物品授权">
                            <i class="fas fa-gift"></i>
                        </button>
                        <button class="btn-agent-slots" onclick="openSlotModal('${member.character_id}', '${safeName}')" title="槽位管理">
                            <i class="fas fa-unlock-alt"></i>
                        </button>
                        <button class="btn-agent-docs" onclick="openDocModal('${member.character_id}', '${safeName}')" title="高墙授权">
                            <i class="fas fa-file-shield"></i>
                        </button>
                        <button class="btn-agent-anomaly" onclick="openGrantAnomalyModal('${member.character_id}', '${safeName}')" title="赋予异常能力">
                            <i class="fas fa-bolt"></i>
                        </button>
                        <button class="btn-remove-agent" onclick="removeMemberFromDetail('${member.character_id}')" title="移除">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    }

    // ==================== 任务报告管理 ====================
    let missionReports = [];

    async function loadMissionReports(missionId) {
        if (!missionId) return;

        try {
            const res = await fetch(`/api/manager/mission/${missionId}/reports`, {
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                missionReports = data.reports || [];
                renderMissionReports();
            }
        } catch (e) {
            console.error('加载任务报告失败', e);
        }
    }

    function renderMissionReports() {
        const container = document.getElementById('missionReportsList');
        const badge = document.getElementById('reportStatusBadge');

        // 更新状态徽章
        if (missionReports.length === 0) {
            badge.className = 'report-status-badge none';
            badge.textContent = '';
        } else {
            const hasUnreviewed = missionReports.some(r => r.status === 'submitted');
            const hasUnsent = missionReports.some(r => r.status === 'reviewed');
            const allSent = missionReports.every(r => r.status === 'sent');

            if (hasUnreviewed) {
                badge.className = 'report-status-badge submitted';
                badge.textContent = '待评审';
            } else if (hasUnsent) {
                badge.className = 'report-status-badge reviewed';
                badge.textContent = '待发送';
            } else if (allSent) {
                badge.className = 'report-status-badge sent';
                badge.textContent = '已完成';
            }
        }

        if (missionReports.length === 0) {
            container.innerHTML = '<div class="report-empty"><i class="fas fa-file-alt"></i><br>等待特工提交报告...</div>';
            return;
        }

        container.innerHTML = missionReports.map(report => {
            const statusNames = { submitted: '待评审', reviewed: '已评审', sent: '已发送' };
            const statusName = statusNames[report.status] || '未知';
            const date = new Date(report.submittedAt);
            const timeStr = date.toLocaleString();
            const isSent = report.status === 'sent';

            return `
                <div class="report-item" data-report-id="${report.id}">
                    <div class="report-item-header">
                        <div>
                            <span class="report-submitter">${escapeHtml(report.submitterName)}</span>
                            <span class="report-time">${timeStr}</span>
                        </div>
                        <span class="report-status ${report.status}">${statusName}</span>
                    </div>
                    <div class="report-rating-row">
                        <div class="report-rating-input">
                            <label>评级</label>
                            <select id="reportRating_${report.id}" ${isSent ? 'disabled' : ''}>
                                <option value="">选择评级</option>
                                <option value="S" ${report.rating === 'S' ? 'selected' : ''}>S</option>
                                <option value="A" ${report.rating === 'A' ? 'selected' : ''}>A</option>
                                <option value="B" ${report.rating === 'B' ? 'selected' : ''}>B</option>
                                <option value="C" ${report.rating === 'C' ? 'selected' : ''}>C</option>
                                <option value="D" ${report.rating === 'D' ? 'selected' : ''}>D</option>
                                <option value="F" ${report.rating === 'F' ? 'selected' : ''}>F</option>
                            </select>
                        </div>
                        <div class="report-rating-input">
                            <label>逸散端</label>
                            <input type="number" id="reportScatter_${report.id}" value="${report.scatterValue || 0}" ${isSent ? 'disabled' : ''}>
                        </div>
                    </div>
                    <div class="report-annotation">
                        <textarea id="reportAnnotation_${report.id}" placeholder="添加批注..." ${isSent ? 'disabled' : ''}>${escapeHtml((report.annotations || []).join('\n'))}</textarea>
                    </div>
                    <div class="report-actions">
                        ${!isSent ? `
                            <button class="btn-report save" onclick="saveReportReview(${report.id})">
                                <i class="fas fa-save"></i> 保存评审
                            </button>
                            <button class="btn-report send" onclick="sendReportRating(${report.id})" ${report.status === 'submitted' ? 'disabled title="请先保存评审"' : ''}>
                                <i class="fas fa-paper-plane"></i> 发送评级
                            </button>
                        ` : `
                            <span style="color:#27ae60;font-size:12px;"><i class="fas fa-check-circle"></i> 已发送给特工</span>
                        `}
                    </div>
                </div>
            `;
        }).join('');
    }

    async function saveReportReview(reportId) {
        if (!currentMissionDetailId) return;

        const rating = document.getElementById(`reportRating_${reportId}`).value;
        const scatterValue = parseInt(document.getElementById(`reportScatter_${reportId}`).value) || 0;
        const annotationText = document.getElementById(`reportAnnotation_${reportId}`).value;
        const annotations = annotationText.trim() ? annotationText.split('\n').filter(a => a.trim()) : [];

        try {
            // 清理数据
            const reviewData = sanitizeObject({ rating, scatterValue, annotations });
            console.log('[保存报告评审] 发送数据:', reviewData);

            const res = await safeFetch(`/api/manager/mission/${currentMissionDetailId}/report/${reportId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify(reviewData)
            });

            const data = await res.json();
            if (data.success) {
                showToast('评审已保存', true);
                await loadMissionReports(currentMissionDetailId);
            } else {
                throw new Error(data.message || '保存失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function sendReportRating(reportId) {
        if (!currentMissionDetailId) return;
        if (!confirm('确定要发送评级给特工吗？发送后将无法修改。')) return;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/report/${reportId}/send`, {
                method: 'POST',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('评级已发送', true);
                await loadMissionReports(currentMissionDetailId);
            } else {
                throw new Error(data.message || '发送失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    // ==================== 任务收件箱 ====================
    let missionInboxMessages = [];

    async function loadMissionInbox(missionId) {
        if (!missionId) return;

        try {
            const res = await fetch(`/api/manager/mission/${missionId}/inbox`, {
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                missionInboxMessages = data.messages || [];
                renderMissionInbox();
            }
        } catch (e) {
            console.error('加载任务收件箱失败', e);
        }
    }

    function renderMissionInbox() {
        const container = document.getElementById('missionInboxList');
        const badge = document.getElementById('missionInboxBadge');

        const unreadCount = missionInboxMessages.filter(m => !m.read).length;
        if (unreadCount > 0) {
            badge.textContent = unreadCount;
            badge.style.display = 'inline';
        } else {
            badge.style.display = 'none';
        }

        if (missionInboxMessages.length === 0) {
            container.innerHTML = '<div class="inbox-empty"><i class="fas fa-envelope-open"></i><br>暂无邮件</div>';
            return;
        }

        container.innerHTML = missionInboxMessages.map(msg => {
            const initial = (msg.sender_name || '?').charAt(0).toUpperCase();
            const typeNames = { mail: '邮件', containment: '收容物', report: '报告' };
            const typeName = typeNames[msg.message_type] || '邮件';
            const date = new Date(msg.created_at);
            const timeStr = `${date.getMonth()+1}/${date.getDate()} ${date.getHours()}:${String(date.getMinutes()).padStart(2,'0')}`;

            return `
                <div class="mission-inbox-item ${msg.read ? '' : 'unread'}" onclick="openMissionMail(${msg.id})">
                    <div class="mission-inbox-sender">${initial}</div>
                    <div class="mission-inbox-content">
                        <div class="mission-inbox-subject">${escapeHtml(msg.subject || '无标题')}</div>
                        <div class="mission-inbox-preview">${escapeHtml(msg.sender_name || '未知')}: ${escapeHtml((msg.content || '').substring(0, 50))}</div>
                    </div>
                    <div class="mission-inbox-meta">
                        <span class="mission-inbox-time">${timeStr}</span>
                        <span class="mission-inbox-type ${msg.message_type}">${typeName}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function openMissionMail(msgId) {
        const msg = missionInboxMessages.find(m => m.id === msgId);
        if (!msg) return;

        // 标记已读
        if (!msg.read && currentMissionDetailId) {
            try {
                await fetch(`/api/manager/mission/${currentMissionDetailId}/inbox/${msgId}/read`, {
                    method: 'PUT',
                    headers: getAuthHeaders()
                });

                msg.read = 1;
                renderMissionInbox();
            } catch (e) {}
        }

        // 使用现有的邮件详情弹窗
        document.getElementById('mailDetailSubject').textContent = msg.subject || '无标题';
        document.getElementById('mailDetailSender').textContent = msg.sender_name || '未知';
        document.getElementById('mailDetailTime').textContent = new Date(msg.created_at).toLocaleString();

        const typeNames = { mail: '普通邮件', containment: '收容物申领', report: '任务报告' };
        document.getElementById('mailDetailType').textContent = typeNames[msg.message_type] || '邮件';

        document.getElementById('mailDetailContent').textContent = msg.content || '';

        // 如果是报告类型，显示报告数据
        const reportDataEl = document.getElementById('mailReportData');
        if (msg.message_type === 'report' && msg.report_id) {
            try {
                const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/reports`, {
                    headers: getAuthHeaders()
                });
                if (res.ok) {
                    const data = await res.json();
                    const reports = (data.reports || []);
                    const report = reports.find(r => r.id === msg.report_id);
                    if (report) {
                        const rd = report.originalData || {};
                        const status = rd.status || {};
                        const analysis = rd.analysis || {};
                        const evaluation = rd.evaluation || {};
                        const scattering = rd.scattering || [];
                        const objectives = rd.objectives || [];
                        let statusText = [];
                        if (status.neutralized) statusText.push('已中和');
                        if (status.captured) statusText.push('已捕获');
                        if (status.escaped) statusText.push('已逃脱');
                        if (status.other) statusText.push(status.other);
                        let scHtml = scattering.map(s => `<li>${escapeHtml(s.name)}: ${escapeHtml(s.qty)} (${escapeHtml(s.note || '-')})</li>`).join('');
                        let objHtml = objectives.map(o => `<li>${escapeHtml(o.target)} - ${escapeHtml(o.reward)} (${escapeHtml(o.agent || '-')})</li>`).join('');
                        reportDataEl.innerHTML = `<div style="margin-top:12px;padding:12px;background:#f8f9fa;border-radius:8px;border-left:3px solid #3498db;">
                            <strong style="color:#2c3e50;"><i class="fas fa-file-alt"></i> 任务报告</strong>
                            <p style="color:#7f8c8d;font-size:12px;margin:4px 0 10px;">提交者: ${escapeHtml(report.submitterName)} | ${new Date(report.submittedAt).toLocaleString('zh-CN')}</p>
                            <div style="margin-bottom:8px;"><strong>异常状态:</strong> ${statusText.join(', ') || '未填写'}</div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px;font-size:13px;">
                                <div><strong>代号:</strong> ${escapeHtml(analysis.codename || '-')}</div>
                                <div><strong>行为:</strong> ${escapeHtml(analysis.behavior || '-')}</div>
                                <div><strong>焦点:</strong> ${escapeHtml(analysis.focus || '-')}</div>
                                <div><strong>领域:</strong> ${escapeHtml(analysis.domain || '-')}</div>
                            </div>
                            <div style="margin-bottom:8px;"><strong>MVP推荐:</strong> ${escapeHtml(evaluation.mvp || '无')}</div>
                            <div style="margin-bottom:8px;"><strong>参与者:</strong><div style="background:#fff;padding:8px;border-radius:4px;margin-top:4px;white-space:pre-wrap;font-size:13px;">${escapeHtml(evaluation.participants || '无')}</div></div>
                            ${scHtml ? `<div style="margin-bottom:8px;"><strong>散逸端:</strong><ul style="margin:4px 0;padding-left:18px;font-size:13px;">${scHtml}</ul></div>` : ''}
                            ${objHtml ? `<div><strong>可选目标:</strong><ul style="margin:4px 0;padding-left:18px;font-size:13px;">${objHtml}</ul></div>` : ''}
                        </div>`;
                        reportDataEl.style.display = 'block';
                    } else {
                        reportDataEl.innerHTML = '<div style="margin-top:10px;padding:10px;background:#f0f0f0;border-radius:8px;color:#999;">报告数据未找到</div>';
                        reportDataEl.style.display = 'block';
                    }
                }
            } catch (e) {
                reportDataEl.style.display = 'none';
            }
        } else {
            reportDataEl.style.display = 'none';
        }

        document.getElementById('mailDetailModal').classList.add('show');
    }

    async function viewMissionReport(reportId) {
        if (!currentMissionDetailId) return;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/reports`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) throw new Error('加载失败');

            const data = await res.json();
            if (!data.success) throw new Error(data.message || '加载失败');
            const reports = data.reports || [];
            const report = reports.find(r => r.id === reportId);

            if (!report) {
                showToast('报告不存在');
                return;
            }

            // 解析报告数据
            const reportData = report.originalData || {};
            const status = reportData.status || {};
            const analysis = reportData.analysis || {};
            const evaluation = reportData.evaluation || {};
            const scattering = reportData.scattering || [];
            const objectives = reportData.objectives || [];

            // 构建报告内容HTML
            let statusText = [];
            if (status.neutralized) statusText.push('已中和');
            if (status.captured) statusText.push('已捕获');
            if (status.escaped) statusText.push('已逃脱');
            if (status.other) statusText.push(status.other);

            let scatteringHtml = scattering.map(s => `<li>${escapeHtml(s.name)}: ${escapeHtml(s.qty)} (${escapeHtml(s.note || '-')})</li>`).join('');
            let objectivesHtml = objectives.map(o => `<li>${escapeHtml(o.target)} - ${escapeHtml(o.reward)} (${escapeHtml(o.agent || '-')})</li>`).join('');

            const reportHtml = `
                <div style="background:#fff;padding:20px;border-radius:8px;max-height:70vh;overflow-y:auto;">
                    <h3 style="margin:0 0 15px;color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px;">
                        <i class="fas fa-file-alt"></i> 任务报告
                    </h3>
                    <p style="color:#7f8c8d;font-size:12px;margin-bottom:15px;">
                        提交者: ${escapeHtml(report.submitterName)} |
                        时间: ${new Date(report.submittedAt).toLocaleString('zh-CN')}
                    </p>

                    <div style="margin-bottom:15px;">
                        <strong>异常状态:</strong> ${statusText.join(', ') || '未填写'}
                    </div>

                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px;">
                        <div><strong>代号:</strong> ${escapeHtml(analysis.codename || '-')}</div>
                        <div><strong>行为:</strong> ${escapeHtml(analysis.behavior || '-')}</div>
                        <div><strong>焦点:</strong> ${escapeHtml(analysis.focus || '-')}</div>
                        <div><strong>领域:</strong> ${escapeHtml(analysis.domain || '-')}</div>
                    </div>

                    <div style="margin-bottom:15px;">
                        <strong>MVP推荐:</strong> ${escapeHtml(evaluation.mvp || '无')}
                    </div>

                    <div style="margin-bottom:15px;">
                        <strong>参与者:</strong>
                        <div style="background:#f8f9fa;padding:10px;border-radius:4px;margin-top:5px;white-space:pre-wrap;">${escapeHtml(evaluation.participants || '无')}</div>
                    </div>

                    ${scatteringHtml ? `
                    <div style="margin-bottom:15px;">
                        <strong>散逸端:</strong>
                        <ul style="margin:5px 0;padding-left:20px;font-size:13px;">${scatteringHtml}</ul>
                    </div>
                    ` : ''}

                    ${objectivesHtml ? `
                    <div style="margin-bottom:15px;">
                        <strong>可选目标:</strong>
                        <ul style="margin:5px 0;padding-left:20px;font-size:13px;">${objectivesHtml}</ul>
                    </div>
                    ` : ''}

                    <button class="btn-modal btn-modal-cancel" onclick="this.closest('.report-view-overlay').remove()" style="width:100%;margin-top:10px;">关闭</button>
                </div>
            `;

            // 创建覆盖层显示报告
            const overlay = document.createElement('div');
            overlay.className = 'report-view-overlay';
            overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10001;display:flex;align-items:center;justify-content:center;padding:20px;';
            overlay.innerHTML = `<div style="max-width:600px;width:100%;">${reportHtml}</div>`;
            overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
            document.body.appendChild(overlay);

        } catch (e) {
            console.error('加载报告失败:', e);
            showToast('加载报告失败');
        }
    }

    async function deleteMissionMail(msgId) {
        if (!currentMissionDetailId) return;
        if (!confirm('确定要删除这封邮件吗？')) return;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/inbox/${msgId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('邮件已删除', true);
                closeMailDetailModal();
                await loadMissionInbox(currentMissionDetailId);
            }
        } catch (e) {
            showToast('删除失败');
        }
    }

    // ==================== 任务数值管理 ====================
    function adjustMissionValue(type, delta) {
        const inputId = type === 'chaos' ? 'missionChaosValue' : 'missionScatterValue';
        const input = document.getElementById(inputId);
        let value = parseInt(input.value) || 0;
        value += delta;
        // 混沌值不能为负，逸散端可以为负
        if (type === 'chaos' && value < 0) value = 0;
        input.value = value;
    }

    async function saveMissionValues() {
        if (!currentMissionDetailId) return;

        const chaosValue = parseInt(document.getElementById('missionChaosValue').value) || 0;
        const scatterValue = parseInt(document.getElementById('missionScatterValue').value) || 0;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ chaosValue, scatterValue })
            });

            const data = await res.json();
            if (data.success) {
                showToast('数值已保存', true);
                // 更新本地数据
                if (currentMissionDetailData) {
                    currentMissionDetailData.chaos_value = chaosValue;
                    currentMissionDetailData.scatter_value = scatterValue;
                }
                await loadMissions();
            } else {
                throw new Error(data.message || '保存失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    // ==================== 特工详情 ====================
    function openAgentDetail(charId) {
        // 在弹窗中显示角色卡的只读模式
        const modal = document.getElementById('agentDetailModal');
        const iframe = document.getElementById('agentDetailIframe');
        iframe.src = `sheet.html?id=${charId}&readonly=true&embed=true`;
        modal.classList.add('show');
    }

    function closeAgentDetailModal() {
        const modal = document.getElementById('agentDetailModal');
        const iframe = document.getElementById('agentDetailIframe');
        modal.classList.remove('show');
        // 清空iframe防止后台继续运行
        iframe.src = 'about:blank';
    }

    async function removeMemberFromDetail(charId) {
        if (!currentMissionDetailId) return;
        if (!confirm('确定要从任务中移除此特工吗？')) return;
                // 刷新详情页面

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/member/${charId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('特工已移除', true);
                await loadMissions();
                const mission = missionsList.find(m => m.id === currentMissionDetailId);
                if (mission) {
                    renderMissionDetailMembers(mission.members || []);
                }
            } else {
                throw new Error(data.message || '移除失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    function editCurrentMission() {
        if (!currentMissionDetailId) return;
        closeMissionDetail();
        openMissionModal(currentMissionDetailId);
    }

    function openMissionPanel() {
        if (!currentMissionDetailId) return;
        window.open('mission-panel.html?missionId=' + currentMissionDetailId, '_blank');
    }

    async function archiveCurrentMission() {
        if (!currentMissionDetailId) return;
        if (!confirm('确定要归档此任务吗？\n\n注意：如果有未发送的报告评级，需先完成所有评审并发送给特工后才能归档。')) return;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}/archive`, {
                method: 'POST',
                headers: getAuthHeaders()
            });

            const data = await res.json();
            if (data.success) {
                showToast('任务已归档', true);
                closeMissionDetail();
                await loadMissions();
            } else {
                throw new Error(data.message || '归档失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    async function restoreCurrentMission() {
        if (!currentMissionDetailId) return;

        try {
            const res = await fetch(`/api/manager/mission/${currentMissionDetailId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status: 'active' })
            });

            const data = await res.json();
            if (data.success) {
                showToast('任务已恢复', true);
                closeMissionDetail();
                await loadMissions();
            } else {
                throw new Error(data.message || '恢复失败');
            }
        } catch (e) {
            showToast(e.message);
        }
    }

    // ==========================================
    // 申领物管理
    // ==========================================
    let requisitionItems = []; // 存储所有申领物
    let currentEditingRequisitionId = null; // 当前编辑的申领物ID
    let currentAssignRequisitionId = null; // 当前要分配的申领物ID
    let allCharactersForSelect = []; // 用于角色选择的所有角色列表
    
    // 加载申领物列表
    async function loadRequisitionItems() {
        try {
            var reqUrl = '/api/manager/requisitions';
            if (currentBranchId) reqUrl += '?branchId=' + currentBranchId;
            const res = await fetch(reqUrl, {
                headers: getAuthHeaders()
            });
            
            if (!res.ok) {
                throw new Error('加载失败');
            }
            
            const data = await res.json();
            if (data.success) {
                requisitionItems = data.items || [];
                renderRequisitionItems();
            } else {
                throw new Error(data.message || '加载失败');
            }
        } catch (e) {
            console.error('加载申领物失败:', e);
            requisitionItems = [];
            renderRequisitionItems();
            showToast('加载申领物失败: ' + e.message, 'error');
        }
    }
    
    // 渲染申领物列表
    function renderRequisitionItems() {
        const container = document.getElementById('requisitionList');
        
        if (!container) {
            console.error('找不到 requisitionList 容器！');
            return;
        }
        
        if (!requisitionItems || requisitionItems.length === 0) {
            container.innerHTML = `
                <div class="requisition-empty">
                    <i class="fas fa-box-open" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i>
                    <p>暂无申领物，点击右上角添加</p>
                </div>
            `;
            return;
        }
        
        const searchInput = document.getElementById('itemSearchInput');
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        
        const filteredItems = requisitionItems.filter(item => {
            if (!searchTerm) return true;
            return (item.name || '').toLowerCase().includes(searchTerm) ||
                   (item.pd || '').toLowerCase().includes(searchTerm) ||
                   (item.effect || '').toLowerCase().includes(searchTerm);
        });
        
        if (filteredItems.length === 0) {
            container.innerHTML = `
                <div class="requisition-empty">
                    <i class="fas fa-search" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i>
                    <p>未找到匹配的申领物</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = filteredItems.map(item => `
            <div class="requisition-item-card" data-id="${item.id}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div class="requisition-item-name">${escapeHtml(item.name || '未命名物品')}</div>
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <span style="font-size: 10px; padding: 3px 8px; border-radius: 4px; font-weight: bold; 
                            ${item.type === 'basic' ? 'background: #e8f5e9; color: #27ae60;' : 'background: #fff3e0; color: #e67e22;'}">
                            ${item.type === 'basic' ? '基础' : '权限'}
                        </span>
                        ${item.once ? '<span style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:bold;background:#ffeaea;color:#e74c3c;">一次性</span>' : ''}
                        <span style="font-size: 12px; color: #f1c40f; font-weight: bold; display: flex; align-items: center; gap: 4px;">
                            <i class="fas fa-award"></i> ${item.price || 0}
                        </span>
                    </div>
                </div>
                <div class="requisition-item-pd">${escapeHtml(item.pd || '')}</div>
                <div class="requisition-item-effect">${item.effect || '暂无效果描述'}</div>
                <div class="requisition-item-actions">
                    <button class="btn-requisition-action btn-edit-requisition" onclick="openRequisitionModal('${item.id}')">
                        <i class="fas fa-edit"></i> 编辑
                    </button>
                    <button class="btn-requisition-action btn-assign-requisition" onclick="openAssignRequisitionModal('${item.id}')">
                        <i class="fas fa-user-plus"></i> 分配给角色
                    </button>
                    <button class="btn-requisition-action btn-delete-requisition" onclick="deleteRequisitionItem('${item.id}')">
                        <i class="fas fa-trash"></i> 删除
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    // 搜索申领物
    function filterRequisitions() {
        renderRequisitionItems();
    }
    
    // 打开新增/编辑申领物模态框
    function openRequisitionModal(itemId = null) {
        currentEditingRequisitionId = itemId;
        const modal = document.getElementById('requisitionModal');
        const title = document.getElementById('requisitionModalTitle');
        const nameInput = document.getElementById('requisitionItemName');
        const pdInput = document.getElementById('requisitionItemPd');
        const typeInput = document.getElementById('requisitionItemType');
        const priceInput = document.getElementById('requisitionItemPrice');
        const effectInput = document.getElementById('requisitionItemEffect');
        const onceInput = document.getElementById('requisitionItemOnce');
        
        // 清空价格选项列表
        document.getElementById('priceOptionsList').innerHTML = '';
        
        if (itemId) {
            const item = requisitionItems.find(i => i.id === itemId);
            if (item) {
                title.textContent = '编辑申领物';
                nameInput.value = item.name || '';
                pdInput.value = item.pd || '';
                typeInput.value = item.type || 'basic';
                priceInput.value = item.price || 0;
                onceInput.checked = !!item.once;
                
                // 加载价格选项
                if (item.prices && Array.isArray(item.prices)) {
                    item.prices.forEach(p => addPriceOption(p.description, p.price));
                }
                effectInput.innerHTML = item.effect || '';
            }
        } else {
            title.textContent = '新增申领物';
            nameInput.value = '';
            pdInput.value = '';
            typeInput.value = 'basic';
            priceInput.value = 0;
            onceInput.checked = false;
            effectInput.innerHTML = '';
        }
        
        modal.classList.add('active');
    }
    
    // 关闭申领物模态框
    function closeRequisitionModal() {
        document.getElementById('requisitionModal').classList.remove('active');
        currentEditingRequisitionId = null;
    }
    
    // 添加价格选项
    function addPriceOption(description = '', price = 0) {
        const container = document.getElementById('priceOptionsList');
        const optionDiv = document.createElement('div');
        optionDiv.className = 'price-option-item';
        const optionIndex = container.children.length + 1;
        optionDiv.innerHTML = `
            <input type="text" class="price-desc-input" placeholder="例如：标准版、豪华版、限定版等..." value="${description}">
            <input type="number" class="price-value-input" placeholder="价格" min="0" value="${price}">
            <button type="button" class="btn-remove-price" onclick="removePriceOption(this)" title="删除此选项">×</button>
        `;
        container.appendChild(optionDiv);
    }
    
    // 移除价格选项
    function removePriceOption(btn) {
        btn.parentElement.remove();
    }
    
    // 获取所有价格选项
    function getPriceOptions() {
        const container = document.getElementById('priceOptionsList');
        const options = [];
        container.querySelectorAll('.price-option-item').forEach(item => {
            const desc = item.querySelector('.price-desc-input').value.trim();
            const price = parseInt(item.querySelector('.price-value-input').value) || 0;
            if (desc || price > 0) {
                options.push({ description: desc, price });
            }
        });
        return options.length > 0 ? options : null;
    }
    
    // 保存申领物
    async function saveRequisitionItem() {
        const name = document.getElementById('requisitionItemName').value.trim();
        const pd = document.getElementById('requisitionItemPd').value.trim();
        const type = document.getElementById('requisitionItemType').value;
        const price = parseInt(document.getElementById('requisitionItemPrice').value) || 0;
        const effect = document.getElementById('requisitionItemEffect').innerHTML.trim();
        const prices = getPriceOptions();
        const once = document.getElementById('requisitionItemOnce').checked;
        
        if (!name) {
            showToast('请输入物品名称', 'error');
            return;
        }
        
        let itemData = {
            id: currentEditingRequisitionId || generateId(),
            name,
            pd,
            type,
            price,
            prices,
            once,
            effect,
            branchId: currentBranchId,
            createdAt: currentEditingRequisitionId ? 
                requisitionItems.find(i => i.id === currentEditingRequisitionId)?.createdAt : 
                new Date().toISOString()
        };
        
        try {
            // 清理数据中的特殊字符
            itemData = sanitizeObject(itemData);
            
            // 调试：打印要发送的数据
            console.log('[保存申领物] 准备发送的数据:', itemData);
            
            let jsonBody;
            try {
                jsonBody = JSON.stringify(itemData);
                console.log('[保存申领物] JSON 字符串长度:', jsonBody.length);
                // 显示前200个字符用于调试
                console.log('[保存申领物] JSON 前200字符:', jsonBody.substring(0, 200));
            } catch (stringifyError) {
                console.error('[保存申领物] JSON.stringify 失败:', stringifyError);
                showToast('数据格式化失败: ' + stringifyError.message, 'error');
                return;
            }
            
            // 保存到服务器数据库
            const res = await safeFetch('/api/manager/requisitions', {
                method: currentEditingRequisitionId ? 'PUT' : 'POST',
                headers: getAuthHeaders(),
                body: jsonBody
            });
            
            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.message || '保存失败');
            }
            
            const data = await res.json();
            
            if (!data.success) {
                throw new Error(data.message || '保存失败');
            }
            
            // 保存成功后重新从数据库加载
            await loadRequisitionItems();
            closeRequisitionModal();
            showToast(currentEditingRequisitionId ? '申领物已更新' : '申领物已创建', 'success');
            
        } catch (e) {
            console.error('保存申领物失败:', e);
            showToast('保存失败: ' + e.message, 'error');
        }
    }
    
    // 删除申领物
    async function deleteRequisitionItem(itemId) {
        if (!confirm('确定要删除这个申领物吗？')) return;
        
        try {
            const res = await fetch(`/api/manager/requisitions/${itemId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });
            
            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.message || '删除失败');
            }
            
            const data = await res.json();
            if (!data.success) {
                throw new Error(data.message || '删除失败');
            }
            
            // 删除成功后重新从数据库加载
            await loadRequisitionItems();
            showToast('申领物已删除', 'success');
            
        } catch (e) {
            console.error('删除申领物失败:', e);
            showToast('删除失败: ' + e.message, 'error');
        }
    }
    
    // 生成唯一ID
    function generateId() {
        return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    // 打开分配申领物模态框
    async function openAssignRequisitionModal(itemId) {
        currentAssignRequisitionId = itemId;
        const modal = document.getElementById('characterSelectModal');
        modal.classList.add('active');
        
        // 加载角色列表
        await loadCharactersForSelect();
        renderCharacterSelectList();
    }
    
    // 关闭角色选择模态框
    function closeCharacterSelectModal() {
        document.getElementById('characterSelectModal').classList.remove('active');
        currentAssignRequisitionId = null;
        document.getElementById('characterFilterInput').value = '';
    }
    
    // 加载可选择的角色列表
    async function loadCharactersForSelect() {
        try {
            var selUrl = '/api/manager/characters';
            if (currentBranchId) selUrl += '?branchId=' + currentBranchId;
            const res = await fetch(selUrl, {
                headers: getAuthHeaders()
            });
            
            if (!res.ok) {
                if (res.status === 401) {
                    showToast('登录已过期，请重新登录', 'error');
                    setTimeout(() => {
                        window.location.href = '/login.html';
                    }, 1500);
                }
                throw new Error('加载失败');
            }
            
            const characters = await res.json();
            
            // 格式化角色数据
            allCharactersForSelect = (characters || []).map(char => {
                let charData = {};
                try {
                    charData = typeof char.data === 'string' ? JSON.parse(char.data) : (char.data || {});
                } catch(e) {
                    charData = {};
                }
                
                return {
                    id: char.id,
                    name: charData.pName || char.name || '未命名角色',
                    playerName: char.ownerName || '未知玩家',
                    data: charData
                };
            });
        } catch (e) {
            console.error('加载角色列表失败:', e);
            allCharactersForSelect = [];
            showToast('加载角色列表失败: ' + e.message, 'error');
        }
    }
    
    // 渲染角色选择列表
    function renderCharacterSelectList() {
        const container = document.getElementById('characterSelectList');
        const filterTerm = document.getElementById('characterFilterInput').value.toLowerCase();
        
        let filteredChars = allCharactersForSelect;
        if (filterTerm) {
            filteredChars = allCharactersForSelect.filter(char => {
                const charName = (char.name || '').toLowerCase();
                const playerName = (char.playerName || '').toLowerCase();
                return charName.includes(filterTerm) || playerName.includes(filterTerm);
            });
        }
        
        if (filteredChars.length === 0) {
            container.innerHTML = `
                <div style="text-align:center;padding:20px;color:#999;">
                    <i class="fas fa-user-slash" style="font-size:36px;margin-bottom:10px;"></i>
                    <p>未找到匹配的角色</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = filteredChars.map(char => {
            const charId = char.id;
            return `
                <div class="character-select-item" data-char-id="${charId}" onclick="toggleCharacterSelection('${charId}')">
                    <input type="checkbox" class="character-select-checkbox" id="char-check-${charId}">
                    <div class="character-select-info">
                        <div class="character-select-name">${escapeHtml(char.name)}</div>
                        <div class="character-select-player">玩家: ${escapeHtml(char.playerName)}</div>
                    </div>
                </div>
            `;
        }).join('');
    }
    
    // 筛选角色列表
    function filterCharacterList() {
        renderCharacterSelectList();
    }
    
    // 切换角色选中状态
    function toggleCharacterSelection(charId) {
        const item = document.querySelector(`.character-select-item[data-char-id="${charId}"]`);
        const checkbox = document.getElementById(`char-check-${charId}`);
        if (item && checkbox) {
            checkbox.checked = !checkbox.checked;
            if (checkbox.checked) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        }
    }
    
    // 确认分配申领物
    async function confirmAssignRequisitions() {
        const selectedCharIds = [];
        document.querySelectorAll('.character-select-checkbox:checked').forEach(checkbox => {
            const charId = checkbox.id.replace('char-check-', '');
            selectedCharIds.push(charId);
        });
        
        if (selectedCharIds.length === 0) {
            showToast('请至少选择一个角色', 'error');
            return;
        }
        
        const item = requisitionItems.find(i => i.id === currentAssignRequisitionId);
        if (!item) {
            showToast('申领物不存在', 'error');
            return;
        }
        
        try {
            // 清理并准备数据
            const assignData = sanitizeObject({
                requisitionId: currentAssignRequisitionId,
                characterIds: selectedCharIds,
                itemData: {
                    item: item.name || '',
                    pd: item.pd || '',
                    eff: item.effect || '',
                    once: !!item.once
                },
                branchId: currentBranchId
            });
            
            console.log('[分配申领物] 发送数据:', assignData);
            
            // 尝试通过API分配
            const res = await safeFetch('/api/manager/assign-requisition', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(assignData)
            });
            const data = await res.json();
            if (data.success) {
                showToast(`已成功分配给 ${selectedCharIds.length} 个角色`, 'success');
                closeCharacterSelectModal();
                return;
            } else {
                throw new Error(data.message || '分配失败');
            }
        } catch (e) {
            console.error('分配申领物失败:', e);
            showToast('分配失败: ' + e.message, 'error');
        }
    }

    // ==========================================
    // 初始化和事件监听
    // ==========================================

    // 初始化页面
    try {
        loadCharacters();
    } catch (e) {
        console.error('loadCharacters failed:', e);
        const container = document.getElementById('charList');
        if (container) {
            container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>初始化失败</h3>
                <p>${e.message || '未知错误'}</p>
            </div>`;
        }
    }
    
    loadMissions();
    loadInbox();
    loadMyBranches().then(function() { loadBranchScatter(); });
    
    // 通用：点击遮罩关闭弹窗
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === this) {
                this.classList.remove('show');
            }
        });
    });

    let siphonProducts = [];
    let currentEditingSiphonId = null;

    async function loadSiphonProducts() {
        try {
            var siphonUrl = '/api/manager/siphon-products';
            if (currentBranchId) siphonUrl += '?branchId=' + currentBranchId;
            const res = await fetch(siphonUrl, { headers: getAuthHeaders() });
            if (!res.ok) throw new Error('加载失败');
            const data = await res.json();
            if (data.success) {
                siphonProducts = data.products || [];
                renderSiphonProducts();
            }
        } catch (e) {
            console.error('加载Siphon商品失败:', e);
            siphonProducts = [];
            renderSiphonProducts();
        }
    }

    function renderSiphonProducts() {
        const container = document.getElementById('siphonProductList');
        if (!container) return;
        container.innerHTML = '';

        const searchTerm = (document.getElementById('siphonSearchInput')?.value || '').toLowerCase();
        const filtered = siphonProducts.filter(p => !searchTerm || p.name.toLowerCase().includes(searchTerm));

        if (filtered.length === 0) {
            container.innerHTML = `<div class="requisition-empty"><i class="fas fa-eye" style="font-size:48px;margin-bottom:15px;opacity:0.3;color:#2980b9"></i><p>${siphonProducts.length === 0 ? '暂无Siphon商品，点击"新增商品"创建' : '没有匹配的商品'}</p></div>`;
            return;
        }

        container.innerHTML = filtered.map(product => `
            <div class="requisition-item-card" data-id="${product.id}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div class="requisition-item-name">${escapeHtml(product.name || '未命名商品')}</div>
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <span style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:bold;background:rgba(41,128,185,0.1);color:#2980b9;">
                            <i class="fas fa-eye"></i> Siphon
                        </span>
                        <span style="font-size:12px;color:#e74c3c;font-weight:bold;display:flex;align-items:center;gap:4px;">
                            <i class="fas fa-exclamation-circle"></i> ${product.price}申诫
                        </span>
                    </div>
                </div>
                <div class="requisition-item-effect">${product.description || '暂无描述'}</div>
                <div class="requisition-item-actions">
                    <button class="btn-requisition-action btn-edit-requisition" onclick="openSiphonModal('${product.id}')">
                        <i class="fas fa-edit"></i> 编辑
                    </button>
                    <button class="btn-requisition-action btn-delete-requisition" onclick="deleteSiphonProduct('${product.id}')">
                        <i class="fas fa-trash"></i> 删除
                    </button>
                </div>
            </div>
        `).join('');
    }

    function filterSiphonProducts() { renderSiphonProducts(); }

    function openSiphonModal(productId = null) {
        currentEditingSiphonId = productId;
        const modal = document.getElementById('siphonModal');
        const title = document.getElementById('siphonModalTitle');
        const nameInput = document.getElementById('siphonProductName');
        const priceInput = document.getElementById('siphonProductPrice');
        const descInput = document.getElementById('siphonProductDesc');

        if (productId) {
            const product = siphonProducts.find(p => p.id === productId);
            if (product) {
                title.textContent = '编辑商品';
                nameInput.value = product.name || '';
                priceInput.value = product.price || 1;
                descInput.innerHTML = product.description || '';
            }
        } else {
            title.textContent = '新增商品';
            nameInput.value = '';
            priceInput.value = 1;
            descInput.innerHTML = '';
        }
        modal.classList.add('active');
    }

    function closeSiphonModal() {
        document.getElementById('siphonModal').classList.remove('active');
        currentEditingSiphonId = null;
    }

    async function saveSiphonProduct() {
        const name = document.getElementById('siphonProductName').value.trim();
        const price = parseInt(document.getElementById('siphonProductPrice').value) || 1;
        const description = document.getElementById('siphonProductDesc').innerHTML.trim();

        if (!name) { showToast('请输入商品名称', 'error'); return; }

        const body = { id: currentEditingSiphonId, name, price, description, branchId: currentBranchId };

        try {
            const res = await fetch('/api/manager/siphon-products', {
                method: currentEditingSiphonId ? 'PUT' : 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(body)
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message, 'success');
                closeSiphonModal();
                await loadSiphonProducts();
            } else {
                showToast(data.message || '保存失败', 'error');
            }
        } catch (e) {
            showToast('保存失败: ' + e.message, 'error');
        }
    }

    async function deleteSiphonProduct(productId) {
        if (!confirm('确定要删除此商品吗？')) return;
        try {
            const res = await fetch(`/api/manager/siphon-products/${productId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });
            const data = await res.json();
            if (data.success) {
                showToast('商品已删除', 'success');
                await loadSiphonProducts();
            } else {
                showToast(data.message || '删除失败', 'error');
            }
        } catch (e) {
            showToast('删除失败', 'error');
        }
    }

    let branchApplications = [];

    async function loadBranchApplications() {
        try {
            const res = await fetch('/api/manager/branch-applications', { headers: getAuthHeaders() });
            const data = await res.json();
            if (data.success) {
                branchApplications = data.applications || [];
                renderBranchApplications();
            }
        } catch (e) {
            console.error('加载申请失败:', e);
            branchApplications = [];
            renderBranchApplications();
        }
    }

    function renderBranchApplications() {
        const container = document.getElementById('applicationList');
        if (!container) return;

        if (branchApplications.length === 0) {
            container.innerHTML = `<div class="requisition-empty"><i class="fas fa-door-open" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i><p>暂无待审批的入职申请</p></div>`;
            return;
        }

        container.innerHTML = branchApplications.map(app => {
            const date = new Date(app.created_at).toLocaleString('zh-CN');
            return `
                <div class="requisition-item-card">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                        <div>
                            <div class="requisition-item-name">${escapeHtml(app.user_name || app.username)}</div>
                            <div style="font-size:12px;color:#aaa;margin-top:4px;">账号: ${escapeHtml(app.username || '')} | 申请加入: ${escapeHtml(app.branch_name || '')}</div>
                            <div style="font-size:11px;color:#999;margin-top:2px;"><i class="fas fa-clock"></i> ${date}</div>
                        </div>
                    </div>
                    <div class="requisition-item-actions">
                        <button class="btn-requisition-action" style="background:#27ae60;color:white;" onclick="reviewApplication(${app.id}, 'approved')">
                            <i class="fas fa-check"></i> 批准
                        </button>
                        <button class="btn-requisition-action" style="background:#e74c3c;color:white;" onclick="reviewApplication(${app.id}, 'rejected')">
                            <i class="fas fa-times"></i> 拒绝
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function reviewApplication(appId, status) {
        const action = status === 'approved' ? '批准' : '拒绝';
        if (!confirm(`确定${action}此申请吗？`)) return;
        try {
            const res = await fetch(`/api/manager/branch-application/${appId}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status })
            });
            const data = await res.json();
            if (data.success) {
                showToast(`已${action}`, 'success');
                await loadBranchApplications();
            } else {
                showToast(data.message || '操作失败', 'error');
            }
        } catch (e) {
            showToast('操作失败', 'error');
        }
    }

    // ==========================================
    // 异常能力模板管理
    // ==========================================

    let anomalyTemplates = [];
    let anomalyDocFiles = [];

    async function loadAnomalyTemplates() {
        if (!currentBranchId) return;
        try {
            const res = await fetch('/api/anomaly-templates?branchId=' + currentBranchId, { headers: getAuthHeaders() });
            anomalyTemplates = await res.json();
            renderAnomalyTemplates();
        } catch(e) {
            showToast('加载异常能力模板失败');
        }
    }

    async function loadAnomalyDocFiles() {
        try {
            const res = await fetch('/api/documents/list', { headers: getAuthHeaders() });
            const files = await res.json();
            anomalyDocFiles = files.map(f => f.filename);
            const sel = document.getElementById('anomTplDocFile');
            if (sel) {
                sel.innerHTML = '<option value="">-- 不关联 --</option>';
                anomalyDocFiles.forEach(f => {
                    sel.innerHTML += '<option value="' + f + '">' + f.replace(/\.md$/i, '') + '</option>';
                });
            }
        } catch(e) {}
    }

    function renderAnomalyTemplates() {
        const container = document.getElementById('anomalyTemplateList');
        if (!container) return;
        if (!anomalyTemplates.length) {
            container.innerHTML = '<div class="requisition-empty"><i class="fas fa-bolt" style="font-size:48px;margin-bottom:15px;opacity:0.3;"></i><p>暂无异常能力模板，点击右上角创建</p></div>';
            return;
        }
        container.innerHTML = anomalyTemplates.map(t => {
            const docLabel = t.doc_filename ? t.doc_filename.replace(/\.md$/i, '') : '';
            let html = '<div class="anomaly-tpl-card">';
            html += '<button class="anom-tpl-edit-btn" onclick="event.stopPropagation();openAnomalyTemplateModal(\'' + t.id + '\')"><i class="fas fa-pen"></i></button>';
            html += '<button class="anom-tpl-del-btn" onclick="event.stopPropagation();deleteAnomalyTemplate(\'' + t.id + '\')"><i class="fas fa-trash"></i></button>';
            html += '<div class="anomaly-tpl-title-bar">';
            html += '<div class="anomaly-tpl-title-row">';
            html += '<span class="anomaly-tpl-disp-name">' + (t.name || '') + '</span>';
            html += '<span class="anomaly-tpl-field-sep">|</span>';
            html += '<span class="anomaly-tpl-disp-trig">' + (t.trig || '') + '</span>';
            if (docLabel) html += '<span class="anomaly-tpl-doc-badge"><i class="fas fa-file-shield"></i> ' + docLabel + '</span>';
            html += '</div>';
            if (t.qual) html += '<div class="anomaly-tpl-disp-qual">' + t.qual + '</div>';
            html += '</div>';
            html += '<div class="anomaly-tpl-body">';
            html += '<div class="anomaly-tpl-result-row">';
            html += '<div class="anomaly-tpl-result succ"><div class="anomaly-tpl-result-label"><i class="fas fa-check-circle"></i> 成功时</div><div class="anomaly-tpl-disp-succ">' + (t.succ || '<span style="color:#555;">-</span>') + '</div></div>';
            html += '<div class="anomaly-tpl-result fail"><div class="anomaly-tpl-result-label"><i class="fas fa-times-circle"></i> 失败时</div><div class="anomaly-tpl-disp-fail">' + (t.fail || '<span style="color:#555;">-</span>') + '</div></div>';
            html += '</div>';
            html += '</div>';
            if (t.tdesc) {
                html += '<div class="anomaly-tpl-question">';
                html += '<div class="anomaly-tpl-question-text"><i class="fas fa-question-circle"></i> ' + t.tdesc + '</div>';
                if (t.t1 || t.t2) {
                    html += '<div class="anomaly-tpl-answers">';
                    if (t.t1) html += '<div class="anomaly-tpl-answer">A: ' + t.t1 + (t.t1v ? ' <code>' + t.t1v + '</code>' : '') + '</div>';
                    if (t.t2) html += '<div class="anomaly-tpl-answer">B: ' + t.t2 + (t.t2v ? ' <code>' + t.t2v + '</code>' : '') + '</div>';
                    html += '</div>';
                }
                html += '</div>';
            }
            html += '</div>';
            return html;
        }).join('');
    }

    async function openAnomalyTemplateModal(editId) {
        const modal = document.getElementById('anomalyTemplateModal');
        document.getElementById('anomalyEditId').value = editId || '';
        document.getElementById('anomalyModalTitle').textContent = editId ? '编辑异常能力模板' : '创建异常能力模板';

        document.getElementById('anomTplName').value = '';
        document.getElementById('anomTplTrig').value = '';
        document.getElementById('anomTplQual').value = '';
        document.getElementById('anomTplSucc').innerHTML = '';
        document.getElementById('anomTplFail').innerHTML = '';
        document.getElementById('anomTplTdesc').value = '';
        document.getElementById('anomTplT1').value = '';
        document.getElementById('anomTplT1v').value = '';
        document.getElementById('anomTplT2').value = '';
        document.getElementById('anomTplT2v').value = '';
        document.getElementById('anomTplDocFile').value = '';

        await loadAnomalyDocFiles();

        if (editId) {
            const t = anomalyTemplates.find(x => x.id === editId);
            if (t) {
                document.getElementById('anomTplName').value = t.name || '';
                document.getElementById('anomTplTrig').value = t.trig || '';
                document.getElementById('anomTplQual').value = t.qual || '';
                document.getElementById('anomTplSucc').innerHTML = t.succ || '';
                document.getElementById('anomTplFail').innerHTML = t.fail || '';
                document.getElementById('anomTplTdesc').value = t.tdesc || '';
                document.getElementById('anomTplT1').value = t.t1 || '';
                document.getElementById('anomTplT1v').value = t.t1v || '';
                document.getElementById('anomTplT2').value = t.t2 || '';
                document.getElementById('anomTplT2v').value = t.t2v || '';
                document.getElementById('anomTplDocFile').value = t.doc_filename || '';
            }
        }

        modal.classList.add('show');
    }

    function closeAnomalyTemplateModal() {
        document.getElementById('anomalyTemplateModal').classList.remove('show');
    }

    async function saveAnomalyTemplate() {
        const editId = document.getElementById('anomalyEditId').value;
        const name = document.getElementById('anomTplName').value.trim();
        if (!name) { showToast('请输入能力名称'); return; }

        const body = {
            branchId: currentBranchId,
            name,
            trig: document.getElementById('anomTplTrig').value,
            qual: document.getElementById('anomTplQual').value,
            succ: document.getElementById('anomTplSucc').innerHTML,
            fail: document.getElementById('anomTplFail').innerHTML,
            tdesc: document.getElementById('anomTplTdesc').value,
            t1: document.getElementById('anomTplT1').value,
            t1v: document.getElementById('anomTplT1v').value,
            t2: document.getElementById('anomTplT2').value,
            t2v: document.getElementById('anomTplT2v').value,
            docFilename: document.getElementById('anomTplDocFile').value
        };

        try {
            const url = editId ? '/api/anomaly-templates/' + editId : '/api/anomaly-templates';
            const method = editId ? 'PUT' : 'POST';
            const res = await fetch(url, { method, headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            const data = await res.json();
            if (data.success) {
                showToast(editId ? '已更新' : '已创建', 'success');
                closeAnomalyTemplateModal();
                await loadAnomalyTemplates();
            } else {
                showToast(data.message || '保存失败');
            }
        } catch(e) {
            showToast('保存失败');
        }
    }

    async function deleteAnomalyTemplate(id) {
        if (!confirm('确定删除此异常能力模板？')) return;
        try {
            const res = await fetch('/api/anomaly-templates/' + id, { method: 'DELETE', headers: getAuthHeaders() });
            const data = await res.json();
            if (data.success) {
                showToast('已删除', 'success');
                await loadAnomalyTemplates();
            } else {
                showToast(data.message || '删除失败');
            }
        } catch(e) {
            showToast('删除失败');
        }
    }

    async function openGrantAnomalyModal(charId, charName) {
        currentGrantAnomalyCharId = charId;
        document.getElementById('grantAnomalyCharName').textContent = charName;

        if (!anomalyTemplates.length) {
            await loadAnomalyTemplates();
        }

        const list = document.getElementById('grantAnomalyList');
        if (!anomalyTemplates.length) {
            list.innerHTML = '<div style="padding:10px;text-align:center;color:#999;">暂无可赋予的异常能力模板</div>';
        } else {
            list.innerHTML = anomalyTemplates.map(t => {
                const docLabel = t.doc_filename ? ' (' + t.doc_filename.replace(/\.md$/i, '') + ')' : '';
                return `
                    <label class="doc-item">
                        <input type="checkbox" value="${t.id}" ${t.granted ? 'checked' : ''}>
                        <div class="doc-item-content">
                            <div class="doc-item-name">${t.name}</div>
                            ${docLabel ? `<div class="doc-item-meta">${docLabel}</div>` : ''}
                        </div>
                    </label>
                `;
            }).join('');
        }

        document.getElementById('grantAnomalyModal').classList.add('show');
    }

    function closeGrantAnomalyModal() {
        document.getElementById('grantAnomalyModal').classList.remove('show');
    }

    async function saveGrantedAnomalies() {
        if (!currentGrantAnomalyCharId) return;

        const selectedIds = Array.from(document.querySelectorAll('#grantAnomalyList input:checked')).map(cb => cb.value);
        const btn = document.querySelector('#grantAnomalyModal .btn-modal-confirm');
        btn.textContent = '保存中...';
        btn.disabled = true;

        try {
            const promises = selectedIds.map(id =>
                fetch('/api/anomaly-templates/' + id + '/grant', {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({ characterId: currentGrantAnomalyCharId })
                })
            );

            await Promise.all(promises);
            showToast('异常能力已赋予', 'success');
            closeGrantAnomalyModal();
        } catch (e) {
            showToast('赋予失败', 'error');
        } finally {
            btn.textContent = '保存';
            btn.disabled = false;
        }
    }

    async function grantAnomalyToChar(templateId) {
        const charId = document.getElementById('grantAnomalyCharId').value;
        try {
            const res = await fetch('/api/anomaly-templates/' + templateId + '/grant', {
                method: 'POST',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ characterId: charId })
            });
            const data = await res.json();
            if (data.success) {
                showToast('异常能力已赋予', 'success');
            } else {
                showToast(data.message || '赋予失败');
            }
        } catch(e) {
            showToast('赋予失败');
        }
    }