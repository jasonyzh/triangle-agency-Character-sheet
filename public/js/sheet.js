const params = new URLSearchParams(window.location.search);
const charId = params.get('id');
const isReadOnly = params.get('readonly') === 'true';
const isEmbed = params.get('embed') === 'true';
const token = localStorage.getItem('ta_token');

// 获取带认证的请求头
function getAuthHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
}

// [修改] 初始化增加 bonuses
let CONFIG_DATA = { anoms: [], realities: [], functions: [], bonuses: [] };

// 槽位限制
let SLOT_LIMITS = { anomSlots: 10, realSlots: 10 };

async function loadConfigData() {
    try {
        const res = await fetch('/api/options');
        if (res.ok) {
            CONFIG_DATA = await res.json();
            console.log("配置数据加载成功:", CONFIG_DATA);
            initDropdowns();
        } else { console.error("无法加载配置数据"); }
    } catch (e) { console.error("配置数据请求出错:", e); }
}

function initDropdowns() {
    const fillSelect = (id, items) => {
        const sel = document.getElementById(id);
        if(!sel) return;
        sel.innerHTML = '<option value="" disabled selected>-- 请选择 --</option>';
        if (items && Array.isArray(items)) {
            items.forEach(item => {
                const val = typeof item === 'string' ? item : item.name;
                const opt = document.createElement('option');
                opt.value = val;
                opt.textContent = val;
                sel.appendChild(opt);
            });
        }
        const customOpt = document.createElement('option');
        customOpt.value = '__CUSTOM__';
        customOpt.textContent = '➤ 自定义 / 手动输入...';
        sel.appendChild(customOpt);
    };
    fillSelect('sel-pAnom', CONFIG_DATA.anoms);
    fillSelect('sel-pReal', CONFIG_DATA.realities);
    fillSelect('sel-pFunc', CONFIG_DATA.functions);
}

function handlePresetChange(fieldId, value) {
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const input = document.getElementById(fieldId);
    if (value === '__CUSTOM__') {
        wrapper.classList.add('show-input');
        input.value = ''; 
        input.focus();
        // 如果是职能且选择自定义，不触发评估
    } else {
        input.value = value;
        applyCascadingLogic(fieldId, value);
    }
}

function resetToDropdown(fieldId) {
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const select = document.getElementById(`sel-${fieldId}`);
    const input = document.getElementById(fieldId);
    wrapper.classList.remove('show-input');
    select.value = ''; 
    input.value = '';  
}

// ===================================
// 联动逻辑
// ===================================
function applyCascadingLogic(fieldId, value) {
    if (!value) return;

    if (fieldId === 'pReal') {
        const config = CONFIG_DATA.realities.find(r => r.name === value);
        if (config) {
            document.getElementById('pTrig1').innerHTML = config.trigger || ''; 
            document.getElementById('pTrig2').innerHTML = config.overload || '';
        }
    } 
    else if (fieldId === 'pFunc') {
        const config = CONFIG_DATA.functions.find(f => f.name === value);
        if (config) {
            document.getElementById('pTrig3').innerHTML = config.directive;
            if (config.perms && config.perms.length === 3) {
                document.getElementById('perm1').value = config.perms[0];
                document.getElementById('perm2').value = config.perms[1];
                document.getElementById('perm3').value = config.perms[2];
            }
            const itemListContainer = document.getElementById('list-item');
            const presetItems = (config.items || []).slice().reverse();
            const numToReplace = presetItems.length;
            for (let i = 0; i < numToReplace; i++) {
                if (itemListContainer.firstChild) {
                    itemListContainer.firstChild.remove();
                }
            }
            presetItems.forEach(itemData => {
                addItem(itemData, true);
            });
            
            // 检查是否有自我评估数据
            if (config.Assessment && config.Assessment.length > 0) {
                showAssessmentModal(config.Assessment);
            }
        }
    }
    else if (fieldId === 'pAnom') {
        const config = CONFIG_DATA.anoms.find(a => a.name === value);
        if (config) {
             const anomListContainer = document.getElementById('list-anom');
            const presetAbilities = (config.abilities || []).slice().reverse();
            const numToReplace = presetAbilities.length;
            for (let i = 0; i < numToReplace; i++) {
                if (anomListContainer.firstChild) {
                    anomListContainer.firstChild.remove();
                }
            }
            presetAbilities.forEach(abilityData => {
                addAnom(abilityData, true);
            });
        }
    }
}

function setHybridInputState(fieldId, value) {
    const select = document.getElementById(`sel-${fieldId}`);
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const input = document.getElementById(fieldId);
    let isPreset = false;
    Array.from(select.options).forEach(opt => { if (opt.value === value) isPreset = true; });
    input.value = value || '';
    if (isPreset) {
        wrapper.classList.remove('show-input');
        select.value = value;
    } else if (value && value.trim() !== '') {
        wrapper.classList.add('show-input');
        select.value = '__CUSTOM__';
    } else {
        wrapper.classList.remove('show-input');
        select.value = '';
    }
}

document.addEventListener('wheel', (e) => { if(document.querySelector('.anom-edit-modal.active')||document.querySelector('#realEditModal.active')||document.querySelector('#itemEditModal.active')||document.querySelector('#charEditModal.active')||document.querySelector('#recordHistoryModal[style*="flex"]')) return; const a=document.querySelectorAll('.tab-view')[currentTab]; if(a&&!a.contains(e.target))a.scrollTop+=e.deltaY;}, {passive:true});
// ==========================================
// 修复：防止拖拽误触 + 防止弹窗/按钮穿透
// ==========================================
let mouseStartX = 0;
let mouseStartY = 0;

// 1. 记录鼠标按下的位置
document.addEventListener('mousedown', (e) => {
    mouseStartX = e.clientX;
    mouseStartY = e.clientY;
});

// 2. 点击监听（包含穿透修复）
document.addEventListener('click', (e) => {
    // A. 拖拽检测：如果移动超过 5 像素，视为选中文本或拖拽，不触发翻页
    const diffX = Math.abs(e.clientX - mouseStartX);
    const diffY = Math.abs(e.clientY - mouseStartY);
    if (diffX > 5 || diffY > 5) return;

    const c = document.querySelector('.container');
    const n = document.querySelector('.nav-bar');
    
    // B. 排除区域（点击这些地方不会触发翻页）
    if (window.innerWidth <= 930 || 
        c.contains(e.target) || 
        (n && n.contains(e.target)) || 
        e.target.closest('.nav-arrow') ||
        e.target.closest('.modal-overlay') || 
        e.target.closest('.full-page-modal') ||
        e.target.closest('.assessment-modal') ||
        e.target.closest('.record-history-modal') ||
        e.target.closest('#recordHistoryModal') ||
        e.target.closest('#mail-reader-overlay') ||
        e.target.closest('#hw-overlay') ||
        e.target.closest('.anom-edit-modal') ||
        e.target.closest('#realEditModal') ||
        e.target.closest('#itemEditModal') ||
        e.target.closest('#charEditModal') ||
        e.target.closest('button') ||        
        ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName)) {
        return;
    }

    // C. 执行翻页逻辑
    const x = e.clientX;
    const m = window.innerWidth / 2;
    
    if (x < m) {
        if (currentTab > 0) { currentTab--; updateSwiper(); }
    } else {
        if (currentTab < tabOrder.length - 1) { currentTab++; updateSwiper(); }
    }
});

let currentTab = 0;
// 修改 tabOrder，移除了 'view-mail'
const tabOrder = ['view-char', 'view-anom', 'view-real', 'view-item'];
const swiperWrapper = document.getElementById('swiperWrapper');
const navBtns = document.querySelectorAll('.nav-btn');
function switchView(id, btn) { 
    if(id === 'view-mail') {
        openMailModal();
        return;
    }
    const i=tabOrder.indexOf(id); 
    if(i!==-1){
        currentTab=i;
        updateSwiper();
    } 
}
function moveTab(dir) { const n=currentTab+dir; if(n>=0&&n<tabOrder.length){currentTab=n;updateSwiper();} }
function updateSwiper() { swiperWrapper.style.transform=`translateX(-${currentTab*25}%)`; navBtns.forEach((b,i)=>{if(i===currentTab)b.classList.add('active');else b.classList.remove('active');}); document.querySelectorAll('.tab-view')[currentTab].scrollTop=0; const l=document.querySelector('.arrow-left'), r=document.querySelector('.arrow-right'); if(l&&r){ if(currentTab===0)l.classList.add('disabled');else l.classList.remove('disabled'); if(currentTab===tabOrder.length-1)r.classList.add('disabled');else r.classList.remove('disabled');} updateCharLayout(); requestAnimationFrame(()=>drawTrackSVG()); }
let touchStartX=0, touchStartY=0, isSwipingDisabled=false; const minSwipe=60, container=document.getElementById('swiperContainer');
container.addEventListener('touchstart',e=>{ if(document.querySelector('.anom-edit-modal.active')||document.querySelector('#realEditModal.active')||document.querySelector('#itemEditModal.active')||document.querySelector('#charEditModal.active')||document.querySelector('#recordHistoryModal[style*="flex"]')){isSwipingDisabled=true;return;} const t=e.target; if(t.tagName.toLowerCase()==='input'||t.tagName.toLowerCase()==='textarea'||t.isContentEditable||t.tagName.toLowerCase()==='select'){isSwipingDisabled=true;}else{isSwipingDisabled=false;touchStartX=e.changedTouches[0].screenX;touchStartY=e.changedTouches[0].screenY;}},{passive:true});
container.addEventListener('touchend',e=>{ if(isSwipingDisabled)return; const x=e.changedTouches[0].screenX, y=e.changedTouches[0].screenY; handleSwipe(x,y);},{passive:true});
function handleSwipe(endX,endY){ const dX=endX-touchStartX, dY=endY-touchStartY; if(Math.abs(dX)>minSwipe&&Math.abs(dX)>Math.abs(dY)){ if(dX<0){if(currentTab<tabOrder.length-1){currentTab++;updateSwiper();}}else{if(currentTab>0){currentTab--;updateSwiper();}}}}
function setRandomVars(el) { el.style.setProperty('--r1',Math.random()); el.style.setProperty('--r2',Math.random()); el.style.setProperty('--r3',Math.random()); }
document.addEventListener('DOMContentLoaded', async () => {
    document.querySelectorAll('.panel').forEach(setRandomVars);
    await loadConfigData();
    updateSwiper();
    initAttrs();
    initDerivativeProgress();
    document.querySelectorAll('#anomEditModal .sq-dot').forEach(d => d.addEventListener('click', () => d.classList.toggle('active')));
    document.querySelectorAll('.real-edit-lvl-dots .dot').forEach(d => d.addEventListener('click', () => {
        const lvlInput = document.querySelector('.real-edit-lvl');
        const idx = parseInt(d.dataset.i);
        const cur = parseInt(lvlInput.value) || 0;
        if (idx === cur) { lvlInput.value = idx - 1; } else { lvlInput.value = idx; }
        updateRealLvlDots(lvlInput.value);
    }));
    // 页面加载完成后加载邮箱状态
    loadMailbox(); 

    // 编辑弹窗中现实计数格子点击
    document.querySelectorAll('.char-deriv-cell').forEach(c => {
        c.addEventListener('click', () => { if (isReadOnly) return; c.classList.toggle('active'); });
    });
    
    // 添加自动保存监听器
    if (!isReadOnly) {
        // 监听所有输入框
        document.querySelectorAll('input[type="text"], input[type="number"], textarea, select').forEach(el => {
            el.addEventListener('input', triggerAutoSave);
            el.addEventListener('change', triggerAutoSave);
        });
        
        // 监听所有可编辑区域
        document.querySelectorAll('[contenteditable="true"]').forEach(el => {
            el.addEventListener('input', triggerAutoSave);
            el.addEventListener('blur', triggerAutoSave);
        });
        
        // 监听进度格子点击
        document.querySelectorAll('.p-cell, .progress-cell').forEach(el => {
            el.addEventListener('click', () => {
                setTimeout(triggerAutoSave, 100);
            });
        });
    }
    
    const offlineDataEl = document.getElementById('__SAVED_DATA__');
    if(offlineDataEl && offlineDataEl.textContent.trim().length > 2) {
        document.body.classList.add('offline-mode');
        populateData(JSON.parse(offlineDataEl.textContent));
        updateCharLayout();
        drawTrackSVG();
    } else {
        if(!charId) { window.location.href='dashboard.html'; return; }
        try {
            const res=await fetch(`/api/character/${charId}`, { headers: getAuthHeaders() });
            if (res.status === 401 || res.status === 403) {
                window.location.href = 'login.html';
                return;
            }
            const data=await res.json();
            populateData(data);
            updateCharLayout();
            drawTrackSVG();
        }
        catch(e) { if(!document.getElementById('list-anom').children.length) addAnom(null, false); if(!document.getElementById('list-real').children.length) document.getElementById('list-real').appendChild(addReal()); if(!document.getElementById('list-item').children.length) addItem(null, false); }
    }
});
if (isReadOnly) {
    document.body.classList.add('readonly-mode');
    document.addEventListener('DOMContentLoaded', () => {
         document.querySelectorAll('[contenteditable]').forEach(el => el.setAttribute('contenteditable', 'false'));
         ['pAnom', 'pReal', 'pFunc'].forEach(id => { document.getElementById(`grp-${id}`).classList.add('show-input'); });
    });
}

// 如果是嵌入模式，隐藏返回按钮和顶部导航
if (isEmbed) {
    document.addEventListener('DOMContentLoaded', () => {
        const backButton = document.querySelector('.btn-back');
        if (backButton) backButton.style.display = 'none';
    });
}
// ==========================================================
// MODIFIED: 重写 goBack 函数以支持多来源返回
// ==========================================================
async function goBack() {
    // 1. 确定目标URL
    const params = new URLSearchParams(window.location.search);
    const cameFromManager = params.get('from') === 'manager';
    
    let destinationUrl = 'dashboard.html'; // 默认是仪表盘
    if (cameFromManager) {
        // 如果来自经理页，返回经理页
        destinationUrl = 'manager.html';
    } else if (isReadOnly) {
        // 只读模式来自监控页
        destinationUrl = 'monitor.html';
    }

    // 2. 如果是离线模式，直接跳转
    if (document.body.classList.contains('offline-mode')) {
        window.location.href = destinationUrl;
        return;
    }

    // 3. 如果不是只读模式，尝试静默保存
    if (!isReadOnly) {
        const backButton = document.querySelector('.btn-back');
        backButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 保存并返回';
        try {
            await saveData(true); // true 表示静默保存
        } catch (e) {
            console.error("返回前自动保存失败:", e);
            // 即使保存失败，也继续跳转
        }
    }
    
    // 4. 跳转到目标URL
    window.location.href = destinationUrl;
}

// ==========================================
// 邮箱系统
// ==========================================
let currentMailTab = 'inbox';
let mailData = { inbox: [], sent: [], highwallFiles: [] };
let isA1Unlocked = false;
let isU2Unlocked = false;
let availableMissions = []; // 可用的任务列表

function openMailModal() {
    const modal = document.getElementById('mail-full-modal');
    modal.classList.add('active');
    
    // 阻止背景页面滚动
    document.body.style.overflow = 'hidden';
    
    // 阻止滚轮事件穿透
    modal.addEventListener('wheel', preventScrollPropagation, { passive: false });
    
    loadMailbox();
}

function closeMailModal() {
    const modal = document.getElementById('mail-full-modal');
    modal.classList.remove('active');
    
    // 恢复背景页面滚动
    document.body.style.overflow = '';
    
    // 移除滚轮事件监听
    modal.removeEventListener('wheel', preventScrollPropagation);
}

// 阻止滚轮事件穿透到背景
function preventScrollPropagation(e) {
    e.stopPropagation();
}

function switchMailTab(tab) {
    currentMailTab = tab;
    document.querySelectorAll('.mail-tab').forEach(t => t.classList.remove('active'));
    const tabIndex = tab === 'inbox' ? 1 : tab === 'sent' ? 2 : tab === 'compose' ? 3 : 4;
    document.querySelector(`.mail-tab:nth-child(${tabIndex})`).classList.add('active');
    renderMailContent();
}

async function loadMailbox() {
    if (!charId || !token) return;

    const content = document.getElementById('mailContent');
    // content.innerHTML = '<div class="mail-empty"><i class="fas fa-circle-notch fa-spin"></i><p>加载中...</p></div>';

    try {
        // 检查A1解锁状态
        const a1Res = await fetch(`/api/character/${charId}/check-a1`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (a1Res.ok) {
            const a1Data = await a1Res.json();
            isA1Unlocked = a1Data.unlocked;
        }

        // 加载收件箱
        const inboxRes = await fetch(`/api/character/${charId}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (inboxRes.ok) {
            mailData.inbox = await inboxRes.json();
        }

        // 加载已发邮件
        const sentRes = await fetch(`/api/character/${charId}/sent-messages`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (sentRes.ok) {
            mailData.sent = await sentRes.json();
        }

        // 加载高墙文件权限
        const hwRes = await fetch(`/api/character/${charId}/highwall-files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (hwRes.ok) {
            mailData.highwallFiles = await hwRes.json();
        }

        // 检查U2解锁状态
        isU2Unlocked = (mailData.highwallFiles || []).some(f => f.filename && f.filename.toLowerCase() === 'u2.md');
        const btnU2 = document.getElementById('btnU2Unleash');
        if (btnU2) btnU2.style.display = isU2Unlocked ? '' : 'none';

        // 更新顶部未读消息标记
        const unreadCount = mailData.inbox.filter(m => !m.read).length;
        const mailBtn = document.querySelector('.top-mail-btn');
        const badge = document.getElementById('topMailBadge');

        if (unreadCount > 0) {
            mailBtn.classList.add('has-unread');
            badge.style.display = 'block';
            badge.textContent = unreadCount;
        } else {
            mailBtn.classList.remove('has-unread');
            badge.style.display = 'none';
        }

        // 高墙文件夹标签 - 只有解锁A1后才显示
        const hwTab = document.getElementById('tab-highwall');
        if (hwTab) {
            if (isA1Unlocked) {
                hwTab.style.display = '';
            } else {
                hwTab.style.display = 'none';
                // 如果当前在高墙标签页，切换到收件箱
                if (currentMailTab === 'highwall') {
                    switchMailTab('inbox');
                    return; // switchMailTab 会调用 renderMailContent
                }
            }
        }

        // 无论是否是当前页签，都刷新内容（因为是在弹窗里）
        renderMailContent();
        
    } catch (e) {
        console.error('加载邮箱失败:', e);
        content.innerHTML = '<div class="mail-empty"><i class="fas fa-exclamation-triangle"></i><p>加载失败</p></div>';
    }
}

function renderMailContent() {
    const content = document.getElementById('mailContent');

    if (currentMailTab === 'inbox') {
        renderInbox(content);
    } else if (currentMailTab === 'sent') {
        renderSentMail(content);
    } else if (currentMailTab === 'compose') {
        renderCompose(content);
    } else if (currentMailTab === 'highwall') {
        renderHighwallFiles(content);
    }
}

function renderInbox(container) {
    // 组合：高墙授权通知(从数据库) + 站内信
    const messages = [];

    // 站内信（包含高墙授权通知，现在从 character_messages 表来）
    mailData.inbox.forEach(m => {
        messages.push({
            type: m.messageType || 'mail',
            id: m.id,
            sender: m.senderName,
            subject: m.subject,
            content: m.content,
            preview: m.content ? m.content.substring(0, 50) : '',
            time: m.createdAt,
            read: m.read,
            hwFilename: m.hwFilename
        });
    });

    // 按时间排序
    messages.sort((a, b) => b.time - a.time);

    if (messages.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-inbox"></i><p>收件箱为空</p></div>';
        return;
    }

    container.innerHTML = '<div class="mail-list">' + messages.map(m => {
        const date = new Date(m.time).toLocaleDateString('zh-CN');
        const isHwAuth = m.type === 'hw_auth';
        const isOS = m.sender === 'OS' || isHwAuth;

        // 构建点击处理
        const clickHandler = `openMailReader(${JSON.stringify(m).replace(/"/g, '&quot;')})`;

        return `
            <div class="mail-item ${isHwAuth ? 'hw-auth' : ''} ${m.read === 0 || m.read === false ? 'unread' : ''}"
                 onclick="${clickHandler}">
                <div class="mail-sender">
                    ${isOS ? '<span class="os-badge">OS</span>' : `<i class="fas fa-user"></i> ${escapeHtmlMail(m.sender)}`}
                </div>
                <div class="mail-subject">${escapeHtmlMail(m.subject)}</div>
                <div class="mail-preview">${escapeHtmlMail(m.preview)}</div>
                <div class="mail-time"><i class="fas fa-clock"></i> ${date}</div>
            </div>
        `;
    }).join('') + '</div>';
}

let currentOutboxForm = null;
function renderSentMail(container) {
    const messages = mailData.sent || [];

    if (messages.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-paper-plane"></i><p>暂无已发记录</p></div>';
        return;
    }

    container.innerHTML = '<div class="mail-list">' + messages.map(m => {
        const date = new Date(m.createdAt);
        const timeStr = date.toLocaleString('zh-CN', {
            month: 'numeric', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
        
        let icon, iconColor, itemInfo, borderColor, statusBadge = '';
        
        if (m.type === 'containment') {
            // 收容物
            icon = 'fa-cube';
            iconColor = '#27ae60';
            itemInfo = `任务: ${escapeHtmlText(m.missionName)}`;
            borderColor = '#27ae60';
        } else if (m.type === 'report') {
            // 任务报告
            icon = 'fa-file-alt';
            iconColor = '#e67e22';
            itemInfo = `任务: ${escapeHtmlText(m.missionName)}`;
            borderColor = '#e67e22';
            
            // 显示报告状态
            const statusMap = {
                'submitted': '待评审',
                'reviewed': '已评审',
                'sent': '已完成'
            };
            const statusClass = m.status || 'submitted';
            statusBadge = `<span class="sent-status-badge ${statusClass}">${statusMap[statusClass] || '未知'}</span>`;
        }
        
        const preview = m.content ? m.content.substring(0, 50) + (m.content.length > 50 ? '...' : '') : '';
        
        return `
            <div class="mail-item sent-mail-item" style="border-left-color: ${borderColor};" onclick="openSentMailReader('${m.id}')">
                <div class="mail-icon sent-icon" style="color: ${iconColor};"><i class="fas ${icon}"></i></div>
                <div class="mail-info">
                    <div class="mail-header-row">
                        <span class="mail-recipient" style="color: ${iconColor};">${itemInfo}</span>
                        ${statusBadge}
                        <span class="mail-time">${timeStr}</span>
                    </div>
                    <div class="mail-subject">${escapeHtmlText(m.subject)}</div>
                    ${m.type === 'report' ? '' : `<div class="mail-preview">${escapeHtmlText(preview)}</div>`}
                </div>
            </div>
        `;
    }).join('') + '</div>';
}

function renderCompose(container) {
    // 提交报告选项 - 只有解锁A1后才显示
    const reportOption = isA1Unlocked ? `
            <div class="outbox-option opt-report" onclick="selectOutboxOption('report')">
                <i class="fas fa-file-alt"></i>
                <h4>提交任务报告</h4>
                <p>填写并提交任务报告</p>
            </div>` : '';

    container.innerHTML = `
        <div class="outbox-options">
            <div class="outbox-option opt-containment" onclick="selectOutboxOption('containment')">
                <i class="fas fa-cube"></i>
                <h4>寄送收容物</h4>
                <p>向经理发送收容物品</p>
            </div>
            ${reportOption}
        </div>

        <!-- 寄送收容物表单 -->
        <div id="form-containment" class="outbox-form">
            <h4><i class="fas fa-cube" style="color:#27ae60;"></i> 寄送收容物</h4>
            
            <!-- 任务选择 -->
            <label>选择任务 *</label>
            <select id="containment-mission-select" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:6px; font-size:14px; margin-bottom:15px;">
                <option value="" disabled selected>-- 请选择要寄送收容物的任务 --</option>
            </select>
            <p style="font-size:12px; color:#7f8c8d; margin-top:-10px; margin-bottom:15px;">
                <i class="fas fa-info-circle"></i> 每个任务只能寄送一次收容物
            </p>
            
            <label>收容物名称 *</label>
            <input type="text" id="containment-name" placeholder="输入收容物名称">
            <label>收容物描述</label>
            <textarea id="containment-desc" placeholder="描述收容物的特征、来源等信息..."></textarea>
            <button class="btn-send" onclick="sendContainment()">
                <i class="fas fa-paper-plane"></i> 寄送
            </button>
        </div>

        <!-- 任务报告表单 -->
        <div id="form-report" class="outbox-form">
            <h4><i class="fas fa-file-alt" style="color:#e67e22;"></i> 任务报告</h4>

            <!-- 任务选择 -->
            <div class="report-section">
                <h5>选择任务 *</h5>
                <select id="rpt-mission-select" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:6px; font-size:14px;">
                    <option value="" disabled selected>-- 请选择要提交报告的任务 --</option>
                </select>
                <p style="font-size:12px; color:#7f8c8d; margin-top:8px;">
                    <i class="fas fa-info-circle"></i> 只能为进行中的任务提交报告，且每个任务只能提交一次
                </p>
            </div>

            <div class="report-section">
                <h5>异常状态</h5>
                <div class="report-status-grid">
                    <label class="report-status-item">
                        <input type="checkbox" id="rpt-neutralized">
                        <span class="status-icon">🔫</span>
                        <div class="status-info"><h6>已中和</h6><small>无影响</small></div>
                    </label>
                    <label class="report-status-item">
                        <input type="checkbox" id="rpt-captured">
                        <span class="status-icon">💼</span>
                        <div class="status-info"><h6>已捕获</h6><small>+3 嘉奖</small></div>
                    </label>
                    <label class="report-status-item">
                        <input type="checkbox" id="rpt-escaped">
                        <span class="status-icon">🚪</span>
                        <div class="status-info"><h6>已逃脱</h6><small>+3 申诫</small></div>
                    </label>
                    <label class="report-status-item">
                        <input type="checkbox" id="rpt-other-check">
                        <span class="status-icon">📝</span>
                        <div class="status-info"><h6>其他</h6><input type="text" id="rpt-other-text" placeholder="..." style="width:80px;padding:2px 5px;font-size:11px;" onclick="event.stopPropagation()"></div>
                    </label>
                </div>
            </div>

            <div class="report-section">
                <h5>异常分析</h5>
                <div class="report-row"><label>代号</label><input type="text" id="rpt-codename"></div>
                <div class="report-row"><label>行为</label><input type="text" id="rpt-behavior"></div>
                <div class="report-row"><label>焦点</label><input type="text" id="rpt-focus"></div>
                <div class="report-row"><label>领域</label><input type="text" id="rpt-domain"></div>
            </div>

            <div class="report-section">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <h5 style="margin:0;">散逸端</h5>
                    <button type="button" class="btn-add-row" onclick="addScatteringRow()" title="添加行">
                        <i class="fas fa-plus-circle"></i>
                    </button>
                </div>
                <table class="report-table" id="table-scattering">
                    <thead><tr><th>姓名</th><th>数量</th><th>备注</th><th></th></tr></thead>
                    <tbody>
                        <tr>
                            <td><input type="text" class="scat-name"></td>
                            <td><input type="text" class="scat-qty"></td>
                            <td><input type="text" class="scat-note"></td>
                            <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="report-section">
                <h5>评优信息</h5>
                <div class="report-row"><label>最终评级</label><input type="text" id="rpt-rating" placeholder="仅供GM使用"></div>
                <div class="report-row"><label>混沌池</label><input type="number" id="rpt-chaos"></div>
                <div class="report-row"><label>MVP</label><input type="text" id="rpt-mvp"></div>
                <div class="report-row"><label>察看期</label><input type="text" id="rpt-probation"></div>
                <label style="margin-top:10px;">参与者</label>
                <textarea id="rpt-participants" placeholder="填写参与任务的特工..."></textarea>
            </div>

            <div class="report-section">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <h5 style="margin:0;">可选目标</h5>
                    <button type="button" class="btn-add-row" onclick="addObjectiveRow()" title="添加行">
                        <i class="fas fa-plus-circle"></i>
                    </button>
                </div>
                <table class="report-table" id="table-objectives">
                    <thead><tr><th>目标</th><th>奖励</th><th>按特工</th><th></th></tr></thead>
                    <tbody>
                        <tr>
                            <td><input type="text" class="obj-target"></td>
                            <td><input type="text" class="obj-reward"></td>
                            <td><input type="text" class="obj-agent"></td>
                            <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <button class="btn-send" onclick="sendReport()">
                <i class="fas fa-paper-plane"></i> 提交报告
            </button>
        </div>
    `;
}

async function loadAvailableMissions() {
    if (!charId || !token) return;
    
    try {
        const res = await fetch(`/api/character/${charId}/available-missions`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            availableMissions = await res.json();
            populateMissionSelect();
        }
    } catch (e) {
        console.error('加载任务列表失败:', e);
    }
}

async function loadAvailableMissionsForContainment() {
    if (!charId || !token) return;
    
    try {
        const res = await fetch(`/api/character/${charId}/available-missions-containment`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            availableMissions = await res.json();
            populateContainmentMissionSelect();
        }
    } catch (e) {
        console.error('加载任务列表失败:', e);
    }
}

function populateMissionSelect() {
    const select = document.getElementById('rpt-mission-select');
    if (!select) return;
    
    select.innerHTML = '<option value="" disabled selected>-- 请选择要提交报告的任务 --</option>';
    
    if (availableMissions.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.disabled = true;
        opt.textContent = '暂无可提交报告的任务';
        select.appendChild(opt);
        return;
    }
    
    availableMissions.forEach(mission => {
        const opt = document.createElement('option');
        opt.value = mission.id;
        
        if (mission.hasSubmitted) {
            opt.textContent = `${mission.name} 【已提交】`;
            opt.disabled = true;
            opt.style.color = '#95a5a6';
        } else {
            opt.textContent = mission.name;
        }
        
        select.appendChild(opt);
    });
}

function populateContainmentMissionSelect() {
    const select = document.getElementById('containment-mission-select');
    if (!select) return;
    
    select.innerHTML = '<option value="" disabled selected>-- 请选择要寄送收容物的任务 --</option>';
    
    if (availableMissions.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.disabled = true;
        opt.textContent = '暂无可寄送收容物的任务';
        select.appendChild(opt);
        return;
    }
    
    availableMissions.forEach(mission => {
        const opt = document.createElement('option');
        opt.value = mission.id;
        
        if (mission.hasSentContainment) {
            opt.textContent = `${mission.name} 【已寄送】`;
            opt.disabled = true;
            opt.style.color = '#95a5a6';
        } else {
            opt.textContent = mission.name;
        }
        
        select.appendChild(opt);
    });
}

function selectOutboxOption(type) {
    // 更新选中状态
    document.querySelectorAll('.outbox-option').forEach(opt => opt.classList.remove('active'));
    document.querySelector(`.opt-${type}`).classList.add('active');

    // 显示对应表单
    document.querySelectorAll('.outbox-form').forEach(form => form.classList.remove('active'));
    document.getElementById(`form-${type}`).classList.add('active');

    currentOutboxForm = type;
    
    // 如果是选择报告或收容物选项，加载可用任务
    if (type === 'report') {
        loadAvailableMissions();
    } else if (type === 'containment') {
        loadAvailableMissionsForContainment();
    }
}

async function sendContainment() {
    // 验证是否选择了任务
    const missionId = document.getElementById('containment-mission-select').value;
    if (!missionId) {
        showToast('请先选择要寄送收容物的任务', 'error');
        return;
    }
    
    const name = document.getElementById('containment-name').value.trim();
    const desc = document.getElementById('containment-desc').value.trim();

    if (!name) {
        showToast('请输入收容物名称', 'error');
        return;
    }

    const btn = document.querySelector('#form-containment .btn-send');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 发送中...';

    try {
        const res = await fetch(`/api/character/${charId}/send-containment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ 
                missionId: missionId,
                name, 
                description: desc 
            })
        });

        const data = await res.json();
        
        if (!res.ok) {
            if (res.status === 409) {
                showToast(data.message || '您已为该任务寄送过收容物', 'error');
            } else if (res.status === 404) {
                showToast('任务不存在或您不在该任务成员中', 'error');
            } else {
                throw new Error(data.message || '发送失败');
            }
        } else {
            showToast('收容物已寄送', 'success');
            document.getElementById('containment-name').value = '';
            document.getElementById('containment-desc').value = '';
            
            // 重新加载任务列表，更新已寄送状态
            loadAvailableMissionsForContainment();
        }
    } catch (e) {
        showToast('发送失败: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-paper-plane"></i> 寄送';
    }
}

function closeSuccessModal() {
    const modal = document.getElementById('reportSuccessModal');
    if (modal) {
        modal.classList.remove('show');
    }
}



async function sendReport() {
    // 验证是否选择了任务
    const missionId = document.getElementById('rpt-mission-select').value;
    if (!missionId) {
        showToast('请先选择要提交报告的任务', 'error');
        return;
    }
    
    // 动态获取散逸端数据
    const scattering = Array.from(document.querySelectorAll('#table-scattering tbody tr')).map(row => ({
        name: row.querySelector('.scat-name').value.trim(),
        qty: row.querySelector('.scat-qty').value.trim(),
        note: row.querySelector('.scat-note').value.trim()
    })).filter(s => s.name);

    // 动态获取可选目标数据
    const objectives = Array.from(document.querySelectorAll('#table-objectives tbody tr')).map(row => ({
        target: row.querySelector('.obj-target').value.trim(),
        reward: row.querySelector('.obj-reward').value.trim(),
        agent: row.querySelector('.obj-agent').value.trim()
    })).filter(o => o.target);

    const reportData = {
        missionId: missionId, // 添加任务ID
        status: {
            neutralized: document.getElementById('rpt-neutralized').checked,
            captured: document.getElementById('rpt-captured').checked,
            escaped: document.getElementById('rpt-escaped').checked,
            other: document.getElementById('rpt-other-check').checked ? document.getElementById('rpt-other-text').value : null
        },
        analysis: {
            codename: document.getElementById('rpt-codename').value,
            behavior: document.getElementById('rpt-behavior').value,
            focus: document.getElementById('rpt-focus').value,
            domain: document.getElementById('rpt-domain').value
        },
        scattering,
        evaluation: {
            rating: document.getElementById('rpt-rating').value,
            chaosPool: document.getElementById('rpt-chaos').value,
            mvp: document.getElementById('rpt-mvp').value,
            probation: document.getElementById('rpt-probation').value,
            participants: document.getElementById('rpt-participants').value
        },
        objectives
    };

    const btn = document.querySelector('#form-report .btn-send');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 提交中...';

    try {
        const res = await fetch(`/api/character/${charId}/send-report`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ reportData })
        });

        const data = await res.json();

        if (!res.ok) {
            if (res.status === 409) {
                 showToast(data.message || '您已为该任务提交过报告', 'error');
            } else if (res.status === 404) {
                 showToast('任务不存在或您不在该任务成员中', 'error');
            } else {
                throw new Error(data.message || '提交失败，请稍后重试');
            }
        } else {
            // 提交成功！显示弹窗并设置延时关闭
            const modal = document.getElementById('reportSuccessModal');
            if (modal) {
                modal.classList.add('show');
                
                // 设置一个 2.5 秒的计时器，之后自动调用关闭函数
                setTimeout(() => {
                    closeSuccessModal();
                }, 2500); 
            }
            
            // 重新加载任务列表，更新已提交状态
            loadAvailableMissions();
        }
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-paper-plane"></i> 提交报告';
    }
}

function renderHighwallFiles(container) {
    if (mailData.highwallFiles.length === 0) {
        container.innerHTML = '<div class="mail-empty"><i class="fas fa-file-shield"></i><p>暂无授权的高墙文件</p></div>';
        return;
    }

    container.innerHTML = '<div class="hw-folder">' + mailData.highwallFiles.map(f => `
        <div class="hw-file" onclick="openHighwallFile('${f.filename}')">
            <i class="fas fa-file-alt"></i>
            <div class="hw-name">${escapeHtmlMail(f.title)}</div>
        </div>
    `).join('') + '</div>';
}

function escapeHtmlMail(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function openHighwallFile(filename) {
    const overlay = document.getElementById('hw-overlay');
    const icon = document.getElementById('hw-icon');
    const text = document.getElementById('hw-text');
    const scanlines = document.getElementById('hw-scanlines');
    const eyeLayer = document.getElementById('hw-eye-layer');
    const eyeIcon = document.getElementById('hw-eye-icon');
    const tentaclesLayer = document.getElementById('hw-tentacles');
    const blackout = document.getElementById('hw-blackout');
    const content = document.getElementById('hw-content');

    // 重置状态
    overlay.classList.remove('active', 'glitch-mode');
    icon.className = 'fas fa-circle-notch fa-spin hw-loader-icon';
    icon.style.color = '';
    icon.style.transform = '';
    text.style.color = '';
    text.style.fontFamily = '';
    text.innerHTML = '访问高墙文件<span class="hw-dots"></span>';
    scanlines.style.display = 'none';
    content.style.display = '';
    eyeLayer.style.opacity = '0';
    eyeIcon.classList.remove('eye-open', 'scared');
    tentaclesLayer.innerHTML = '';
    blackout.classList.remove('active');

    // 阶段 1: 伪装 (0s - 1.0s)
    overlay.classList.add('active');

    // 阶段 2: 故障 (1.0s)
    setTimeout(() => {
        icon.classList.remove('fa-spin');
        icon.style.transform = 'rotate(160deg)';

        setTimeout(() => {
            icon.className = 'fas fa-exclamation-triangle hw-loader-icon';
            icon.style.color = '#ff0000';
            text.style.color = '#ff0000';
            text.style.fontFamily = 'monospace';
            text.innerHTML = 'SYSTEM FAILURE /// 0xFF';
            overlay.classList.add('glitch-mode');
            scanlines.style.display = 'block';
        }, 100);
    }, 1000);

    // 阶段 3: 凝视 (1.5s) - 眼睛在黑暗中睁开
    setTimeout(() => {
        overlay.classList.remove('glitch-mode');
        scanlines.style.display = 'none';
        content.style.display = 'none';

        eyeLayer.style.opacity = '1';

        setTimeout(() => {
            eyeIcon.classList.add('eye-open');
        }, 100);
    }, 1500);

    // 阶段 4: 吞噬 (1.9s) - 触手开始蔓延
    setTimeout(() => {
        eyeIcon.classList.add('scared');

        tentaclesLayer.innerHTML = '';
        const count = 20;
        for (let i = 0; i < count; i++) {
            const div = document.createElement('div');
            div.className = 'tendril';

            const deg = i * (360 / count);
            div.style.setProperty('--r', `${deg}deg`);
            div.style.animationDelay = `${Math.random() * 0.4}s`;

            tentaclesLayer.appendChild(div);

            requestAnimationFrame(() => div.classList.add('creeping'));
        }
    }, 1900);

    // 阶段 5: 熄灭 & 跳转 (2.5s)
    setTimeout(() => {
        blackout.classList.add('active');
        setTimeout(() => {
            // 传递角色卡ID和来源，用于返回和权限筛选
            window.location.href = `documents.html?file=${encodeURIComponent(filename)}&charId=${encodeURIComponent(charId)}&from=sheet`;
        }, 500);
    }, 2500);
}

// ==========================================
// 蓝色眼睛邮件阅读器
// ==========================================
let currentOpenMail = null;

function openMailReader(mailData) {
    currentOpenMail = mailData;

    const overlay = document.getElementById('mail-reader-overlay');
    const subjectEl = document.getElementById('mail-reader-subject');
    const senderEl = document.getElementById('mail-reader-sender');
    const timeEl = document.getElementById('mail-reader-time');
    const bodyEl = document.getElementById('mail-reader-body');
    const actionsEl = document.getElementById('mail-reader-actions');
    const eyeContainer = document.querySelector('.mail-eye-container');

    // 填充内容
    subjectEl.textContent = mailData.subject || '无主题';

    const isOS = mailData.sender === 'OS' || mailData.type === 'hw_auth';
    senderEl.innerHTML = isOS
        ? '<span class="os-badge">OS</span> 系统通知'
        : `<i class="fas fa-user"></i> ${escapeHtmlMail(mailData.sender)}`;

    const date = new Date(mailData.time);
    timeEl.innerHTML = `<i class="fas fa-clock"></i> ${date.toLocaleDateString('zh-CN')} ${date.toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit'})}`;

    bodyEl.textContent = mailData.content || '';

    // 根据邮件类型设置操作按钮
    if (mailData.type === 'hw_auth' && mailData.hwFilename) {
        actionsEl.innerHTML = `
            <button class="mail-reader-btn secondary" onclick="closeMailReader()">
                <i class="fas fa-times"></i> 关闭
            </button>
            <button class="mail-reader-btn danger" onclick="openHighwallFromMail('${escapeHtmlMail(mailData.hwFilename)}')">
                <i class="fas fa-file-shield"></i> 查看高墙文件
            </button>
        `;
    } else {
        actionsEl.innerHTML = `
            <button class="mail-reader-btn secondary" onclick="closeMailReader()">
                <i class="fas fa-check"></i> 关闭
            </button>
        `;
    }

    // 标记已读
    if (mailData.id && (mailData.read === 0 || mailData.read === false)) {
        markMessageRead(mailData.id);
    }

    // 眨眼动画
    eyeContainer.classList.add('mail-eye-blink');
    setTimeout(() => eyeContainer.classList.remove('mail-eye-blink'), 300);

    // 显示覆盖层
    overlay.classList.add('active');
}

function closeMailReader() {
    const overlay = document.getElementById('mail-reader-overlay');
    const eyeContainer = document.querySelector('.mail-eye-container');

    // 眨眼动画
    eyeContainer.classList.add('mail-eye-blink');

    setTimeout(() => {
        overlay.classList.remove('active');
        eyeContainer.classList.remove('mail-eye-blink');
        currentOpenMail = null;
    }, 200);
}

function openHighwallFromMail(filename) {
    closeMailReader();
    setTimeout(() => {
        openHighwallFile(filename);
    }, 300);
}

function openSentMailReader(msgId) {
    const msg = mailData.sent.find(m => m.id == msgId);
    if (!msg) return;

    const overlay = document.getElementById('mail-reader-overlay');
    const subjectEl = document.getElementById('mail-reader-subject');
    const senderEl = document.getElementById('mail-reader-sender');
    const timeEl = document.getElementById('mail-reader-time');
    const bodyEl = document.getElementById('mail-reader-body');
    const actionsEl = document.getElementById('mail-reader-actions');
    const eyeContainer = document.querySelector('.mail-eye-container');

    subjectEl.textContent = msg.subject || '无主题';
    
    // 根据消息类型显示不同的信息
    let icon, iconColor, recipientInfo;
    if (msg.type === 'containment') {
        icon = 'fa-cube';
        iconColor = '#27ae60';
        recipientInfo = `任务: ${escapeHtmlMail(msg.missionName)}`;
    } else if (msg.type === 'report') {
        icon = 'fa-file-alt';
        iconColor = '#e67e22';
        recipientInfo = `任务: ${escapeHtmlMail(msg.missionName)}`;
    }
    
    senderEl.innerHTML = `<i class="fas ${icon}" style="color:${iconColor};"></i> ${recipientInfo}`;

    const date = new Date(msg.createdAt);
    timeEl.innerHTML = `<i class="fas fa-clock"></i> ${date.toLocaleDateString('zh-CN')} ${date.toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit'})}`;

    // 根据类型显示不同的内容
    if (msg.type === 'report') {
        // 任务报告格式化显示
        const reportData = msg.reportData || {};
        const statusMap = {
            'submitted': '待评审',
            'reviewed': '已评审',
            'sent': '已完成'
        };
        const statusName = statusMap[msg.status] || '未知';
        
        let reportHTML = '';
        
        // 状态和评级（如果有）
        reportHTML += `<div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #34495e;">`;
        reportHTML += `<div style="margin-bottom: 8px;"><strong style="color: #ffffff; font-size: 14px;">状态：</strong><span style="color: ${msg.status === 'sent' ? '#2ecc71' : '#f39c12'}; font-weight: bold;">${statusName}</span></div>`;
        
        if (msg.rating) {
            reportHTML += `<div style="display: flex; gap: 20px;">`;
            reportHTML += `<div><strong style="color: #ffffff; font-size: 14px;">评级：</strong><span style="font-size: 18px; font-weight: bold; color: #9b59b6;">${msg.rating}</span></div>`;
            reportHTML += `<div><strong style="color: #ffffff; font-size: 14px;">逸散端：</strong><span style="font-size: 18px; font-weight: bold; color: #e67e22;">${msg.scatterValue || 0}</span></div>`;
            reportHTML += `</div>`;
        }
        reportHTML += `</div>`;
        
        // 经理批注
        if (msg.annotations && msg.annotations.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px; padding: 12px; background: rgba(243, 156, 18, 0.15); border-left: 4px solid #f39c12; border-radius: 4px;">`;
            reportHTML += `<div style="font-weight: bold; color: #f39c12; margin-bottom: 8px; font-size: 14px;">📝 经理批注</div>`;
            msg.annotations.forEach(a => {
                reportHTML += `<div style="color: #ecf0f1; margin: 5px 0; font-size: 13px;">• ${escapeHtmlMail(a)}</div>`;
            });
            reportHTML += `</div>`;
        }
        
        // 任务状态
        if (reportData.status) {
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<strong style="color: #ffffff; font-size: 14px;">任务状态：</strong>`;
            const statusLabels = [];
            if (reportData.status.neutralized) statusLabels.push('✓ 已中和');
            if (reportData.status.captured) statusLabels.push('✓ 已捕获');
            if (reportData.status.escaped) statusLabels.push('✓ 已逃脱');
            if (reportData.status.other) statusLabels.push('✓ 其他');
            reportHTML += `<span style="color: #2ecc71; font-weight: bold;">${statusLabels.join(' / ') || '未设置'}</span>`;
            reportHTML += `</div>`;
        }
        
        // 威胁分析
        if (reportData.analysis) {
            const analysis = reportData.analysis;
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">🔍 威胁分析</div>`;
            if (analysis.codename) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">代号：${escapeHtmlMail(analysis.codename)}</div>`;
            if (analysis.behavior) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">行为：${escapeHtmlMail(analysis.behavior)}</div>`;
            if (analysis.focus) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">专注：${escapeHtmlMail(analysis.focus)}</div>`;
            if (analysis.domain) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">区域：${escapeHtmlMail(analysis.domain)}</div>`;
            reportHTML += `</div>`;
        }
        
        // 散逸端记录
        if (reportData.scattering && reportData.scattering.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">⚠️ 散逸端记录</div>`;
            reportData.scattering.forEach(s => {
                if (typeof s === 'string') {
                    reportHTML += `<div style="margin: 5px 0; color: #e67e22; font-weight: bold; font-size: 13px;">• ${escapeHtmlMail(s)}</div>`;
                } else {
                    // 散逸端：姓名、数量、备注
                    const name = s.name || '';
                    const qty = s.qty || '';
                    const note = s.note || '';
                    reportHTML += `<div style="margin: 5px 0; color: #e67e22; font-size: 13px;">`;
                    reportHTML += `• <strong>${escapeHtmlMail(name)}</strong>`;
                    if (qty) reportHTML += ` × ${escapeHtmlMail(qty)}`;
                    if (note) reportHTML += ` <span style="color: #95a5a6;">(${escapeHtmlMail(note)})</span>`;
                    reportHTML += `</div>`;
                }
            });
            reportHTML += `</div>`;
        }
        
        // 评估信息
        if (reportData.evaluation) {
            const eval_data = reportData.evaluation;
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">📊 评估</div>`;
            if (eval_data.rating) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">威胁等级：${escapeHtmlMail(eval_data.rating)}</div>`;
            if (eval_data.chaosPool) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">混沌池：${escapeHtmlMail(eval_data.chaosPool)}</div>`;
            if (eval_data.mvp) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">MVP：${escapeHtmlMail(eval_data.mvp)}</div>`;
            if (eval_data.probation) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">察看期：${escapeHtmlMail(eval_data.probation)}</div>`;
            if (eval_data.participants) reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">参与者：${escapeHtmlMail(eval_data.participants)}</div>`;
            reportHTML += `</div>`;
        }
        
        // 任务目标
        if (reportData.objectives && reportData.objectives.length > 0) {
            reportHTML += `<div style="margin-bottom: 15px;">`;
            reportHTML += `<div style="font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px;">🎯 任务目标</div>`;
            reportData.objectives.forEach(o => {
                if (typeof o === 'string') {
                    reportHTML += `<div style="margin: 5px 0; color: #3498db; font-size: 13px;">• ${escapeHtmlMail(o)}</div>`;
                } else {
                    // 任务目标：目标、奖励、特工
                    const target = o.target || '';
                    const reward = o.reward || '';
                    const agent = o.agent || '';
                    reportHTML += `<div style="margin: 5px 0; color: #ecf0f1; font-size: 13px;">`;
                    reportHTML += `• <strong style="color: #3498db;">${escapeHtmlMail(target)}</strong>`;
                    if (reward) reportHTML += ` → <span style="color: #2ecc71;">奖励: ${escapeHtmlMail(reward)}</span>`;
                    if (agent) reportHTML += ` <span style="color: #95a5a6;">[${escapeHtmlMail(agent)}]</span>`;
                    reportHTML += `</div>`;
                }
            });
            reportHTML += `</div>`;
        }
        
        bodyEl.innerHTML = reportHTML || '<div style="color: #95a5a6;">暂无报告内容</div>';
    } else {
        // 收容物直接显示内容
        bodyEl.textContent = msg.content || '';
    }

    actionsEl.innerHTML = `
        <button class="mail-reader-btn secondary" onclick="closeMailReader()">
            <i class="fas fa-check"></i> 关闭
        </button>
    `;

    eyeContainer.classList.add('mail-eye-blink');
    setTimeout(() => eyeContainer.classList.remove('mail-eye-blink'), 300);

    overlay.classList.add('active');
}

async function markMessageRead(msgId) {
    try {
        await fetch(`/api/character/${charId}/message/${msgId}/read`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        // 更新本地数据
        const msg = mailData.inbox.find(m => m.id === msgId);
        if (msg) msg.read = 1;
        
        // 更新顶部未读图标状态
        const unreadCount = mailData.inbox.filter(m => !m.read).length;
        const mailBtn = document.querySelector('.top-mail-btn');
        const badge = document.getElementById('topMailBadge');

        if (unreadCount > 0) {
            mailBtn.classList.add('has-unread');
            badge.style.display = 'block';
            badge.textContent = unreadCount;
        } else {
            mailBtn.classList.remove('has-unread');
            badge.style.display = 'none';
        }
    } catch (e) {
        console.error('标记已读失败:', e);
    }
}

function openMessage(msgId) {
    // 从收件箱数据中找到消息
    const msg = mailData.inbox.find(m => m.id === msgId);
    if (msg) {
        openMailReader({
            type: msg.messageType || 'mail',
            id: msg.id,
            sender: msg.senderName,
            subject: msg.subject,
            content: msg.content,
            time: msg.createdAt,
            read: msg.read,
            hwFilename: msg.hwFilename
        });
    }
}

const ATTRS=['专注','欺瞒','活力','共情','主动','坚毅','气场','专业','诡秘'];
function initAttrs(){ 
    const c=document.getElementById('attrs-list');
    c.innerHTML='';
    ATTRS.forEach(a=>{ 
        const d=document.createElement('div');
        d.className='attr-row';
        // 生成9个三角形，正三角和倒三角交替
        const triangles = Array(9).fill(0).map((_, i) => {
            const direction = i % 2 === 0 ? 'up' : 'down';
            return `<div class="tri-btn ${direction}" data-i="${i+1}"></div>`;
        }).join('');
        d.innerHTML=`<div class="attr-label">${a}</div><div class="attr-input-wrapper"><button class="attr-btn attr-minus" data-attr="${a}">−</button><input type="text" class="attr-input" data-attr="${a}" value="0"><button class="attr-btn attr-plus" data-attr="${a}">+</button></div><div class="attr-dots-container"><div class="attr-dots" data-attr="${a}">${triangles}</div></div>`;
        c.appendChild(d); 
        
        const i=d.querySelector('input');
        i.oninput=(e)=>renderTriangles(a,e.target.value);
        
        // 加减按钮事件
        const minusBtn = d.querySelector('.attr-minus');
        const plusBtn = d.querySelector('.attr-plus');
        
        minusBtn.onclick = () => {
            if(isReadOnly) return;
            let val = parseInt(i.value) || 0;
            if(val > 0) {
                val--;
                i.value = val;
                renderTriangles(a, val);
                triggerAutoSave();
            }
        };
        
        plusBtn.onclick = () => {
            if(isReadOnly) return;
            let val = parseInt(i.value) || 0;
            if(val < 9) {
                val++;
                i.value = val;
                renderTriangles(a, val);
                triggerAutoSave();
            }
        };
        
        // 三角形容器事件
        const dotsContainer = d.querySelector('.attr-dots-container');
        
        // 左键点击：最右边的红色变黑
        dotsContainer.onclick = (e) => {
            if(isReadOnly) return;
            const max = parseInt(i.value) || 0;
            if(max === 0) return;
            
            const allTris = d.querySelectorAll('.tri-btn');
            // 从右到左找第一个红色的变黑
            for(let idx = max; idx >= 1; idx--) {
                const tri = allTris[idx - 1];
                if(tri && tri.classList.contains('active') && !tri.classList.contains('marked')) {
                    tri.classList.remove('active');
                    tri.classList.add('marked');
                    triggerAutoSave();
                    return;
                }
            }
        };
        
        // 右键点击：最左边的黑色变红
        dotsContainer.oncontextmenu = (e) => {
            e.preventDefault();
            if(isReadOnly) return;
            const max = parseInt(i.value) || 0;
            if(max === 0) return;
            
            const allTris = d.querySelectorAll('.tri-btn');
            // 从左到右找第一个黑色的变红
            for(let idx = 1; idx <= max; idx++) {
                const tri = allTris[idx - 1];
                if(tri && tri.classList.contains('marked')) {
                    tri.classList.remove('marked');
                    tri.classList.add('active');
                    triggerAutoSave();
                    return;
                }
            }
        };
    });
}

function renderTriangles(a,v){
    const val=parseInt(v)||0;
    const container = document.querySelector(`.attr-dots[data-attr="${a}"]`);
    if(!container) return;
    
    container.querySelectorAll('.tri-btn').forEach((tri,i)=>{
        const idx = i + 1;
        if(idx <= val){
            // 在点亮范围内
            if(!tri.classList.contains('marked')){
                tri.classList.add('active');
            }
        }else{
            // 超出范围，移除所有状态
            tri.classList.remove('active', 'marked');
        }
    });
}

function renderDots(a,v){
    // 保留此函数以兼容旧代码
    renderTriangles(a,v);
}

// 全局重置所有属性的标记
function resetAllAttrs() {
    if(isReadOnly) return;
    ATTRS.forEach(a => {
        const container = document.querySelector(`.attr-dots[data-attr="${a}"]`);
        const input = document.querySelector(`.attr-input[data-attr="${a}"]`);
        if(!container || !input) return;
        
        const max = parseInt(input.value) || 0;
        const allTris = container.querySelectorAll('.tri-btn');
        for(let idx = 0; idx < max; idx++) {
            const tri = allTris[idx];
            if(tri && tri.classList.contains('marked')) {
                tri.classList.remove('marked');
                tri.classList.add('active');
            }
        }
    });
}

// 衍生进度条初始化
function initDerivativeProgress() {
    document.querySelectorAll('.progress-cell').forEach(cell => {
        cell.onclick = () => {
            if (isReadOnly) return;
            cell.classList.toggle('active');
        };
    });
}
function createDelBtn(type){
    return`<button class="btn-del" onclick="deleteCard(this, '${type}')">×</button>`;
}

function deleteCard(btn, type) {
    if(!confirm('确定删除?')) return;
    btn.parentElement.remove();
    updateSlotButtons();
}

// 更新添加按钮状态
function updateSlotButtons() {
    const anomCount = document.querySelectorAll('#list-anom .card').length;
    const realCount = document.querySelectorAll('#list-real .card').length;

    const btnAddAnom = document.querySelector('#view-anom .btn-add');
    const btnAddReal = document.querySelector('#view-real .btn-add');

    if (btnAddAnom) {
        if (anomCount >= SLOT_LIMITS.anomSlots) {
            btnAddAnom.disabled = true;
            btnAddAnom.innerHTML = `<i class="fas fa-lock"></i> 已满 (${anomCount}/${SLOT_LIMITS.anomSlots})`;
            btnAddAnom.style.opacity = '0.5';
            btnAddAnom.style.cursor = 'not-allowed';
        } else {
            btnAddAnom.disabled = false;
            btnAddAnom.innerHTML = `<i class="fas fa-plus"></i> 添加 (${anomCount}/${SLOT_LIMITS.anomSlots})`;
            btnAddAnom.style.opacity = '1';
            btnAddAnom.style.cursor = 'pointer';
        }
    }

    if (btnAddReal) {
        if (realCount >= SLOT_LIMITS.realSlots) {
            btnAddReal.disabled = true;
            btnAddReal.innerHTML = `<i class="fas fa-lock"></i> 已满 (${realCount}/${SLOT_LIMITS.realSlots})`;
            btnAddReal.style.opacity = '0.5';
            btnAddReal.style.cursor = 'not-allowed';
        } else {
            btnAddReal.disabled = false;
            btnAddReal.innerHTML = `<i class="fas fa-plus"></i> 添加 (${realCount}/${SLOT_LIMITS.realSlots})`;
            btnAddReal.style.opacity = '1';
            btnAddReal.style.cursor = 'pointer';
        }
    }
}

function addAnom(d=null, prepend=false, skipCheck=false){
    if (!skipCheck && !d) {
        const currentCount = document.querySelectorAll('#list-anom .card').length;
        if (currentCount >= SLOT_LIMITS.anomSlots) {
            showToast('异常能力槽位已满，请联系经理解锁更多槽位', 'error');
            return;
        }
    }
    const div=document.createElement('div');div.className='card bd-anom anom-card';div.innerHTML=`<button class="anom-card-edit-btn" onclick="openAnomCardEdit(this.closest('.anom-card'))"><i class="fas fa-pen"></i></button>${createDelBtn('anom')}<input type="hidden" class="f-name"><input type="hidden" class="f-trig"><input type="hidden" class="f-qual"><input type="hidden" class="f-tdesc"><input type="hidden" class="f-t1"><input type="hidden" class="f-t1-val"><input type="hidden" class="f-t2"><input type="hidden" class="f-t2-val"><input type="checkbox" class="f-chk" style="display:none"><div class="sq-dots d1" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="sq-dots d2" style="display:none"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div><div class="rich-editor f-succ" contenteditable="true" style="display:none"></div><div class="rich-editor f-fail" contenteditable="true" style="display:none"></div><div class="anom-title-bar"><div class="anom-title-row"><span class="anom-disp-name"></span><span class="anom-field-sep">|</span><span class="anom-disp-trig"></span></div><div class="anom-disp-qual-row"><span class="anom-disp-qual"></span></div></div><div class="anom-body"><div class="anom-result-row"><div class="anom-result succ-section"><div class="anom-result-label c-anom"><i class="fas fa-check-circle"></i> 成功时</div><div class="anom-disp-succ"></div></div><div class="anom-result fail-section"><div class="anom-result-label" style="color:#c0392b"><i class="fas fa-times-circle"></i> 失败时</div><div class="anom-disp-fail"></div></div></div></div><div class="anom-question-section"><div class="anom-disp-question"></div><div class="anom-disp-answers"><div class="anom-disp-a1"></div><div class="anom-disp-a2"></div></div></div>`; setupSq(div);if(d)fillAnom(div,d);setRandomVars(div);syncAnomDisplay(div); const container = document.getElementById('list-anom'); if(prepend) { container.prepend(div); } else { container.appendChild(div); } updateSlotButtons();
}

function getBonusOptions() {
    let opts = '<option value="" disabled selected>-- 选择连结加成 --</option>';
    if (CONFIG_DATA.bonuses && Array.isArray(CONFIG_DATA.bonuses)) {
        CONFIG_DATA.bonuses.forEach(b => {
            const val = typeof b === 'string' ? b : (b.content || b.name);
            const name = typeof b === 'string' ? b : b.name;
            let displayName = name;
            if (displayName.length > 20) { displayName = displayName.substring(0, 20) + '...'; }
            const safeVal = val.replace(/"/g, '&quot;');
            opts += `<option value="${safeVal}">${displayName}</option>`;
        });
    }
    opts += '<option value="__CUSTOM__">➤ 自定义 / 手动输入...</option>';
    return opts;
}

window.handleBonusChange = function(select) {
    const wrapper = select.parentElement;
    const editor = wrapper.querySelector('.rich-editor');
    const val = select.value;
    wrapper.classList.add('show-input'); 
    if (val === '__CUSTOM__') {
        editor.focus();
    } else {
        editor.innerHTML = val;
    }
};

window.resetBonus = function(btn) {
    const wrapper = btn.parentElement;
    const select = wrapper.querySelector('select');
    wrapper.classList.remove('show-input');
    select.value = ''; 
};

function addReal(d = null, skipCheck = false) {
    if (!skipCheck && !d) {
        const currentCount = document.querySelectorAll('#list-real .card').length;
        if (currentCount >= SLOT_LIMITS.realSlots) {
            showToast('关系网槽位已满，请联系经理解锁更多槽位', 'error');
            return null;
        }
    }
    const div = document.createElement('div');
    div.className = 'card bd-real real-card';
    div.innerHTML = `<button class="real-card-edit-btn" onclick="openRealCardEdit(this.closest('.real-card'))"><i class="fas fa-pen"></i></button>${createDelBtn('real')}<input type="hidden" class="f-name"><input type="hidden" class="f-actor"><div class="rich-editor f-desc" contenteditable="true" style="display:none"></div><input type="checkbox" class="f-act" style="display:none"><div class="rich-editor f-conn" contenteditable="true" style="display:none"></div><div class="r-dots-hidden" style="display:none"><div class="dot" data-i="1"></div><div class="dot" data-i="2"></div><div class="dot" data-i="3"></div><div class="dot" data-i="4"></div><div class="dot" data-i="5"></div><div class="dot" data-i="6"></div><div class="dot" data-i="7"></div><div class="dot" data-i="8"></div><div class="dot" data-i="9"></div></div><div class="real-title-bar"><div class="real-title-row"><span class="real-disp-name"></span><span class="real-field-sep">|</span><span class="real-disp-actor"></span></div><div class="real-disp-desc"></div></div><div class="real-body"><div class="real-conn-row"><span class="real-disp-lbl"><i class="fas fa-link"></i> 连结</span><span class="real-disp-lvl"></span><span class="real-disp-act"></span></div><div class="real-disp-conn"></div></div>`;
    if (d) fillReal(div, d);
    setRandomVars(div);
    syncRealDisplay(div);
    setTimeout(updateSlotButtons, 0);
    return div;
}

function addItem(d=null, prepend=false){
    const div=document.createElement('div');
    div.className='card bd-func item-card';
    div.innerHTML=`${createDelBtn('item')}<input type="hidden" class="f-item"><input type="hidden" class="f-pd"><input type="hidden" class="f-once" value="0"><div class="rich-editor f-eff" contenteditable="true" style="display:none"></div><div class="item-title-bar"><div class="item-title-row"><span class="item-disp-once"><i class="fas fa-fire"></i> 一次性</span><span class="item-disp-name"></span><span class="item-field-sep">|</span><span class="item-disp-pd"></span></div></div><div class="item-body"><div class="item-disp-eff"></div></div><div class="item-actions"><button class="item-card-edit-btn" onclick="openItemCardEdit(this.closest('.item-card'))"><i class="fas fa-pen"></i> 编辑</button><button class="item-use-btn" onclick="useItem(this.closest('.item-card'))"><i class="fas fa-hand-sparkles"></i> 使用</button></div>`;
    if(d){div.querySelector('.f-item').value=d.item||'';div.querySelector('.f-pd').value=d.pd||'';div.querySelector('.f-eff').innerHTML=d.eff||'';div.querySelector('.f-once').value=d.once?'1':'0';}
    setRandomVars(div);
    syncItemDisplay(div);
    const container = document.getElementById('list-item');
    if(prepend) { container.prepend(div); } else { container.appendChild(div); }
}

function syncItemDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
    const item = card.querySelector('.f-item').value;
    const pd = card.querySelector('.f-pd').value;
    const eff = card.querySelector('.f-eff');
    const once = card.querySelector('.f-once').value === '1';
    if (once) { card.classList.add('bd-once'); card.classList.remove('bd-func'); } else { card.classList.remove('bd-once'); card.classList.add('bd-func'); }
    const dn = card.querySelector('.item-disp-name');
    if (dn) dn.innerHTML = item ? '<span class="item-disp-label">物品：</span>' + esc(item) : '<span class="anom-empty">未命名</span>';
    const dp = card.querySelector('.item-disp-pd');
    const sep = card.querySelector('.item-field-sep');
    if (dp && sep) { if (pd) { dp.innerHTML = '<span class="item-disp-label">PD：</span>' + esc(pd); dp.style.display = ''; sep.style.display = ''; } else { dp.style.display = 'none'; sep.style.display = 'none'; } }
    const de = card.querySelector('.item-disp-eff');
    if (de) de.innerHTML = eff?.textContent?.trim() ? eff.innerHTML : '';
}

function useItem(card) {
    if (isReadOnly) return;
    const name = card.querySelector('.f-item').value || '此物品';
    if (!confirm(`确定使用「${name}」？此物品将被消耗。`)) return;
    card.style.transition = 'all 0.3s';
    card.style.opacity = '0';
    card.style.transform = 'scale(0.9)';
    setTimeout(() => { card.remove(); triggerAutoSave(); }, 300);
}

function openItemCardEdit(cardEl) {
    if (isReadOnly) return;
    const modal = document.getElementById('itemEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    q('.item-edit-name').value = cardEl.querySelector('.f-item').value;
    q('.item-edit-pd').value = cardEl.querySelector('.f-pd').value;
    q('.item-edit-eff').innerHTML = cardEl.querySelector('.f-eff').innerHTML || '';
    q('.item-edit-once').checked = cardEl.querySelector('.f-once').value === '1';
    window._itemEditCard = cardEl;
    q('.item-edit-name').focus();
}

function closeItemCardEdit() {
    const modal = document.getElementById('itemEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._itemEditCard = null;
}

function saveItemCardEdit() {
    const modal = document.getElementById('itemEditModal');
    const card = window._itemEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-item').value = q('.item-edit-name').value;
    card.querySelector('.f-pd').value = q('.item-edit-pd').value;
    card.querySelector('.f-eff').innerHTML = q('.item-edit-eff').innerHTML || '';
    card.querySelector('.f-once').value = q('.item-edit-once').checked ? '1' : '0';
    syncItemDisplay(card);
    triggerAutoSave();
    closeItemCardEdit();
}

function get3Sq(){return` <div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div> `;}
function get9Dots(){return Array(9).fill(0).map((_,i)=>`<div class="dot" data-i="${i+1}"></div>`).join('');}
function setupSq(div){div.querySelectorAll('.sq-dot').forEach(d=>d.onclick=()=>{if(!isReadOnly)d.classList.toggle('active');});}

function addRealSafe() {
    const card = addReal(null, false);
    if (card) {
        document.getElementById('list-real').appendChild(card);
    }
}
function setupRDots(div){const d=div.querySelectorAll('.r-dots .dot');d.forEach(dot=>{dot.onclick=()=>{if(isReadOnly)return;const idx=parseInt(dot.dataset.i);d.forEach((dd,i)=>{if(i<idx)dd.classList.add('active');else dd.classList.remove('active');});}});}
function fillAnom(div,d){div.querySelector('.f-name').value=d.name||'';div.querySelector('.f-trig').value=d.qual||'';div.querySelector('.f-qual').value=d.trig||'';div.querySelector('.f-succ').innerHTML=d.succ||'';div.querySelector('.f-fail').innerHTML=d.fail||'';if(d.chk)div.querySelector('.f-chk').checked=d.chk;if(d.tdesc)div.querySelector('.f-tdesc').value=d.tdesc;if(d.t1)div.querySelector('.f-t1').value=d.t1;if(d.t1v)div.querySelector('.f-t1-val').value=d.t1v;if(d.t2)div.querySelector('.f-t2').value=d.t2;if(d.t2v)div.querySelector('.f-t2-val').value=d.t2v;if(d.p1)div.querySelectorAll('.d1 .sq-dot').forEach((e,i)=>{if(d.p1[i])e.classList.add('active')});if(d.p2)div.querySelectorAll('.d2 .sq-dot').forEach((e,i)=>{if(d.p2[i])e.classList.add('active')});}

function syncAnomDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
    const name = card.querySelector('.f-name').value;
    const trig = card.querySelector('.f-trig').value;
    const qual = card.querySelector('.f-qual').value;
    const succ = card.querySelector('.f-succ');
    const fail = card.querySelector('.f-fail');
    const tdesc = card.querySelector('.f-tdesc').value;
    const t1 = card.querySelector('.f-t1').value;
    const t1v = card.querySelector('.f-t1-val').value;
    const t2 = card.querySelector('.f-t2').value;
    const t2v = card.querySelector('.f-t2-val').value;

    const dn = card.querySelector('.anom-disp-name');
    if (dn) dn.innerHTML = esc(name) || '<span class="anom-empty">未命名</span>';
    const dt = card.querySelector('.anom-disp-trig');
    if (dt) dt.innerHTML = trig ? '<span class="anom-disp-tag c-anom"><i class="fas fa-bolt"></i></span> ' + esc(trig) : '<span class="anom-empty">无触发器</span>';
    const dq = card.querySelector('.anom-disp-qual');
    if (dq) dq.innerHTML = qual ? '<span class="anom-disp-tag c-anom"><i class="fas fa-star"></i> 资质</span> ' + esc(qual) : '';
    const dr = card.querySelector('.anom-disp-qual-row');
    if (dr) dr.style.display = qual ? '' : 'none';
    const ds = card.querySelector('.anom-disp-succ');
    if (ds) ds.innerHTML = succ?.textContent?.trim() ? succ.innerHTML : '<span class="anom-empty">无</span>';
    const df = card.querySelector('.anom-disp-fail');
    if (df) df.innerHTML = fail?.textContent?.trim() ? fail.innerHTML : '<span class="anom-empty">无</span>';
    const dqs = card.querySelector('.anom-disp-question');
    if (dqs) {
        let qhtml = '';
        if (card.querySelector('.f-chk').checked) qhtml += '<span class="anom-disp-trained"><i class="fas fa-graduation-cap"></i> 已训练</span> ';
        if (tdesc) qhtml += '<strong>' + esc(tdesc) + '</strong>';
        if (t1) qhtml += '<div class="anom-disp-a"><span class="anom-disp-tag"><i class="fas fa-angle-right"></i> ' + esc(t1) + '</span>' + (t1v ? ' <code>' + esc(t1v) + '</code>' : '') + renderDotsHtml(card, 'd1') + '</div>';
        if (t2) qhtml += '<div class="anom-disp-a"><span class="anom-disp-tag"><i class="fas fa-angle-right"></i> ' + esc(t2) + '</span>' + (t2v ? ' <code>' + esc(t2v) + '</code>' : '') + renderDotsHtml(card, 'd2') + '</div>';
        if (!qhtml) qhtml = '<span class="anom-empty">无问题</span>';
        dqs.innerHTML = qhtml;
    }
}

function renderDotsHtml(card, cls) {
    const dots = card.querySelectorAll('.' + cls + ' .sq-dot');
    if (!dots.length) return '';
    let h = '<span class="anom-disp-dots">';
    dots.forEach(d => { h += d.classList.contains('active') ? '<span class="sq-dot active"></span>' : '<span class="sq-dot"></span>'; });
    return h + '</span>';
}

function openAnomCardEdit(cardEl) {
    if (isReadOnly) return;
    const modal = document.getElementById('anomEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    q('.anom-edit-name').value = cardEl.querySelector('.f-name').value;
    q('.anom-edit-trig').value = cardEl.querySelector('.f-trig').value;
    q('.anom-edit-qual').value = cardEl.querySelector('.f-qual').value;
    q('.anom-edit-succ').innerHTML = cardEl.querySelector('.f-succ').innerHTML || '';
    q('.anom-edit-fail').innerHTML = cardEl.querySelector('.f-fail').innerHTML || '';
    q('.anom-edit-tdesc').value = cardEl.querySelector('.f-tdesc').value;
    q('.anom-edit-chk').checked = cardEl.querySelector('.f-chk').checked;
    q('.anom-edit-t1').value = cardEl.querySelector('.f-t1').value;
    q('.anom-edit-t1v').value = cardEl.querySelector('.f-t1-val').value;
    q('.anom-edit-t2').value = cardEl.querySelector('.f-t2').value;
    q('.anom-edit-t2v').value = cardEl.querySelector('.f-t2-val').value;
    cardEl.querySelectorAll('.d1 .sq-dot').forEach((d,i) => { const md = q('.anom-edit-d1 .sq-dot:nth-child('+(i+1)+')'); if(md){d.classList.contains('active')?md.classList.add('active'):md.classList.remove('active');} });
    cardEl.querySelectorAll('.d2 .sq-dot').forEach((d,i) => { const md = q('.anom-edit-d2 .sq-dot:nth-child('+(i+1)+')'); if(md){d.classList.contains('active')?md.classList.add('active'):md.classList.remove('active');} });
    window._anomEditCard = cardEl;
    q('.anom-edit-name').focus();
}

function closeAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._anomEditCard = null;
}

function saveAnomCardEdit() {
    const modal = document.getElementById('anomEditModal');
    const card = window._anomEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-name').value = q('.anom-edit-name').value;
    card.querySelector('.f-trig').value = q('.anom-edit-trig').value;
    card.querySelector('.f-qual').value = q('.anom-edit-qual').value;
    card.querySelector('.f-succ').innerHTML = q('.anom-edit-succ').innerHTML || '';
    card.querySelector('.f-fail').innerHTML = q('.anom-edit-fail').innerHTML || '';
    card.querySelector('.f-tdesc').value = q('.anom-edit-tdesc').value;
    card.querySelector('.f-chk').checked = q('.anom-edit-chk').checked;
    card.querySelector('.f-t1').value = q('.anom-edit-t1').value;
    card.querySelector('.f-t1-val').value = q('.anom-edit-t1v').value;
    card.querySelector('.f-t2').value = q('.anom-edit-t2').value;
    card.querySelector('.f-t2-val').value = q('.anom-edit-t2v').value;
    card.querySelectorAll('.d1 .sq-dot').forEach((d,i) => { const md = q('.anom-edit-d1 .sq-dot:nth-child('+(i+1)+')'); if(md){md.classList.contains('active')?d.classList.add('active'):d.classList.remove('active');} });
    card.querySelectorAll('.d2 .sq-dot').forEach((d,i) => { const md = q('.anom-edit-d2 .sq-dot:nth-child('+(i+1)+')'); if(md){md.classList.contains('active')?d.classList.add('active'):d.classList.remove('active');} });
    syncAnomDisplay(card);
    triggerAutoSave();
    closeAnomCardEdit();
}

function fillReal(div, d) {
    div.querySelector('.f-name').value = d.name || '';
    div.querySelector('.f-actor').value = d.actor || '';
    div.querySelector('.f-desc').innerHTML = d.desc || '';
    if (d.act) div.querySelector('.f-act').checked = d.act;
    div.querySelector('.f-conn').innerHTML = d.conn || '';
    div.querySelectorAll('.r-dots-hidden .dot').forEach((e, i) => {
        if (i < (d.lvl || 0)) e.classList.add('active');
    });
}

function syncRealDisplay(card) {
    if (!card) return;
    const esc = s => s ? s.replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
    const name = card.querySelector('.f-name').value;
    const actor = card.querySelector('.f-actor').value;
    const desc = card.querySelector('.f-desc');
    const act = card.querySelector('.f-act').checked;
    const conn = card.querySelector('.f-conn');
    const lvl = card.querySelectorAll('.r-dots-hidden .dot.active').length;

    const dn = card.querySelector('.real-disp-name');
    if (dn) dn.innerHTML = name ? '<span class="real-disp-label">姓名：</span>' + esc(name) : '<span class="anom-empty">未命名</span>';
    const da = card.querySelector('.real-disp-actor');
    const sep = card.querySelector('.real-field-sep');
    if (da && sep) { if (actor) { da.innerHTML = '<span class="real-disp-label">扮演者：</span>' + esc(actor); da.style.display = ''; sep.style.display = ''; } else { da.style.display = 'none'; sep.style.display = 'none'; } }

    const dd = card.querySelector('.real-disp-desc');
    if (dd) dd.innerHTML = desc?.textContent?.trim() ? desc.innerHTML : '';
    const dl = card.querySelector('.real-disp-lvl');
    if (dl) {
        let dots = '';
        for (let i = 1; i <= 9; i++) dots += `<span class="real-lvl-dot${i <= lvl ? ' active' : ''}"></span>`;
        dl.innerHTML = dots;
    }
    const dact = card.querySelector('.real-disp-act');
    if (dact) dact.innerHTML = act ? '<span class="real-act-badge"><i class="fas fa-check"></i> 已激活</span>' : '';
    const dc = card.querySelector('.real-disp-conn');
    if (dc) dc.innerHTML = conn?.textContent?.trim() ? conn.innerHTML : '';
}

function openRealCardEdit(cardEl) {
    if (isReadOnly) return;
    const modal = document.getElementById('realEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.real-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });
    const q = s => modal.querySelector(s);
    const bonusSel = q('.real-edit-conn-sel');
    bonusSel.innerHTML = getBonusOptions();
    const connWrapper = bonusSel.closest('.hybrid-input-wrapper');
    connWrapper.classList.remove('show-input');
    bonusSel.value = '';

    q('.real-edit-name').value = cardEl.querySelector('.f-name').value;
    q('.real-edit-actor').value = cardEl.querySelector('.f-actor').value;
    q('.real-edit-desc').innerHTML = cardEl.querySelector('.f-desc').innerHTML || '';
    q('.real-edit-act').checked = cardEl.querySelector('.f-act').checked;

    const connVal = cardEl.querySelector('.f-conn').innerHTML || '';
    q('.real-edit-conn').innerHTML = connVal;
    if (connVal.trim()) {
        connWrapper.classList.add('show-input');
        bonusSel.value = '__CUSTOM__';
    }

    const lvl = cardEl.querySelectorAll('.r-dots-hidden .dot.active').length;
    q('.real-edit-lvl').value = lvl;
    updateRealLvlDots(lvl);
    window._realEditCard = cardEl;
    q('.real-edit-name').focus();
}

window.handleRealBonusChange = function(select) {
    const wrapper = select.parentElement;
    const editor = wrapper.querySelector('.rich-editor');
    const val = select.value;
    wrapper.classList.add('show-input');
    if (val === '__CUSTOM__') {
        editor.focus();
    } else {
        editor.innerHTML = val;
    }
};

window.resetRealBonus = function(btn) {
    const wrapper = btn.parentElement;
    const select = wrapper.querySelector('select');
    wrapper.classList.remove('show-input');
    select.value = '';
};

function updateRealLvlDots(val) {
    const v = parseInt(val) || 0;
    document.querySelectorAll('.real-edit-lvl-dots .dot').forEach((d, i) => {
        i < v ? d.classList.add('active') : d.classList.remove('active');
    });
}

function closeRealCardEdit() {
    const modal = document.getElementById('realEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
    window._realEditCard = null;
}

function saveRealCardEdit() {
    const modal = document.getElementById('realEditModal');
    const card = window._realEditCard;
    if (!card) return;
    const q = s => modal.querySelector(s);
    card.querySelector('.f-name').value = q('.real-edit-name').value;
    card.querySelector('.f-actor').value = q('.real-edit-actor').value;
    card.querySelector('.f-desc').innerHTML = q('.real-edit-desc').innerHTML || '';
    card.querySelector('.f-act').checked = q('.real-edit-act').checked;
    card.querySelector('.f-conn').innerHTML = q('.real-edit-conn').innerHTML || '';
    const lvl = parseInt(q('.real-edit-lvl').value) || 0;
    card.querySelectorAll('.r-dots-hidden .dot').forEach((d, i) => {
        i < lvl ? d.classList.add('active') : d.classList.remove('active');
    });
    syncRealDisplay(card);
    triggerAutoSave();
    closeRealCardEdit();
}

function syncCharDisplay() {
    const body = document.getElementById('charInfoBody');
    if (!body) return;
    const esc = s => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const richVal = id => { const el = document.getElementById(id); return el ? el.innerHTML.trim() : ''; };
    const textVal = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };

    const pName = textVal('pName');
    const pAnom = textVal('pAnom');
    const pReal = textVal('pReal');
    const pFunc = textVal('pFunc');
    const trig1 = richVal('pTrig1');
    const trig2 = richVal('pTrig2');
    const trig3 = richVal('pTrig3');
    const perm1 = textVal('perm1');
    const perm2 = textVal('perm2');
    const perm3 = textVal('perm3');
    const derivCells = document.querySelectorAll('.derivative-progress .progress-cell');
    const derivActive = [];
    derivCells.forEach((c, i) => { if (c.classList.contains('active')) derivActive.push(i + 1); });

    let html = '';
    if (pName) html += `<div class="char-info-row"><span class="char-info-label">姓名</span><span class="char-info-value">${esc(pName)}</span></div>`;

    const typeItems = [];
    if (pAnom) typeItems.push(`<span class="char-info-type type-anom"><i class="fas fa-bolt"></i><span>${esc(pAnom)}</span></span>`);
    if (pReal) typeItems.push(`<span class="char-info-type type-real"><i class="fas fa-heart"></i><span>${esc(pReal)}</span></span>`);
    if (pFunc) typeItems.push(`<span class="char-info-type type-func"><i class="fas fa-briefcase"></i><span>${esc(pFunc)}</span></span>`);
    if (typeItems.length) html += `<div class="char-info-types">${typeItems.join('')}</div>`;

    if (trig1 || trig2) {
        html += `<div class="char-info-section">`;
        if (trig1) html += `<div class="char-info-row"><span class="char-info-label">过载解除</span><span class="char-info-value rich-content">${trig1}</span></div>`;
        if (trig2) html += `<div class="char-info-row"><span class="char-info-label">现实触发器</span><span class="char-info-value rich-content">${trig2}</span></div>`;
        html += `</div>`;
    }

    if (derivCells.length > 0) {
        html += `<div class="char-info-section inline-section"><div class="char-info-section-title">现实计数</div><div class="char-info-dots">`;
        derivCells.forEach((c, i) => {
            html += `<span class="char-info-dot${c.classList.contains('active') ? ' active' : ''}">${i + 1}</span>`;
        });
        html += `</div></div>`;
    }

    if (trig3) {
        html += `<div class="char-info-section"><div class="char-info-section-title" style="color:var(--functional)">首要指令</div><div class="char-info-value rich-content">${trig3}</div></div>`;
    }

    if (perm1 || perm2 || perm3) {
        html += `<div class="char-info-section"><div class="char-info-section-title">许可行为</div><div class="char-info-perms">`;
        if (perm1) html += `<div class="char-info-perm-item">${esc(perm1)}</div>`;
        if (perm2) html += `<div class="char-info-perm-item">${esc(perm2)}</div>`;
        if (perm3) html += `<div class="char-info-perm-item">${esc(perm3)}</div>`;
        html += `</div></div>`;
    }

    body.innerHTML = html || '<div style="color:var(--text-dim); font-size:11px; text-align:center; padding:20px;">点击"编辑"填写基础信息</div>';
}

function openCharEdit() {
    if (isReadOnly) return;
    const modal = document.getElementById('charEditModal');
    modal.classList.add('active');
    modal._wheelBlock = (e) => { const body = modal.querySelector('.anom-edit-body'); if (!body.contains(e.target)) e.preventDefault(); };
    modal.addEventListener('wheel', modal._wheelBlock, { passive: false });

    const q = s => modal.querySelector(s);
    q('.char-edit-name').value = document.getElementById('pName').value;
    q('.char-edit-anom').value = document.getElementById('pAnom').value;
    q('.char-edit-real').value = document.getElementById('pReal').value;
    q('.char-edit-func').value = document.getElementById('pFunc').value;
    q('.char-edit-trig1').innerHTML = document.getElementById('pTrig1').innerHTML || '';
    q('.char-edit-trig2').innerHTML = document.getElementById('pTrig2').innerHTML || '';
    q('.char-edit-trig3').innerHTML = document.getElementById('pTrig3').innerHTML || '';
    q('.char-edit-perm1').value = document.getElementById('perm1').value;
    q('.char-edit-perm2').value = document.getElementById('perm2').value;
    q('.char-edit-perm3').value = document.getElementById('perm3').value;

    const anomSel = q('.char-edit-anom-sel');
    const realSel = q('.char-edit-real-sel');
    const funcSel = q('.char-edit-func-sel');
    const fillSel = (sel, items) => {
        sel.innerHTML = '<option value="" disabled selected>-- 请选择 --</option>';
        if (items && Array.isArray(items)) items.forEach(item => { const val = typeof item === 'string' ? item : item.name; const o = document.createElement('option'); o.value = val; o.textContent = val; sel.appendChild(o); });
        const co = document.createElement('option'); co.value = '__CUSTOM__'; co.textContent = '➤ 自定义 / 手动输入...'; sel.appendChild(co);
    };
    fillSel(anomSel, CONFIG_DATA.anoms);
    fillSel(realSel, CONFIG_DATA.realities);
    fillSel(funcSel, CONFIG_DATA.functions);

    const setModalHybrid = (selClass, inputClass, grpId, val) => {
        const sel = q(selClass);
        const wrapper = document.getElementById(grpId);
        let isPreset = false;
        Array.from(sel.options).forEach(opt => { if (opt.value === val) isPreset = true; });
        if (isPreset) { wrapper.classList.remove('show-input'); sel.value = val; }
        else if (val && val.trim()) { wrapper.classList.add('show-input'); sel.value = '__CUSTOM__'; }
        else { wrapper.classList.remove('show-input'); sel.value = ''; }
    };
    setModalHybrid('.char-edit-anom-sel', '.char-edit-anom', 'grp-char-pAnom', document.getElementById('pAnom').value);
    setModalHybrid('.char-edit-real-sel', '.char-edit-real', 'grp-char-pReal', document.getElementById('pReal').value);
    setModalHybrid('.char-edit-func-sel', '.char-edit-func', 'grp-char-pFunc', document.getElementById('pFunc').value);

    const hiddenDeriv = document.querySelectorAll('.derivative-progress .progress-cell');
    modal.querySelectorAll('.char-deriv-cell[data-idx]').forEach((c, i) => {
        if (hiddenDeriv[i] && hiddenDeriv[i].classList.contains('active')) c.classList.add('active');
        else c.classList.remove('active');
    });

    q('.char-edit-name').focus();
}

window.handleCharPresetChange = function(fieldId, value) {
    const map = { pAnom: ['.char-edit-anom-sel', '.char-edit-anom', 'grp-char-pAnom'], pReal: ['.char-edit-real-sel', '.char-edit-real', 'grp-char-pReal'], pFunc: ['.char-edit-func-sel', '.char-edit-func', 'grp-char-pFunc'] };
    const m = map[fieldId];
    if (!m) return;
    const modal = document.getElementById('charEditModal');
    const wrapper = document.getElementById(m[2]);
    const input = modal.querySelector(m[1]);
    if (value === '__CUSTOM__') {
        wrapper.classList.add('show-input');
        input.value = '';
        input.focus();
    } else {
        input.value = value;
        wrapper.classList.remove('show-input');
        document.getElementById(fieldId).value = value;
        if (fieldId === 'pReal') {
            const config = CONFIG_DATA.realities.find(r => r.name === value);
            if (config) {
                modal.querySelector('.char-edit-trig1').innerHTML = config.trigger || '';
                modal.querySelector('.char-edit-trig2').innerHTML = config.overload || '';
                document.getElementById('pTrig1').innerHTML = config.trigger || '';
                document.getElementById('pTrig2').innerHTML = config.overload || '';
            }
        } else if (fieldId === 'pFunc') {
            const config = CONFIG_DATA.functions.find(f => f.name === value);
            if (config) {
                modal.querySelector('.char-edit-trig3').innerHTML = config.directive || '';
                document.getElementById('pTrig3').innerHTML = config.directive || '';
                if (config.perms && config.perms.length === 3) {
                    modal.querySelector('.char-edit-perm1').value = config.perms[0];
                    modal.querySelector('.char-edit-perm2').value = config.perms[1];
                    modal.querySelector('.char-edit-perm3').value = config.perms[2];
                    document.getElementById('perm1').value = config.perms[0];
                    document.getElementById('perm2').value = config.perms[1];
                    document.getElementById('perm3').value = config.perms[2];
                }
                const itemListContainer = document.getElementById('list-item');
                const presetItems = (config.items || []).slice().reverse();
                const numToReplace = presetItems.length;
                for (let i = 0; i < numToReplace; i++) {
                    if (itemListContainer.firstChild) itemListContainer.firstChild.remove();
                }
                presetItems.forEach(itemData => addItem(itemData, true));
                if (config.Assessment && config.Assessment.length > 0) {
                    modal._pendingAssessment = config.Assessment;
                }
            }
        } else if (fieldId === 'pAnom') {
            const config = CONFIG_DATA.anoms.find(a => a.name === value);
            if (config) {
                const anomListContainer = document.getElementById('list-anom');
                const presetAbilities = (config.abilities || []).slice().reverse();
                const numToReplace = presetAbilities.length;
                for (let i = 0; i < numToReplace; i++) {
                    if (anomListContainer.firstChild) anomListContainer.firstChild.remove();
                }
                presetAbilities.forEach(abilityData => addAnom(abilityData, true));
            }
        }
    }
};

window.resetCharDropdown = function(fieldId) {
    const map = { pAnom: ['.char-edit-anom-sel', 'grp-char-pAnom'], pReal: ['.char-edit-real-sel', 'grp-char-pReal'], pFunc: ['.char-edit-func-sel', 'grp-char-pFunc'] };
    const m = map[fieldId];
    if (!m) return;
    const modal = document.getElementById('charEditModal');
    const wrapper = document.getElementById(m[1]);
    const sel = modal.querySelector(m[0]);
    wrapper.classList.remove('show-input');
    sel.value = '';
};

function closeCharEdit() {
    const modal = document.getElementById('charEditModal');
    modal.classList.remove('active');
    if (modal._wheelBlock) { modal.removeEventListener('wheel', modal._wheelBlock); modal._wheelBlock = null; }
}

function saveCharEdit() {
    const modal = document.getElementById('charEditModal');
    const q = s => modal.querySelector(s);
    const assessment = modal._pendingAssessment;
    modal._pendingAssessment = null;

    document.getElementById('pName').value = q('.char-edit-name').value;
    document.getElementById('pAnom').value = q('.char-edit-anom').value;
    document.getElementById('pReal').value = q('.char-edit-real').value;
    document.getElementById('pFunc').value = q('.char-edit-func').value;
    document.getElementById('pTrig1').innerHTML = q('.char-edit-trig1').innerHTML || '';
    document.getElementById('pTrig2').innerHTML = q('.char-edit-trig2').innerHTML || '';
    document.getElementById('pTrig3').innerHTML = q('.char-edit-trig3').innerHTML || '';
    document.getElementById('perm1').value = q('.char-edit-perm1').value;
    document.getElementById('perm2').value = q('.char-edit-perm2').value;
    document.getElementById('perm3').value = q('.char-edit-perm3').value;

    modal.querySelectorAll('.char-deriv-cell[data-idx]').forEach((c, i) => {
        const hiddenCells = document.querySelectorAll('.derivative-progress .progress-cell');
        if (hiddenCells[i]) {
            if (c.classList.contains('active')) hiddenCells[i].classList.add('active');
            else hiddenCells[i].classList.remove('active');
        }
    });

    syncCharDisplay();
    triggerAutoSave();
    closeCharEdit();
    if (assessment) showAssessmentModal(assessment);
}

function updateCharLayout() {
    const leftPanel = document.querySelector('.char-attrs-panel');
    const rightPanel = document.querySelector('.char-info-panel');
    const sideLeft = document.getElementById('char-side-left');
    const sideRight = document.getElementById('char-side-right');
    const colLeft = document.querySelector('.char-col-left');
    const colRight = document.querySelector('.char-col-right');
    if (!leftPanel || !rightPanel || !sideLeft || !sideRight || !colLeft || !colRight) return;
    const isDesktop = window.innerWidth >= 1600;
    if (isDesktop) {
        if (!sideLeft.contains(leftPanel)) sideLeft.appendChild(leftPanel);
        if (!sideRight.contains(rightPanel)) sideRight.appendChild(rightPanel);
        sideLeft.classList.add('active');
        sideRight.classList.add('active');
    } else {
        if (!colLeft.contains(leftPanel)) colLeft.appendChild(leftPanel);
        if (!colLeft.contains(rightPanel)) colLeft.appendChild(rightPanel);
        sideLeft.classList.remove('active');
        sideRight.classList.remove('active');
    }
}
window.addEventListener('resize', () => { updateCharLayout(); drawTrackSVG(); });

function drawTrackSVG() {
    const isMobile = window.innerWidth < 768;
    document.querySelectorAll('.track-svg').forEach(svg => {
        svg.innerHTML = '';
        if (isMobile) return;
        const wrap = svg.parentElement;
        const snake = wrap.querySelector('.track-snake');
        if (!snake) return;
        const wrapRect = wrap.getBoundingClientRect();
        if (!snake.querySelector('[data-idx="30"]')) return;

        const getEdge = (idx, edge) => {
            const cell = snake.querySelector('[data-idx="' + idx + '"]');
            if (!cell) return null;
            const r = cell.getBoundingClientRect();
            const cx = r.left + r.width / 2 - wrapRect.left;
            const cy = r.top + r.height / 2 - wrapRect.top;
            if (edge === 'right') return { x: r.right - wrapRect.left, y: cy };
            if (edge === 'left') return { x: r.left - wrapRect.left, y: cy };
            if (edge === 'bottom') return { x: cx, y: r.bottom - wrapRect.top };
            if (edge === 'top') return { x: cx, y: r.top - wrapRect.top };
            return { x: cx, y: cy };
        };

        const makeArrow = (x, y, angle) => {
            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('transform', 'translate(' + x + ',' + y + ') rotate(' + angle + ')');
            const p = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
            p.setAttribute('points', '-4,-4 4,0 -4,4');
            p.setAttribute('fill', '#95a5a6');
            g.appendChild(p);
            return g;
        };

        const seq = [];
        for (let i = 1; i <= 15; i++) seq.push(i);
        for (let i = 16; i <= 30; i++) seq.push(i);

        for (let i = 0; i < seq.length - 1; i++) {
            const aIdx = seq[i], bIdx = seq[i + 1];
            if (aIdx <= 15 && bIdx <= 15) {
                const a = getEdge(aIdx, 'right');
                const b = getEdge(bIdx, 'left');
                if (a && b) svg.appendChild(makeArrow((a.x + b.x) / 2, a.y, 0));
            } else if (aIdx === 15 && bIdx === 16) {
                const a = getEdge(aIdx, 'bottom');
                const b = getEdge(bIdx, 'top');
                if (a && b) svg.appendChild(makeArrow(a.x, (a.y + b.y) / 2, 90));
            } else if (aIdx >= 16 && bIdx >= 16) {
                const a = getEdge(aIdx, 'left');
                const b = getEdge(bIdx, 'right');
                if (a && b) svg.appendChild(makeArrow((a.x + b.x) / 2, a.y, 180));
            }
        }
    });
}

document.querySelectorAll('.p-cell').forEach(c=>{c.addEventListener('click',()=>{if(isReadOnly)return;if(c.classList.contains('active')){c.classList.remove('active');c.classList.add('ignored');}else if(c.classList.contains('ignored')){c.classList.remove('ignored');}else{c.classList.add('active');}});c.addEventListener('contextmenu',(e)=>{e.preventDefault();if(isReadOnly)return;c.classList.remove('active');c.classList.add('ignored');});});
function populateData(d){
    // 加载数据时清除评估记录，因为属性值来自外部数据
    lastAssessmentAttributes = [];
    
    SLOT_LIMITS.anomSlots = d.anomSlots || 10;
    SLOT_LIMITS.realSlots = d.realSlots || 10;
    ['pName','pTrig1','pTrig2','pTrig3','perm1','perm2','perm3','pComm','pRep','mvpCount','watchCount','noteTitle','noteBody'].forEach(id=>{const e=document.getElementById(id);if(d[id]&&e){if(e.tagName==='DIV')e.innerHTML=d[id];else e.value=d[id];}});
	    document.getElementById('mvpCount').value = d.mvpCount || (d.rewards || []).reduce((sum, r) => sum + (r.count || 1), 0);
    document.getElementById('watchCount').value = d.watchCount || (d.reprimands || []).reduce((sum, r) => sum + (r.count || 1), 0);
	setHybridInputState('pAnom',d.pAnom);setHybridInputState('pReal',d.pReal);setHybridInputState('pFunc',d.pFunc);if(d.qs)d.qs.forEach((h,i)=>{const q=document.getElementById(`q${i+1}`);if(q)q.innerHTML=h;});if(d.attrs){for(let k in d.attrs){const r=document.querySelector(`.attr-input[data-attr="${k}"]`);if(r){r.value=d.attrs[k].v;renderTriangles(k,d.attrs[k].v);const container=document.querySelector(`.attr-dots[data-attr="${k}"]`);if(container && d.attrs[k].m){d.attrs[k].m.forEach(idx=>{const tri=container.querySelector(`.tri-btn[data-i="${idx}"]`);if(tri){tri.classList.remove('active');tri.classList.add('marked');}});}}}}document.getElementById('list-anom').innerHTML='';document.getElementById('list-real').innerHTML='';document.getElementById('list-item').innerHTML='';
    (d.anoms||[]).forEach(x=>addAnom(x, false, true));
    (d.reals||[]).forEach(x=>{const card = addReal(x, true); if(card) document.getElementById('list-real').appendChild(card);});
    (d.items||[]).forEach(x=>addItem(x, false));
    if(!document.getElementById('list-anom').children.length)addAnom(null, false, true);
    if(!document.getElementById('list-real').children.length){const card = addReal(null, true); if(card) document.getElementById('list-real').appendChild(card);}
    if(!document.getElementById('list-item').children.length)addItem(null, false);
    (d.pf||[]).forEach(i=>document.querySelector(`.f-cell[data-idx="${i}"]`)?.classList.add('active'));(d.pr||[]).forEach(i=>document.querySelector(`.r-cell[data-idx="${i}"]`)?.classList.add('active'));(d.pa||[]).forEach(i=>document.querySelector(`.a-cell[data-idx="${i}"]`)?.classList.add('active'));(d.pf_ign||[]).forEach(i=>document.querySelector(`.f-cell[data-idx="${i}"]`)?.classList.add('ignored'));(d.pr_ign||[]).forEach(i=>document.querySelector(`.r-cell[data-idx="${i}"]`)?.classList.add('ignored'));(d.pa_ign||[]).forEach(i=>document.querySelector(`.a-cell[data-idx="${i}"]`)?.classList.add('ignored'));
    // 加载衍生进度
    if(d.derivativeProgress){d.derivativeProgress.forEach(i=>document.querySelector(`.progress-cell[data-idx="${i}"]`)?.classList.add('active'));}
    updateSlotButtons();
    syncCharDisplay();
}
function gatherData(){const d={pName:document.getElementById('pName').value,pAnom:document.getElementById('pAnom').value,pReal:document.getElementById('pReal').value,pFunc:document.getElementById('pFunc').value,pTrig1:document.getElementById('pTrig1').innerHTML,pTrig2:document.getElementById('pTrig2').innerHTML,pTrig3:document.getElementById('pTrig3').innerHTML,perm1:document.getElementById('perm1').value,perm2:document.getElementById('perm2').value,perm3:document.getElementById('perm3').value,pComm:document.getElementById('pComm').value,pRep:document.getElementById('pRep').value,mvpCount:document.getElementById('mvpCount').value,watchCount:document.getElementById('watchCount').value,noteTitle:document.getElementById('noteTitle').value,noteBody:document.getElementById('noteBody').innerHTML,qs:[],attrs:{},anoms:[],reals:[],items:[],pf:[],pr:[],pa:[],pf_ign:[],pr_ign:[],pa_ign:[],derivativeProgress:[],anomSlots:SLOT_LIMITS.anomSlots,realSlots:SLOT_LIMITS.realSlots};for(let i=1;i<=7;i++)d.qs.push(document.getElementById(`q${i}`).innerHTML);ATTRS.forEach(a=>{const container=document.querySelector(`.attr-dots[data-attr="${a}"]`),m=[];if(container){container.querySelectorAll('.tri-btn.marked').forEach(tri=>m.push(parseInt(tri.dataset.i)));}const input=document.querySelector(`.attr-input[data-attr="${a}"]`);d.attrs[a]={v:input?input.value:'0',m:m};});document.querySelectorAll('#list-anom .card').forEach(c=>{d.anoms.push({name:c.querySelector('.f-name').value,trig:c.querySelector('.f-qual').value,qual:c.querySelector('.f-trig').value,succ:c.querySelector('.f-succ').innerHTML,fail:c.querySelector('.f-fail').innerHTML,chk:c.querySelector('.f-chk').checked,tdesc:c.querySelector('.f-tdesc').value,t1:c.querySelector('.f-t1').value,t1v:c.querySelector('.f-t1-val').value,t2:c.querySelector('.f-t2').value,t2v:c.querySelector('.f-t2-val').value,p1:Array.from(c.querySelectorAll('.d1 .sq-dot')).map(e=>e.classList.contains('active')),p2:Array.from(c.querySelectorAll('.d2 .sq-dot')).map(e=>e.classList.contains('active'))});});document.querySelectorAll('#list-real .card').forEach(c=>{let l=0;c.querySelectorAll('.r-dots-hidden .dot').forEach((e,i)=>{if(e.classList.contains('active'))l=i+1});d.reals.push({name:c.querySelector('.f-name').value,actor:c.querySelector('.f-actor').value,desc:c.querySelector('.f-desc').innerHTML,act:c.querySelector('.f-act').checked,conn:c.querySelector('.f-conn').innerHTML,lvl:l});});document.querySelectorAll('#list-item .card').forEach(c=>{d.items.push({item:c.querySelector('.f-item').value,pd:c.querySelector('.f-pd').value,eff:c.querySelector('.f-eff').innerHTML,once:c.querySelector('.f-once').value==='1'});});document.querySelectorAll('.f-cell.active').forEach(e=>d.pf.push(parseInt(e.dataset.idx)));document.querySelectorAll('.r-cell.active').forEach(e=>d.pr.push(parseInt(e.dataset.idx)));document.querySelectorAll('.a-cell.active').forEach(e=>d.pa.push(parseInt(e.dataset.idx)));document.querySelectorAll('.f-cell.ignored').forEach(e=>d.pf_ign.push(parseInt(e.dataset.idx)));document.querySelectorAll('.r-cell.ignored').forEach(e=>d.pr_ign.push(parseInt(e.dataset.idx)));document.querySelectorAll('.a-cell.ignored').forEach(e=>d.pa_ign.push(parseInt(e.dataset.idx)));d.derivativeProgress=[];document.querySelectorAll('.progress-cell.active').forEach(e=>d.derivativeProgress.push(parseInt(e.dataset.idx)));return d;}
function showToast(msg, type='success') {
    const m = document.getElementById('status-msg');
    m.innerHTML = type === 'error' ? `<i class="fas fa-exclamation-circle"></i> ${msg}` : `<i class="fas fa-save"></i> ${msg}`;
    m.className = type === 'error' ? 'error' : 'success';
    m.style.display = 'block';
    setTimeout(() => m.style.display = 'none', 2500);
}
// 自动保存防抖
let autoSaveTimer = null;
function triggerAutoSave() {
    if (isReadOnly) return;
    if (autoSaveTimer) clearTimeout(autoSaveTimer);
    autoSaveTimer = setTimeout(() => {
        saveData(true); // 静默保存
    }, 1000); // 1秒后保存
}

async function saveData(silent=false){if(isReadOnly)return;const d=gatherData();const res=await fetch(`/api/character/${charId}`,{method:'PUT',headers:getAuthHeaders(),body:JSON.stringify(d)});if(res.ok){if(!silent){showToast('DATA_SAVED', 'success');}}else if(res.status===401||res.status===403){window.location.href='login.html';}else{if(!silent){showToast('保存失败', 'error');}}}
async function exportOffline(){
    const d=gatherData();
    const dataJson=JSON.stringify(d);
    let cssText='', jsText='';
    try{ const r=await fetch('css/sheet.css'); if(r.ok) cssText=await r.text(); }catch(e){}
    try{ const r=await fetch('js/sheet.js'); if(r.ok) jsText=await r.text(); }catch(e){}
    const html=`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no,viewport-fit=cover"/>
<title>${(d.pName||'角色')}_离线备份 // TRIANGLE AGENCY</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>${cssText}</style>
</head>
<body class="offline-mode">
<div id="status-msg"><i class="fas fa-save"></i> DATA_SAVED</div>
<div class="container">
<div class="top-nav">
    <button class="btn-back" onclick="window.close()"><i class="fas fa-chevron-left"></i> 关闭</button>
    <div class="brand-logo-sm"><span>TRIANGLE</span><span>AGENCY</span></div>
    <div class="header-right">
        <h1>职员档案 <span class="sub"><span class="offline-tag">OFFLINE</span></span></h1>
    </div>
</div>
<div class="swiper-container" id="swiperContainer">
<div class="swiper-wrapper" id="swiperWrapper">
<div id="view-char" class="tab-view">
<div class="char-layout">
<div class="panel"><h2><i class="fas fa-shield-alt"></i> 资质保证<button class="btn-reset-all-attrs" onclick="resetAllAttrs()" title="重置所有标记">↻</button></h2><div id="attrs-list"></div></div>
<div class="panel">
<h2><i class="fas fa-id-card"></i> 基础信息</h2>
<label>玩家姓名</label><input type="text" id="pName" placeholder="输入姓名">
<div class="row-2">
<div><label>异常能力</label><div class="hybrid-input-wrapper" id="grp-pAnom"><select id="sel-pAnom" onchange="handlePresetChange('pAnom', this.value)"></select><input type="text" id="pAnom" placeholder="输入异常能力"><button class="btn-reset-list" onclick="resetToDropdown('pAnom')"><i class="fas fa-list"></i></button></div></div>
<div><label>现实身份</label><div class="hybrid-input-wrapper" id="grp-pReal"><select id="sel-pReal" onchange="handlePresetChange('pReal', this.value)"></select><input type="text" id="pReal" placeholder="输入现实身份"><button class="btn-reset-list" onclick="resetToDropdown('pReal')"><i class="fas fa-list"></i></button></div></div>
</div>
<label>机构职能</label><div class="hybrid-input-wrapper" id="grp-pFunc"><select id="sel-pFunc" onchange="handlePresetChange('pFunc', this.value)"></select><input type="text" id="pFunc" placeholder="输入机构职能"><button class="btn-reset-list" onclick="resetToDropdown('pFunc')"><i class="fas fa-list"></i></button></div>
<label>过载解除</label><div class="rich-editor" id="pTrig1" contenteditable="true" placeholder="如何解除过载"></div>
<label>现实触发器</label><div class="rich-editor" id="pTrig2" contenteditable="true" placeholder="GM可随时触发此项"></div>
<label>现实计数</label>
<div class="derivative-progress">
    <div class="progress-cell" data-idx="1"><span class="cell-number">1</span></div>
    <div class="progress-cell" data-idx="2"><span class="cell-number">2</span></div>
    <div class="progress-cell" data-idx="3"><span class="cell-number">3</span></div>
    <div class="progress-cell" data-idx="4"><span class="cell-number">4</span></div>
</div>
<label>首要指令</label><div class="rich-editor" id="pTrig3" contenteditable="true" placeholder="如果你……，则获得1点申诫"></div>
<label>许可行为</label><div class="perm-group"><input type="text" id="perm1" placeholder="许可行为 1"><input type="text" id="perm2" placeholder="许可行为 2"><input type="text" id="perm3" placeholder="许可行为 3"></div>
<div class="perm-note">如果你在单次任务中完成全部 3 项，将获得 3 点额外嘉奖。</div>
</div>
</div>
<div class="panel">
<h2><i class="fas fa-chart-bar"></i> 进度追踪</h2>
<div class="track-header">
<div class="track-stat"><label>MVP</label><input type="text" id="pComm" placeholder="0"></div>
<div class="track-stat"><label>嘉奖</label><input type="text" id="mvpCount" placeholder="0" readonly></div>
<div class="track-stat"><label>申诫</label><input type="text" id="watchCount" placeholder="0" readonly></div>
<div class="track-stat"><label>察看期</label><input type="text" id="pRep" placeholder="0"></div>
</div>
<div class="track-sec"><h3 class="c-func" style="font-size:12px; margin:5px 0;">职能</h3><div class="track-row-wrap"><svg class="track-svg" data-type="f"></svg><div class="track-snake" data-type="f"><div class="p-cell f-cell" data-idx="1"></div><div class="p-cell f-cell" data-idx="2"></div><div class="p-cell f-cell" data-idx="3"><span>A3</span></div><div class="p-cell f-cell" data-idx="4"></div><div class="p-cell f-cell" data-idx="5"></div><div class="p-cell f-cell" data-idx="6"><span>D4</span></div><div class="p-cell f-cell" data-idx="7"></div><div class="p-cell f-cell" data-idx="8"></div><div class="p-cell f-cell" data-idx="9"><span>G3</span></div><div class="p-cell f-cell" data-idx="10"></div><div class="p-cell f-cell" data-idx="11"></div><div class="p-cell f-cell" data-idx="12"><span>J3</span></div><div class="p-cell f-cell" data-idx="13"></div><div class="p-cell f-cell" data-idx="14"></div><div class="p-cell f-cell" data-idx="15"><span>N3</span></div><div class="p-cell f-cell" data-idx="30"></div><div class="p-cell f-cell" data-idx="29"></div><div class="p-cell f-cell" data-idx="28"></div><div class="p-cell f-cell" data-idx="27"><span>Y2</span></div><div class="p-cell f-cell" data-idx="26"></div><div class="p-cell f-cell" data-idx="25"></div><div class="p-cell f-cell" data-idx="24"><span>W8</span></div><div class="p-cell f-cell" data-idx="23"></div><div class="p-cell f-cell" data-idx="22"></div><div class="p-cell f-cell" data-idx="21"><span>T3</span></div><div class="p-cell f-cell" data-idx="20"></div><div class="p-cell f-cell" data-idx="19"></div><div class="p-cell f-cell" data-idx="18"><span>Q3</span></div><div class="p-cell f-cell" data-idx="17"></div><div class="p-cell f-cell" data-idx="16"></div></div></div><div class="track-rule">当你获得任务MVP时，在你的职能记录条上标记1格，且无需从其他记录条上移除一格。</div><div class="track-rule">每当你在职能记录条上标记一格时，将任意一项资质的"资质保证上限"提升1点，最高不超过9点。</div></div>
<div class="track-sec"><h3 class="c-real" style="font-size:12px; margin:5px 0;">现实</h3><div class="track-row-wrap"><svg class="track-svg" data-type="r"></svg><div class="track-snake" data-type="r"><div class="p-cell r-cell" data-idx="1"><span>C4</span></div><div class="p-cell r-cell" data-idx="2"></div><div class="p-cell r-cell" data-idx="3"></div><div class="p-cell r-cell" data-idx="4"><span>L11</span></div><div class="p-cell r-cell" data-idx="5"></div><div class="p-cell r-cell" data-idx="6"></div><div class="p-cell r-cell" data-idx="7"></div><div class="p-cell r-cell" data-idx="8"><span>E2</span></div><div class="p-cell r-cell" data-idx="9"></div><div class="p-cell r-cell" data-idx="10"><span>O4</span></div><div class="p-cell r-cell" data-idx="11"></div><div class="p-cell r-cell" data-idx="12"><span>J3</span></div><div class="p-cell r-cell" data-idx="13"></div><div class="p-cell r-cell" data-idx="14"><span>T6</span></div><div class="p-cell r-cell" data-idx="15"></div><div class="p-cell r-cell" data-idx="30"></div><div class="p-cell r-cell" data-idx="29"></div><div class="p-cell r-cell" data-idx="28"></div><div class="p-cell r-cell" data-idx="27"><span>E3</span></div><div class="p-cell r-cell" data-idx="26"></div><div class="p-cell r-cell" data-idx="25"></div><div class="p-cell r-cell" data-idx="24"></div><div class="p-cell r-cell" data-idx="23"></div><div class="p-cell r-cell" data-idx="22"><span>H5</span></div><div class="p-cell r-cell" data-idx="21"></div><div class="p-cell r-cell" data-idx="20"><span>X3</span></div><div class="p-cell r-cell" data-idx="19"></div><div class="p-cell r-cell" data-idx="18"></div><div class="p-cell r-cell" data-idx="17"></div><div class="p-cell r-cell" data-idx="16"><span>V2</span></div></div></div><div class="track-rule">当你既未获得任务MVP也未进入察看期时，你可以将你与任意一段关系的连结提升1点。</div><div class="track-rule">每当你在现实记录条上标记一格时，将你与任意一段"关系"的"连结"提升1点，然后对关系网内的每段关系重复此操作。</div></div>
<div class="track-sec"><h3 class="c-anom" style="font-size:12px; margin:5px 0;">异常</h3><div class="track-row-wrap"><svg class="track-svg" data-type="a"></svg><div class="track-snake" data-type="a"><div class="p-cell a-cell" data-idx="1"><span>H4</span></div><div class="p-cell a-cell" data-idx="2"><span>H3</span></div><div class="p-cell a-cell" data-idx="3"></div><div class="p-cell a-cell" data-idx="4"></div><div class="p-cell a-cell" data-idx="5"><span>U2</span></div><div class="p-cell a-cell" data-idx="6"></div><div class="p-cell a-cell" data-idx="7"><span>X2</span></div><div class="p-cell a-cell" data-idx="8"></div><div class="p-cell a-cell" data-idx="9"></div><div class="p-cell a-cell" data-idx="10"></div><div class="p-cell a-cell" data-idx="11"><span>N1</span></div><div class="p-cell a-cell" data-idx="12"></div><div class="p-cell a-cell" data-idx="13"><span>Q2</span></div><div class="p-cell a-cell" data-idx="14"></div><div class="p-cell a-cell" data-idx="15"></div><div class="p-cell a-cell" data-idx="30"></div><div class="p-cell a-cell" data-idx="29"></div><div class="p-cell a-cell" data-idx="28"></div><div class="p-cell a-cell" data-idx="27"></div><div class="p-cell a-cell" data-idx="26"></div><div class="p-cell a-cell" data-idx="25"></div><div class="p-cell a-cell" data-idx="24"></div><div class="p-cell a-cell" data-idx="23"><span>A7</span></div><div class="p-cell a-cell" data-idx="22"></div><div class="p-cell a-cell" data-idx="21"></div><div class="p-cell a-cell" data-idx="20"></div><div class="p-cell a-cell" data-idx="19"><span>G8</span></div><div class="p-cell a-cell" data-idx="18"></div><div class="p-cell a-cell" data-idx="17"><span>L10</span></div><div class="p-cell a-cell" data-idx="16"></div></div></div><div class="track-rule">当你进入察看期时，在你的异常记录条上标记1格，且无需从其他记录条上移除一格。</div><div class="track-rule">每当你在异常记录条上标记一格时，选择一项：<br>➤练习：在任意一项异常能力上标记"熟练"。 <br>➤广为人知：从一项异常能力中移除"熟练"标记，并向你的团队提出该能力的问题。在获得最多票数的答案轨道上做标记，然后获得所有已解锁的能力。</div></div>
</div>
<div class="panel"><h2><i class="fas fa-file-contract"></i> 欢迎你，特工！</h2><div style="margin-bottom:12px;"><label>1. 你是如何与你的异常接触的？</label><div class="rich-editor" id="q1" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>2. 机构是如何找到你的？</label><div class="rich-editor" id="q2" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>3. 你的能力有独特的外在视觉表现吗？</label><div class="rich-editor" id="q3" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>4. 你喝咖啡有什么偏好？</label><div class="rich-editor" id="q4" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>5. 请描述你过往的工作经历</label><div class="rich-editor" id="q5" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>6. 你对Adobe、Excel和Google套件的熟悉程度如何？</label><div class="rich-editor" id="q6" contenteditable="true"></div></div><div style="margin-bottom:12px;"><label>7. 在协作工作环境中，你能做出什么贡献？</label><div class="rich-editor" id="q7" contenteditable="true"></div></div></div>
<div class="panel"><h2><i class="fas fa-sticky-note"></i> 备注/笔记</h2><label>标题</label><input type="text" id="noteTitle" style="margin-bottom: 12px; font-weight: bold;"><label>内容</label><div class="rich-editor" id="noteBody" contenteditable="true" placeholder="摘要..."></div></div>
</div>
 <div id="view-anom" class="tab-view"><div class="mod-header"><h2>异常能力</h2><button class="btn-u2-unleash" id="btnU2Unleash" style="display:none" onclick="confirmU2Unleash()"><i class="fas fa-eye"></i></button><button class="btn-add" onclick="addAnom(null, false)"><i class="fas fa-plus"></i> 添加</button></div><div id="list-anom"></div></div>
<div id="view-real" class="tab-view"><div class="mod-header"><h2>关系网</h2><button class="btn-add" onclick="addRealSafe()"><i class="fas fa-plus"></i> 添加</button></div><div id="list-real"></div></div>
<div id="view-item" class="tab-view"><div class="mod-header"><h2>申领物/福利</h2><button class="btn-add" onclick="addItem(null, false)"><i class="fas fa-plus"></i> 添加</button></div><div id="list-item"></div></div>
</div>
</div>
</div>
<div class="nav-bar">
<div class="nav-btn active n-char" onclick="switchView('view-char', this)"><i class="fas fa-id-badge"></i><span>档案</span></div>
<div class="nav-btn n-anom" onclick="switchView('view-anom', this)"><i class="fas fa-bolt"></i><span>异常</span></div>
<div class="nav-btn n-real" onclick="switchView('view-real', this)"><i class="fas fa-heart"></i><span>关系</span></div>
<div class="nav-btn n-item" onclick="switchView('view-item', this)"><i class="fas fa-box-open"></i><span>物品</span></div>
</div>
<div id="anomEditModal" class="anom-edit-modal" onclick="event.target===this&&closeAnomCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-bolt" style="color:var(--accent)"></i> 编辑异常能力</h3>
            <button class="anom-edit-close" onclick="closeAnomCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>能力名称</label><input type="text" class="anom-edit-name" placeholder="能力名称"></div>
                <div><label><i class="fas fa-bolt"></i> 触发器</label><input type="text" class="anom-edit-trig" placeholder="触发器"></div>
            </div>
            <label><i class="fas fa-star"></i> 资质</label><input type="text" class="anom-edit-qual" placeholder="资质">
            <div class="anom-edit-row-2">
                <div><label style="color:var(--accent)"><i class="fas fa-check-circle"></i> 成功时</label><div class="rich-editor anom-edit-succ" contenteditable="true"></div></div>
                <div><label style="color:#c0392b"><i class="fas fa-times-circle"></i> 失败时</label><div class="rich-editor anom-edit-fail" contenteditable="true"></div></div>
            </div>
            <div class="anom-edit-divider"></div>
            <label><i class="fas fa-question-circle"></i> 问题</label>
            <div class="anom-edit-q-row"><input type="text" class="anom-edit-tdesc" placeholder="问题"><label class="chk-btn chk-trained"><input type="checkbox" class="anom-edit-chk"><span></span></label></div>
            <div class="anom-edit-a-row"><input type="text" class="anom-edit-t1" placeholder="答案1"><input type="text" class="small-input anom-edit-t1v" placeholder="值"><div class="sq-dots anom-edit-d1"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div></div>
            <div class="anom-edit-a-row"><input type="text" class="anom-edit-t2" placeholder="答案2"><input type="text" class="small-input anom-edit-t2v" placeholder="值"><div class="sq-dots anom-edit-d2"><div class="sq-dot"></div><div class="sq-dot"></div><div class="sq-dot"></div></div></div>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" onclick="saveAnomCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<div id="realEditModal" class="anom-edit-modal" onclick="event.target===this&&closeRealCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-heart" style="color:var(--reality)"></i> 编辑关系</h3>
            <button class="anom-edit-close" onclick="closeRealCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>姓名</label><input type="text" class="real-edit-name" placeholder="姓名"></div>
                <div><label>扮演者</label><input type="text" class="real-edit-actor" placeholder="扮演者"></div>
            </div>
            <label><i class="fas fa-align-left"></i> 描述</label><div class="rich-editor real-edit-desc" contenteditable="true" placeholder="描述"></div>
            <div class="anom-edit-divider"></div>
            <label><i class="fas fa-link"></i> 连结进度</label>
            <div class="real-edit-lvl-row">
                <button class="real-lvl-btn" onclick="const v=document.querySelector('.real-edit-lvl');v.value=Math.max(0,parseInt(v.value||0)-1);updateRealLvlDots(v.value)">-</button>
                <div class="real-edit-lvl-dots"><div class="dot" data-i="1"></div><div class="dot" data-i="2"></div><div class="dot" data-i="3"></div><div class="dot" data-i="4"></div><div class="dot" data-i="5"></div><div class="dot" data-i="6"></div><div class="dot" data-i="7"></div><div class="dot" data-i="8"></div><div class="dot" data-i="9"></div></div>
                <button class="real-lvl-btn" onclick="const v=document.querySelector('.real-edit-lvl');v.value=Math.min(9,parseInt(v.value||0)+1);updateRealLvlDots(v.value)">+</button>
                <input type="hidden" class="real-edit-lvl" value="0">
                <label class="chk-btn"><input type="checkbox" class="real-edit-act"><span></span></label>
            </div>
            <label><i class="fas fa-gift"></i> 连结加成</label><div class="hybrid-input-wrapper has-editor"><select class="real-edit-conn-sel" onchange="handleRealBonusChange(this)"></select><div class="rich-editor real-edit-conn" contenteditable="true" placeholder="选择预设或输入加成效果..."></div><button class="btn-reset-list" onclick="resetRealBonus(this)"><i class="fas fa-list"></i></button></div>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" style="background:var(--reality)" onclick="saveRealCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<div id="itemEditModal" class="anom-edit-modal" onclick="event.target===this&&closeItemCardEdit()">
    <div class="anom-edit-box">
        <div class="anom-edit-header">
            <h3><i class="fas fa-box-open" style="color:var(--functional)"></i> 编辑申领物</h3>
            <button class="anom-edit-close" onclick="closeItemCardEdit()"><i class="fas fa-times"></i></button>
        </div>
        <div class="anom-edit-body">
            <div class="anom-edit-row-2">
                <div><label>物品名称</label><input type="text" class="item-edit-name" placeholder="物品名称"></div>
                <div><label>页面/PD码</label><input type="text" class="item-edit-pd" placeholder="页面/PD码"></div>
            </div>
            <label><i class="fas fa-magic"></i> 效果</label>
            <div class="rich-editor item-edit-eff" contenteditable="true" placeholder="效果描述..."></div>
            <div class="anom-edit-divider"></div>
            <label class="chk-btn chk-once" style="margin-top:10px"><input type="checkbox" class="item-edit-once"><span></span></label>
        </div>
        <div class="anom-edit-footer">
            <button class="anom-edit-save" style="background:var(--functional)" onclick="saveItemCardEdit()"><i class="fas fa-check"></i> 保存</button>
        </div>
    </div>
</div>
<script id="__SAVED_DATA__" type="application/json">${dataJson}<\/script>
<script>${jsText}<\/script>
<div class="nav-arrow arrow-left" onclick="moveTab(-1)"><i class="fas fa-caret-left"></i></div>
<div class="nav-arrow arrow-right" onclick="moveTab(1)"><i class="fas fa-caret-right"></i></div>
</body>
</html>`;
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));
    a.download=`${d.pName||'角色'}_离线备份.html`;
    a.click();
}

// 嘉奖/申诫历史记录功能
let cachedRecords = null;

async function showRecordHistory(type) {
    const modal = document.getElementById('recordHistoryModal');
    const titleEl = document.getElementById('recordHistoryTitle');
    const contentEl = document.getElementById('recordHistoryContent');

    titleEl.textContent = type === 'reward' ? '嘉奖记录' : '申诫记录';
    contentEl.innerHTML = '<div style="text-align:center; padding:40px; color:#95a5a6;"><i class="fas fa-circle-notch fa-spin"></i> 加载中...</div>';
    modal.style.display = 'flex';
    
    // 阻止背景滚动
    document.body.style.overflow = 'hidden';
    
    // 阻止滚轮事件穿透
    modal.addEventListener('wheel', function(e) {
        e.stopPropagation();
    }, { passive: false });

    try {
        // 如果已有缓存且不需要重新加载
        if (!cachedRecords && charId) {
            const res = await fetch(`/api/character/${charId}/records`, {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                cachedRecords = await res.json();
            }
        }

        const records = type === 'reward'
            ? (cachedRecords?.rewards || [])
            : (cachedRecords?.reprimands || []);

        if (records.length === 0) {
            contentEl.innerHTML = `<div style="text-align:center; padding:40px; color:#95a5a6;">暂无${type === 'reward' ? '嘉奖' : '申诫'}记录</div>`;
            return;
        }

        // 按时间倒序
        const sorted = [...records].sort((a, b) => (b.date || 0) - (a.date || 0));

        contentEl.innerHTML = sorted.map(r => {
            const date = r.date ? new Date(r.date).toLocaleString('zh-CN', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            }) : '未知时间';
            const countBadge = (r.count && r.count > 1)
                ? `<span style="padding:2px 6px; border-radius:3px; font-size:11px; font-weight:bold; background:${type === 'reward' ? '#e74c3c' : '#3498db'}; color:white; margin-left:8px;">x${r.count}</span>`
                : '';
            const bgColor = type === 'reward' ? '#fff5f5' : '#f0f8ff';
            const borderColor = type === 'reward' ? '#e74c3c' : '#3498db';
            return `
                <div style="background:${bgColor}; border-left:4px solid ${borderColor}; border-radius:6px; padding:15px; margin-bottom:12px;">
                    <div style="font-size:14px; font-weight:bold; color:#2c3e50; margin-bottom:8px;">${escapeHtmlText(r.reason || '无原因')}${countBadge}</div>
                    <div style="font-size:12px; color:#7f8c8d;">
                        <i class="fas fa-clock"></i> ${date}
                        ${r.addedByName ? `&nbsp;&nbsp;<i class="fas fa-user-tie"></i> ${escapeHtmlText(r.addedByName)}` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        console.error('加载记录失败:', e);
        contentEl.innerHTML = '<div style="text-align:center; padding:40px; color:#e74c3c;">加载失败</div>';
    }
}

function closeRecordHistory() {
    document.getElementById('recordHistoryModal').style.display = 'none';
    document.body.style.overflow = '';
}

// 动态增行功能
function addScatteringRow() {
    const tbody = document.querySelector('#table-scattering tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><input type="text" class="scat-name"></td>
        <td><input type="text" class="scat-qty"></td>
        <td><input type="text" class="scat-note"></td>
        <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
    `;
    tbody.appendChild(tr);
}

function addObjectiveRow() {
    const tbody = document.querySelector('#table-objectives tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><input type="text" class="obj-target"></td>
        <td><input type="text" class="obj-reward"></td>
        <td><input type="text" class="obj-agent"></td>
        <td><button type="button" class="btn-del-row" onclick="this.closest('tr').remove()"><i class="fas fa-times"></i></button></td>
    `;
    tbody.appendChild(tr);
}

function escapeHtmlText(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==========================================
// 自我评估弹窗功能
// ==========================================
let currentAssessmentData = null;
let lastAssessmentAttributes = []; // 记录上次评估填入的属性名列表

// 阻止滚轮事件穿透
function preventWheelPenetration(e) {
    const target = e.target;
    const body = document.getElementById('assessmentBody');
    
    // 如果滚动的是评估内容区域
    if (body && body.contains(target)) {
        const scrollTop = body.scrollTop;
        const scrollHeight = body.scrollHeight;
        const clientHeight = body.clientHeight;
        const delta = e.deltaY;
        
        // 检查是否到达顶部或底部
        const isAtTop = scrollTop === 0 && delta < 0;
        const isAtBottom = scrollTop + clientHeight >= scrollHeight && delta > 0;
        
        // 如果到达边界，阻止默认行为（防止穿透）
        if (isAtTop || isAtBottom) {
            e.preventDefault();
            e.stopPropagation();
        }
    } else {
        // 如果是在其他区域滚动，完全阻止（防止穿透）
        e.preventDefault();
        e.stopPropagation();
    }
}

function showAssessmentModal(assessmentData) {
    if (isReadOnly) return; // 只读模式不显示评估
    
    currentAssessmentData = assessmentData;
    const modal = document.getElementById('assessment-modal');
    const body = document.getElementById('assessmentBody');
    
    // 清除之前的内容和选择状态
    body.innerHTML = '';
    
    // 生成问题HTML（确保每次都是全新的）
    body.innerHTML = assessmentData.map((qa, index) => {
        const qNum = index + 1;
        return `
            <div class="assessment-question">
                <div class="assessment-q-text">${qNum}. ${escapeHtmlText(qa.q)}</div>
                <div class="assessment-options">
                    <label class="assessment-option" onclick="selectAssessmentOption(${index}, 1)">
                        <input type="radio" name="q${index}" value="a1">
                        <span class="assessment-option-text">${escapeHtmlText(qa.a1[0])}</span>
                        <span class="assessment-option-badge">${escapeHtmlText(qa.a1[1])} +${qa.a1[2]}</span>
                    </label>
                    <label class="assessment-option" onclick="selectAssessmentOption(${index}, 2)">
                        <input type="radio" name="q${index}" value="a2">
                        <span class="assessment-option-text">${escapeHtmlText(qa.a2[0])}</span>
                        <span class="assessment-option-badge">${escapeHtmlText(qa.a2[1])} +${qa.a2[2]}</span>
                    </label>
                </div>
            </div>
        `;
    }).join('');
    
    // 重置滚动位置到顶部
    body.scrollTop = 0;
    
    modal.classList.add('active');
    
    // 阻止模态框背后的内容滚动
    document.body.style.overflow = 'hidden';
    
    // 阻止滚轮事件穿透到背后的内容
    // 移除之前可能存在的监听器（避免重复添加）
    modal.removeEventListener('wheel', preventWheelPenetration);
    modal.addEventListener('wheel', preventWheelPenetration, { passive: false });
}

function selectAssessmentOption(qIndex, optNum) {
    const radio = document.querySelector(`input[name="q${qIndex}"][value="a${optNum}"]`);
    if (radio) radio.checked = true;
    
    // 更新选中样式
    const options = document.querySelectorAll(`.assessment-question:nth-child(${qIndex + 1}) .assessment-option`);
    options.forEach((opt, i) => {
        if (i === optNum - 1) {
            opt.classList.add('selected');
        } else {
            opt.classList.remove('selected');
        }
    });
}

function submitAssessment() {
    if (!currentAssessmentData) return;
    
    // 检查是否所有问题都已回答
    const totalQuestions = currentAssessmentData.length;
    const answeredCount = document.querySelectorAll('.assessment-question input[type="radio"]:checked').length;
    
    if (answeredCount < totalQuestions) {
        showToast('请回答所有问题后再提交', 'error');
        return;
    }
    
    // 先将所有属性重置为0
    ATTRS.forEach(attrName => {
        const inputEl = document.querySelector(`.attr-input[data-attr="${attrName}"]`);
        if (inputEl) {
            inputEl.value = 0;
            renderDots(attrName, 0);
        }
    });
    
    // 收集答案并应用到属性
    const attrModifications = {};
    
    currentAssessmentData.forEach((qa, index) => {
        const selected = document.querySelector(`input[name="q${index}"]:checked`);
        if (selected) {
            const answerKey = selected.value; // 'a1' or 'a2'
            const answerData = qa[answerKey]; // [显示文本, 属性名, 值]
            const attrName = answerData[1];
            const attrValue = parseInt(answerData[2]) || 0;
            
            // 累加属性值（同一个属性可能被多个问题选中）
            if (!attrModifications[attrName]) {
                attrModifications[attrName] = 0;
            }
            attrModifications[attrName] += attrValue;
        }
    });
    
    // 应用属性值到界面（直接设置而不是累加）
    for (const attrName in attrModifications) {
        const inputEl = document.querySelector(`.attr-input[data-attr="${attrName}"]`);
        if (inputEl) {
            const newValue = attrModifications[attrName];
            inputEl.value = newValue;
            renderDots(attrName, newValue);
        }
    }
    
    // 更新上次评估属性记录
    lastAssessmentAttributes = Object.keys(attrModifications);
    
    // 关闭弹窗
    closeAssessmentModal();
    
    // 触发自动保存
    triggerAutoSave();

    // 显示提示
    const attrSummary = Object.entries(attrModifications)
        .map(([name, val]) => `${name} +${val}`)
        .join(', ');
    showToast(`评估完成！${attrSummary}`, 'success');
}

function closeAssessmentModal() {
    const modal = document.getElementById('assessment-modal');
    modal.classList.remove('active');
    currentAssessmentData = null;
    
    // 恢复背后内容的滚动
    document.body.style.overflow = '';
    
    // 移除滚轮事件监听器
    modal.removeEventListener('wheel', preventWheelPenetration);
}

async function confirmU2Unleash() {
    if (!charId || !token) return;
    const watchCount = parseInt(document.getElementById('watchCount').value) || 0;
    if (watchCount < 3) {
        showToast('申诫不足3点', 'error');
        return;
    }

    const overlay = document.getElementById('u2-overlay');
    const eyeIcon = document.getElementById('u2-eye-icon');

    eyeIcon.classList.remove('eye-open', 'eye-closing');
    overlay.classList.add('active');

    setTimeout(() => { eyeIcon.classList.add('eye-open'); }, 200);
}

function cancelU2Unleash() {
    closeU2Overlay();
}

async function executeU2Unleash() {
    const eyeIcon = document.getElementById('u2-eye-icon');
    eyeIcon.classList.remove('eye-open');
    eyeIcon.classList.add('eye-closing');
    setTimeout(() => { document.getElementById('u2-overlay').classList.remove('active'); }, 400);

    try {
        const res = await fetch(`/api/character/${charId}/u2-unleash`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('watchCount').value = data.watchCount;
            showToast('已消耗3点申诫', 'success');
        } else {
            showToast(data.message || '操作失败', 'error');
        }
    } catch (e) {
        showToast('操作失败', 'error');
    }
}

function closeU2Overlay() {
    const eyeIcon = document.getElementById('u2-eye-icon');
    eyeIcon.classList.remove('eye-open');
    eyeIcon.classList.add('eye-closing');
    setTimeout(() => { document.getElementById('u2-overlay').classList.remove('active'); }, 300);
}
