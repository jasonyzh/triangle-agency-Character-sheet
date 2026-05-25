import { S, tabOrder, swiperWrapper, navBtns } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, setRandomVars } from './ui.js';
import { loadConfigData, triggerAutoSave, gatherData, populateData, saveData, exportOffline } from './api.js';
import { switchView, updateSwiper, toggleCharBoard } from './tabs.js';
import { initDropdowns, handlePresetChange, resetToDropdown, applyCascadingLogic, setHybridInputState } from './dropdowns.js';
import { initAttrs, renderTriangles, renderDots, resetAllAttrs, initDerivativeProgress } from './track.js';
import { updateCharLayout, drawTrackSVG } from './layout.js';
import { addAnom, deleteCard, updateSlotButtons, openAnomCardEdit, closeAnomCardEdit, saveAnomCardEdit, openAnomWindow, closeAnomWindow, initAnomDrag, handleBonusChange, resetBonus } from './anomaly.js';
import { addReal, addRealSafe, openRealCardEdit, closeRealCardEdit, saveRealCardEdit, updateRealLvlDots, openRealPhone, closePhoneOverlay, initPhoneDrag, handleRealBonusChange, resetRealBonus } from './reality.js';
import { addItem, syncItemDisplay, useItem, openItemCardEdit, closeItemCardEdit, saveItemCardEdit, openBriefcase, closeBriefcase, initBriefcaseDrag } from './items.js';
import { syncCharDisplay, openCharEdit, closeCharEdit, saveCharEdit, handleCharPresetChange, resetCharDropdown } from './chars.js';
import { showAssessmentModal, selectAssessmentOption, submitAssessment, closeAssessmentModal, confirmU2Unleash, cancelU2Unleash, executeU2Unleash, closeU2Overlay } from './assessment.js';
import { openMailModal, closeMailModal, switchMailTab, renderMailContent, renderInbox, renderSentMail, renderCompose, loadMailbox, deleteMail, renderHighwallFiles, openHighwallFile, openMailReader, closeMailReader, openHighwallFromMail, openSentMailReader, openMessage, sendContainment, sendReport, closeSuccessModal, selectOutboxOption, addScatteringRow, addObjectiveRow } from './mail.js';
import { rollDice, rollCheck, broadcastDiceResult, showDiceResult, saveToHistory, showDiceHistory, clearDiceHistory, toggleDicePanel } from './dice.js';
import { initPlayerBoard, switchBoardMission, makeCtxMenu, showPlayerNpcContextMenu, hidePlayerNpcMenu, showNpcLineMenu, deleteNpcConnection, startNpcConnect, showFloatingCancelBtn, hideFloatingCancelBtn, cancelNpcConnect, finishNpcConnect, showNpcTypeModal, createNpcConnection, promptNpcLabel, showImagePopup } from './board.js';
import { showRecordHistory, closeRecordHistory } from './records.js';
import { checkDestructionAccess, openDestructionTrackModal, closeDestructionTrackModal } from './destruction-view.js';

window.triggerAutoSave = triggerAutoSave;
window.gatherData = gatherData;
window.populateData = populateData;
window.saveData = saveData;
window.exportOffline = exportOffline;
window.switchView = switchView;
window.updateSwiper = updateSwiper;
window.toggleCharBoard = toggleCharBoard;
window.initDropdowns = initDropdowns;
window.handlePresetChange = handlePresetChange;
window.resetToDropdown = resetToDropdown;
window.applyCascadingLogic = applyCascadingLogic;
window.setHybridInputState = setHybridInputState;
window.initAttrs = initAttrs;
window.renderTriangles = renderTriangles;
window.renderDots = renderDots;
window.resetAllAttrs = resetAllAttrs;
window.initDerivativeProgress = initDerivativeProgress;
window.updateCharLayout = updateCharLayout;
window.drawTrackSVG = drawTrackSVG;
window.addAnom = addAnom;
window.deleteCard = deleteCard;
window.updateSlotButtons = updateSlotButtons;
window.openAnomCardEdit = openAnomCardEdit;
window.closeAnomCardEdit = closeAnomCardEdit;
window.saveAnomCardEdit = saveAnomCardEdit;
window.openAnomWindow = openAnomWindow;
window.closeAnomWindow = closeAnomWindow;
window.addReal = addReal;
window.addRealSafe = addRealSafe;
window.openRealCardEdit = openRealCardEdit;
window.closeRealCardEdit = closeRealCardEdit;
window.saveRealCardEdit = saveRealCardEdit;
window.updateRealLvlDots = updateRealLvlDots;
window.openRealPhone = openRealPhone;
window.closePhoneOverlay = closePhoneOverlay;
window.addItem = addItem;
window.syncItemDisplay = syncItemDisplay;
window.useItem = useItem;
window.openItemCardEdit = openItemCardEdit;
window.closeItemCardEdit = closeItemCardEdit;
window.saveItemCardEdit = saveItemCardEdit;
window.openBriefcase = openBriefcase;
window.closeBriefcase = closeBriefcase;
window.syncCharDisplay = syncCharDisplay;
window.openCharEdit = openCharEdit;
window.closeCharEdit = closeCharEdit;
window.saveCharEdit = saveCharEdit;
window.handleCharPresetChange = handleCharPresetChange;
window.resetCharDropdown = resetCharDropdown;
window.showAssessmentModal = showAssessmentModal;
window.selectAssessmentOption = selectAssessmentOption;
window.submitAssessment = submitAssessment;
window.closeAssessmentModal = closeAssessmentModal;
window.confirmU2Unleash = confirmU2Unleash;
window.cancelU2Unleash = cancelU2Unleash;
window.executeU2Unleash = executeU2Unleash;
window.closeU2Overlay = closeU2Overlay;
window.openMailModal = openMailModal;
window.closeMailModal = closeMailModal;
window.switchMailTab = switchMailTab;
window.renderMailContent = renderMailContent;
window.renderInbox = renderInbox;
window.renderSentMail = renderSentMail;
window.renderCompose = renderCompose;
window.loadMailbox = loadMailbox;
window.deleteMail = deleteMail;
window.renderHighwallFiles = renderHighwallFiles;
window.openHighwallFile = openHighwallFile;
window.openMailReader = openMailReader;
window.closeMailReader = closeMailReader;
window.openHighwallFromMail = openHighwallFromMail;
window.openSentMailReader = openSentMailReader;
window.openMessage = openMessage;
window.sendContainment = sendContainment;
window.sendReport = sendReport;
window.closeSuccessModal = closeSuccessModal;
window.selectOutboxOption = selectOutboxOption;
window.addScatteringRow = addScatteringRow;
window.addObjectiveRow = addObjectiveRow;
window.rollDice = rollDice;
window.rollCheck = rollCheck;
window.broadcastDiceResult = broadcastDiceResult;
window.showDiceResult = showDiceResult;
window.saveToHistory = saveToHistory;
window.showDiceHistory = showDiceHistory;
window.clearDiceHistory = clearDiceHistory;
window.toggleDicePanel = toggleDicePanel;
window.initPlayerBoard = initPlayerBoard;
window.switchBoardMission = switchBoardMission;
window.makeCtxMenu = makeCtxMenu;
window.showPlayerNpcContextMenu = showPlayerNpcContextMenu;
window.hidePlayerNpcMenu = hidePlayerNpcMenu;
window.showNpcLineMenu = showNpcLineMenu;
window.deleteNpcConnection = deleteNpcConnection;
window.startNpcConnect = startNpcConnect;
window.showFloatingCancelBtn = showFloatingCancelBtn;
window.hideFloatingCancelBtn = hideFloatingCancelBtn;
window.cancelNpcConnect = cancelNpcConnect;
window.finishNpcConnect = finishNpcConnect;
window.showNpcTypeModal = showNpcTypeModal;
window.createNpcConnection = createNpcConnection;
window.promptNpcLabel = promptNpcLabel;
window.showImagePopup = showImagePopup;
window.showRecordHistory = showRecordHistory;
window.closeRecordHistory = closeRecordHistory;
window.openDestructionTrackModal = openDestructionTrackModal;
window.closeDestructionTrackModal = closeDestructionTrackModal;
window.isReadOnly = S.isReadOnly;
window.handleBonusChange = handleBonusChange;
window.resetBonus = resetBonus;
window.handleRealBonusChange = handleRealBonusChange;
window.resetRealBonus = resetRealBonus;
window.getAuthHeaders = getAuthHeaders;
window.showToast = showToast;
window.setRandomVars = setRandomVars;

document.addEventListener('DOMContentLoaded', async () => {
    document.querySelectorAll('.panel').forEach(setRandomVars);
    await loadConfigData();
    var savedTab = localStorage.getItem('ta_sheet_tab');
    if (savedTab && tabOrder.indexOf(savedTab) !== -1) S.currentTab = tabOrder.indexOf(savedTab);
    swiperWrapper.style.transition = 'none';
    updateSwiper();
    swiperWrapper.offsetHeight;
    swiperWrapper.style.transition = '';

    navBtns.forEach(function (b) { b.classList.remove('active'); });
    if (S.currentTab === 0) document.querySelector('.nav-btn.n-board').classList.add('active');
    else if (S.currentTab === 1) document.querySelector('.nav-btn.n-char').classList.add('active');
    var toggle = document.getElementById('toggleCharBoard');
    if (toggle) {
        var opts = toggle.querySelectorAll('.toggle-opt');
        var slider = toggle.querySelector('.toggle-slider');
        if (S.currentTab === 1) {
            opts[0].classList.remove('active'); opts[1].classList.add('active'); slider.classList.add('right');
        } else {
            opts[1].classList.remove('active'); opts[0].classList.add('active'); slider.classList.remove('right');
        }
    }
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

    loadMailbox();
    checkDestructionAccess();

    document.querySelectorAll('.char-deriv-cell').forEach(c => {
        c.addEventListener('click', () => { if (S.isReadOnly) return; c.classList.toggle('active'); });
    });

    if (!S.isReadOnly) {
        document.querySelectorAll('input[type="text"], input[type="number"], textarea, select').forEach(el => {
            el.addEventListener('input', triggerAutoSave);
            el.addEventListener('change', triggerAutoSave);
        });

        document.querySelectorAll('[contenteditable="true"]').forEach(el => {
            el.addEventListener('input', triggerAutoSave);
            el.addEventListener('blur', triggerAutoSave);
        });

        document.querySelectorAll('.p-cell, .progress-cell').forEach(el => {
            el.addEventListener('click', () => {
                setTimeout(triggerAutoSave, 100);
            });
        });
    }

    const offlineDataEl = document.getElementById('__SAVED_DATA__');
    if (offlineDataEl && offlineDataEl.textContent.trim().length > 2) {
        document.body.classList.add('offline-mode');
        populateData(JSON.parse(offlineDataEl.textContent));
        updateCharLayout();
        drawTrackSVG();
    } else {
        if (!S.charId) { window.location.href = 'dashboard.html'; return; }
        try {
            const res = await fetch(`/api/character/${S.charId}`, { headers: getAuthHeaders() });
            if (res.status === 401 || res.status === 403) {
                window.location.href = 'login.html';
                return;
            }
            const data = await res.json();
            populateData(data);
            updateCharLayout();
            drawTrackSVG();
        }
        catch (e) {
            if (!document.getElementById('list-anom').children.length) addAnom(null, false);
            if (!document.getElementById('list-real').children.length) document.getElementById('list-real').appendChild(addReal());
            if (!document.getElementById('list-item').children.length) addItem(null, false);
        }
    }

    initPhoneDrag();
    initBriefcaseDrag();
    initAnomDrag();
});

if (S.isReadOnly) {
    document.body.classList.add('readonly-mode');
    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('[contenteditable]').forEach(el => el.setAttribute('contenteditable', 'false'));
        ['pAnom', 'pReal', 'pFunc'].forEach(id => { document.getElementById(`grp-${id}`).classList.add('show-input'); });
    });
}

if (S.isEmbed) {
    document.addEventListener('DOMContentLoaded', () => {
        const backButton = document.querySelector('.btn-back');
        if (backButton) backButton.style.display = 'none';
    });
}

async function goBack() {
    const params = new URLSearchParams(window.location.search);
    const cameFromManager = params.get('from') === 'manager';

    let destinationUrl = 'dashboard.html';
    if (cameFromManager) {
        destinationUrl = 'manager.html';
    } else if (S.isReadOnly) {
        destinationUrl = 'monitor.html';
    }

    const overlay = document.getElementById('transition-overlay');
    if (overlay) {
        const textContent = overlay.querySelector('.loader-text');
        const textNode = textContent ? textContent.childNodes[0] : null;
        if (textNode) textNode.textContent = cameFromManager ? '返回经理台' : '返回档案库';
        overlay.classList.add('active');
    }

    if (S.isReadOnly) {
        setTimeout(() => { window.location.href = destinationUrl; }, 800);
        return;
    }

    const backButton = document.querySelector('.btn-back');
    backButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 保存中';
    try {
        await saveData(true);
    } catch (e) {
        console.error("返回前自动保存失败:", e);
    }
    setTimeout(() => { window.location.href = destinationUrl; }, 800);
}

window.goBack = goBack;

document.querySelectorAll('.p-cell').forEach(c => {
    c.addEventListener('click', () => {
        if (S.isReadOnly) return;
        if (c.classList.contains('active')) {
            c.classList.remove('active');
            c.classList.add('ignored');
        } else if (c.classList.contains('ignored')) {
            c.classList.remove('ignored');
        } else {
            c.classList.add('active');
        }
    });
    c.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        if (S.isReadOnly) return;
        c.classList.remove('active');
        c.classList.add('ignored');
    });
});
