import { S } from './state.js';

import { logout, goAdmin, goToDashboard } from './auth.js';
import { showToast, escapeHtml, renderBranchSelector, toggleSideMenu, closeSideMenu, switchMainTab, reloadAllForBranch, loadMyBranches, loadBranchScatter } from './ui.js';
import { loadCharacters, handleSearch, renderCharacters, deleteCharacter, handleSwipe, openSheet, printSheet, openSlotModal, closeSlotModal, adjustSlot, saveSlots, openRequisitionPermModal, filterRequisitionPerms, closeRequisitionPermModal, saveRequisitionPerms, openDocModal, renderDocList, filterDocs, closeDocModal, saveDocPermissions, openRecordModal, closeRecordModal, switchRecordTab, updateAddButton, loadRecords, renderRecords, addRecord, deleteRecord, openAgentDetail, closeAgentDetailModal, togglePlazaVisibility, toggleArchive } from './characters.js';
import { loadMissions, renderMissions, switchMissionTab, openMissionModal, closeMissionModal, editMission, saveMission, archiveMission, restoreMission, deleteMission, openAddMemberModal, filterAvailableMembers, renderAvailableMembers, closeAddMemberModal, addMemberToMission, removeMember, openMissionDetail, closeMissionDetail, renderMissionDetailMembers, loadMissionReports, renderMissionReports, saveReportReview, sendReportRating, loadMissionInbox, renderMissionInbox, openMissionMail, viewMissionReport, deleteMissionMail, adjustMissionValue, saveMissionValues, removeMemberFromDetail, editCurrentMission, openMissionPanel, archiveCurrentMission, restoreCurrentMission } from './missions.js';
import { loadInbox, updateInboxBadge, openInboxModal, closeInboxModal, renderInboxList, getMessageTypeLabel, getMessageTypeIcon, openMailDetail, renderReportData, closeMailDetailModal } from './mail.js';
import { loadRequisitionItems, renderRequisitionItems, filterRequisitions, openRequisitionModal, closeRequisitionModal, saveRequisitionItem, deleteRequisitionItem, addPriceOption, removePriceOption, getPriceOptions, generateId, openAssignRequisitionModal, closeCharacterSelectModal, renderCharacterSelectList, filterCharacterList, toggleCharacterSelection, confirmAssignRequisitions } from './items.js';
import { loadSiphonProducts, renderSiphonProducts, filterSiphonProducts, openSiphonModal, closeSiphonModal, saveSiphonProduct, deleteSiphonProduct } from './siphon.js';
import { loadBranchApplications, renderBranchApplications, reviewApplication } from './branches.js';
import { loadAnomalyTemplates, renderAnomalyTemplates, openAnomalyTemplateModal, closeAnomalyTemplateModal, saveAnomalyTemplate, deleteAnomalyTemplate, openGrantAnomalyModal, closeGrantAnomalyModal, saveGrantedAnomalies, grantAnomalyToChar, filterGrantAnomaly } from './anomaly-templates.js';
import { loadNpcTemplates, renderNpcTemplates, openNpcTemplateModal, closeNpcTemplateModal, handleNpcBonusChange, resetNpcBonus, setNpcLvlDots, clickNpcLvlDot, saveNpcTemplate, deleteNpcTemplate, openGrantNpcModal, closeGrantNpcModal, saveGrantedNpcs, filterGrantNpc } from './npc-templates.js';
import { loadDestructionTrack, saveDestructionTrack } from './destruction.js';

// Auth & navigation
window.logout = logout;
window.goAdmin = goAdmin;
window.goToDashboard = goToDashboard;

// UI
window.switchMainTab = switchMainTab;
window.toggleSideMenu = toggleSideMenu;
window.closeSideMenu = closeSideMenu;

// Characters
window.loadCharacters = loadCharacters;
window.handleSearch = handleSearch;
window.openSheet = openSheet;
window.printSheet = printSheet;
window.deleteCharacter = deleteCharacter;
window.openSlotModal = openSlotModal;
window.closeSlotModal = closeSlotModal;
window.adjustSlot = adjustSlot;
window.saveSlots = saveSlots;
window.openRequisitionPermModal = openRequisitionPermModal;
window.filterRequisitionPerms = filterRequisitionPerms;
window.closeRequisitionPermModal = closeRequisitionPermModal;
window.saveRequisitionPerms = saveRequisitionPerms;
window.openDocModal = openDocModal;
window.filterDocs = filterDocs;
window.closeDocModal = closeDocModal;
window.saveDocPermissions = saveDocPermissions;
window.openRecordModal = openRecordModal;
window.closeRecordModal = closeRecordModal;
window.switchRecordTab = switchRecordTab;
window.addRecord = addRecord;
window.deleteRecord = deleteRecord;
window.openAgentDetail = openAgentDetail;
window.closeAgentDetailModal = closeAgentDetailModal;
window.togglePlazaVisibility = togglePlazaVisibility;
window.toggleArchive = toggleArchive;
window.openGrantAnomalyModal = openGrantAnomalyModal;
window.closeGrantAnomalyModal = closeGrantAnomalyModal;

// Missions
window.loadMissions = loadMissions;
window.switchMissionTab = switchMissionTab;
window.openMissionModal = openMissionModal;
window.closeMissionModal = closeMissionModal;
window.editMission = editMission;
window.saveMission = saveMission;
window.archiveMission = archiveMission;
window.restoreMission = restoreMission;
window.deleteMission = deleteMission;
window.openMissionDetail = openMissionDetail;
window.closeMissionDetail = closeMissionDetail;
window.openAddMemberModal = openAddMemberModal;
window.filterAvailableMembers = filterAvailableMembers;
window.closeAddMemberModal = closeAddMemberModal;
window.addMemberToMission = addMemberToMission;
window.removeMember = removeMember;
window.loadMissionReports = loadMissionReports;
window.saveReportReview = saveReportReview;
window.sendReportRating = sendReportRating;
window.loadMissionInbox = loadMissionInbox;
window.openMissionMail = openMissionMail;
window.viewMissionReport = viewMissionReport;
window.deleteMissionMail = deleteMissionMail;
window.adjustMissionValue = adjustMissionValue;
window.saveMissionValues = saveMissionValues;
window.removeMemberFromDetail = removeMemberFromDetail;
window.editCurrentMission = editCurrentMission;
window.openMissionPanel = openMissionPanel;
window.archiveCurrentMission = archiveCurrentMission;
window.restoreCurrentMission = restoreCurrentMission;

// Mail
window.openInboxModal = openInboxModal;
window.closeInboxModal = closeInboxModal;
window.openMailDetail = openMailDetail;
window.closeMailDetailModal = closeMailDetailModal;

// Items
window.loadRequisitionItems = loadRequisitionItems;
window.filterRequisitions = filterRequisitions;
window.openRequisitionModal = openRequisitionModal;
window.closeRequisitionModal = closeRequisitionModal;
window.saveRequisitionItem = saveRequisitionItem;
window.deleteRequisitionItem = deleteRequisitionItem;
window.addPriceOption = addPriceOption;
window.removePriceOption = removePriceOption;
window.openAssignRequisitionModal = openAssignRequisitionModal;
window.closeCharacterSelectModal = closeCharacterSelectModal;
window.filterCharacterList = filterCharacterList;
window.toggleCharacterSelection = toggleCharacterSelection;
window.confirmAssignRequisitions = confirmAssignRequisitions;

// Siphon
window.filterSiphonProducts = filterSiphonProducts;
window.openSiphonModal = openSiphonModal;
window.closeSiphonModal = closeSiphonModal;
window.saveSiphonProduct = saveSiphonProduct;
window.deleteSiphonProduct = deleteSiphonProduct;

// Branches
window.loadBranchApplications = loadBranchApplications;
window.reviewApplication = reviewApplication;

// Anomaly templates
window.loadAnomalyTemplates = loadAnomalyTemplates;
window.openAnomalyTemplateModal = openAnomalyTemplateModal;
window.closeAnomalyTemplateModal = closeAnomalyTemplateModal;
window.saveAnomalyTemplate = saveAnomalyTemplate;
window.deleteAnomalyTemplate = deleteAnomalyTemplate;
window.saveGrantedAnomalies = saveGrantedAnomalies;
window.grantAnomalyToChar = grantAnomalyToChar;
window.filterGrantAnomaly = filterGrantAnomaly;

// NPC templates
window.loadNpcTemplates = loadNpcTemplates;
window.openNpcTemplateModal = openNpcTemplateModal;
window.closeNpcTemplateModal = closeNpcTemplateModal;
window.handleNpcBonusChange = handleNpcBonusChange;
window.resetNpcBonus = resetNpcBonus;
window.setNpcLvlDots = setNpcLvlDots;
window.clickNpcLvlDot = clickNpcLvlDot;
window.saveNpcTemplate = saveNpcTemplate;
window.deleteNpcTemplate = deleteNpcTemplate;
window.openGrantNpcModal = openGrantNpcModal;
window.closeGrantNpcModal = closeGrantNpcModal;
window.saveGrantedNpcs = saveGrantedNpcs;
window.filterGrantNpc = filterGrantNpc;

// Destruction track
window.loadDestructionTrack = loadDestructionTrack;
window.saveDestructionTrack = saveDestructionTrack;

Object.defineProperty(window, 'currentMissionDetailId', {
    get() { return S.currentMissionDetailId; }
});

// Touch events
document.addEventListener('touchstart', e => {
    S.touchStartX = e.changedTouches[0].screenX;
    S.touchStartY = e.changedTouches[0].screenY;
}, {passive: true});

document.addEventListener('touchend', e => {
    const touchEndX = e.changedTouches[0].screenX;
    const touchEndY = e.changedTouches[0].screenY;
    handleSwipe(S.touchStartX, S.touchStartY, touchEndX, touchEndY);
}, {passive: true});

// Nav visibility
(function initNav() {
    const role = parseInt(localStorage.getItem('ta_role') || '0');

    if (role >= 2) {
        if(document.getElementById('deskBtnAdmin'))
            document.getElementById('deskBtnAdmin').style.display = 'inline-flex';
        if(document.getElementById('mobBtnAdmin'))
            document.getElementById('mobBtnAdmin').style.display = 'flex';
    }
})();

// Initialize page
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

document.querySelectorAll('.modal-overlay').forEach(modal => {
    modal.addEventListener('click', function(e) {
        if (e.target === this) {
            this.classList.remove('show');
        }
    });
});
