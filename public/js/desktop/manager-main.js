/* 管理台模块（manager.html → desktop.html 迁移宿主）
   复用 js/manager/* 全部模块；按窗口懒加载数据；
   分部统一由 desktop.js 开始菜单选择，经 setBranch 同步到 S 并重载已打开窗口 */
import { S } from '../manager/state.js';
import { getAuthHeaders } from '../manager/auth.js';
import { showToast, escapeHtml, loadMyBranches } from '../manager/ui.js';
import { loadCharacters, handleSearch, deleteCharacter, openSheet, printSheet, openSlotModal, closeSlotModal, adjustSlot, saveSlots, openRequisitionPermModal, filterRequisitionPerms, closeRequisitionPermModal, saveRequisitionPerms, openDocModal, filterDocs, closeDocModal, saveDocPermissions, openRecordModal, closeRecordModal, switchRecordTab, addRecord, deleteRecord, openAgentDetail, closeAgentDetailModal, togglePlazaVisibility, toggleArchive } from '../manager/characters.js';
import { openGrantAnomalyModal, closeGrantAnomalyModal, saveGrantedAnomalies, filterGrantAnomaly, loadAnomalyTemplates, openAnomalyTemplateModal, closeAnomalyTemplateModal, saveAnomalyTemplate, deleteAnomalyTemplate, handleAnomTplPassiveChange, tplAddListRow, importAnomalyJson } from '../manager/anomaly-templates.js';
import { openGrantNpcModal, closeGrantNpcModal, saveGrantedNpcs, filterGrantNpc, loadNpcTemplates, openNpcTemplateModal, closeNpcTemplateModal, handleNpcBonusChange, resetNpcBonus, clickNpcLvlDot, saveNpcTemplate, deleteNpcTemplate } from '../manager/npc-templates.js';
import { loadMissions, switchMissionTab, openMissionModal, closeMissionModal, saveMission, archiveMission, restoreMission, deleteMission, openMissionDetail, closeMissionDetail, openAddMemberModal, filterAvailableMembers, closeAddMemberModal, addMemberToMission, loadMissionReports, saveReportReview, sendReportRating, loadMissionInbox, openMissionMail, viewMissionReport, deleteMissionMail, adjustMissionValue, saveMissionValues, removeMemberFromDetail, editCurrentMission, openMissionPanel, archiveCurrentMission, restoreCurrentMission } from '../manager/missions.js';
import { loadInbox, openInboxModal, closeInboxModal, openMailDetail, closeMailDetailModal } from '../manager/mail.js';
import { loadRequisitionItems, filterRequisitions, openRequisitionModal, closeRequisitionModal, saveRequisitionItem, deleteRequisitionItem, addPriceOption, removePriceOption, openAssignRequisitionModal, closeCharacterSelectModal, filterCharacterList, toggleCharacterSelection, confirmAssignRequisitions } from '../manager/items.js';
import { loadSiphonProducts, filterSiphonProducts, openSiphonModal, closeSiphonModal, saveSiphonProduct, deleteSiphonProduct } from '../manager/siphon.js';
import { loadDestructionTrack, saveDestructionTrack } from '../manager/destruction.js';
import { loadBranchApplications, reviewApplication } from '../manager/branches.js';
import { loadAdmin, loadUsers, loadBranches, loadConfig, switchAdminTab, closeRoleModal as closeAdminRoleModal, closePasswordModal as closeAdminPwdModal, closeBranchModal as closeAdminBranchModal } from '../manager/admin-panel.js';

/* 权限守卫：非经理/超管不初始化（loader 已挡，这里双保险） */
var authorized = !!S.token && S.role >= 1;

/* 各管理台窗口首次打开时的数据加载 */
var TAB_LOADERS = {
  'm-char': loadCharacters,
  'm-missions': loadMissions,
  'm-items': loadRequisitionItems,
  'm-siphon': loadSiphonProducts,
  'm-anomaly': loadAnomalyTemplates,
  'm-dest': loadDestructionTrack,
  'm-apps': loadBranchApplications,
  'm-npc': loadNpcTemplates,
  'm-admin': loadAdmin,
};

function startApp(key) {
  if (!authorized) return;
  /* 系统设置仅超级管理员 */
  if (key === 'm-admin' && S.role < 2) { showToast('需要超级管理员权限'); return; }
  var loader = TAB_LOADERS[key];
  if (loader) loader();
}

/* 分部切换（开始菜单触发）：同步 S 并重载当前打开的管理台窗口 */
function setBranch(branchId) {
  if (!authorized) return;
  S.currentBranchId = branchId || null;
  Array.prototype.forEach.call(document.querySelectorAll('.appwin.mgr-win.show'), function (w) {
    var loader = TAB_LOADERS[w.dataset.appkey];
    if (loader) loader();
  });
}

/* 暴露给 desktop.js 的入口 */
window.MANAGER_APP = { startApp: startApp, setBranch: setBranch };

/* ================= window.* 绑定（HTML inline onclick 调用） ================= */
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
window.saveGrantedAnomalies = saveGrantedAnomalies;
window.filterGrantAnomaly = filterGrantAnomaly;
window.openGrantNpcModal = openGrantNpcModal;
window.closeGrantNpcModal = closeGrantNpcModal;
window.saveGrantedNpcs = saveGrantedNpcs;
window.filterGrantNpc = filterGrantNpc;

/* 任务模块 */
window.loadMissions = loadMissions;
window.switchMissionTab = switchMissionTab;
window.openMissionModal = openMissionModal;
window.closeMissionModal = closeMissionModal;
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

/* 邮件/收件箱（任务详情使用） */
window.loadInbox = loadInbox;
window.openInboxModal = openInboxModal;
window.closeInboxModal = closeInboxModal;
window.openMailDetail = openMailDetail;
window.closeMailDetailModal = closeMailDetailModal;

/* 申领物模块 */
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

/* Siphon 模块 */
window.loadSiphonProducts = loadSiphonProducts;
window.filterSiphonProducts = filterSiphonProducts;
window.openSiphonModal = openSiphonModal;
window.closeSiphonModal = closeSiphonModal;
window.saveSiphonProduct = saveSiphonProduct;
window.deleteSiphonProduct = deleteSiphonProduct;

/* 异常能力模板模块 */
window.loadAnomalyTemplates = loadAnomalyTemplates;
window.openAnomalyTemplateModal = openAnomalyTemplateModal;
window.closeAnomalyTemplateModal = closeAnomalyTemplateModal;
window.saveAnomalyTemplate = saveAnomalyTemplate;
window.deleteAnomalyTemplate = deleteAnomalyTemplate;
window.handleAnomTplPassiveChange = handleAnomTplPassiveChange;
window.tplAddListRow = tplAddListRow;
window.importAnomalyJson = importAnomalyJson;

/* 破坏条模块 */
window.loadDestructionTrack = loadDestructionTrack;
window.saveDestructionTrack = saveDestructionTrack;

/* 入职申请模块 */
window.loadBranchApplications = loadBranchApplications;
window.reviewApplication = reviewApplication;

/* NPC 关系模板模块 */
window.loadNpcTemplates = loadNpcTemplates;
window.openNpcTemplateModal = openNpcTemplateModal;
window.closeNpcTemplateModal = closeNpcTemplateModal;
window.handleNpcBonusChange = handleNpcBonusChange;
window.resetNpcBonus = resetNpcBonus;
window.clickNpcLvlDot = clickNpcLvlDot;
window.saveNpcTemplate = saveNpcTemplate;
window.deleteNpcTemplate = deleteNpcTemplate;

/* 系统设置（admin）弹窗关闭（HTML inline onclick 使用） */
window.closeAdminRoleModal = closeAdminRoleModal;
window.closeAdminPwdModal = closeAdminPwdModal;
window.closeAdminBranchModal = closeAdminBranchModal;

/* 任务详情 inline onclick 使用 currentMissionDetailId */
Object.defineProperty(window, 'currentMissionDetailId', {
  get: function () { return S.currentMissionDetailId; }
});

/* ================= 初始化 ================= */
var branchesReady = null;
if (authorized) {
  branchesReady = loadMyBranches();

  branchesReady.then(function () {
    /* 预载角色与任务（其余模块首次打开窗口时再加载） */
    loadCharacters();
    loadMissions();
    loadInbox();

    /* loadMyBranches 可能自动选定了分部：通知 desktop.js 刷新开始菜单并按分部重拉角色 */
    if (window.DESKTOP && window.DESKTOP.onBranchChanged) window.DESKTOP.onBranchChanged();

    /* 刷新后恢复打开的管理台窗口：desktop.js 已恢复显示，这里补数据 */
    Array.prototype.forEach.call(document.querySelectorAll('.appwin.mgr-win.show'), function (w) {
      startApp(w.dataset.appkey);
    });
  });
}
