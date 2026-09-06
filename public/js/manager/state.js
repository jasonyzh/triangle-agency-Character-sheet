const token = localStorage.getItem('ta_token');
const role = parseInt(localStorage.getItem('ta_role') || '0');

/* 管理台已内嵌桌面壳：无会话/无权限时不跳独立登录页（已移除），改由桌面登录层兜底 */
if (!token || role < 1) {
    if (window.LS) window.LS.show();
}

const S = {
    token,
    role,
    myBranches: [],
    currentBranchId: localStorage.getItem('ta_current_branch'),
    allCharacters: [],
    currentSlotCharId: null,
    currentSlotData: { anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 },
    touchStartX: 0,
    touchStartY: 0,
    swipeThreshold: 80,
    edgeThreshold: 60,
    currentDocCharId: null,
    currentGrantAnomalyCharId: null,
    currentPermUserId: null,
    currentRecordCharId: null,
    currentRecordTab: 'reward',
    currentRecords: { rewards: [], reprimands: [], mvpRecords: [], watchRecords: [] },
    currentMissionTab: 'active',
    currentMissionId: null,
    missionsList: [],
    inboxMessages: [],
    lastLoadedTab: null,
    currentMissionDetailId: null,
    currentMissionDetailData: null,
    missionReports: [],
    missionInboxMessages: [],
    addMemberMissionId: null,
    allAvailableCharacters: [],
    requisitionItems: [],
    currentEditingRequisitionId: null,
    currentAssignRequisitionId: null,
    allCharactersForSelect: [],
    siphonProducts: [],
    currentEditingSiphonId: null,
    branchApplications: [],
    anomalyTemplates: [],
    anomalyDocFiles: [],
    npcTemplates: [],
    currentGrantNpcCharId: null,
    npcBonusOptions: []
};

export { S };
