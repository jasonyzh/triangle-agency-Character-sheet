const params = new URLSearchParams(window.location.search);
const charId = params.get('id');
const isReadOnly = params.get('readonly') === 'true';
const isEmbed = params.get('embed') === 'true';
const token = localStorage.getItem('ta_token');

const ATTRS = ['专注','欺瞒','活力','共情','主动','坚毅','气场','专业','诡秘'];
const tabOrder = ['view-board', 'view-char', 'view-anom', 'view-real', 'view-item'];
const swiperWrapper = document.getElementById('swiperWrapper');
const navBtns = document.querySelectorAll('.nav-btn');

const S = {
    params, charId, isReadOnly, isEmbed, token,
    CONFIG_DATA: { anoms: [], realities: [], functions: [], bonuses: [] },
    SLOT_LIMITS: { anomSlots: 10, realSlots: 10 },
    currentTab: 0,
    currentMailTab: 'inbox',
    mailData: { inbox: [], sent: [], highwallFiles: [] },
    isA1Unlocked: false,
    isU2Unlocked: false,
    availableMissions: [],
    currentOutboxForm: null,
    currentOpenMail: null,
    autoSaveTimer: null,
    currentAssessmentData: null,
    lastAssessmentAttributes: [],
    playerSocket: null,
    playerBoard: null,
    playerBoardMissions: [],
    currentPlayerBoardMissionId: null,
    playerNpcCtxMenu: null,
    npcConnectSourceId: null,
    npcConnectMissionId: null,
    cachedRecords: null,
    diceHistory: JSON.parse(localStorage.getItem('ta_dice_history') || '[]')
};

export { S, ATTRS, tabOrder, swiperWrapper, navBtns };
