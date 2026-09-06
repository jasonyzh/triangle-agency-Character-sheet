const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { db, DATA_DIR } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole, optionalAuth } = require('../middleware/auth');
const { isCosEnabled, isCosConfigured, uploadToCos, deleteFromCos, keyFromCosUrl } = require('../cos');

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const PCIMG_DIR = path.join(UPLOADS_DIR, 'pcimg');
if (!fs.existsSync(PCIMG_DIR)) fs.mkdirSync(PCIMG_DIR, { recursive: true });

// 头像上传：memoryStorage，限 5MB，仅图片
const avatarUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.webp'];
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, allowed.includes(ext));
    }
});

function checkBranchAccess(userId, characterBranchId, userRole) {
    if (userRole >= ROLE.SUPER_ADMIN) return true;
    if (!characterBranchId) return false;
    const row = db.prepare('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?').get(userId, characterBranchId);
    return !!row;
}

router.get('/api/characters', (req, res) => {
    try {
        const { userId, branchId } = req.query;
        let query = 'SELECT id, user_id, data, branch_id FROM characters WHERE user_id = ?';
        let params = [userId];
        if (branchId) { query += ' AND branch_id = ?'; params.push(branchId); }
        const rows = db.prepare(query).all(...params);
        const list = (rows || []).map(row => {
            let d = {};
            try { d = JSON.parse(row.data); } catch(e) {}
            return { id: row.id, userId: row.user_id, name: d.pName || "未命名干员", func: d.pFunc || "---", anom: d.pAnom || "---", real: d.pReal || "---", plazaVisible: !d.plazaHidden, isArchived: !!d.isArchived, trackProgress: { func: (d.pf || []).length, real: (d.pr || []).length, anom: (d.pa || []).length }, data: row.data };
        });
        res.json(list);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/character/:id', optionalAuth, (req, res) => {
    try {
        const row = db.prepare('SELECT * FROM characters WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({});

        let hasAccess = false;
        if (req.user && req.user.role >= ROLE.SUPER_ADMIN) hasAccess = true;
        else if (req.user && req.user.userId === row.user_id) hasAccess = true;
        else if (req.user && req.user.role >= ROLE.MANAGER) hasAccess = checkBranchAccess(req.user.userId, row.branch_id, req.user.role);

        if (!hasAccess && req.user) return res.status(403).json({ error: '无权访问此角色卡' });

        const owner = db.prepare('SELECT name, username FROM users WHERE id = ?').get(row.user_id);
        try {
            const data = JSON.parse(row.data);
            const totalRewards = (data.rewards || []).reduce((sum, r) => sum + (r.count || 1), 0);
            const totalReprimands = (data.reprimands || []).reduce((sum, r) => sum + (r.count || 1), 0);
            data.mvpCount = totalRewards;
            data.watchCount = totalReprimands;
            const totalMvp = (data.mvpRecords || []).reduce((sum, r) => sum + (r.count || 1), 0);
            const totalWatch = (data.watchRecords || []).reduce((sum, r) => sum + (r.count || 1), 0);
            data.pComm = String(totalMvp);
            data.pRep = String(totalWatch);
            data._ownerId = row.user_id;
            data._canEdit = hasAccess && !data.isArchived;
            data.ownerName = owner ? (owner.name || owner.username) : '未知';
            data.anomSlots = data.anomSlots || 10;
            data.realSlots = data.realSlots || 10;
            res.json(data);
        } catch (e) { res.status(500).json({}); }
    } catch (err) {
        res.status(500).json({});
    }
});

router.post('/api/character', (req, res) => {
    try {
        const newId = Date.now().toString();
        const { userId, branchId } = req.body;
        if (!branchId) return res.status(400).json({ success: false, message: '必须指定分部' });
        const data = JSON.stringify({ pName: "新进职员" });
        db.prepare('INSERT INTO characters (id, user_id, data, created_at, branch_id) VALUES (?, ?, ?, ?, ?)').run(newId, userId, data, Date.now(), branchId);
        res.json({ success: true, id: newId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/character/:id', optionalAuth, (req, res) => {
    try {
        const row = db.prepare('SELECT user_id, branch_id FROM characters WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false });

        let canEdit = false;
        if (req.user && req.user.role >= ROLE.SUPER_ADMIN) canEdit = true;
        else if (req.user && req.user.userId === row.user_id) canEdit = true;
        else if (req.user && req.user.role >= ROLE.MANAGER) canEdit = checkBranchAccess(req.user.userId, row.branch_id, req.user.role);

        if (!canEdit) return res.status(403).json({ success: false, message: '无权编辑此角色卡' });

        const existingRow = db.prepare('SELECT data FROM characters WHERE id = ?').get(req.params.id);
        let existingData = {};
        try { if (existingRow && existingRow.data) existingData = JSON.parse(existingRow.data); } catch (e) {}
        if (existingData.isArchived) return res.status(403).json({ success: false, message: '角色已归档，无法编辑' });
        const newData = { ...req.body, rewards: existingData.rewards || [], reprimands: existingData.reprimands || [], mvpRecords: existingData.mvpRecords || [], watchRecords: existingData.watchRecords || [] };
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(newData), req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/character/:id', authenticateToken, (req, res) => {
    try {
        const row = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });
        if (row.user_id != req.user.userId && req.user.role < ROLE.MANAGER) {
            return res.status(403).json({ success: false, message: '无权删除此角色' });
        }
        db.prepare('DELETE FROM characters WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

router.get('/api/manager/characters', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.query.branchId;
        if (!branchId) return res.json([]);

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchAccess(req.user.userId, branchId, req.user.role)) {
                return res.status(403).json({ success: false, message: '你不属于该分部' });
            }
        }

        const rows = db.prepare(`SELECT c.id, c.data, c.user_id, u.name as owner_name FROM characters c JOIN users u ON c.user_id = u.id WHERE c.branch_id = ?`).all(branchId);
        const list = (rows || []).map(row => {
            let d = {}; try { d = JSON.parse(row.data); } catch(e) {}
            return { id: row.id, name: d.pName || "未命名干员", func: d.pFunc || "---", anom: d.pAnom || "---", real: d.pReal || "---", ownerName: row.owner_name, ownerId: row.user_id, plazaHidden: !!d.plazaHidden, isArchived: !!d.isArchived };
        });
        res.json(list);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/character/:id/slots', authenticateToken, (req, res) => {
    try {
        const charId = req.params.id;
        const row = db.prepare('SELECT data, user_id, branch_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ error: '角色不存在' });

        let hasAccess = false;
        if (req.user.role >= ROLE.SUPER_ADMIN) hasAccess = true;
        else if (req.user.userId === row.user_id) hasAccess = true;
        else if (req.user.role >= ROLE.MANAGER) hasAccess = checkBranchAccess(req.user.userId, row.branch_id, req.user.role);

        if (!hasAccess) return res.status(403).json({ error: '无权访问' });
        try {
            const data = JSON.parse(row.data);
            res.json({ anomSlots: data.anomSlots || 10, realSlots: data.realSlots || 10, currentAnoms: (data.anoms || []).length, currentReals: (data.reals || []).length });
        } catch (e) { res.json({ anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 }); }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/character/:id/slots', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { anomSlots, realSlots } = req.body;
        const row = db.prepare('SELECT data, user_id, branch_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        let hasAccess = false;
        if (req.user.role >= ROLE.SUPER_ADMIN) hasAccess = true;
        else hasAccess = checkBranchAccess(req.user.userId, row.branch_id, req.user.role);

        if (!hasAccess) return res.status(403).json({ success: false, message: '无权修改此角色' });
        try {
            const data = JSON.parse(row.data);
            if (anomSlots !== undefined) { data.anomSlots = Math.max(anomSlots, (data.anoms || []).length, 10); }
            if (realSlots !== undefined) { data.realSlots = Math.max(realSlots, (data.reals || []).length, 10); }
            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, anomSlots: data.anomSlots, realSlots: data.realSlots });
        } catch (e) { res.status(500).json({ success: false, message: '数据解析失败' }); }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/plaza/characters', authenticateToken, (req, res) => {
    try {
        const branchId = req.query.branchId;
        if (!branchId) return res.json([]);

        if (req.user.role < ROLE.SUPER_ADMIN) {
            const access = db.prepare('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?').get(req.user.userId, branchId);
            if (!access) return res.status(403).json({ success: false, message: '你不属于该分部' });
        }

        const rows = db.prepare('SELECT c.id, c.data, c.user_id FROM characters c WHERE c.branch_id = ?').all(branchId);
        const list = [];
        for (const row of (rows || [])) {
            let d = {};
            try { d = JSON.parse(row.data); } catch (e) {}
            if (d.plazaHidden) continue;

            const totalMvp = parseInt(d.pComm) || 0;
            const totalWatch = parseInt(d.pRep) || 0;

            const missions = db.prepare(
                `SELECT fm.name FROM field_mission_members fmm
                 JOIN field_missions fm ON fmm.mission_id = fm.id
                 WHERE fmm.character_id = ?`
            ).all(row.id);

            list.push({
                id: row.id,
                ownerId: row.user_id,
                name: d.pName || "未命名干员",
                anom: d.pAnom || "---",
                real: d.pReal || "---",
                func: d.pFunc || "---",
                pAvatar: d.pAvatar || '',
                mvpCount: totalMvp,
                watchCount: totalWatch,
                missions: (missions || []).map(m => m.name),
                plazaMessage: d.plazaMessage || '',
                isArchived: !!d.isArchived,
                trackProgress: { func: (d.pf || []).length, real: (d.pr || []).length, anom: (d.pa || []).length }
            });
        }
        res.json(list);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/character/:id/plaza-visibility', authenticateToken, (req, res) => {
    try {
        const charId = req.params.id;
        const { visible } = req.body;

        const row = db.prepare('SELECT user_id, branch_id, data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        let canEdit = false;
        if (req.user.role >= ROLE.SUPER_ADMIN) canEdit = true;
        else if (req.user.userId === row.user_id) canEdit = true;
        else if (req.user.role >= ROLE.MANAGER) canEdit = checkBranchAccess(req.user.userId, row.branch_id, req.user.role);

        if (!canEdit) return res.status(403).json({ success: false, message: '无权操作' });

        const data = JSON.parse(row.data || '{}');
        if (visible) {
            delete data.plazaHidden;
        } else {
            data.plazaHidden = true;
        }
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
        res.json({ success: true, plazaVisible: visible });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/character/:id/plaza-message', authenticateToken, (req, res) => {
    try {
        const charId = req.params.id;
        const message = typeof req.body.message === 'string' ? req.body.message.slice(0, 300) : '';

        const row = db.prepare('SELECT user_id, data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // 仅角色本人或超管可编辑广场留言
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '只能编辑自己角色的广场留言' });
        }

        const data = JSON.parse(row.data || '{}');
        data.plazaMessage = message;
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
        res.json({ success: true, message: data.plazaMessage });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/character/:id/archive', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { archived } = req.body;

        const row = db.prepare('SELECT user_id, branch_id, data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchAccess(req.user.userId, row.branch_id, req.user.role)) {
                return res.status(403).json({ success: false, message: '无权操作' });
            }
        }

        const data = JSON.parse(row.data || '{}');
        if (archived) {
            data.isArchived = true;
        } else {
            delete data.isArchived;
        }
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
        res.json({ success: true, isArchived: !!archived });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// 头像上传：裁剪后的方形图片，存 pcimg 文件夹（COS 或本地）
router.post('/api/character/:id/avatar', authenticateToken, avatarUpload.single('avatar'), async (req, res) => {
    try {
        const charId = req.params.id;
        if (!req.file) return res.status(400).json({ success: false, message: '请选择图片' });

        const row = db.prepare('SELECT user_id, branch_id, data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // 鉴权：仅本人或超管
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '只能上传自己角色的头像' });
        }

        const data = JSON.parse(row.data || '{}');
        const oldAvatar = data.pAvatar || '';

        // 统一存为 .jpg（前端 toBlob('image/jpeg') 输出）
        const fileName = charId + '.jpg';

        let avatarUrl;
        if (isCosEnabled()) {
            if (!isCosConfigured()) {
                return res.status(400).json({ success: false, message: 'COS 已启用但凭证未配置完整' });
            }
            const cosKey = 'pcimg/' + fileName;
            const { Url } = await uploadToCos(cosKey, req.file.buffer);
            avatarUrl = Url;
            // 删除旧的 COS 头像（若旧的是 COS URL 且不是同一个）
            if (oldAvatar && oldAvatar.startsWith('http')) {
                const oldKey = keyFromCosUrl(oldAvatar);
                if (oldKey && oldKey !== cosKey) { try { await deleteFromCos(oldKey); } catch (e) {} }
            }
        } else {
            // 本地模式：落盘到 data/uploads/pcimg/{charId}.png
            fs.writeFileSync(path.join(PCIMG_DIR, fileName), req.file.buffer);
            avatarUrl = 'pcimg/' + fileName;
            // 删除旧本地头像（若旧的是本地路径）
            if (oldAvatar && !oldAvatar.startsWith('http') && oldAvatar !== avatarUrl) {
                const oldPath = path.join(UPLOADS_DIR, oldAvatar);
                if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch (e) {} }
            }
        }

        data.pAvatar = avatarUrl;
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
        res.json({ success: true, avatar: avatarUrl });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message || '上传失败' });
    }
});

module.exports = router;
