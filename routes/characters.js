const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole, optionalAuth } = require('../middleware/auth');

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
        const newData = { ...req.body, rewards: existingData.rewards || [], reprimands: existingData.reprimands || [] };
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
                name: d.pName || "未命名干员",
                anom: d.pAnom || "---",
                real: d.pReal || "---",
                func: d.pFunc || "---",
                mvpCount: totalMvp,
                watchCount: totalWatch,
                missions: (missions || []).map(m => m.name),
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

module.exports = router;
