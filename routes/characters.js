const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole, optionalAuth } = require('../middleware/auth');

function checkBranchAccess(userId, characterBranchId, userRole, callback) {
    if (userRole >= ROLE.SUPER_ADMIN) return callback(true);
    if (!characterBranchId) return callback(false);
    db.get('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?',
        [userId, characterBranchId], (err, row) => { callback(!!row); });
}

router.get('/api/characters', (req, res) => {
    const { userId, branchId } = req.query;
    let query = 'SELECT id, user_id, data, branch_id FROM characters WHERE user_id = ?';
    let params = [userId];
    if (branchId) { query += ' AND branch_id = ?'; params.push(branchId); }
    db.all(query, params, (err, rows) => {
        const list = (rows || []).map(row => {
            let d = {};
            try { d = JSON.parse(row.data); } catch(e) {}
            return { id: row.id, userId: row.user_id, name: d.pName || "未命名干员", func: d.pFunc || "---", anom: d.pAnom || "---", real: d.pReal || "---", data: row.data };
        });
        res.json(list);
    });
});

router.get('/api/character/:id', optionalAuth, (req, res) => {
    db.get('SELECT * FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({});

        const checkAccess = () => {
            if (req.user && req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user && req.user.userId === row.user_id) return Promise.resolve(true);
            if (!req.user || req.user.role < ROLE.MANAGER) return Promise.resolve(false);
            return new Promise((resolve) => {
                checkBranchAccess(req.user.userId, row.branch_id, req.user.role, resolve);
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess && req.user) return res.status(403).json({ error: '无权访问此角色卡' });

            db.get('SELECT name, username FROM users WHERE id = ?', [row.user_id], (err, owner) => {
                try {
                    const data = JSON.parse(row.data);
                    const totalRewards = (data.rewards || []).reduce((sum, r) => sum + (r.count || 1), 0);
                    const totalReprimands = (data.reprimands || []).reduce((sum, r) => sum + (r.count || 1), 0);
                    data.mvpCount = totalRewards;
                    data.watchCount = totalReprimands;
                    data._ownerId = row.user_id;
                    data._canEdit = hasAccess;
                    data.ownerName = owner ? (owner.name || owner.username) : '未知';
                    data.anomSlots = data.anomSlots || 10;
                    data.realSlots = data.realSlots || 10;
                    res.json(data);
                } catch (e) { res.status(500).json({}); }
            });
        });
    });
});

router.post('/api/character', (req, res) => {
    const newId = Date.now().toString();
    const { userId, branchId } = req.body;
    if (!branchId) return res.status(400).json({ success: false, message: '必须指定分部' });
    const data = JSON.stringify({ pName: "新进职员" });
    db.run('INSERT INTO characters (id, user_id, data, created_at, branch_id) VALUES (?, ?, ?, ?, ?)',
        [newId, userId, data, Date.now(), branchId],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, id: newId });
        });
});

router.put('/api/character/:id', optionalAuth, (req, res) => {
    db.get('SELECT user_id, branch_id FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false });

        const checkEditAccess = () => {
            if (req.user && req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user && req.user.userId === row.user_id) return Promise.resolve(true);
            if (!req.user || req.user.role < ROLE.MANAGER) return Promise.resolve(false);
            return new Promise((resolve) => {
                checkBranchAccess(req.user.userId, row.branch_id, req.user.role, resolve);
            });
        };

        Promise.resolve(checkEditAccess()).then(canEdit => {
            if (!canEdit) return res.status(403).json({ success: false, message: '无权编辑此角色卡' });

            db.get('SELECT data FROM characters WHERE id = ?', [req.params.id], (err, existingRow) => {
                let existingData = {};
                try { if (existingRow && existingRow.data) existingData = JSON.parse(existingRow.data); } catch (e) {}
                const newData = { ...req.body, rewards: existingData.rewards || [], reprimands: existingData.reprimands || [] };
                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(newData), req.params.id],
                    function(err) { if (err) res.status(500).json({ success: false }); else res.json({ success: true }); });
            });
        });
    });
});

router.delete('/api/character/:id', authenticateToken, (req, res) => {
    db.get('SELECT user_id FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });
        if (row.user_id != req.user.userId && req.user.role < ROLE.MANAGER) {
            return res.status(403).json({ success: false, message: '无权删除此角色' });
        }
        db.run('DELETE FROM characters WHERE id = ?', [req.params.id], function(err) {
            if (err) return res.status(500).json({ success: false, message: '服务器错误' });
            res.json({ success: true });
        });
    });
});

router.get('/api/manager/characters', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const branchId = req.query.branchId;
    if (!branchId) return res.json([]);

    if (req.user.role >= ROLE.SUPER_ADMIN) {
        db.all(`SELECT c.id, c.data, c.user_id, u.name as owner_name FROM characters c JOIN users u ON c.user_id = u.id WHERE c.branch_id = ?`, [branchId], (err, rows) => {
            const list = (rows || []).map(row => {
                let d = {}; try { d = JSON.parse(row.data); } catch(e) {}
                return { id: row.id, name: d.pName || "未命名干员", func: d.pFunc || "---", anom: d.pAnom || "---", real: d.pReal || "---", ownerName: row.owner_name, ownerId: row.user_id };
            });
            res.json(list);
        });
    } else {
        checkBranchAccess(req.user.userId, branchId, req.user.role, (hasAccess) => {
            if (!hasAccess) return res.status(403).json({ success: false, message: '你不属于该分部' });
            db.all(`SELECT c.id, c.data, c.user_id, u.name as owner_name FROM characters c JOIN users u ON c.user_id = u.id WHERE c.branch_id = ?`, [branchId], (err, rows) => {
                const list = (rows || []).map(row => {
                    let d = {}; try { d = JSON.parse(row.data); } catch(e) {}
                    return { id: row.id, name: d.pName || "未命名干员", func: d.pFunc || "---", anom: d.pAnom || "---", real: d.pReal || "---", ownerName: row.owner_name, ownerId: row.user_id };
                });
                res.json(list);
            });
        });
    }
});

router.get('/api/character/:id/slots', authenticateToken, (req, res) => {
    const charId = req.params.id;
    db.get('SELECT data, user_id, branch_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ error: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);
            if (req.user.role < ROLE.MANAGER) return Promise.resolve(false);
            return new Promise((resolve) => { checkBranchAccess(req.user.userId, row.branch_id, req.user.role, resolve); });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) return res.status(403).json({ error: '无权访问' });
            try {
                const data = JSON.parse(row.data);
                res.json({ anomSlots: data.anomSlots || 10, realSlots: data.realSlots || 10, currentAnoms: (data.anoms || []).length, currentReals: (data.reals || []).length });
            } catch (e) { res.json({ anomSlots: 10, realSlots: 10, currentAnoms: 0, currentReals: 0 }); }
        });
    });
});

router.put('/api/character/:id/slots', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { anomSlots, realSlots } = req.body;
    db.get('SELECT data, user_id, branch_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => { checkBranchAccess(req.user.userId, row.branch_id, req.user.role, resolve); });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) return res.status(403).json({ success: false, message: '无权修改此角色' });
            try {
                const data = JSON.parse(row.data);
                if (anomSlots !== undefined) { data.anomSlots = Math.max(anomSlots, (data.anoms || []).length, 10); }
                if (realSlots !== undefined) { data.realSlots = Math.max(realSlots, (data.reals || []).length, 10); }
                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId],
                    function(err) {
                        if (err) return res.status(500).json({ success: false });
                        res.json({ success: true, anomSlots: data.anomSlots, realSlots: data.realSlots });
                    });
            } catch (e) { res.status(500).json({ success: false, message: '数据解析失败' }); }
        });
    });
});

module.exports = router;
