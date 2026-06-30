const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

function checkRecordAccess(req, charId) {
    if (req.user.role >= ROLE.SUPER_ADMIN) return true;
    if (req.user.role < ROLE.MANAGER) return false;
    const charRow = db.prepare('SELECT branch_id FROM characters WHERE id = ?').get(charId);
    if (!charRow || !charRow.branch_id) return false;
    const ub = db.prepare('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?').get(req.user.userId, charRow.branch_id);
    return !!ub;
}

router.get('/api/character/:id/records', authenticateToken, (req, res) => {
    try {
        const charId = req.params.id;

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ error: '角色不存在' });

        let hasAccess = false;
        if (req.user.role >= ROLE.SUPER_ADMIN) hasAccess = true;
        else if (req.user.userId === row.user_id) hasAccess = true;
        else hasAccess = checkRecordAccess(req, charId);

        if (!hasAccess) return res.status(403).json({ error: '无权访问' });

        try {
            const data = JSON.parse(row.data);
            res.json({
                rewards: data.rewards || [],
                reprimands: data.reprimands || [],
                mvpRecords: data.mvpRecords || [],
                watchRecords: data.watchRecords || []
            });
        } catch (e) {
            res.json({ rewards: [], reprimands: [] });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/character/:id/reward', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { reason, count } = req.body;
        const recordCount = Math.max(-99, Math.min(99, parseInt(count) || 1));

        if (recordCount === 0) {
            return res.status(400).json({ success: false, message: '数量不能为0' });
        }

        if (!reason || !reason.trim()) {
            return res.status(400).json({ success: false, message: '请填写嘉奖原因' });
        }

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.rewards) data.rewards = [];

            data.rewards.push({
                id: Date.now().toString(),
                reason: reason.trim(),
                count: recordCount,
                date: Date.now(),
                addedByName: req.user.username
            });

            const totalRewards = data.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
            data.mvpCount = totalRewards;

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            const actionText = recordCount > 0 ? '添加' : '扣除';
            res.json({ success: true, message: `已${actionText} ${Math.abs(recordCount)} 个嘉奖` });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/character/:id/reprimand', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { reason, count } = req.body;
        const recordCount = Math.max(-99, Math.min(99, parseInt(count) || 1));

        if (recordCount === 0) {
            return res.status(400).json({ success: false, message: '数量不能为0' });
        }

        if (!reason || !reason.trim()) {
            return res.status(400).json({ success: false, message: '请填写申诫原因' });
        }

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.reprimands) data.reprimands = [];

            data.reprimands.push({
                id: Date.now().toString(),
                reason: reason.trim(),
                count: recordCount,
                date: Date.now(),
                addedByName: req.user.username
            });

            const totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
            data.watchCount = totalReprimands;

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            const actionText = recordCount > 0 ? '添加' : '扣除';
            res.json({ success: true, message: `已${actionText} ${Math.abs(recordCount)} 个申诫` });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/character/:id/record/:recordId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const recordId = req.params.recordId;
        const { type } = req.query;

        if (!type || !['reward', 'reprimand'].includes(type)) {
            return res.status(400).json({ success: false, message: '无效的记录类型' });
        }

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            const arrayKey = type === 'reward' ? 'rewards' : 'reprimands';
            const countKey = type === 'reward' ? 'mvpCount' : 'watchCount';

            if (!data[arrayKey]) return res.status(404).json({ success: false, message: '记录不存在' });

            data[arrayKey] = data[arrayKey].filter(r => r.id !== recordId);
            const newTotal = data[arrayKey].reduce((sum, r) => sum + (r.count || 1), 0);
            data[countKey] = newTotal;

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, message: `记录已删除` });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/character/:id/mvp', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { reason, count } = req.body;
        const recordCount = Math.max(1, Math.min(99, parseInt(count) || 1));

        if (!reason || !reason.trim()) {
            return res.status(400).json({ success: false, message: '请填写原因' });
        }

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.mvpRecords) data.mvpRecords = [];

            data.mvpRecords.push({
                id: Date.now().toString(),
                reason: reason.trim(),
                count: recordCount,
                date: Date.now(),
                addedByName: req.user.username
            });

            data.pComm = String(data.mvpRecords.reduce((sum, r) => sum + (r.count || 1), 0));

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, message: `已添加 ${recordCount} 次MVP`, total: parseInt(data.pComm) });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/character/:id/watch', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const { reason, count } = req.body;
        const recordCount = Math.max(1, Math.min(99, parseInt(count) || 1));

        if (!reason || !reason.trim()) {
            return res.status(400).json({ success: false, message: '请填写原因' });
        }

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.watchRecords) data.watchRecords = [];

            data.watchRecords.push({
                id: Date.now().toString(),
                reason: reason.trim(),
                count: recordCount,
                date: Date.now(),
                addedByName: req.user.username
            });

            data.pRep = String(data.watchRecords.reduce((sum, r) => sum + (r.count || 1), 0));

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, message: `已添加 ${recordCount} 次察看期`, total: parseInt(data.pRep) });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/character/:id/mvp-record/:recordId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const recordId = req.params.recordId;

        const row = db.prepare('SELECT data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.mvpRecords) return res.status(404).json({ success: false, message: '记录不存在' });

            data.mvpRecords = data.mvpRecords.filter(r => r.id !== recordId);
            data.pComm = String(data.mvpRecords.reduce((sum, r) => sum + (r.count || 1), 0));

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, message: 'MVP记录已删除' });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/character/:id/watch-record/:recordId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const charId = req.params.id;
        const recordId = req.params.recordId;

        const row = db.prepare('SELECT data FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (!checkRecordAccess(req, charId) && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此角色' });
        }

        try {
            const data = JSON.parse(row.data);
            if (!data.watchRecords) return res.status(404).json({ success: false, message: '记录不存在' });

            data.watchRecords = data.watchRecords.filter(r => r.id !== recordId);
            data.pRep = String(data.watchRecords.reduce((sum, r) => sum + (r.count || 1), 0));

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
            res.json({ success: true, message: '察看期记录已删除' });
        } catch (e) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

module.exports = router;
