const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/character/:id/records', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ error: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);

            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) { resolve(false); return; }
                db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
                    if (!charRow || !charRow.branch_id) return resolve(false);
                    db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?',
                        [req.user.userId, charRow.branch_id], (err, ub) => { resolve(!!ub); });
                });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ error: '无权访问' });
            }

            try {
                const data = JSON.parse(row.data);
                res.json({
                    rewards: data.rewards || [],
                    reprimands: data.reprimands || []
                });
            } catch (e) {
                res.json({ rewards: [], reprimands: [] });
            }
        });
    });
});

router.post('/api/character/:id/reward', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { reason, count } = req.body;
    const recordCount = Math.max(-99, Math.min(99, parseInt(count) || 1));

    if (recordCount === 0) {
        return res.status(400).json({ success: false, message: '数量不能为0' });
    }

    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '请填写嘉奖原因' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
                    if (!charRow || !charRow.branch_id) return resolve(false);
                    db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, charRow.branch_id], (err, ub) => resolve(!!ub));
                });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
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

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    const actionText = recordCount > 0 ? '添加' : '扣除';
                    res.json({ success: true, message: `已${actionText} ${Math.abs(recordCount)} 个嘉奖` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

router.post('/api/character/:id/reprimand', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { reason, count } = req.body;
    const recordCount = Math.max(-99, Math.min(99, parseInt(count) || 1));

    if (recordCount === 0) {
        return res.status(400).json({ success: false, message: '数量不能为0' });
    }

    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '请填写申诫原因' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
                    if (!charRow || !charRow.branch_id) return resolve(false);
                    db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, charRow.branch_id], (err, ub) => resolve(!!ub));
                });
            });
        };
        
        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
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

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    const actionText = recordCount > 0 ? '添加' : '扣除';
                    res.json({ success: true, message: `已${actionText} ${Math.abs(recordCount)} 个申诫` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

router.delete('/api/character/:id/record/:recordId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const recordId = req.params.recordId;
    const { type } = req.query;

    if (!type || !['reward', 'reprimand'].includes(type)) {
        return res.status(400).json({ success: false, message: '无效的记录类型' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
                    if (!charRow || !charRow.branch_id) return resolve(false);
                    db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, charRow.branch_id], (err, ub) => resolve(!!ub));
                });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
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

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    res.json({ success: true, message: `记录已删除` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

module.exports = router;
