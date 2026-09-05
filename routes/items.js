const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

function getBranchParam(req) {
    return req.query.branchId || req.body.branchId || null;
}

function checkBranchMembership(userId, branchId) {
    if (!branchId) return false;
    const row = db.prepare('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?').get(userId, branchId);
    return !!row;
}

router.get('/api/manager/requisitions', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = getBranchParam(req);
        if (!branchId) return res.json({ success: true, items: [] });

        const query = req.user.role >= ROLE.SUPER_ADMIN
            ? 'SELECT id, name, pd, effect, type, price, prices, once, created_at as createdAt FROM requisitions WHERE branch_id = ? ORDER BY created_at DESC'
            : 'SELECT id, name, pd, effect, type, price, prices, once, created_at as createdAt FROM requisitions WHERE branch_id = ? ORDER BY created_at DESC';

        if (!checkBranchMembership(req.user.userId, branchId) && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ success: false, message: '你不属于该分部' });
        const rows = db.prepare(query).all(branchId);
        const items = (rows || []).map(row => ({ ...row, prices: row.prices ? JSON.parse(row.prices) : null }));
        res.json({ success: true, items });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/manager/requisitions', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { id, name, pd, effect, type, price, prices, once, createdAt, branchId } = req.body;
        const managerId = req.user.userId;
        if (!name || !name.trim()) return res.status(400).json({ success: false, message: '物品名称不能为空' });
        if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

        const timestamp = createdAt ? new Date(createdAt).getTime() : Date.now();
        const itemType = type || 'basic';
        const itemPrice = parseInt(price) || 0;
        const pricesJson = prices ? JSON.stringify(prices) : null;
        const itemOnce = once ? 1 : 0;
        db.prepare('INSERT INTO requisitions (id, manager_id, name, pd, effect, type, price, prices, once, created_at, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, managerId, name, pd || '', effect || '', itemType, itemPrice, pricesJson, itemOnce, timestamp, branchId);
        res.json({ success: true, itemId: id });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.put('/api/manager/requisitions', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { id, name, pd, effect, type, price, prices, once } = req.body;
        const managerId = req.user.userId;
        if (!name || !name.trim()) return res.status(400).json({ success: false, message: '物品名称不能为空' });
        const itemType = type || 'basic';
        const itemPrice = parseInt(price) || 0;
        const pricesJson = prices ? JSON.stringify(prices) : null;
        const itemOnce = once ? 1 : 0;
        const row = db.prepare('SELECT id FROM requisitions WHERE id = ? AND manager_id = ?').get(id, managerId);
        if (!row && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '申领物不存在或无权限' });
        db.prepare('UPDATE requisitions SET name = ?, pd = ?, effect = ?, type = ?, price = ?, prices = ?, once = ? WHERE id = ?').run(name, pd || '', effect || '', itemType, itemPrice, pricesJson, itemOnce, id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.delete('/api/manager/requisitions/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const itemId = req.params.id;
        const managerId = req.user.userId;
        const result = db.prepare('DELETE FROM requisitions WHERE id = ? AND manager_id = ?').run(itemId, managerId);
        if (result.changes === 0 && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '申领物不存在或无权限' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/manager/assign-requisition', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { requisitionId, characterIds, itemData, branchId } = req.body;
        if (!characterIds || characterIds.length === 0) return res.status(400).json({ success: false, message: '未选择角色' });

        let failed = [];
        for (const charId of characterIds) {
            const row = db.prepare('SELECT data, branch_id FROM characters WHERE id = ?').get(charId);
            if (!row) { failed.push(charId); continue; }
            if (branchId && row.branch_id !== branchId && req.user.role < ROLE.SUPER_ADMIN) { failed.push(charId); continue; }
            let charData = {};
            try { charData = JSON.parse(row.data || '{}'); } catch(e) { charData = {}; }
            if (!charData.items) charData.items = [];
            charData.items.push({ item: itemData.item, pd: itemData.pd, eff: itemData.eff, once: !!itemData.once });
            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(charData), charId);
        }
        if (failed.length > 0) res.json({ success: true, message: `成功分配 ${characterIds.length - failed.length} 个，失败 ${failed.length} 个`, failedCount: failed.length });
        else res.json({ success: true, message: `已成功分配给 ${characterIds.length} 个角色` });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.get('/api/character/:charId/requisitions', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId; const userId = req.user.userId;
        const charRow = db.prepare('SELECT user_id, branch_id FROM characters WHERE id = ?').get(charId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });
        if (charRow.user_id !== userId) return res.status(403).json({ success: false, message: '无权访问该角色' });

        const branchId = charRow.branch_id;
        if (!branchId) return res.json({ success: true, items: [] });

        const userPerms = db.prepare('SELECT requisition_id FROM user_requisition_permissions WHERE user_id = ?').all(userId);
        const userRequisitionIds = userPerms ? userPerms.map(p => p.requisition_id) : [];

        let query = `SELECT id, name, pd, effect, type, price, prices, manager_id FROM requisitions WHERE branch_id = ? AND (type = 'basic'`;
        let params = [branchId];
        if (userRequisitionIds.length > 0) {
            const ph = userRequisitionIds.map(() => '?').join(',');
            query += ` OR (type = 'permission' AND id IN (${ph}))`;
            params = [...params, ...userRequisitionIds];
        }
        query += ') ORDER BY created_at DESC';

        const items = db.prepare(query).all(...params);
        const parsedItems = (items || []).map(item => ({ ...item, prices: item.prices ? JSON.parse(item.prices) : null }));
        res.json({ success: true, items: parsedItems });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/character/:charId/purchase-requisition', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId; const { requisitionId, priceIndex } = req.body; const userId = req.user.userId;
        if (!requisitionId) return res.status(400).json({ success: false, message: '缺少申领物ID' });
        const charRow = db.prepare('SELECT user_id, data, branch_id FROM characters WHERE id = ?').get(charId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });
        if (charRow.user_id !== userId) return res.status(403).json({ success: false, message: '无权访问该角色' });
        const item = db.prepare('SELECT id, name, pd, effect, price, prices, type, manager_id, branch_id FROM requisitions WHERE id = ?').get(requisitionId);
        if (!item) return res.status(404).json({ success: false, message: '申领物不存在' });
        if (item.branch_id !== charRow.branch_id) return res.status(403).json({ success: false, message: '该申领物不属于你的分部' });
        if (item.type === 'permission') {
            const userPerm = db.prepare('SELECT id FROM user_requisition_permissions WHERE user_id = ? AND requisition_id = ?').get(userId, requisitionId);
            if (!userPerm) return res.status(403).json({ success: false, message: '无权购买该申领物' });
        }

        let charData = {};
        try { charData = JSON.parse(charRow.data || '{}'); } catch(e) { charData = {}; }
        let actualPrice = item.price; let priceDescription = '';
        if (item.prices && priceIndex !== undefined && priceIndex !== null) { try { const pa = typeof item.prices === 'string' ? JSON.parse(item.prices) : item.prices; if (pa && pa[priceIndex]) { actualPrice = parseInt(pa[priceIndex].price) || 0; priceDescription = pa[priceIndex].description || ''; } } catch(e) {} }
        const rewards = charData.rewards || []; const totalRewards = rewards.reduce((sum, r) => sum + (r.count || 0), 0);
        if (totalRewards < actualPrice) return res.status(400).json({ success: false, message: `嘉奖不足，需要 ${actualPrice} 个，当前只有 ${totalRewards} 个` });
        if (!charData.rewards) charData.rewards = [];
        charData.rewards.push({ id: `purchase-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, reason: `购买申领物：${item.name}${priceDescription ? ` (${priceDescription})` : ''}`, count: -actualPrice, date: new Date().toISOString(), managerId: item.manager_id });
        let effectText = item.effect || ''; if (priceDescription) effectText = `【${priceDescription}】${effectText}`;
        if (!charData.items) charData.items = []; charData.items.push({ item: item.name, pd: item.pd || '', eff: effectText });
        const purchaseId = `purchase-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        db.prepare('INSERT INTO requisition_purchases (id, character_id, requisition_id, price, purchased_at) VALUES (?, ?, ?, ?, ?)').run(purchaseId, charId, requisitionId, actualPrice, Date.now());
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(charData), charId);
        res.json({ success: true, message: `成功购买 ${item.name}${priceDescription ? ` (${priceDescription})` : ''}，消耗 ${actualPrice} 个嘉奖`, remainingBonus: totalRewards - actualPrice });
    } catch (err) {
        res.status(500).json({ success: false, message: '购买失败' });
    }
});

router.get('/api/user/permission-requisitions', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const branchId = req.query.branchId;
        let query = 'SELECT id, name, pd, effect, price, manager_id FROM requisitions WHERE type = ?';
        let params = ['permission'];
        if (branchId) { query += ' AND branch_id = ?'; params.push(branchId); }
        query += ' ORDER BY created_at DESC';
        const items = db.prepare(query).all(...params);
        const perms = db.prepare('SELECT requisition_id FROM user_requisition_permissions WHERE user_id = ?').all(userId);
        const grantedIds = perms ? perms.map(p => p.requisition_id) : [];
        res.json({ success: true, items: items.map(item => ({ ...item, granted: grantedIds.includes(item.id) })) });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.get('/api/admin/user/:userId/requisition-permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const rows = db.prepare('SELECT requisition_id FROM user_requisition_permissions WHERE user_id = ?').all(req.params.userId);
        res.json({ success: true, permissions: rows ? rows.map(r => r.requisition_id) : [] });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.put('/api/admin/user/:userId/requisition-permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const userId = req.params.userId; const { requisitionIds } = req.body;
        if (!Array.isArray(requisitionIds)) return res.status(400).json({ success: false, message: '参数错误' });
        db.prepare('DELETE FROM user_requisition_permissions WHERE user_id = ?').run(userId);
        if (requisitionIds.length > 0) {
            const stmt = db.prepare('INSERT INTO user_requisition_permissions (user_id, requisition_id, granted_at) VALUES (?, ?, ?)');
            const now = Date.now();
            for (const reqId of requisitionIds) {
                stmt.run(userId, reqId, now);
            }
        }
        res.json({ success: true, message: '授权已更新' });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/user/toggle-requisition-permission', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId; const { requisitionId } = req.body;
        if (!requisitionId) return res.status(400).json({ success: false, message: '缺少申领物ID' });
        const existing = db.prepare('SELECT id FROM user_requisition_permissions WHERE user_id = ? AND requisition_id = ?').get(userId, requisitionId);
        if (existing) {
            db.prepare('DELETE FROM user_requisition_permissions WHERE user_id = ? AND requisition_id = ?').run(userId, requisitionId);
            res.json({ success: true, granted: false, message: '已取消授权' });
        } else {
            db.prepare('INSERT INTO user_requisition_permissions (user_id, requisition_id, granted_at) VALUES (?, ?, ?)').run(userId, requisitionId, Date.now());
            res.json({ success: true, granted: true, message: '已授权' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

router.get('/api/character/:charId/purchased-requisitions', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId; const userId = req.user.userId;
        const charRow = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });
        if (charRow.user_id !== userId) return res.status(403).json({ success: false, message: '无权访问该角色' });
        const purchases = db.prepare('SELECT rp.id, rp.purchased_at, rp.price, r.id as requisition_id, r.name, r.pd, r.effect, r.type FROM requisition_purchases rp JOIN requisitions r ON rp.requisition_id = r.id WHERE rp.character_id = ? ORDER BY rp.purchased_at DESC').all(charId);
        res.json({ success: true, purchases: purchases || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

module.exports = router;
