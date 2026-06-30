const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

router.get('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.query.branchId;
        if (!branchId) return res.json({ success: true, products: [] });
        const rows = db.prepare('SELECT * FROM siphon_products WHERE branch_id = ? ORDER BY created_at DESC').all(branchId);
        res.json({ success: true, products: rows || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: '加载失败' });
    }
});

router.post('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const managerId = req.user.userId;
        const { name, description, price, branchId } = req.body;
        if (!name || !name.trim()) return res.status(400).json({ success: false, message: '请输入商品名称' });
        if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

        const id = generateId();
        db.prepare('INSERT INTO siphon_products (id, manager_id, name, description, price, created_at, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(id, managerId, name.trim(), description || '', parseInt(price) || 0, Date.now(), branchId);
        res.json({ success: true, message: '商品已创建' });
    } catch (err) {
        res.status(500).json({ success: false, message: '创建失败' });
    }
});

router.put('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const managerId = req.user.userId;
        const { id, name, description, price } = req.body;
        if (!id) return res.status(400).json({ success: false, message: '缺少商品ID' });
        if (!name || !name.trim()) return res.status(400).json({ success: false, message: '请输入商品名称' });

        const result = db.prepare('UPDATE siphon_products SET name = ?, description = ?, price = ? WHERE id = ? AND manager_id = ?')
            .run(name.trim(), description || '', parseInt(price) || 0, id, managerId);
        if (result.changes === 0 && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '商品不存在' });
        res.json({ success: true, message: '商品已更新' });
    } catch (err) {
        res.status(500).json({ success: false, message: '更新失败' });
    }
});

router.delete('/api/manager/siphon-products/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const managerId = req.user.userId;
        const result = db.prepare('DELETE FROM siphon_products WHERE id = ? AND manager_id = ?').run(req.params.id, managerId);
        if (result.changes === 0 && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '商品不存在' });
        res.json({ success: true, message: '商品已删除' });
    } catch (err) {
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

router.get('/api/character/:id/check-x2', authenticateToken, (req, res) => {
    try {
        const charId = req.params.id;
        const row = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ unlocked: false });
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ unlocked: false });
        const perm = db.prepare(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`).get(charId);
        res.json({ unlocked: !!perm });
    } catch (err) {
        res.status(500).json({ unlocked: false });
    }
});

router.get('/api/character/:charId/siphon-products', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId;

        const perm = db.prepare(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`).get(charId);
        if (!perm && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ success: false, message: '未获得X2授权' });

        const charRow = db.prepare('SELECT branch_id FROM characters WHERE id = ?').get(charId);
        const branchId = charRow ? charRow.branch_id : null;
        let products;
        if (branchId) {
            products = db.prepare('SELECT * FROM siphon_products WHERE branch_id = ? ORDER BY created_at DESC').all(branchId);
        } else {
            products = db.prepare('SELECT * FROM siphon_products ORDER BY created_at DESC').all();
        }
        res.json({ success: true, products: products || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: '加载失败' });
    }
});

router.get('/api/character/:charId/siphon-purchased', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId;
        const row = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false });
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ success: false });
        const purchases = db.prepare(`SELECT sp.id, sp.purchased_at, sp.price, p.name, p.description
                 FROM siphon_purchases sp JOIN siphon_products p ON sp.product_id = p.id
                 WHERE sp.character_id = ? ORDER BY sp.purchased_at DESC`).all(charId);
        res.json({ success: true, purchases: purchases || [] });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/character/:charId/siphon-purchase', authenticateToken, (req, res) => {
    try {
        const charId = req.params.charId;
        const { productId } = req.body;
        if (!productId) return res.status(400).json({ success: false, message: '缺少商品ID' });

        const row = db.prepare('SELECT data, user_id FROM characters WHERE id = ?').get(charId);
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });
        if (req.user.role < ROLE.SUPER_ADMIN && req.user.userId !== row.user_id) return res.status(403).json({ success: false, message: '无权操作' });

        const perm = db.prepare(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`).get(charId);
        if (!perm) return res.status(403).json({ success: false, message: '未获得X2授权' });

        const product = db.prepare('SELECT * FROM siphon_products WHERE id = ?').get(productId);
        if (!product) return res.status(404).json({ success: false, message: '商品不存在' });

        const data = JSON.parse(row.data);
        if (!data.reprimands) data.reprimands = [];
        const totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
        if (totalReprimands < product.price) return res.status(400).json({ success: false, message: `申诫不足${product.price}点` });

        data.reprimands.push({ id: Date.now().toString(), reason: `Siphon商店购买：${product.name}`, count: -product.price, date: Date.now(), addedByName: req.user.username || '系统' });
        const newTotal = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
        data.watchCount = newTotal;

        const purchaseId = generateId();
        db.prepare('INSERT INTO siphon_purchases (id, character_id, product_id, price, purchased_at) VALUES (?, ?, ?, ?, ?)')
            .run(purchaseId, charId, productId, product.price, Date.now());
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
        res.json({ success: true, message: `已购买「${product.name}」，消耗${product.price}点申诫`, watchCount: newTotal });
    } catch (e) {
        if (e instanceof SyntaxError) {
            res.status(500).json({ success: false, message: '数据解析失败' });
        } else {
            res.status(500).json({ success: false, message: e.message });
        }
    }
});

module.exports = router;
