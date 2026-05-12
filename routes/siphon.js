const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

// Manager: list branch products
router.get('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const branchId = req.query.branchId;
    if (!branchId) return res.json({ success: true, products: [] });
    db.all('SELECT * FROM siphon_products WHERE branch_id = ? ORDER BY created_at DESC', [branchId], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: '加载失败' });
        res.json({ success: true, products: rows || [] });
    });
});

// Manager: create product
router.post('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const managerId = req.user.userId;
    const { name, description, price, branchId } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ success: false, message: '请输入商品名称' });
    if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

    const id = generateId();
    db.run('INSERT INTO siphon_products (id, manager_id, name, description, price, created_at, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [id, managerId, name.trim(), description || '', parseInt(price) || 0, Date.now(), branchId],
        (err) => {
            if (err) return res.status(500).json({ success: false, message: '创建失败' });
            res.json({ success: true, message: '商品已创建' });
        });
});

// Manager: update product
router.put('/api/manager/siphon-products', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const managerId = req.user.userId;
    const { id, name, description, price } = req.body;
    if (!id) return res.status(400).json({ success: false, message: '缺少商品ID' });
    if (!name || !name.trim()) return res.status(400).json({ success: false, message: '请输入商品名称' });

    db.run('UPDATE siphon_products SET name = ?, description = ?, price = ? WHERE id = ? AND manager_id = ?',
        [name.trim(), description || '', parseInt(price) || 0, id, managerId],
        function (err) {
            if (err) return res.status(500).json({ success: false, message: '更新失败' });
            if (this.changes === 0 && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '商品不存在' });
            res.json({ success: true, message: '商品已更新' });
        });
});

// Manager: delete product
router.delete('/api/manager/siphon-products/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const managerId = req.user.userId;
    db.run('DELETE FROM siphon_products WHERE id = ? AND manager_id = ?', [req.params.id, managerId], function (err) {
        if (err) return res.status(500).json({ success: false, message: '删除失败' });
        if (this.changes === 0 && req.user.role < ROLE.SUPER_ADMIN) return res.status(404).json({ success: false, message: '商品不存在' });
        res.json({ success: true, message: '商品已删除' });
    });
});

// Player: check X2 permission
router.get('/api/character/:id/check-x2', authenticateToken, (req, res) => {
    const charId = req.params.id;
    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ unlocked: false });
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ unlocked: false });
        db.get(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`,
            [charId], (err, perm) => { res.json({ unlocked: !!perm }); });
    });
});

// Player: list available siphon products (filtered by character's branch)
router.get('/api/character/:charId/siphon-products', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    db.get(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`,
        [charId], (err, perm) => {
            if (!perm && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ success: false, message: '未获得X2授权' });

            db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
                const branchId = charRow ? charRow.branch_id : null;
                const query = branchId
                    ? 'SELECT * FROM siphon_products WHERE branch_id = ? ORDER BY created_at DESC'
                    : 'SELECT * FROM siphon_products ORDER BY created_at DESC';
                const params = branchId ? [branchId] : [];

                db.all(query, params, (err, products) => {
                    if (err) return res.status(500).json({ success: false, message: '加载失败' });
                    res.json({ success: true, products: products || [] });
                });
            });
        });
});

// Player: list purchased siphon products
router.get('/api/character/:charId/siphon-purchased', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false });
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) return res.status(403).json({ success: false });
        db.all(`SELECT sp.id, sp.purchased_at, sp.price, p.name, p.description
                 FROM siphon_purchases sp JOIN siphon_products p ON sp.product_id = p.id
                 WHERE sp.character_id = ? ORDER BY sp.purchased_at DESC`,
            [charId], (err, purchases) => {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true, purchases: purchases || [] });
            });
    });
});

// Player: purchase siphon product
router.post('/api/character/:charId/siphon-purchase', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const { productId } = req.body;
    if (!productId) return res.status(400).json({ success: false, message: '缺少商品ID' });

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });
        if (req.user.role < ROLE.SUPER_ADMIN && req.user.userId !== row.user_id) return res.status(403).json({ success: false, message: '无权操作' });

        db.get(`SELECT 1 FROM character_document_permissions WHERE character_id = ? AND LOWER(filename) = 'x2.md'`,
            [charId], (err, perm) => {
                if (!perm) return res.status(403).json({ success: false, message: '未获得X2授权' });

                db.get('SELECT * FROM siphon_products WHERE id = ?', [productId], (err, product) => {
                    if (!product) return res.status(404).json({ success: false, message: '商品不存在' });

                    try {
                        const data = JSON.parse(row.data);
                        if (!data.reprimands) data.reprimands = [];
                        const totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                        if (totalReprimands < product.price) return res.status(400).json({ success: false, message: `申诫不足${product.price}点` });

                        data.reprimands.push({ id: Date.now().toString(), reason: `Siphon商店购买：${product.name}`, count: -product.price, date: Date.now(), addedByName: req.user.username || '系统' });
                        const newTotal = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                        data.watchCount = newTotal;

                        const purchaseId = generateId();
                        db.run('INSERT INTO siphon_purchases (id, character_id, product_id, price, purchased_at) VALUES (?, ?, ?, ?, ?)',
                            [purchaseId, charId, productId, product.price, Date.now()],
                            (err) => {
                                if (err) return res.status(500).json({ success: false, message: '购买记录保存失败' });
                                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], (err) => {
                                    if (err) return res.status(500).json({ success: false, message: '保存失败' });
                                    res.json({ success: true, message: `已购买「${product.name}」，消耗${product.price}点申诫`, watchCount: newTotal });
                                });
                            });
                    } catch (e) { res.status(500).json({ success: false, message: '数据解析失败' }); }
                });
            });
    });
});

module.exports = router;
