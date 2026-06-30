const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/admin/monitor', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const users = db.prepare('SELECT id, name, username, is_admin, role FROM users').all();
        if (!users || users.length === 0) return res.json([]);
        const result = users.map(u => {
            const chars = db.prepare('SELECT id, data FROM characters WHERE user_id = ?').all(u.id);
            const userChars = (chars || []).map(c => {
                let d = {};
                try { d = JSON.parse(c.data); } catch(e) {}
                return { id: c.id, name: d.pName || "未命名", func: d.pFunc || "未知" };
            });
            return {
                userId: u.id,
                userName: u.name,
                userAccount: u.username,
                isAdmin: u.role >= ROLE.SUPER_ADMIN || !!u.is_admin,
                role: u.role || (u.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER),
                characters: userChars
            };
        });
        res.json(result);
    } catch (err) {
        res.status(500).json([]);
    }
});

module.exports = router;
