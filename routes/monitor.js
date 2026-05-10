const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/admin/monitor', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.all('SELECT id, name, username, is_admin, role FROM users', [], (err, users) => {
        if (err || !users || users.length === 0) return res.json([]);
        let completed = 0;
        const result = [];
        users.forEach(u => {
            db.all('SELECT id, data FROM characters WHERE user_id = ?', [u.id], (err, chars) => {
                const userChars = (chars || []).map(c => {
                    let d = {};
                    try { d = JSON.parse(c.data); } catch(e) {}
                    return { id: c.id, name: d.pName || "未命名", func: d.pFunc || "未知" };
                });
                result.push({
                    userId: u.id,
                    userName: u.name,
                    userAccount: u.username,
                    isAdmin: u.role >= ROLE.SUPER_ADMIN || !!u.is_admin,
                    role: u.role || (u.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER),
                    characters: userChars
                });
                completed++;
                if (completed === users.length) res.json(result);
            });
        });
    });
});

module.exports = router;
