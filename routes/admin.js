const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { db } = require('../db/init');
const { ROLE, BCRYPT_ROUNDS } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { getAllConfig, setConfig, createMailTransporter } = require('../utils');

router.get('/api/admin/config', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const config = await getAllConfig();
        if (config.smtp_pass) {
            config.smtp_pass_set = true;
            config.smtp_pass = '********';
        }
        res.json(config);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.put('/api/admin/config', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const updates = req.body;
        for (const [key, value] of Object.entries(updates)) {
            if (key === 'smtp_pass' && value === '********') continue;
            await setConfig(key, value);
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.post('/api/admin/test-smtp', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const transporter = await createMailTransporter();
        await transporter.verify();
        res.json({ success: true, message: 'SMTP连接成功' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'SMTP连接失败: ' + e.message });
    }
});

router.get('/api/users', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.all('SELECT id, username, name, is_admin, role, email, email_verified, created_at FROM users', [], (err, users) => {
        if (err || !users || users.length === 0) return res.json([]);
        let processed = 0;
        const result = [];
        users.forEach(u => {
            db.get('SELECT COUNT(*) as count FROM characters WHERE user_id = ?', [u.id], (err, row) => {
                result.push({
                    id: u.id,
                    username: u.username,
                    hasPassword: true,
                    name: u.name,
                    isAdmin: u.role >= ROLE.SUPER_ADMIN || !!u.is_admin,
                    role: u.role || (u.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER),
                    email: u.email,
                    emailVerified: !!u.email_verified,
                    charCount: row ? row.count : 0
                });
                processed++;
                if (processed === users.length) res.json(result);
            });
        });
    });
});

router.post('/api/users', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const { username, password, name, role } = req.body;
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userRole = role !== undefined ? role : ROLE.PLAYER;

        const userId = Date.now();
        db.run('INSERT INTO users (id, username, password_hash, name, is_admin, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, username, passwordHash, name || '新职员', userRole >= ROLE.SUPER_ADMIN ? 1 : 0, userRole, Date.now()],
            function(err) {
                if (err) res.json({ success: false, message: '账号已存在' });
                else res.json({ success: true });
            });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.delete('/api/users/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.get('SELECT role, is_admin FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (row && (row.role >= ROLE.SUPER_ADMIN || row.is_admin)) {
            return res.json({ success: false, message: '不能删除超级管理员' });
        }
        db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err) {
            res.json({ success: true });
        });
    });
});

router.put('/api/users/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const { password, role } = req.body;

        if (password) {
            const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
            db.run('UPDATE users SET password = NULL, password_hash = ? WHERE id = ?',
                [passwordHash, req.params.id]);
        }

        if (role !== undefined) {
            db.run('UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
                [role, role >= ROLE.SUPER_ADMIN ? 1 : 0, req.params.id]);
        }

        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.put('/api/admin/users/:id/role', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const { role } = req.body;
    if (role === undefined) {
        return res.status(400).json({ success: false, message: '角色不能为空' });
    }

    db.run('UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
        [role, role >= ROLE.SUPER_ADMIN ? 1 : 0, req.params.id],
        function(err) {
            if (err) res.status(500).json({ success: false });
            else res.json({ success: true });
        });
});

module.exports = router;
