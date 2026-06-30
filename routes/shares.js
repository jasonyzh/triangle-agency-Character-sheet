const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { db } = require('../db/init');
const { ROLE, BCRYPT_ROUNDS } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { generateShortCode } = require('../utils');

router.post('/api/character/:id/share', authenticateToken, async (req, res) => {
    try {
        const charId = req.params.id;
        const { password, expiresIn } = req.body;

        const char = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);

        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '只有所有者可以分享' });
        }

        db.prepare('DELETE FROM character_shares WHERE character_id = ?').run(charId);

        const shareCode = generateShortCode(8);
        const passwordHash = password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null;
        const expiresAt = expiresIn ? Date.now() + expiresIn * 60 * 60 * 1000 : null;

        db.prepare('INSERT INTO character_shares (character_id, share_code, password_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
            .run(charId, shareCode, passwordHash, Date.now(), expiresAt);
        res.json({
            success: true,
            shareCode: shareCode,
            hasPassword: !!password,
            expiresAt: expiresAt
        });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.post('/api/share/:code', async (req, res) => {
    try {
        const { password } = req.body;

        const share = db.prepare('SELECT * FROM character_shares WHERE share_code = ?').get(req.params.code);

        if (!share) {
            return res.status(404).json({ success: false, message: '分享链接不存在' });
        }

        if (share.expires_at && share.expires_at < Date.now()) {
            return res.status(410).json({ success: false, message: '分享链接已过期' });
        }

        if (share.password_hash) {
            if (!password) {
                return res.json({ success: false, needPassword: true });
            }
            const valid = await bcrypt.compare(password, share.password_hash);
            if (!valid) {
                return res.status(401).json({ success: false, message: '密码错误' });
            }
        }

        const char = db.prepare('SELECT data FROM characters WHERE id = ?').get(share.character_id);

        if (!char) {
            return res.status(404).json({ success: false, message: '角色不存在' });
        }

        res.json({ success: true, data: JSON.parse(char.data) });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.get('/api/share/:code/status', async (req, res) => {
    try {
        const share = db.prepare('SELECT password_hash, expires_at FROM character_shares WHERE share_code = ?').get(req.params.code);

        if (!share) {
            return res.status(404).json({ exists: false });
        }

        if (share.expires_at && share.expires_at < Date.now()) {
            return res.status(410).json({ exists: false, expired: true });
        }

        res.json({
            exists: true,
            needPassword: !!share.password_hash
        });
    } catch (e) {
        res.status(500).json({ exists: false });
    }
});

router.delete('/api/character/:id/share', authenticateToken, (req, res) => {
    try {
        const row = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false });
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false });
        }

        db.prepare('DELETE FROM character_shares WHERE character_id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/character/:id/share', authenticateToken, (req, res) => {
    try {
        const row = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ exists: false });
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ exists: false });
        }

        const share = db.prepare('SELECT share_code, password_hash, created_at, expires_at FROM character_shares WHERE character_id = ?')
            .get(req.params.id);
        if (!share) return res.json({ exists: false });
        res.json({
            exists: true,
            shareCode: share.share_code,
            hasPassword: !!share.password_hash,
            createdAt: share.created_at,
            expiresAt: share.expires_at
        });
    } catch (err) {
        res.status(500).json({ exists: false });
    }
});

module.exports = router;
