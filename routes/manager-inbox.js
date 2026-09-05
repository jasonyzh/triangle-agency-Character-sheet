const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/manager/inbox', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const messages = db.prepare('SELECT * FROM manager_inbox WHERE manager_id = ? ORDER BY created_at DESC').all(req.user.userId);
        res.json(messages || []);
    } catch (err) {
        res.status(500).json([]);
    }
});

router.get('/api/manager/inbox/unread-count', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const row = db.prepare('SELECT COUNT(*) as count FROM manager_inbox WHERE manager_id = ? AND read = 0').get(req.user.userId);
        res.json({ count: row ? row.count : 0 });
    } catch (err) {
        res.json({ count: 0 });
    }
});

router.get('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const msg = db.prepare('SELECT * FROM manager_inbox WHERE id = ? AND manager_id = ?').get(req.params.msgId, req.user.userId);
        if (!msg) return res.status(404).json({ error: '邮件不存在' });

        if (msg.report_data) {
            try {
                msg.reportData = JSON.parse(msg.report_data);
            } catch(e) {}
        }

        res.json(msg);
    } catch (err) {
        res.status(500).json({ error: '加载失败' });
    }
});

router.put('/api/manager/inbox/:msgId/read', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        db.prepare('UPDATE manager_inbox SET read = 1 WHERE id = ? AND manager_id = ?').run(req.params.msgId, req.user.userId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        db.prepare('DELETE FROM manager_inbox WHERE id = ? AND manager_id = ?').run(req.params.msgId, req.user.userId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

module.exports = router;
