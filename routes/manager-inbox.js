const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/manager/inbox', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.all('SELECT * FROM manager_inbox WHERE manager_id = ? ORDER BY created_at DESC',
        [req.user.userId], (err, messages) => {
            if (err) return res.status(500).json([]);
            res.json(messages || []);
        });
});

router.get('/api/manager/inbox/unread-count', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get('SELECT COUNT(*) as count FROM manager_inbox WHERE manager_id = ? AND read = 0',
        [req.user.userId], (err, row) => {
            if (err) return res.json({ count: 0 });
            res.json({ count: row ? row.count : 0 });
        });
});

router.get('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get('SELECT * FROM manager_inbox WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], (err, msg) => {
            if (!msg) return res.status(404).json({ error: '邮件不存在' });

            if (msg.report_data) {
                try {
                    msg.reportData = JSON.parse(msg.report_data);
                } catch(e) {}
            }

            res.json(msg);
        });
});

router.put('/api/manager/inbox/:msgId/read', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('UPDATE manager_inbox SET read = 1 WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

router.delete('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('DELETE FROM manager_inbox WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

module.exports = router;
