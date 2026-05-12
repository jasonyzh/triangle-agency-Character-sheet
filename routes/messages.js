const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { checkManagerCharacterAuth } = require('../utils');

router.get('/api/character/:id/highwall-files', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);

        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);

            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) {
                    resolve(false);
                    return;
                }
                db.get('SELECT 1 FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [charId, req.user.userId], (err, auth) => resolve(!!auth));
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) return res.status(403).json([]);

            db.all('SELECT filename, granted_at FROM character_document_permissions WHERE character_id = ?',
                [charId], (err, rows) => {
                    if (err) return res.json([]);

                    const files = (rows || []).map(r => ({
                        filename: r.filename,
                        title: r.filename.replace(/\.md$/i, ''),
                        grantedAt: r.granted_at
                    }));

                    res.json(files);
                });
        });
    });
});

router.get('/api/character/:id/check-a1', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ unlocked: false });

        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ unlocked: false });
        }

        db.get(`SELECT 1 FROM character_document_permissions
                WHERE character_id = ? AND LOWER(filename) = 'a1.md'`,
            [charId], (err, perm) => {
                res.json({ unlocked: !!perm });
            });
    });
});

router.get('/api/character/:id/messages', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);

        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json([]);
        }

        db.all(`SELECT * FROM character_messages WHERE character_id = ? AND (message_type IS NULL OR message_type != 'sent') ORDER BY created_at DESC`,
            [charId], (err, rows) => {
                if (err) return res.json([]);
                const messages = (rows || []).map(r => ({
                    id: r.id,
                    characterId: r.character_id,
                    senderId: r.sender_id,
                    senderName: r.sender_name || '未知发件人',
                    subject: r.subject,
                    content: r.content,
                    messageType: r.message_type,
                    hwFilename: r.hw_filename,
                    read: r.read,
                    createdAt: r.created_at
                }));
                res.json(messages);
            });
    });
});

router.get('/api/character/:id/sent-messages', authenticateToken, async (req, res) => {
    const charId = req.params.id;

    try {
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) return res.status(404).json([]);
        if (req.user.userId !== char.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json([]);
        }

        const containments = await new Promise((resolve, reject) => {
            db.all(`
                SELECT mi.*, fm.name as mission_name
                FROM mission_inbox mi
                JOIN field_missions fm ON mi.mission_id = fm.id
                WHERE mi.sender_character_id = ? AND mi.message_type = 'containment'
                ORDER BY mi.created_at DESC
            `, [charId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        const reports = await new Promise((resolve, reject) => {
            db.all(`
                SELECT mr.*, fm.name as mission_name
                FROM mission_reports mr
                JOIN field_missions fm ON mr.mission_id = fm.id
                WHERE mr.submitted_by = ?
                ORDER BY mr.submitted_at DESC
            `, [charId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        const allMessages = [];

        containments.forEach(c => {
            allMessages.push({
                id: `containment_${c.id}`,
                type: 'containment',
                missionName: c.mission_name,
                subject: c.subject,
                content: c.content,
                createdAt: c.created_at
            });
        });

        reports.forEach(r => {
            let reportData = null;
            try {
                reportData = r.original_data ? JSON.parse(r.original_data) : null;
            } catch(e) {}
            
            allMessages.push({
                id: `report_${r.id}`,
                type: 'report',
                missionName: r.mission_name,
                subject: '任务报告',
                reportData: reportData,
                rating: r.rating,
                scatterValue: r.scatter_value,
                annotations: r.annotations ? JSON.parse(r.annotations) : [],
                status: r.status,
                createdAt: r.submitted_at
            });
        });

        allMessages.sort((a, b) => b.createdAt - a.createdAt);

        res.json(allMessages);
    } catch (error) {
        console.error('获取已发邮件失败:', error);
        res.status(500).json([]);
    }
});

router.post('/api/manager/character/:charId/message', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { subject, content } = req.body;

        if (!subject || !content) {
            return res.status(400).json({ success: false, message: '标题和内容不能为空' });
        }

        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权向该角色卡发送消息' });
        }

        const sender = await new Promise((resolve) => {
            db.get('SELECT name, username FROM users WHERE id = ?', [managerId], (err, row) => {
                resolve(row ? (row.name || row.username) : '未知');
            });
        });

        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [charId, managerId, sender, subject, content, Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, messageId: this.lastID });
            });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

router.put('/api/character/:charId/message/:msgId/read', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const msgId = req.params.msgId;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false });

        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false });
        }

        db.run('UPDATE character_messages SET read = 1 WHERE id = ? AND character_id = ?',
            [msgId, charId], function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
    });
});

router.delete('/api/character/:id/message/:msgId', authenticateToken, (req, res) => {
    const charId = req.params.id;
    const msgId = req.params.msgId;
    db.get('SELECT * FROM character_messages WHERE id = ? AND character_id = ?', [msgId, charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '消息不存在' });
        db.run('DELETE FROM character_messages WHERE id = ? AND character_id = ?', [msgId, charId], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true });
        });
    });
});

router.post('/api/character/:id/u2-unleash', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.get(`SELECT 1 FROM character_document_permissions
                WHERE character_id = ? AND LOWER(filename) = 'u2.md'`,
            [charId], (err, perm) => {
                if (!perm) return res.status(403).json({ success: false, message: '未获得U2授权' });

                try {
                    const data = JSON.parse(row.data);
                    if (!data.reprimands) data.reprimands = [];

                    const totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                    if (totalReprimands < 3) {
                        return res.status(400).json({ success: false, message: '申诫不足3点' });
                    }

                    data.reprimands.push({
                        id: Date.now().toString(),
                        reason: '消耗3点申诫（修改骰子）',
                        count: -3,
                        date: Date.now(),
                        addedByName: req.user.username || '系统'
                    });

                    const newTotal = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                    data.watchCount = newTotal;

                    db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                        if (err) return res.status(500).json({ success: false, message: '保存失败' });
                        res.json({ success: true, message: '已消耗3点申诫', watchCount: newTotal });
                    });
                } catch (e) {
                    res.status(500).json({ success: false, message: '数据解析失败' });
                }
            });
    });
});

module.exports = router;
