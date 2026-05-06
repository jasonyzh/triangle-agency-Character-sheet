const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken } = require('../middleware/auth');

router.get('/api/character/:charId/send-targets', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ error: '角色不存在' });

        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权访问' });
        }

        db.all(`
            SELECT DISTINCT u.id, u.name, u.username
            FROM character_authorizations ca
            JOIN users u ON ca.manager_id = u.id
            WHERE ca.character_id = ?
        `, [charId], (err, managers) => {
            const managerList = (managers || []).map(m => ({
                id: m.id,
                name: m.name || m.username,
                type: 'manager'
            }));

            db.all(`
                SELECT c.id, c.data
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                JOIN field_mission_members fmm2 ON fmm.mission_id = fmm2.mission_id
                JOIN characters c ON fmm2.character_id = c.id
                WHERE fmm.character_id = ? AND fm.status = 'active' AND fmm2.character_id != ?
            `, [charId, charId], (err, teammates) => {
                const teammateList = (teammates || []).map(t => {
                    let d = {};
                    try { d = JSON.parse(t.data); } catch(e) {}
                    return {
                        id: t.id,
                        name: d.pName || '未命名',
                        type: 'character'
                    };
                });

                res.json({
                    managers: managerList,
                    teammates: teammateList
                });
            });
        });
    });
});

router.post('/api/character/:charId/send-mail', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    const { recipientType, recipientId, subject, content } = req.body;

    const char = await new Promise((resolve) => {
        db.get('SELECT user_id, data FROM characters WHERE id = ?', [charId], (err, row) => resolve(row));
    });

    if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
    if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
        return res.status(403).json({ success: false, message: '无权操作' });
    }

    if (!subject || !content) {
        return res.status(400).json({ success: false, message: '标题和内容不能为空' });
    }

    let charData = {};
    try { charData = JSON.parse(char.data); } catch(e) {}
    const senderName = charData.pName || '未命名角色';

    const now = Date.now();

    let recipientName = '未知';
    if (recipientType === 'manager') {
        const manager = await new Promise(resolve => {
            db.get('SELECT name, username FROM users WHERE id = ?', [recipientId], (err, row) => resolve(row));
        });
        recipientName = manager ? (manager.name || manager.username) : '经理';
    } else if (recipientType === 'character') {
        const recipient = await new Promise(resolve => {
            db.get('SELECT data FROM characters WHERE id = ?', [recipientId], (err, row) => resolve(row));
        });
        if (recipient) {
            try {
                const rData = JSON.parse(recipient.data);
                recipientName = rData.pName || '未命名角色';
            } catch(e) {}
        }
    }

    if (recipientType === 'manager') {
        const activeMission = await new Promise((resolve) => {
            db.get(`
                SELECT fm.id as mission_id, fm.created_by as manager_id
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                WHERE fmm.character_id = ? AND fm.status = 'active'
            `, [charId], (err, row) => resolve(row));
        });

        if (activeMission) {
            db.run('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [activeMission.mission_id, charId, senderName, subject, content, 'mail', now],
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: err.message });
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                        [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                    res.json({ success: true, messageId: this.lastID, sentToMission: true });
                });
        } else {
            db.run('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [recipientId, charId, senderName, subject, content, 'mail', now],
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: err.message });
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                        [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                    res.json({ success: true, messageId: this.lastID, sentToMission: false });
                });
        }
    } else if (recipientType === 'character') {
        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [recipientId, req.user.userId, senderName, subject, content, 'mail', charId, recipientName, now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                    [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                res.json({ success: true, messageId: this.lastID });
            });
    } else {
        return res.status(400).json({ success: false, message: '无效的收件人类型' });
    }
});

router.post('/api/character/:charId/send-containment', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    const { missionId, name: containmentName, description } = req.body;

    if (!missionId) {
        return res.status(400).json({ success: false, message: '请选择要寄送收容物的任务' });
    }

    const char = await new Promise((resolve) => {
        db.get('SELECT user_id, data FROM characters WHERE id = ?', [charId], (err, row) => resolve(row));
    });

    if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
    if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
        return res.status(403).json({ success: false, message: '无权操作' });
    }

    if (!containmentName) {
        return res.status(400).json({ success: false, message: '收容物名称不能为空' });
    }

    let charData = {};
    try { charData = JSON.parse(char.data); } catch(e) {}
    const senderName = charData.pName || '未命名角色';

    const subject = `[收容物] ${containmentName}`;
    const content = `收容物名称: ${containmentName}\n\n描述:\n${description || '无'}`;
    const now = Date.now();

    try {
        const activeMission = await new Promise((resolve, reject) => {
            db.get(`
                SELECT fm.id as mission_id, fm.created_by as manager_id
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                WHERE fmm.character_id = ? AND fm.id = ? AND fm.status = 'active'
            `, [charId, missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!activeMission) {
            return res.status(404).json({ success: false, message: '任务不存在或您不在该任务成员中' });
        }

        const existingContainment = await new Promise((resolve, reject) => {
            db.get(`SELECT id FROM mission_inbox 
                    WHERE mission_id = ? AND sender_character_id = ? AND message_type = 'containment'`, 
                [missionId, charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingContainment) {
            return res.status(409).json({ success: false, message: '您已为该任务寄送过收容物' });
        }

        db.run('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [missionId, charId, senderName, subject, content, 'containment', now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, messageId: this.lastID, sentToMission: true });
            });
    } catch (error) {
        console.error('寄送收容物失败:', error);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

router.get('/api/character/:charId/available-missions-containment', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    
    try {
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问' });
        }
        
        const missions = await new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    fm.id,
                    fm.name,
                    fm.description,
                    (SELECT COUNT(*) FROM mission_inbox mi 
                     WHERE mi.mission_id = fm.id 
                     AND mi.sender_character_id = ? 
                     AND mi.message_type = 'containment') as containment_count
                FROM field_missions fm
                JOIN field_mission_members fmm ON fm.id = fmm.mission_id
                WHERE fmm.character_id = ? AND fm.status = 'active'
                ORDER BY fm.created_at DESC
            `, [charId, charId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
        
        const formattedMissions = missions.map(m => ({
            id: m.id,
            name: m.name,
            description: m.description,
            hasSentContainment: m.containment_count > 0
        }));
        
        res.json(formattedMissions);
    } catch (error) {
        console.error('获取可用任务列表失败:', error);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

router.get('/api/character/:charId/available-missions', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    
    try {
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问' });
        }
        
        const missions = await new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    fm.id,
                    fm.name,
                    fm.description,
                    (SELECT COUNT(*) FROM mission_reports mr WHERE mr.mission_id = fm.id AND mr.submitted_by = ?) as report_count
                FROM field_missions fm
                JOIN field_mission_members fmm ON fm.id = fmm.mission_id
                WHERE fmm.character_id = ? AND fm.status = 'active'
                ORDER BY fm.created_at DESC
            `, [charId, charId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
        
        const formattedMissions = missions.map(m => ({
            id: m.id,
            name: m.name,
            description: m.description,
            hasSubmitted: m.report_count > 0
        }));
        
        res.json(formattedMissions);
    } catch (error) {
        console.error('获取可用任务列表失败:', error);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

router.post('/api/character/:charId/send-report', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    let { recipientId, reportData } = req.body;

    if (!reportData && (req.body.status || req.body.analysis)) {
        reportData = req.body;
    }

    if (!reportData) {
        return res.status(400).json({ success: false, message: '报告数据不能为空' });
    }

    const missionId = reportData.missionId;
    if (!missionId) {
        return res.status(400).json({ success: false, message: '请选择要提交报告的任务' });
    }

    try {
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT user_id, data FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        let charData = {};
        try { charData = JSON.parse(char.data); } catch(e) {}
        const senderName = charData.pName || '未命名角色';

        const subject = `[任务报告] 来自 ${senderName}`;
        const content = `任务报告已提交，详情请查看报告数据`;
        const now = Date.now();

        const activeMission = await new Promise((resolve, reject) => {
            db.get(`
                SELECT fm.id as mission_id, fm.created_by as manager_id
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                WHERE fmm.character_id = ? AND fm.id = ? AND fm.status = 'active'
            `, [charId, missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!activeMission) {
            return res.status(404).json({ success: false, message: '任务不存在或您不在该任务成员中' });
        }

        const existingReport = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM mission_reports WHERE mission_id = ? AND submitted_by = ?', 
                [missionId, charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingReport) {
            return res.status(409).json({ success: false, message: '您已为该任务提交过报告' });
        }

        if (activeMission) {
            const result = await new Promise((resolve, reject) => {
                db.run(`INSERT INTO mission_reports (mission_id, submitted_by, original_data, status, submitted_at)
                        VALUES (?, ?, ?, 'submitted', ?)`,
                    [activeMission.mission_id, charId, JSON.stringify(reportData), now],
                    function(err) {
                        if (err) return reject(err);
                        const reportId = this.lastID;

                        db.run(`INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, report_id, created_at)
                                VALUES (?, ?, ?, ?, ?, 'report', ?, ?)`,
                            [activeMission.mission_id, charId, senderName, subject, content, reportId, now],
                            function(err) {
                                if (err) return reject(err);
                                const messageId = this.lastID;

                                db.run('UPDATE field_missions SET report_status = ? WHERE id = ?', ['submitted', activeMission.mission_id], (err) => {
                                    if (err) console.error('更新任务状态失败:', err);
                                    resolve({ reportId, messageId });
                                });
                            });
                    });
            });
            res.json({ success: true, reportId: result.reportId, messageId: result.messageId, sentToMission: true });
        } else {
            let finalRecipientId = recipientId;
            if (!finalRecipientId) {
                const authManager = await new Promise((resolve) => {
                    db.get('SELECT manager_id FROM character_authorizations WHERE character_id = ? ORDER BY created_at DESC LIMIT 1', [charId], (err, row) => resolve(row));
                });
                if (authManager) {
                    finalRecipientId = authManager.manager_id;
                } else {
                    return res.status(400).json({ success: false, message: '未找到关联的任务或接收者' });
                }
            }

            db.run('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [finalRecipientId, charId, senderName, subject, content, 'report', JSON.stringify(reportData), now],
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: '发送至经理收件箱失败: ' + err.message });
                    res.json({ success: true, messageId: this.lastID, sentToMission: false });
                });
        }
    } catch (error) {
        console.error('发送报告失败:', error);
        res.status(500).json({ success: false, message: '服务器内部错误: ' + error.message });
    }
});

module.exports = router;
