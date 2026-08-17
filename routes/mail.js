const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.get('/api/character/:charId/send-targets', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    try {
        const char = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        if (!char) return res.status(404).json({ error: '角色不存在' });

        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权访问' });
        }

        const managers = db.prepare(`
            SELECT DISTINCT u.id, u.name, u.username
            FROM character_authorizations ca
            JOIN users u ON ca.manager_id = u.id
            WHERE ca.character_id = ?
        `).all(charId);

        const managerList = (managers || []).map(m => ({
            id: m.id,
            name: m.name || m.username,
            type: 'manager'
        }));

        const teammates = db.prepare(`
            SELECT c.id, c.data
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            JOIN field_mission_members fmm2 ON fmm.mission_id = fmm2.mission_id
            JOIN characters c ON fmm2.character_id = c.id
            WHERE fmm.character_id = ? AND fm.status = 'active' AND fmm2.character_id != ?
        `).all(charId, charId);

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
    } catch (err) {
        return res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/character/:charId/send-mail', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const { recipientType, recipientId, subject, content } = req.body;

    try {
        const char = db.prepare('SELECT user_id, data FROM characters WHERE id = ?').get(charId);

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
            const manager = db.prepare('SELECT name, username FROM users WHERE id = ?').get(recipientId);
            recipientName = manager ? (manager.name || manager.username) : '经理';
        } else if (recipientType === 'character') {
            const recipient = db.prepare('SELECT data FROM characters WHERE id = ?').get(recipientId);
            if (recipient) {
                try {
                    const rData = JSON.parse(recipient.data);
                    recipientName = rData.pName || '未命名角色';
                } catch(e) {}
            }
        }

        if (recipientType === 'manager') {
            const activeMission = db.prepare(`
                SELECT fm.id as mission_id, fm.created_by as manager_id
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                WHERE fmm.character_id = ? AND fm.status = 'active'
            `).get(charId);

            if (activeMission) {
                const doInsert = db.transaction(() => {
                    const inboxResult = db.prepare('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(activeMission.mission_id, charId, senderName, subject, content, 'mail', now);
                    db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)').run(charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now);
                    return inboxResult.lastInsertRowid;
                });
                const messageId = doInsert();
                res.json({ success: true, messageId, sentToMission: true });
            } else {
                const doInsert = db.transaction(() => {
                    const inboxResult = db.prepare('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(recipientId, charId, senderName, subject, content, 'mail', now);
                    db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)').run(charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now);
                    return inboxResult.lastInsertRowid;
                });
                const messageId = doInsert();
                res.json({ success: true, messageId, sentToMission: false });
            }
        } else if (recipientType === 'character') {
            const doInsert = db.transaction(() => {
                const recvResult = db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(recipientId, req.user.userId, senderName, subject, content, 'mail', charId, recipientName, now);
                db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)').run(charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now);
                return recvResult.lastInsertRowid;
            });
            const messageId = doInsert();
            res.json({ success: true, messageId });
        } else {
            return res.status(400).json({ success: false, message: '无效的收件人类型' });
        }
    } catch (err) {
        return res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/character/:charId/send-containment', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const { missionId, name: containmentName, description } = req.body;

    if (!missionId) {
        return res.status(400).json({ success: false, message: '请选择要寄送收容物的任务' });
    }

    try {
        const char = db.prepare('SELECT user_id, data FROM characters WHERE id = ?').get(charId);

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

        const activeMission = db.prepare(`
            SELECT fm.id as mission_id, fm.created_by as manager_id
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.id = ? AND fm.status = 'active'
        `).get(charId, missionId);

        if (!activeMission) {
            return res.status(404).json({ success: false, message: '任务不存在或您不在该任务成员中' });
        }

        const existingContainment = db.prepare(`SELECT id FROM mission_inbox 
                WHERE mission_id = ? AND sender_character_id = ? AND message_type = 'containment'`).get(missionId, charId);

        if (existingContainment) {
            return res.status(409).json({ success: false, message: '您已为该任务寄送过收容物' });
        }

        const result = db.prepare('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(missionId, charId, senderName, subject, content, 'containment', now);
        res.json({ success: true, messageId: result.lastInsertRowid, sentToMission: true });
    } catch (error) {
        console.error('寄送收容物失败:', error);
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.get('/api/character/:charId/available-missions-containment', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    
    try {
        const char = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问' });
        }
        
        const missions = db.prepare(`
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
        `).all(charId, charId);
        
        const formattedMissions = (missions || []).map(m => ({
            id: m.id,
            name: m.name,
            description: m.description,
            hasSentContainment: m.containment_count > 0
        }));
        
        res.json(formattedMissions);
    } catch (error) {
        console.error('获取可用任务列表失败:', error);
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.get('/api/character/:charId/available-missions', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    
    try {
        const char = db.prepare('SELECT user_id FROM characters WHERE id = ?').get(charId);
        
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问' });
        }
        
        const missions = db.prepare(`
            SELECT 
                fm.id,
                fm.name,
                fm.description,
                (SELECT COUNT(*) FROM mission_reports mr WHERE mr.mission_id = fm.id AND mr.submitted_by = ?) as report_count
            FROM field_missions fm
            JOIN field_mission_members fmm ON fm.id = fmm.mission_id
            WHERE fmm.character_id = ? AND fm.status = 'active'
            ORDER BY fm.created_at DESC
        `).all(charId, charId);
        
        const formattedMissions = (missions || []).map(m => ({
            id: m.id,
            name: m.name,
            description: m.description,
            hasSubmitted: m.report_count > 0
        }));
        
        res.json(formattedMissions);
    } catch (error) {
        console.error('获取可用任务列表失败:', error);
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/character/:charId/send-report', authenticateToken, (req, res) => {
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
        const char = db.prepare('SELECT user_id, data FROM characters WHERE id = ?').get(charId);

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

        const activeMission = db.prepare(`
            SELECT fm.id as mission_id, fm.created_by as manager_id
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.id = ? AND fm.status = 'active'
        `).get(charId, missionId);

        if (!activeMission) {
            return res.status(404).json({ success: false, message: '任务不存在或您不在该任务成员中' });
        }

        const existingReport = db.prepare('SELECT id FROM mission_reports WHERE mission_id = ? AND submitted_by = ?').get(missionId, charId);

        if (existingReport) {
            return res.status(409).json({ success: false, message: '您已为该任务提交过报告' });
        }

        if (activeMission) {
            const doInsert = db.transaction(() => {
                const reportResult = db.prepare(`INSERT INTO mission_reports (mission_id, submitted_by, original_data, status, submitted_at)
                        VALUES (?, ?, ?, 'submitted', ?)`).run(activeMission.mission_id, charId, JSON.stringify(reportData), now);
                const reportId = reportResult.lastInsertRowid;

                const inboxResult = db.prepare(`INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, report_id, created_at)
                        VALUES (?, ?, ?, ?, ?, 'report', ?, ?)`).run(activeMission.mission_id, charId, senderName, subject, content, reportId, now);
                const messageId = inboxResult.lastInsertRowid;

                db.prepare('UPDATE field_missions SET report_status = ? WHERE id = ?').run('submitted', activeMission.mission_id);

                return { reportId, messageId };
            });
            const result = doInsert();
            res.json({ success: true, reportId: result.reportId, messageId: result.messageId, sentToMission: true });
        } else {
            let finalRecipientId = recipientId;
            if (!finalRecipientId) {
                const authManager = db.prepare('SELECT manager_id FROM character_authorizations WHERE character_id = ? ORDER BY created_at DESC LIMIT 1').get(charId);
                if (authManager) {
                    finalRecipientId = authManager.manager_id;
                } else {
                    return res.status(400).json({ success: false, message: '未找到关联的任务或接收者' });
                }
            }

            const inboxResult = db.prepare('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(finalRecipientId, charId, senderName, subject, content, 'report', JSON.stringify(reportData), now);
            res.json({ success: true, messageId: inboxResult.lastInsertRowid, sentToMission: false });
        }
    } catch (error) {
        console.error('发送报告失败:', error);
        res.status(500).json({ success: false, message: '数据库错误' });
    }
});

router.post('/api/manager/send-mail', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { characterIds, subject, content } = req.body;
    if (!characterIds || !characterIds.length) return res.status(400).json({ success: false, message: '缺少收件人' });
    if (!subject || !content) return res.status(400).json({ success: false, message: '标题和内容不能为空' });
    const now = Date.now();
    var senderName = req.user.name || req.user.username || '经理';
    var sentCount = 0, recipientIds = [];

    try {
        const getCharStmt = db.prepare('SELECT user_id, data FROM characters WHERE id = ?');
        const insertMsgStmt = db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');

        for (var i = 0; i < characterIds.length; i++) {
            var charId = characterIds[i];
            var row = getCharStmt.get(charId);
            if (!row) continue;
            var charName = '未命名';
            try { charName = JSON.parse(row.data).pName || '未命名'; } catch(e) {}
            insertMsgStmt.run(charId, req.user.userId, senderName, subject, content, 'mail', now);
            sentCount++;
            recipientIds.push(row.user_id);
        }
        res.json({ success: true, sentCount, recipientIds });
    } catch (err) {
        return res.status(500).json({ success: false, message: '数据库错误' });
    }
});

module.exports = router;
