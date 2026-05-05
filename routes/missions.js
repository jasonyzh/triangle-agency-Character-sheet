const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.post('/api/manager/mission', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name, description, missionType, characterIds, branchId } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ success: false, message: '任务名称不能为空' });
    }

    const validType = ['containment', 'sweep'].includes(missionType) ? missionType : 'containment';

    const missionId = Date.now().toString();
    const now = Date.now();

    db.run(`INSERT INTO field_missions
        (id, name, description, mission_type, status, created_by, created_at, updated_at, report_status, branch_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [missionId, name.trim(), description || '', validType, 'active', req.user.userId, now, now, 'none', branchId || null],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });

            if (characterIds && characterIds.length > 0) {
                const stmt = db.prepare('INSERT OR IGNORE INTO field_mission_members (mission_id, character_id, member_status, joined_at) VALUES (?, ?, ?, ?)');
                characterIds.forEach(charId => {
                    stmt.run(missionId, charId, '待命', now);
                });
                stmt.finalize();
            }

            res.json({ success: true, missionId });
        });
});

router.get('/api/manager/missions', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const managerId = req.user.userId;
    const statusFilter = req.query.status;
    const branchId = req.query.branchId;

    let sql = 'SELECT * FROM field_missions';
    let params = [];
    const conditions = [];

    if (branchId) {
        conditions.push('branch_id = ?');
        params.push(branchId);
    } else if (req.user.role < ROLE.SUPER_ADMIN) {
        conditions.push('created_by = ?');
        params.push(managerId);
    }
    
    if (statusFilter === 'active' || statusFilter === 'archived') {
        conditions.push('status = ?');
        params.push(statusFilter);
    }
    
    if (conditions.length > 0) {
        sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ' ORDER BY created_at DESC';

    db.all(sql, params, (err, missions) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }

        if (!missions || missions.length === 0) {
            return res.json([]);
        }

        let completed = 0;
        const result = [];
        missions.forEach(mission => {
            db.all(`
                SELECT fmm.character_id, c.data, c.user_id, fmm.member_status, fmm.joined_at
                FROM field_mission_members fmm
                JOIN characters c ON fmm.character_id = c.id
                WHERE fmm.mission_id = ?
            `, [mission.id], (err, members) => {
                const memberList = (members || []).map(m => {
                    let d = {};
                    try { d = JSON.parse(m.data); } catch(e) {}
                    return {
                        character_id: m.character_id,
                        user_id: m.user_id,
                        name: d.pName || '未命名',
                        member_status: m.member_status,
                        joined_at: m.joined_at
                    };
                });
                
                const missionData = {
                    ...mission,
                    members: memberList,
                    mission_type: mission.mission_type || 'containment'
                };

                result.push(missionData);
                completed++;
                if (completed === missions.length) {
                    result.sort((a, b) => b.created_at - a.created_at);
                    res.json(result);
                }
            });
        });
    });
});

router.put('/api/manager/mission/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { name, description, status, missionType, chaosValue, scatterValue } = req.body;

    db.get('SELECT * FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (req.user.role >= ROLE.SUPER_ADMIN) {
            doUpdate();
        } else {
            db.get('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?',
                [req.user.userId, mission.branch_id], (err, row) => {
                    if (!row) return res.status(403).json({ success: false, message: '无权修改此任务' });
                    doUpdate();
                });
        }

        function doUpdate() {
            const updates = [];
            const params = [];

            if (name !== undefined) {
                updates.push('name = ?');
                params.push(name.trim());
            }
            if (description !== undefined) {
                updates.push('description = ?');
                params.push(description);
            }
            if (status !== undefined && ['active', 'archived'].includes(status)) {
                updates.push('status = ?');
                params.push(status);
            }
            if (missionType !== undefined && ['containment', 'sweep'].includes(missionType)) {
                updates.push('mission_type = ?');
                params.push(missionType);
            }
            if (chaosValue !== undefined && !isNaN(parseInt(chaosValue))) {
                updates.push('chaos_value = ?');
                params.push(parseInt(chaosValue));
            }
            if (scatterValue !== undefined && !isNaN(parseInt(scatterValue))) {
                updates.push('scatter_value = ?');
                params.push(parseInt(scatterValue));
            }

            if (updates.length === 0) {
                return res.json({ success: true });
            }

            updates.push('updated_at = ?');
            params.push(Date.now());
            params.push(missionId);

            db.run(`UPDATE field_missions SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
        }
    });
});

router.delete('/api/manager/mission/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权删除此任务' });
        }

        db.run('DELETE FROM field_missions WHERE id = ?', [missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

router.post('/api/manager/mission/:id/member', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { characterId } = req.body;

    if (!characterId) {
        return res.status(400).json({ success: false, message: '角色卡ID不能为空' });
    }

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        db.get('SELECT 1 FROM field_mission_members WHERE mission_id = ? AND character_id = ?', 
            [missionId, characterId], (err, existing) => {
            if (existing) {
                return res.status(400).json({
                    success: false,
                    message: '该特工已在本任务中'
                });
            }

            db.run('INSERT INTO field_mission_members (mission_id, character_id, member_status, joined_at) VALUES (?, ?, ?, ?)',
                [missionId, characterId, '待命', Date.now()],
                function(err) {
                    if (err) return res.status(500).json({ success: false });

                    db.run('UPDATE field_missions SET updated_at = ? WHERE id = ?', [Date.now(), missionId]);

                    res.json({ success: true });
                });
        });
    });
});

router.delete('/api/manager/mission/:id/member/:charId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const charId = req.params.charId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        db.run('DELETE FROM field_mission_members WHERE mission_id = ? AND character_id = ?',
            [missionId, charId],
            function(err) {
                if (err) return res.status(500).json({ success: false });

                db.run('UPDATE field_missions SET updated_at = ? WHERE id = ?', [Date.now(), missionId]);

                res.json({ success: true });
            });
    });
});

router.get('/api/manager/mission/:id/inbox', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.all(`
            SELECT * FROM mission_inbox
            WHERE mission_id = ?
            ORDER BY created_at DESC
        `, [missionId], (err, messages) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, messages: messages || [] });
        });
    });
});

router.get('/api/manager/mission/:id/inbox/unread-count', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.get('SELECT COUNT(*) as count FROM mission_inbox WHERE mission_id = ? AND read = 0', [missionId], (err, row) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, count: row ? row.count : 0 });
        });
    });
});

router.put('/api/manager/mission/:id/inbox/:msgId/read', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const msgId = req.params.msgId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.run('UPDATE mission_inbox SET read = 1 WHERE id = ? AND mission_id = ?', [msgId, missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

router.delete('/api/manager/mission/:id/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const msgId = req.params.msgId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.run('DELETE FROM mission_inbox WHERE id = ? AND mission_id = ?', [msgId, missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

router.get('/api/manager/mission/:id/reports', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.all(`
            SELECT mr.*, c.data as char_data
            FROM mission_reports mr
            LEFT JOIN characters c ON mr.submitted_by = c.id
            WHERE mr.mission_id = ?
            ORDER BY mr.submitted_at DESC
        `, [missionId], (err, reports) => {
            if (err) return res.status(500).json({ success: false });

            const result = (reports || []).map(r => {
                let charName = '未知特工';
                try {
                    const charData = JSON.parse(r.char_data || '{}');
                    charName = charData.pName || '未命名';
                } catch(e) {}

                return {
                    id: r.id,
                    missionId: r.mission_id,
                    submittedBy: r.submitted_by,
                    submitterName: charName,
                    originalData: r.original_data ? JSON.parse(r.original_data) : null,
                    revisedData: r.revised_data ? JSON.parse(r.revised_data) : null,
                    annotations: r.annotations ? JSON.parse(r.annotations) : [],
                    rating: r.rating,
                    scatterValue: r.scatter_value,
                    status: r.status,
                    submittedAt: r.submitted_at,
                    reviewedAt: r.reviewed_at,
                    sentAt: r.sent_at
                };
            });

            res.json({ success: true, reports: result });
        });
    });
});

router.put('/api/manager/mission/:id/report/:reportId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;
    const { revisedData, annotations, rating, scatterValue } = req.body;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        const updates = ['reviewed_at = ?', 'status = ?'];
        const params = [Date.now(), 'reviewed'];

        if (revisedData !== undefined) {
            updates.push('revised_data = ?');
            params.push(JSON.stringify(revisedData));
        }
        if (annotations !== undefined) {
            updates.push('annotations = ?');
            params.push(JSON.stringify(annotations));
        }
        if (rating !== undefined) {
            updates.push('rating = ?');
            params.push(rating);
        }
        if (scatterValue !== undefined) {
            updates.push('scatter_value = ?');
            params.push(parseInt(scatterValue) || 0);
        }

        params.push(reportId, missionId);

        db.run(`UPDATE mission_reports SET ${updates.join(', ')} WHERE id = ? AND mission_id = ?`, params, function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });

            db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?',
                ['reviewed', Date.now(), missionId]);

            res.json({ success: true });
        });
    });
});

router.post('/api/manager/mission/:id/report/:reportId/send', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;

    db.get('SELECT created_by, name FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.get('SELECT * FROM mission_reports WHERE id = ? AND mission_id = ?', [reportId, missionId], (err, report) => {
            if (!report) return res.status(404).json({ success: false, message: '报告不存在' });

            const now = Date.now();

            db.run('UPDATE mission_reports SET status = ?, sent_at = ? WHERE id = ?', ['sent', now, reportId], function(err) {
                if (err) return res.status(500).json({ success: false });

                db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['sent', now, missionId]);

                if (report.submitted_by) {
                    const subject = `[评级通知] ${mission.name} - 任务报告已评审`;
                    const content = `您提交的任务报告已被经理评审。\n\n任务: ${mission.name}\n评级: ${report.rating || '未评级'}\n逸散端: ${report.scatter_value || 0}`;

                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [report.submitted_by, req.user.userId, '任务系统', subject, content, 'system', now]);
                }

                res.json({ success: true });
            });
        });
    });
});

router.post('/api/manager/mission/:id/archive', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT * FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.get('SELECT COUNT(*) as count FROM mission_reports WHERE mission_id = ?', [missionId], (err, reportCount) => {
            if (reportCount && reportCount.count > 0) {
                db.get('SELECT COUNT(*) as unsent FROM mission_reports WHERE mission_id = ? AND status != ?', [missionId, 'sent'], (err, unsent) => {
                    if (unsent && unsent.unsent > 0) {
                        return res.status(400).json({
                            success: false,
                            message: '存在未发送的报告评级，请先完成所有报告评审并发送给特工'
                        });
                    }

                    doArchive();
                });
            } else {
                doArchive();
            }
        });

        function doArchive() {
            const now = Date.now();
            db.run('UPDATE field_missions SET status = ?, updated_at = ? WHERE id = ?', ['archived', now, missionId], function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
        }
    });
});

router.get('/api/character/:charId/mission', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ error: '角色不存在' });

        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权访问' });
        }

        db.get(`
            SELECT fm.*, fmm.member_status
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.status = 'active'
            ORDER BY fm.created_at DESC
            LIMIT 1
        `, [charId], (err, mission) => {
            if (!mission) {
                return res.json({ inMission: false });
            }

            db.all(`
                SELECT fmm.character_id, fmm.member_status, c.data
                FROM field_mission_members fmm
                JOIN characters c ON fmm.character_id = c.id
                WHERE fmm.mission_id = ?
            `, [mission.id], (err, members) => {
                const teammates = (members || []).map(m => {
                    let d = {};
                    try { d = JSON.parse(m.data); } catch(e) {}
                    return {
                        characterId: m.character_id,
                        characterName: d.pName || '未命名',
                        status: m.member_status,
                        isMe: m.character_id === charId
                    };
                });

                res.json({
                    inMission: true,
                    missionId: mission.id,
                    missionName: mission.name,
                    myStatus: mission.member_status,
                    teammates
                });
            });
        });
    });
});

module.exports = router;
