const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

// === 管理员：创建分部 ===
router.post('/api/admin/branch', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const { name, description } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ success: false, message: '分部名称不能为空' });

    const branchId = Date.now().toString();
    const now = Date.now();
    db.run(`INSERT INTO branches (id, name, description, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
        [branchId, name.trim(), description || '', req.user.userId, now, now],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            db.all('SELECT id FROM users WHERE role >= ?', [ROLE.SUPER_ADMIN], (e2, admins) => {
                if (admins) {
                    admins.forEach(a => {
                        db.run('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)',
                            [a.id, branchId, now]);
                    });
                }
            });
            res.json({ success: true, branchId });
        });
});

// === 管理员/经理：获取所有分部列表 ===
router.get('/api/admin/branches', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.all(`
        SELECT b.*,
            (SELECT COUNT(*) FROM user_branches WHERE branch_id = b.id) as user_count,
            (SELECT COUNT(*) FROM characters WHERE branch_id = b.id) as character_count,
            (SELECT COALESCE(SUM(fm.scatter_value), 0)
             FROM field_missions fm WHERE fm.branch_id = b.id AND fm.status = 'archived') as total_scatter
        FROM branches b ORDER BY b.created_at DESC
    `, [], (err, branches) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, branches: branches || [] });
    });
});

// === 管理员/经理：获取分部详情 ===
router.get('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const branchId = req.params.id;
    db.get('SELECT * FROM branches WHERE id = ?', [branchId], (err, branch) => {
        if (!branch) return res.status(404).json({ success: false, message: '分部不存在' });

        db.all(`
            SELECT u.id, u.username, u.name, u.role, ub.assigned_at
            FROM user_branches ub
            JOIN users u ON ub.user_id = u.id
            WHERE ub.branch_id = ?
        `, [branchId], (err, users) => {
            db.get(`
                SELECT COUNT(*) as mission_count,
                    COALESCE(SUM(scatter_value), 0) as total_scatter,
                    COALESCE(SUM(chaos_value), 0) as total_chaos
                FROM field_missions WHERE branch_id = ? AND status = 'archived'
            `, [branchId], (err, stats) => {
                db.get('SELECT COUNT(*) as count FROM characters WHERE branch_id = ?', [branchId], (err, charStats) => {
                    res.json({
                        success: true,
                        branch: {
                            ...branch,
                            users: users || [],
                            stats: stats || { mission_count: 0, total_scatter: 0, total_chaos: 0 },
                            character_count: charStats ? charStats.count : 0
                        }
});

module.exports = router;
    });
});

module.exports = router;
        });
    });
});

// === 管理员：更新分部 ===
router.put('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;
    const { name, description } = req.body;
    const updates = ['updated_at = ?'];
    const params = [Date.now()];
    if (name !== undefined) { updates.push('name = ?'); params.push(name.trim()); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    params.push(branchId);
    db.run(`UPDATE branches SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// === 管理员：删除分部 ===
router.delete('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.run('DELETE FROM branches WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// === 管理员：分配用户到分部 ===
router.post('/api/admin/branch/:id/user', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: '用户ID不能为空' });

    db.run('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)',
        [userId, branchId, Date.now()],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true });
        });
});

// === 管理员：从分部移除用户 ===
router.delete('/api/admin/branch/:id/user/:userId', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.run('DELETE FROM user_branches WHERE branch_id = ? AND user_id = ?',
        [req.params.id, req.params.userId],
        function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

// === 任意已登录用户：获取自己所属的分部列表 ===
router.get('/api/user/my-branches', authenticateToken, (req, res) => {
    db.all(`
        SELECT b.* FROM user_branches ub
        JOIN branches b ON ub.branch_id = b.id
        WHERE ub.user_id = ?
        ORDER BY b.created_at DESC
    `, [req.user.userId], (err, branches) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, branches: branches || [] });
    });
});

// === 经理：获取分部内的角色列表（按branch_id） ===
router.get('/api/manager/branch/:branchId/characters', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { branchId } = req.params;
    const userId = req.user.userId;

    db.get('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?',
        [userId, branchId], (err, row) => {
            if (!row && req.user.role < ROLE.SUPER_ADMIN) {
                return res.status(403).json({ success: false, message: '你不属于该分部' });
            }

            const query = req.user.role >= ROLE.SUPER_ADMIN
                ? 'SELECT id, user_id, data, created_at FROM characters WHERE branch_id = ? ORDER BY created_at DESC'
                : 'SELECT id, user_id, data, created_at FROM characters WHERE branch_id = ? ORDER BY created_at DESC';
            const params = [branchId];

            db.all(query, params, (err, characters) => {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, characters: characters || [] });
            });
        });
});

// === 经理：分配任务到分部（保留旧接口） ===
router.put('/api/manager/mission/:id/branch', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { branchId } = req.body;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });
        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }
        db.run('UPDATE field_missions SET branch_id = ?, updated_at = ? WHERE id = ?',
            [branchId || null, Date.now(), missionId],
            function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
    });
});

router.get('/api/branches', authenticateToken, (req, res) => {
    db.all('SELECT id, name, description FROM branches ORDER BY created_at DESC', [], (err, branches) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, branches: branches || [] });
    });
});

router.post('/api/branch-application', authenticateToken, (req, res) => {
    const { branchId } = req.body;
    if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

    db.get('SELECT id FROM branch_applications WHERE user_id = ? AND status = \'pending\'', [req.user.userId], (err, existing) => {
        if (existing) return res.status(400).json({ success: false, message: '已有待审批的申请' });

        db.run('INSERT INTO branch_applications (user_id, branch_id, status, created_at) VALUES (?, ?, \'pending\', ?)',
            [req.user.userId, branchId, Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true });
            });
    });
});

router.get('/api/manager/branch-applications', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    if (req.user.role >= ROLE.SUPER_ADMIN) {
        db.all(`SELECT ba.*, b.name as branch_name, u.name as user_name, u.username
                FROM branch_applications ba
                JOIN branches b ON ba.branch_id = b.id
                JOIN users u ON ba.user_id = u.id
                WHERE ba.status = 'pending' ORDER BY ba.created_at DESC`, [], (err, applications) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, applications: applications || [] });
        });
        return;
    }

    db.all('SELECT branch_id FROM user_branches WHERE user_id = ?', [req.user.userId], (err, rows) => {
        if (err || !rows || rows.length === 0) return res.json({ success: true, applications: [] });
        const branchIds = rows.map(r => r.branch_id);
        const placeholders = branchIds.map(() => '?').join(',');
        db.all(`SELECT ba.*, b.name as branch_name, u.name as user_name, u.username
                FROM branch_applications ba
                JOIN branches b ON ba.branch_id = b.id
                JOIN users u ON ba.user_id = u.id
                WHERE ba.status = 'pending' AND ba.branch_id IN (${placeholders}) ORDER BY ba.created_at DESC`,
            branchIds, (err, applications) => {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true, applications: applications || [] });
            });
    });
});

router.put('/api/manager/branch-application/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { status } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ success: false, message: '无效状态' });

    db.get('SELECT * FROM branch_applications WHERE id = ?', [req.params.id], (err, app) => {
        if (!app) return res.status(404).json({ success: false, message: '申请不存在' });

        const finish = () => {
            db.run('UPDATE branch_applications SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?',
                [status, Date.now(), req.user.userId, req.params.id],
                function(err) {
                    if (err) return res.status(500).json({ success: false });
                    res.json({ success: true });
                });
        };

        if (status === 'approved') {
            db.run('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)',
                [app.user_id, app.branch_id, Date.now()], finish);
        } else {
            finish();
        }
    });
});

module.exports = router;
