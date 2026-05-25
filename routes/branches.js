const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.post('/api/admin/branch', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const { name, description } = req.body;
        if (!name || !name.trim()) return res.status(400).json({ success: false, message: '分部名称不能为空' });

        const branchId = Date.now().toString();
        const now = Date.now();
        db.prepare(`INSERT INTO branches (id, name, description, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`).run(branchId, name.trim(), description || '', req.user.userId, now, now);

        const admins = db.prepare('SELECT id FROM users WHERE role >= ?').all(ROLE.SUPER_ADMIN);
        if (admins) {
            const insertStmt = db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)');
            for (const a of admins) insertStmt.run(a.id, branchId, now);
        }
        res.json({ success: true, branchId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.get('/api/admin/branches', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branches = db.prepare(`
            SELECT b.*,
                (SELECT COUNT(*) FROM user_branches WHERE branch_id = b.id) as user_count,
                (SELECT COUNT(*) FROM characters WHERE branch_id = b.id) as character_count,
                (SELECT COALESCE(SUM(fm.scatter_value), 0)
                 FROM field_missions fm WHERE fm.branch_id = b.id AND fm.status = 'archived') as total_scatter
            FROM branches b ORDER BY b.created_at DESC
        `).all();
        res.json({ success: true, branches: branches || [] });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.params.id;
        const branch = db.prepare('SELECT * FROM branches WHERE id = ?').get(branchId);
        if (!branch) return res.status(404).json({ success: false, message: '分部不存在' });

        const users = db.prepare(`
            SELECT u.id, u.username, u.name, u.role, ub.assigned_at
            FROM user_branches ub
            JOIN users u ON ub.user_id = u.id
            WHERE ub.branch_id = ?
        `).all(branchId);
        const stats = db.prepare(`
            SELECT COUNT(*) as mission_count,
                COALESCE(SUM(scatter_value), 0) as total_scatter,
                COALESCE(SUM(chaos_value), 0) as total_chaos
            FROM field_missions WHERE branch_id = ? AND status = 'archived'
        `).get(branchId);
        const charStats = db.prepare('SELECT COUNT(*) as count FROM characters WHERE branch_id = ?').get(branchId);

        res.json({
            success: true,
            branch: {
                ...branch,
                users: users || [],
                stats: stats || { mission_count: 0, total_scatter: 0, total_chaos: 0 },
                character_count: charStats ? charStats.count : 0
            }
        });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const branchId = req.params.id;
        const { name, description } = req.body;
        const updates = ['updated_at = ?'];
        const params = [Date.now()];
        if (name !== undefined) { updates.push('name = ?'); params.push(name.trim()); }
        if (description !== undefined) { updates.push('description = ?'); params.push(description); }
        params.push(branchId);
        db.prepare(`UPDATE branches SET ${updates.join(', ')} WHERE id = ?`).run(...params);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.delete('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        db.prepare('DELETE FROM branches WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/admin/branch/:id/user', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        const branchId = req.params.id;
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ success: false, message: '用户ID不能为空' });

        db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)').run(userId, branchId, Date.now());
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/admin/branch/:id/user/:userId', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    try {
        db.prepare('DELETE FROM user_branches WHERE branch_id = ? AND user_id = ?').run(req.params.id, req.params.userId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/user/my-branches', authenticateToken, (req, res) => {
    try {
        const branches = db.prepare(`
            SELECT b.* FROM user_branches ub
            JOIN branches b ON ub.branch_id = b.id
            WHERE ub.user_id = ?
            ORDER BY b.created_at DESC
        `).all(req.user.userId);
        res.json({ success: true, branches: branches || [] });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/manager/branch/:branchId/characters', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { branchId } = req.params;
        const userId = req.user.userId;

        const row = db.prepare('SELECT branch_id FROM user_branches WHERE user_id = ? AND branch_id = ?').get(userId, branchId);
        if (!row && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '你不属于该分部' });
        }

        const query = req.user.role >= ROLE.SUPER_ADMIN
            ? 'SELECT id, user_id, data, created_at FROM characters WHERE branch_id = ? ORDER BY created_at DESC'
            : 'SELECT id, user_id, data, created_at FROM characters WHERE branch_id = ? ORDER BY created_at DESC';
        const characters = db.prepare(query).all(branchId);
        res.json({ success: true, characters: characters || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/manager/mission/:id/branch', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const missionId = req.params.id;
        const { branchId } = req.body;

        const mission = db.prepare('SELECT created_by FROM field_missions WHERE id = ?').get(missionId);
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });
        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }
        db.prepare('UPDATE field_missions SET branch_id = ?, updated_at = ? WHERE id = ?').run(branchId || null, Date.now(), missionId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/branches', authenticateToken, (req, res) => {
    try {
        const branches = db.prepare('SELECT id, name, description FROM branches ORDER BY created_at DESC').all();
        const apps = db.prepare('SELECT branch_id FROM branch_applications WHERE user_id = ? AND status = \'pending\'').all(req.user.userId);
        const pendingIds = new Set((apps || []).map(a => a.branch_id));
        const result = (branches || []).map(b => ({ ...b, applied: pendingIds.has(b.id) }));
        res.json({ success: true, branches: result });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/branch-application', authenticateToken, (req, res) => {
    try {
        const { branchId } = req.body;
        if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

        const existing = db.prepare('SELECT id FROM branch_applications WHERE user_id = ? AND status = \'pending\'').get(req.user.userId);
        if (existing) return res.status(400).json({ success: false, message: '已有待审批的申请' });

        db.prepare('INSERT INTO branch_applications (user_id, branch_id, status, created_at) VALUES (?, ?, \'pending\', ?)').run(req.user.userId, branchId, Date.now());
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.get('/api/manager/branch-applications', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        if (req.user.role >= ROLE.SUPER_ADMIN) {
            const applications = db.prepare(`SELECT ba.*, b.name as branch_name, u.name as user_name, u.username
                    FROM branch_applications ba
                    JOIN branches b ON ba.branch_id = b.id
                    JOIN users u ON ba.user_id = u.id
                    WHERE ba.status = 'pending' ORDER BY ba.created_at DESC`).all();
            return res.json({ success: true, applications: applications || [] });
        }

        const rows = db.prepare('SELECT branch_id FROM user_branches WHERE user_id = ?').all(req.user.userId);
        if (!rows || rows.length === 0) return res.json({ success: true, applications: [] });
        const branchIds = rows.map(r => r.branch_id);
        const placeholders = branchIds.map(() => '?').join(',');
        const applications = db.prepare(`SELECT ba.*, b.name as branch_name, u.name as user_name, u.username
                FROM branch_applications ba
                JOIN branches b ON ba.branch_id = b.id
                JOIN users u ON ba.user_id = u.id
                WHERE ba.status = 'pending' AND ba.branch_id IN (${placeholders}) ORDER BY ba.created_at DESC`).all(...branchIds);
        res.json({ success: true, applications: applications || [] });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.put('/api/manager/branch-application/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { status } = req.body;
        if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ success: false, message: '无效状态' });

        const app = db.prepare('SELECT * FROM branch_applications WHERE id = ?').get(req.params.id);
        if (!app) return res.status(404).json({ success: false, message: '申请不存在' });

        if (status === 'approved') {
            db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)').run(app.user_id, app.branch_id, Date.now());
        }
        db.prepare('UPDATE branch_applications SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?').run(status, Date.now(), req.user.userId, req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

module.exports = router;
