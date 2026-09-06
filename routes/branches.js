const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { isCosEnabled, isCosConfigured, uploadToCos, deleteFromCos, keyFromCosUrl } = require('../cos');

// 分部图标上传（同角色头像：内存存储 + 白名单格式）
const UPLOADS_DIR = path.join(__dirname, '..', 'data', 'uploads');
const PCIMG_DIR = path.join(UPLOADS_DIR, 'pcimg');
if (!fs.existsSync(PCIMG_DIR)) fs.mkdirSync(PCIMG_DIR, { recursive: true });
const iconUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = ['.png', '.jpg', '.jpeg', '.webp'].includes(path.extname(file.originalname).toLowerCase());
        cb(ok ? null : new Error('仅支持 png/jpg/webp'), ok);
    }
});

// 经理仅能管理自己所属分部；超管不限
function canManageBranch(req, branchId) {
    if (req.user.role >= ROLE.SUPER_ADMIN) return true;
    return !!db.prepare('SELECT 1 AS ok FROM user_branches WHERE user_id = ? AND branch_id = ?').get(req.user.userId, branchId);
}

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

// 用户所属分部的散逸端监控数据（桌面"区域监控"卡片，仅总数，不含明细）
router.get('/api/user/branch-scatter', authenticateToken, (req, res) => {
    try {
        const branches = db.prepare(`
            SELECT b.id, b.name,
                (SELECT COALESCE(SUM(fm.scatter_value), 0)
                 FROM field_missions fm WHERE fm.branch_id = b.id AND fm.status = 'archived') as total_scatter
            FROM branches b
            JOIN user_branches ub ON ub.branch_id = b.id AND ub.user_id = ?
            ORDER BY b.created_at DESC
        `).all(req.user.userId);
        res.json({ success: true, branches: branches || [] });
    } catch (err) {
        res.status(500).json({ success: false });
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
        const branches = db.prepare(`
            SELECT b.id, b.name, b.description, b.icon, b.intro,
                (SELECT COUNT(*) FROM user_branches ub WHERE ub.branch_id = b.id) AS user_count
            FROM branches b ORDER BY b.created_at DESC`).all();
        /* 每个分部取该用户最新一条申请状态（供门禁遮罩/加入分部窗口渲染） */
        const apps = db.prepare(`
            SELECT ba.branch_id, ba.status FROM branch_applications ba
            JOIN (SELECT branch_id, MAX(id) AS max_id FROM branch_applications WHERE user_id = ? GROUP BY branch_id) latest
              ON ba.id = latest.max_id`).all(req.user.userId);
        const statusMap = {};
        (apps || []).forEach(a => { statusMap[a.branch_id] = a.status; });
        const joined = new Set((db.prepare('SELECT branch_id FROM user_branches WHERE user_id = ?').all(req.user.userId) || []).map(r => r.branch_id));
        const result = (branches || []).map(b => {
            const st = statusMap[b.id] || null;
            return { ...b, applied: st === 'pending', application_status: st, joined: joined.has(b.id) };
        });
        res.json({ success: true, branches: result });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/branch-application', authenticateToken, (req, res) => {
    try {
        const { branchId } = req.body;
        if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

        const branch = db.prepare('SELECT id FROM branches WHERE id = ?').get(branchId);
        if (!branch) return res.status(404).json({ success: false, message: '分部不存在' });

        const joined = db.prepare('SELECT 1 AS ok FROM user_branches WHERE user_id = ? AND branch_id = ?').get(req.user.userId, branchId);
        if (joined) return res.status(400).json({ success: false, message: '你已是该分部成员' });

        /* 同一分部同时只能有一条待审批申请；不同分部可同时申请 */
        const existing = db.prepare('SELECT id FROM branch_applications WHERE user_id = ? AND branch_id = ? AND status = \'pending\'').get(req.user.userId, branchId);
        if (existing) return res.status(400).json({ success: false, message: '该分部已有待审批的申请' });

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

        const app = db.prepare(`
            SELECT ba.*, b.name AS branch_name FROM branch_applications ba
            JOIN branches b ON ba.branch_id = b.id WHERE ba.id = ?`).get(req.params.id);
        if (!app) return res.status(404).json({ success: false, message: '申请不存在' });
        if (app.status !== 'pending') return res.status(400).json({ success: false, message: '该申请已处理' });

        /* 超管可审批所有分部；经理只能审批自己所属分部的申请 */
        if (req.user.role < ROLE.SUPER_ADMIN) {
            const member = db.prepare('SELECT 1 AS ok FROM user_branches WHERE user_id = ? AND branch_id = ?').get(req.user.userId, app.branch_id);
            if (!member) return res.status(403).json({ success: false, message: '只能审批自己所属分部的申请' });
        }

        if (status === 'approved') {
            db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)').run(app.user_id, app.branch_id, Date.now());
        }
        db.prepare('UPDATE branch_applications SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?').run(status, Date.now(), req.user.userId, req.params.id);

        /* 实时通知申请人（desktop 门禁遮罩/加入分部窗口监听） */
        if (global.io) {
            global.io.to('user-' + app.user_id).emit('branch:reviewed', {
                status: status,
                branchId: app.branch_id,
                branchName: app.branch_name
            });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 分部资料（图标/介绍短语）管理：超管任意分部，经理仅自己所属分部
router.get('/api/manager/branch/:id/profile', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.params.id;
        if (!canManageBranch(req, branchId)) return res.status(403).json({ success: false, message: '只能管理自己所属的分部' });
        const b = db.prepare('SELECT id, name, icon, intro, description FROM branches WHERE id = ?').get(branchId);
        if (!b) return res.status(404).json({ success: false, message: '分部不存在' });
        res.json({ success: true, branch: b });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/manager/branch/:id/profile', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.params.id;
        if (!canManageBranch(req, branchId)) return res.status(403).json({ success: false, message: '只能管理自己所属的分部' });

        const intro = String(req.body.intro || '').trim();
        if ([...intro].length > 50) return res.status(400).json({ success: false, message: '介绍短语不能超过 50 字' });

        db.prepare('UPDATE branches SET intro = ?, updated_at = ? WHERE id = ?').run(intro, Date.now(), branchId);
        res.json({ success: true, intro });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 分部图标上传：前端已完成方形裁剪（同头像链路，COS 启用时传 COS，否则落盘 pcimg）
router.post('/api/manager/branch/:id/icon', authenticateToken, requireRole(ROLE.MANAGER), iconUpload.single('icon'), async (req, res) => {
    try {
        const branchId = req.params.id;
        if (!canManageBranch(req, branchId)) return res.status(403).json({ success: false, message: '只能管理自己所属的分部' });
        if (!req.file) return res.status(400).json({ success: false, message: '请选择图片' });

        const branch = db.prepare('SELECT id, icon FROM branches WHERE id = ?').get(branchId);
        if (!branch) return res.status(404).json({ success: false, message: '分部不存在' });

        const oldIcon = branch.icon || '';
        // 统一存为 .jpg（前端 toBlob('image/jpeg') 输出）
        const fileName = 'branch_' + branchId + '.jpg';

        // 清理旧图标：当前存储模式下的旧文件 + 存储模式切换后遗留在另一侧的旧文件，保证每个分部只保留一份
        async function cleanupOld(currentUrl) {
            if (oldIcon.startsWith('http')) {
                const oldKey = keyFromCosUrl(oldIcon);
                if (oldKey && oldKey !== currentUrl) { try { await deleteFromCos(oldKey); } catch (e) {} }
            } else if (oldIcon && oldIcon !== currentUrl) {
                const oldPath = path.join(UPLOADS_DIR, oldIcon);
                if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch (e) {} }
            }
        }

        let iconUrl;
        if (isCosEnabled()) {
            if (!isCosConfigured()) {
                return res.status(400).json({ success: false, message: 'COS 已启用但凭证未配置完整' });
            }
            const cosKey = 'pcimg/' + fileName;
            const { Url } = await uploadToCos(cosKey, req.file.buffer);
            iconUrl = Url;
            await cleanupOld(cosKey);
        } else {
            fs.writeFileSync(path.join(PCIMG_DIR, fileName), req.file.buffer);
            iconUrl = 'pcimg/' + fileName;
            await cleanupOld(iconUrl);
        }

        db.prepare('UPDATE branches SET icon = ?, updated_at = ? WHERE id = ?').run(iconUrl, Date.now(), branchId);
        res.json({ success: true, icon: iconUrl });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message || '上传失败' });
    }
});

module.exports = router;
