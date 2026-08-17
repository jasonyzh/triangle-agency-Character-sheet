const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');

function checkBranchMembership(userId, branchId) {
    if (!branchId) return false;
    const row = db.prepare('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?').get(userId, branchId);
    return !!row;
}

router.get('/api/npc-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.query.branchId;
        if (!branchId) return res.json([]);

        let query = 'SELECT * FROM npc_templates WHERE branch_id = ? ORDER BY created_at DESC';
        let params = [branchId];

        if (req.user.role >= ROLE.SUPER_ADMIN) {
            const rows = db.prepare(query).all(...params);
            res.json(rows || []);
        } else {
            if (!checkBranchMembership(req.user.userId, branchId)) return res.status(403).json({ success: false, message: '无权访问此分部' });
            const rows = db.prepare(query).all(...params);
            res.json(rows || []);
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/api/npc-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { branchId, name, actor, description, conn, lvl, act } = req.body;
        if (!branchId || !name) return res.status(400).json({ success: false, message: '缺少分部ID或姓名' });

        const id = uuidv4();
        const now = Date.now();

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, branchId)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        const safeLvl = Math.max(0, Math.min(9, parseInt(lvl) || 0));
        db.prepare(`INSERT INTO npc_templates (id, branch_id, name, actor, description, conn, lvl, act, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
            id, branchId, name, actor || '', description || '', conn || '', safeLvl, act ? 1 : 0, now
        );
        res.json({ success: true, id });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/npc-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { name, actor, description, conn, lvl, act } = req.body;

        const row = db.prepare('SELECT branch_id FROM npc_templates WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, row.branch_id)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        const safeLvl = Math.max(0, Math.min(9, parseInt(lvl) || 0));
        const result = db.prepare(`UPDATE npc_templates SET name=?, actor=?, description=?, conn=?, lvl=?, act=? WHERE id=?`).run(
            name || '', actor || '', description || '', conn || '', safeLvl, act ? 1 : 0, req.params.id
        );
        if (result.changes === 0) return res.status(404).json({ success: false, message: '模板不存在' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/npc-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const row = db.prepare('SELECT branch_id FROM npc_templates WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, row.branch_id)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        db.prepare('DELETE FROM npc_templates WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 赋予关系：把模板作为一条关系写入目标角色 data.reals[]
router.post('/api/npc-templates/:id/grant', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { characterId } = req.body;
        if (!characterId) return res.status(400).json({ success: false, message: '缺少角色ID' });

        const tmpl = db.prepare('SELECT * FROM npc_templates WHERE id = ?').get(req.params.id);
        if (!tmpl) return res.status(404).json({ success: false, message: '模板不存在' });

        const charRow = db.prepare('SELECT c.data, c.branch_id FROM characters c WHERE c.id = ?').get(characterId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, charRow.branch_id)) return res.status(403).json({ success: false, message: '无权操作此角色' });
        }

        try {
            let data = JSON.parse(charRow.data);
            if (!data.reals) data.reals = [];

            // 归档角色不允许修改
            if (data.isArchived) return res.status(403).json({ success: false, message: '角色已归档，无法添加关系' });

            // 槽位校验
            const realSlots = data.realSlots || 10;
            if (data.reals.length >= realSlots) return res.json({ success: false, message: '关系网槽位已满，请先解锁更多槽位' });

            const alreadyHas = data.reals.some(r => r.name === tmpl.name);
            if (alreadyHas) return res.json({ success: false, message: '角色已有同名关系' });

            data.reals.push({
                name: tmpl.name,
                actor: tmpl.actor,
                desc: tmpl.description,
                conn: tmpl.conn,
                lvl: tmpl.lvl,
                act: tmpl.act ? true : false
            });

            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), characterId);
            res.json({ success: true });
        } catch(e) {
            res.status(500).json({ success: false, message: '角色数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 移除关系：按 name 从 data.reals[] 移除
router.post('/api/npc-templates/:id/revoke', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { characterId } = req.body;
        if (!characterId) return res.status(400).json({ success: false, message: '缺少角色ID' });

        const tmpl = db.prepare('SELECT * FROM npc_templates WHERE id = ?').get(req.params.id);
        if (!tmpl) return res.status(404).json({ success: false, message: '模板不存在' });

        const charRow = db.prepare('SELECT c.data, c.branch_id FROM characters c WHERE c.id = ?').get(characterId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, charRow.branch_id)) return res.status(403).json({ success: false, message: '无权操作此角色' });
        }

        try {
            let data = JSON.parse(charRow.data);
            if (!data.reals) data.reals = [];
            data.reals = data.reals.filter(r => r.name !== tmpl.name);
            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), characterId);
            res.json({ success: true });
        } catch(e) {
            res.status(500).json({ success: false, message: '角色数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = router;
