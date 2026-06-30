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

router.get('/api/anomaly-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const branchId = req.query.branchId;
        if (!branchId) return res.json([]);

        let query = 'SELECT * FROM anomaly_templates WHERE branch_id = ? ORDER BY created_at DESC';
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

router.post('/api/anomaly-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { branchId, name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, docFilename } = req.body;
        if (!branchId || !name) return res.status(400).json({ success: false, message: '缺少分部ID或名称' });

        const id = uuidv4();
        const now = Date.now();

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, branchId)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        db.prepare(`INSERT INTO anomaly_templates (id, branch_id, name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, doc_filename, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
            id, branchId, name, trig || '', qual || '', succ || '', fail || '', chk ? 1 : 0, tdesc || '', t1 || '', t1v || '', t2 || '', t2v || '', JSON.stringify(p1 || []), JSON.stringify(p2 || []), docFilename || '', now
        );
        res.json({ success: true, id });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/anomaly-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, docFilename } = req.body;

        const row = db.prepare('SELECT branch_id FROM anomaly_templates WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, row.branch_id)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        const result = db.prepare(`UPDATE anomaly_templates SET name=?, trig=?, qual=?, succ=?, fail=?, chk=?, tdesc=?, t1=?, t1v=?, t2=?, t2v=?, p1=?, p2=?, doc_filename=? WHERE id=?`).run(
            name || '', trig || '', qual || '', succ || '', fail || '', chk ? 1 : 0, tdesc || '', t1 || '', t1v || '', t2 || '', t2v || '', JSON.stringify(p1 || []), JSON.stringify(p2 || []), docFilename || '', req.params.id
        );
        if (result.changes === 0) return res.status(404).json({ success: false, message: '模板不存在' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/anomaly-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const row = db.prepare('SELECT branch_id FROM anomaly_templates WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, row.branch_id)) return res.status(403).json({ success: false, message: '无权操作此分部' });
        }

        db.prepare('DELETE FROM anomaly_templates WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/api/anomaly-templates/:id/grant', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { characterId } = req.body;
        if (!characterId) return res.status(400).json({ success: false, message: '缺少角色ID' });

        const tmpl = db.prepare('SELECT * FROM anomaly_templates WHERE id = ?').get(req.params.id);
        if (!tmpl) return res.status(404).json({ success: false, message: '模板不存在' });

        const charRow = db.prepare('SELECT c.data, c.branch_id FROM characters c WHERE c.id = ?').get(characterId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, charRow.branch_id)) return res.status(403).json({ success: false, message: '无权操作此角色' });
        }

        try {
            let data = JSON.parse(charRow.data);
            if (!data.anoms) data.anoms = [];

            const alreadyHas = data.anoms.some(a => a.name === tmpl.name);
            if (alreadyHas) return res.json({ success: false, message: '角色已有同名异常能力' });

            let p1 = [], p2 = [];
            try { p1 = JSON.parse(tmpl.p1); } catch(e) {}
            try { p2 = JSON.parse(tmpl.p2); } catch(e) {}

            data.anoms.push({
                name: tmpl.name,
                trig: tmpl.trig,
                qual: tmpl.qual,
                succ: tmpl.succ,
                fail: tmpl.fail,
                chk: tmpl.chk ? true : false,
                tdesc: tmpl.tdesc,
                t1: tmpl.t1,
                t1v: tmpl.t1v,
                t2: tmpl.t2,
                t2v: tmpl.t2v,
                p1: p1,
                p2: p2
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

router.post('/api/anomaly-templates/:id/revoke', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { characterId } = req.body;
        if (!characterId) return res.status(400).json({ success: false, message: '缺少角色ID' });

        const tmpl = db.prepare('SELECT * FROM anomaly_templates WHERE id = ?').get(req.params.id);
        if (!tmpl) return res.status(404).json({ success: false, message: '模板不存在' });

        const charRow = db.prepare('SELECT c.data, c.branch_id FROM characters c WHERE c.id = ?').get(characterId);
        if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });

        if (req.user.role < ROLE.SUPER_ADMIN) {
            if (!checkBranchMembership(req.user.userId, charRow.branch_id)) return res.status(403).json({ success: false, message: '无权操作此角色' });
        }

        try {
            let data = JSON.parse(charRow.data);
            if (!data.anoms) data.anoms = [];
            data.anoms = data.anoms.filter(a => a.name !== tmpl.name);
            db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), characterId);
            res.json({ success: true });
        } catch(e) {
            res.status(500).json({ success: false, message: '角色数据解析失败' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

function grantAnomalyByDoc(db, charId, filename) {
    const charRow = db.prepare('SELECT branch_id, data FROM characters WHERE id = ?').get(charId);
    if (!charRow) return;
    const tmpl = db.prepare('SELECT * FROM anomaly_templates WHERE doc_filename = ? AND branch_id = ?').get(filename, charRow.branch_id);
    if (!tmpl) return;
    try {
        let data = JSON.parse(charRow.data);
        if (!data.anoms) data.anoms = [];
        const alreadyHas = data.anoms.some(a => a.name === tmpl.name);
        if (alreadyHas) return;
        let p1 = [], p2 = [];
        try { p1 = JSON.parse(tmpl.p1); } catch(e) {}
        try { p2 = JSON.parse(tmpl.p2); } catch(e) {}
        data.anoms.push({
            name: tmpl.name, trig: tmpl.trig, qual: tmpl.qual,
            succ: tmpl.succ, fail: tmpl.fail, chk: tmpl.chk ? true : false,
            tdesc: tmpl.tdesc, t1: tmpl.t1, t1v: tmpl.t1v,
            t2: tmpl.t2, t2v: tmpl.t2v, p1: p1, p2: p2
        });
        db.prepare('UPDATE characters SET data = ? WHERE id = ?').run(JSON.stringify(data), charId);
    } catch(e) {}
}

module.exports = router;
module.exports.grantAnomalyByDoc = grantAnomalyByDoc;
