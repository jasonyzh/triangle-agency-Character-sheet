const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');

router.get('/api/anomaly-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const branchId = req.query.branchId;
    if (!branchId) return res.json([]);

    let query = 'SELECT * FROM anomaly_templates WHERE branch_id = ? ORDER BY created_at DESC';
    let params = [branchId];

    if (req.user.role >= ROLE.SUPER_ADMIN) {
        db.all(query, params, (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json(rows || []);
        });
    } else {
        db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, branchId], (err, row) => {
            if (!row) return res.status(403).json({ success: false, message: '无权访问此分部' });
            db.all(query, params, (err, rows) => {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json(rows || []);
            });
        });
    }
});

router.post('/api/anomaly-templates', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { branchId, name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, docFilename } = req.body;
    if (!branchId || !name) return res.status(400).json({ success: false, message: '缺少分部ID或名称' });

    const id = uuidv4();
    const now = Date.now();

    const doInsert = () => {
        db.run(`INSERT INTO anomaly_templates (id, branch_id, name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, doc_filename, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, branchId, name, trig || '', qual || '', succ || '', fail || '', chk ? 1 : 0, tdesc || '', t1 || '', t1v || '', t2 || '', t2v || '', JSON.stringify(p1 || []), JSON.stringify(p2 || []), docFilename || '', now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, id });
            }
        );
    };

    if (req.user.role >= ROLE.SUPER_ADMIN) {
        doInsert();
    } else {
        db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, branchId], (err, row) => {
            if (!row) return res.status(403).json({ success: false, message: '无权操作此分部' });
            doInsert();
        });
    }
});

router.put('/api/anomaly-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name, trig, qual, succ, fail, chk, tdesc, t1, t1v, t2, t2v, p1, p2, docFilename } = req.body;

    const doUpdate = (branchId) => {
        db.run(`UPDATE anomaly_templates SET name=?, trig=?, qual=?, succ=?, fail=?, chk=?, tdesc=?, t1=?, t1v=?, t2=?, t2v=?, p1=?, p2=?, doc_filename=? WHERE id=?`,
            [name || '', trig || '', qual || '', succ || '', fail || '', chk ? 1 : 0, tdesc || '', t1 || '', t1v || '', t2 || '', t2v || '', JSON.stringify(p1 || []), JSON.stringify(p2 || []), docFilename || '', req.params.id],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                if (this.changes === 0) return res.status(404).json({ success: false, message: '模板不存在' });
                res.json({ success: true });
            }
        );
    };

    db.get('SELECT branch_id FROM anomaly_templates WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });
        if (req.user.role >= ROLE.SUPER_ADMIN) {
            doUpdate(row.branch_id);
        } else {
            db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, row.branch_id], (err2, authRow) => {
                if (!authRow) return res.status(403).json({ success: false, message: '无权操作此分部' });
                doUpdate(row.branch_id);
            });
        }
    });
});

router.delete('/api/anomaly-templates/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get('SELECT branch_id FROM anomaly_templates WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '模板不存在' });

        const doDelete = () => {
            db.run('DELETE FROM anomaly_templates WHERE id = ?', [req.params.id], function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true });
            });
        };

        if (req.user.role >= ROLE.SUPER_ADMIN) {
            doDelete();
        } else {
            db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, row.branch_id], (err2, authRow) => {
                if (!authRow) return res.status(403).json({ success: false, message: '无权操作此分部' });
                doDelete();
            });
        }
    });
});

router.post('/api/anomaly-templates/:id/grant', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { characterId } = req.body;
    if (!characterId) return res.status(400).json({ success: false, message: '缺少角色ID' });

    db.get('SELECT * FROM anomaly_templates WHERE id = ?', [req.params.id], (err, tmpl) => {
        if (!tmpl) return res.status(404).json({ success: false, message: '模板不存在' });

        db.get('SELECT c.data, c.branch_id FROM characters c WHERE c.id = ?', [characterId], (err, charRow) => {
            if (!charRow) return res.status(404).json({ success: false, message: '角色不存在' });

            const doGrant = () => {
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

                    db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), characterId], function(err) {
                        if (err) return res.status(500).json({ success: false, message: err.message });
                        res.json({ success: true });
                    });
                } catch(e) {
                    res.status(500).json({ success: false, message: '角色数据解析失败' });
                }
            };

            if (req.user.role >= ROLE.SUPER_ADMIN) {
                doGrant();
            } else {
                db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?', [req.user.userId, charRow.branch_id], (err2, authRow) => {
                    if (!authRow) return res.status(403).json({ success: false, message: '无权操作此角色' });
                    doGrant();
                });
            }
        });
    });
});

function grantAnomalyByDoc(db, charId, filename) {
    return new Promise((resolve) => {
        db.get('SELECT branch_id, data FROM characters WHERE id = ?', [charId], (err, charRow) => {
            if (!charRow) return resolve();
            db.get('SELECT * FROM anomaly_templates WHERE doc_filename = ? AND branch_id = ?', [filename, charRow.branch_id], (err, tmpl) => {
                if (!tmpl) return resolve();
                try {
                    let data = JSON.parse(charRow.data);
                    if (!data.anoms) data.anoms = [];
                    const alreadyHas = data.anoms.some(a => a.name === tmpl.name);
                    if (alreadyHas) return resolve();
                    let p1 = [], p2 = [];
                    try { p1 = JSON.parse(tmpl.p1); } catch(e) {}
                    try { p2 = JSON.parse(tmpl.p2); } catch(e) {}
                    data.anoms.push({
                        name: tmpl.name, trig: tmpl.trig, qual: tmpl.qual,
                        succ: tmpl.succ, fail: tmpl.fail, chk: tmpl.chk ? true : false,
                        tdesc: tmpl.tdesc, t1: tmpl.t1, t1v: tmpl.t1v,
                        t2: tmpl.t2, t2v: tmpl.t2v, p1: p1, p2: p2
                    });
                    db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], () => resolve());
                } catch(e) { resolve(); }
            });
        });
    });
}

module.exports = router;
module.exports.grantAnomalyByDoc = grantAnomalyByDoc;
