const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');

// GET /api/destruction-track?branchId=xxx — get marked cells for a branch
router.get('/api/destruction-track', authenticateToken, (req, res) => {
    try {
        const { branchId } = req.query;
        if (!branchId) return res.json({ success: true, cells: [] });
        const rows = db.prepare('SELECT cell_index FROM destruction_tracks WHERE branch_id = ?').all(branchId);
        res.json({ success: true, cells: rows.map(r => r.cell_index) });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// PUT /api/destruction-track — update cells (manager only)
router.put('/api/destruction-track', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { branchId, cells } = req.body;
        if (!branchId) return res.status(400).json({ success: false, message: '缺少分部ID' });

        const doUpdate = db.transaction(() => {
            db.prepare('DELETE FROM destruction_tracks WHERE branch_id = ?').run(branchId);
            const stmt = db.prepare('INSERT INTO destruction_tracks (branch_id, cell_index, marked_at) VALUES (?, ?, ?)');
            const now = Date.now();
            cells.forEach(idx => stmt.run(branchId, idx, now));
        });
        doUpdate();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// GET /api/destruction-track/has-access?charId=xxx — check if character has access to destruction track
router.get('/api/destruction-track/has-access', authenticateToken, (req, res) => {
    try {
        const { charId } = req.query;
        if (!charId) return res.json({ success: true, hasAccess: false });
        
        const charRow = db.prepare('SELECT branch_id FROM characters WHERE id = ?').get(charId);
        const branchId = charRow ? charRow.branch_id : null;

        const rows = db.prepare(
            "SELECT filename FROM character_document_permissions WHERE character_id = ? AND filename IN ('L10.md', 'Q3.md', 'X3.md')"
        ).all(charId);
        res.json({ success: true, hasAccess: rows.length > 0, branchId });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

module.exports = router;
