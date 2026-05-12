const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');

function getOrCreateBoard(missionId, callback) {
    db.get('SELECT * FROM mission_boards WHERE mission_id = ?', [missionId], (err, board) => {
        if (board) return callback(board);
        const id = uuidv4();
        db.run('INSERT INTO mission_boards (id, mission_id, name, created_at) VALUES (?, ?, ?, ?)',
            [id, missionId, '默认画板', Date.now()],
            function(err) { callback({ id, mission_id: missionId, name: '默认画板', show_connections: 1 }); }
        );
    });
}

router.get('/api/board/:missionId', authenticateToken, (req, res) => {
    getOrCreateBoard(req.params.missionId, (board) => {
        db.all(`SELECT bi.*, il.filename as image_lib_filename
            FROM board_images bi
            LEFT JOIN image_library il ON bi.image_lib_id = il.id
            WHERE bi.board_id = ? ORDER BY bi.z_index`, [board.id], (err, images) => {
            db.all('SELECT * FROM board_connections WHERE board_id = ?', [board.id], (err2, connections) => {
                res.json({ success: true, board, images: images || [], connections: connections || [] });
            });
        });
    });
});

router.post('/api/board/:missionId/image', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { imageLibId, name, x, y, w, h, isMapNode } = req.body;
    if (!imageLibId) return res.status(400).json({ success: false, message: '缺少图片ID' });
    getOrCreateBoard(req.params.missionId, (board) => {
        const id = uuidv4();
        const nx = x || 100, ny = y || 100, nw = w || 120, nh = h || 120;
        db.run(`INSERT INTO board_images (id, board_id, image_lib_id, name, m_x, m_y, m_w, m_h, p_x, p_y, p_w, p_h, is_map_node, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, board.id, imageLibId, name || '', nx, ny, nw, nh, nx, ny, nw, nh, isMapNode ? 1 : 0, Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                db.get('SELECT filename FROM image_library WHERE id = ?', [imageLibId], (e2, lib) => {
                    res.json({ success: true, id, imageLibId, imageFile: lib ? lib.filename : '', name: name || '', m_x: nx, m_y: ny, m_w: nw, m_h: nh, p_x: nx, p_y: ny, p_w: nw, p_h: nh, is_map_node: isMapNode ? 1 : 0 });
                });
            }
        );
    });
});

router.put('/api/board/:missionId/image/:imageId', authenticateToken, (req, res) => {
    const { x, y, w, h, name, role } = req.body;
    const updates = [], params = [];
    if (role === 'player') {
        if (x !== undefined) { updates.push('p_x = ?'); params.push(x); }
        if (y !== undefined) { updates.push('p_y = ?'); params.push(y); }
        if (w !== undefined) { updates.push('p_w = ?'); params.push(w); }
        if (h !== undefined) { updates.push('p_h = ?'); params.push(h); }
    } else {
        if (x !== undefined) { updates.push('m_x = ?'); params.push(x); }
        if (y !== undefined) { updates.push('m_y = ?'); params.push(y); }
        if (w !== undefined) { updates.push('m_w = ?'); params.push(w); }
        if (h !== undefined) { updates.push('m_h = ?'); params.push(h); }
    }
    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (!updates.length) return res.json({ success: true });
    params.push(req.params.imageId);
    db.run(`UPDATE board_images SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

router.delete('/api/board/:missionId/image/:imageId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('DELETE FROM board_connections WHERE node_a = ? OR node_b = ?', [req.params.imageId, req.params.imageId]);
    db.run('DELETE FROM board_images WHERE id = ?', [req.params.imageId], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

router.post('/api/board/:missionId/connection', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { nodeA, nodeB, label } = req.body;
    if (!nodeA || !nodeB) return res.status(400).json({ success: false, message: '缺少节点' });
    getOrCreateBoard(req.params.missionId, (board) => {
        const id = uuidv4();
        db.run('INSERT INTO board_connections (id, board_id, node_a, node_b, label, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [id, board.id, nodeA, nodeB, label || '', Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, id, nodeA, nodeB, label: label || '' });
            }
        );
    });
});

router.delete('/api/board/:missionId/connection/:connId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('DELETE FROM board_connections WHERE id = ?', [req.params.connId], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

router.put('/api/board/:missionId/connections-toggle', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    getOrCreateBoard(req.params.missionId, (board) => {
        const newVal = board.show_connections ? 0 : 1;
        db.run('UPDATE mission_boards SET show_connections = ? WHERE id = ?', [newVal, board.id], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, showConnections: !!newVal });
        });
    });
});

router.get('/api/character/:charId/mission-boards', authenticateToken, (req, res) => {
    db.all(`SELECT DISTINCT fm.id as mission_id, fm.name as mission_name, mb.id as board_id
        FROM field_mission_members fmm
        JOIN field_missions fm ON fmm.mission_id = fm.id
        LEFT JOIN mission_boards mb ON mb.mission_id = fm.id
        WHERE fmm.character_id = ? AND fm.status = 'active'
        ORDER BY fm.created_at DESC`, [req.params.charId], (err, rows) => {
            if (err) return res.status(500).json({ success: false });
            res.json(rows || []);
        }
    );
});

router.get('/api/board/:missionId/npc-connections', authenticateToken, (req, res) => {
    getOrCreateBoard(req.params.missionId, (board) => {
        db.all('SELECT * FROM player_npc_connections WHERE board_id = ?', [board.id], (err, rows) => {
            if (err) return res.status(500).json({ success: false });
            res.json(rows || []);
        });
    });
});

router.post('/api/board/:missionId/npc-connection', authenticateToken, (req, res) => {
    const { nodeA, nodeB, connType, label } = req.body;
    if (!nodeA || !nodeB) return res.status(400).json({ success: false, message: '缺少节点' });
    getOrCreateBoard(req.params.missionId, (board) => {
        const id = uuidv4();
        db.run('INSERT INTO player_npc_connections (id, board_id, node_a, node_b, conn_type, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, board.id, nodeA, nodeB, connType || 'neutral', label || '', Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, id, nodeA, nodeB, connType: connType || 'neutral', label: label || '' });
            }
        );
    });
});

router.delete('/api/board/:missionId/npc-connection/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM player_npc_connections WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

router.put('/api/board/:missionId/npc-connection/:id', authenticateToken, (req, res) => {
    const { label, connType } = req.body;
    const updates = [], params = [];
    if (label !== undefined) { updates.push('label = ?'); params.push(label); }
    if (connType !== undefined) { updates.push('conn_type = ?'); params.push(connType); }
    if (!updates.length) return res.json({ success: true });
    params.push(req.params.id);
    db.run('UPDATE player_npc_connections SET ' + updates.join(', ') + ' WHERE id = ?', params, function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

module.exports = router;
