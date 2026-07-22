const express = require('express');
const router = express.Router();
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');

function getOrCreateBoard(missionId) {
    let board = db.prepare('SELECT * FROM mission_boards WHERE mission_id = ?').get(missionId);
    if (board) return board;
    const id = uuidv4();
    db.prepare('INSERT INTO mission_boards (id, mission_id, name, created_at) VALUES (?, ?, ?, ?)')
        .run(id, missionId, '默认画板', Date.now());
    return { id, mission_id: missionId, name: '默认画板', show_connections: 1 };
}

router.get('/api/board/:missionId', authenticateToken, (req, res) => {
    try {
        const board = getOrCreateBoard(req.params.missionId);
        const images = db.prepare(`SELECT bi.*, il.filename as image_lib_filename
            FROM board_images bi
            LEFT JOIN image_library il ON bi.image_lib_id = il.id
            WHERE bi.board_id = ? ORDER BY bi.z_index`).all(board.id);
        const connections = db.prepare('SELECT * FROM board_connections WHERE board_id = ?').all(board.id);
        const mission = db.prepare('SELECT weather FROM field_missions WHERE id = ?').get(req.params.missionId);
        res.json({ success: true, board, images: images || [], connections: connections || [], weather: (mission && mission.weather) || '' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/api/board/:missionId/image', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { imageLibId, name, x, y, w, h, isMapNode } = req.body;
        if (!imageLibId) return res.status(400).json({ success: false, message: '缺少图片ID' });
        const board = getOrCreateBoard(req.params.missionId);
        const id = uuidv4();
        const nx = x || 100, ny = y || 100, nw = w || 120, nh = h || 120;
        db.prepare(`INSERT INTO board_images (id, board_id, image_lib_id, name, m_x, m_y, m_w, m_h, p_x, p_y, p_w, p_h, is_map_node, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(id, board.id, imageLibId, name || '', nx, ny, nw, nh, nx, ny, nw, nh, isMapNode ? 1 : 0, Date.now());
        const lib = db.prepare('SELECT filename FROM image_library WHERE id = ?').get(imageLibId);
        res.json({ success: true, id, imageLibId, imageFile: lib ? lib.filename : '', name: name || '', m_x: nx, m_y: ny, m_w: nw, m_h: nh, p_x: nx, p_y: ny, p_w: nw, p_h: nh, is_map_node: isMapNode ? 1 : 0 });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/board/:missionId/image/:imageId', authenticateToken, (req, res) => {
    try {
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
        db.prepare(`UPDATE board_images SET ${updates.join(', ')} WHERE id = ?`).run(...params);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/board/:missionId/image/:imageId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        db.prepare('DELETE FROM board_connections WHERE node_a = ? OR node_b = ?').run(req.params.imageId, req.params.imageId);
        db.prepare('DELETE FROM board_images WHERE id = ?').run(req.params.imageId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/api/board/:missionId/connection', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const { nodeA, nodeB, label } = req.body;
        if (!nodeA || !nodeB) return res.status(400).json({ success: false, message: '缺少节点' });
        const board = getOrCreateBoard(req.params.missionId);
        const id = uuidv4();
        db.prepare('INSERT INTO board_connections (id, board_id, node_a, node_b, label, created_at) VALUES (?, ?, ?, ?, ?, ?)')
            .run(id, board.id, nodeA, nodeB, label || '', Date.now());
        res.json({ success: true, id, nodeA, nodeB, label: label || '' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/board/:missionId/connection/:connId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        db.prepare('DELETE FROM board_connections WHERE id = ?').run(req.params.connId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/board/:missionId/connections-toggle', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    try {
        const board = getOrCreateBoard(req.params.missionId);
        const newVal = board.show_connections ? 0 : 1;
        db.prepare('UPDATE mission_boards SET show_connections = ? WHERE id = ?').run(newVal, board.id);
        res.json({ success: true, showConnections: !!newVal });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/character/:charId/mission-boards', authenticateToken, (req, res) => {
    try {
        const rows = db.prepare(`SELECT DISTINCT fm.id as mission_id, fm.name as mission_name, mb.id as board_id
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            LEFT JOIN mission_boards mb ON mb.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.status = 'active'
            ORDER BY fm.created_at DESC`).all(req.params.charId);
        res.json(rows || []);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/board/:missionId/npc-connections', authenticateToken, (req, res) => {
    try {
        const board = getOrCreateBoard(req.params.missionId);
        const rows = db.prepare('SELECT * FROM player_npc_connections WHERE board_id = ?').all(board.id);
        res.json(rows || []);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/board/:missionId/npc-connection', authenticateToken, (req, res) => {
    try {
        const { nodeA, nodeB, connType, label } = req.body;
        if (!nodeA || !nodeB) return res.status(400).json({ success: false, message: '缺少节点' });
        const board = getOrCreateBoard(req.params.missionId);
        const id = uuidv4();
        db.prepare('INSERT INTO player_npc_connections (id, board_id, node_a, node_b, conn_type, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(id, board.id, nodeA, nodeB, connType || 'neutral', label || '', Date.now());
        res.json({ success: true, id, nodeA, nodeB, connType: connType || 'neutral', label: label || '' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/api/board/:missionId/npc-connection/:id', authenticateToken, (req, res) => {
    try {
        db.prepare('DELETE FROM player_npc_connections WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/board/:missionId/npc-connection/:id', authenticateToken, (req, res) => {
    try {
        const { label, connType } = req.body;
        const updates = [], params = [];
        if (label !== undefined) { updates.push('label = ?'); params.push(label); }
        if (connType !== undefined) { updates.push('conn_type = ?'); params.push(connType); }
        if (!updates.length) return res.json({ success: true });
        params.push(req.params.id);
        db.prepare('UPDATE player_npc_connections SET ' + updates.join(', ') + ' WHERE id = ?').run(...params);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = router;
