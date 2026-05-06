const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { db } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { HIGH_SECURITY_DIR, checkManagerAuthorization, checkManagerCharacterAuth } = require('../utils');

router.get('/api/documents/list', authenticateToken, (req, res) => {
    const charId = req.query.charId;

    fs.readdir(HIGH_SECURITY_DIR, (err, files) => {
        if (err) return res.status(500).json({ error: '无法读取文件目录' });

        const mdFiles = files.filter(f => f.endsWith('.md'));

        let sql, params;
        if (charId) {
            sql = `
                SELECT cdp.filename
                FROM character_document_permissions cdp
                JOIN characters c ON cdp.character_id = c.id
                WHERE cdp.character_id = ? AND c.user_id = ?
            `;
            params = [charId, req.user.userId];
        } else {
            sql = `
                SELECT DISTINCT cdp.filename
                FROM character_document_permissions cdp
                JOIN characters c ON cdp.character_id = c.id
                WHERE c.user_id = ?
            `;
            params = [req.user.userId];
        }

        db.all(sql, params, (err, rows) => {
            if (err) return res.status(500).json({ error: '数据库错误' });

            const allowedFiles = new Set(rows.map(r => r.filename));

            let result;
            if (charId) {
                result = mdFiles
                    .filter(file => allowedFiles.has(file) || req.user.role >= ROLE.SUPER_ADMIN)
                    .map(file => ({
                        filename: file,
                        title: file.replace(/\.md$/i, ''),
                        allowed: true
                    }));
            } else {
                result = mdFiles.map(file => ({
                    filename: file,
                    title: file.replace(/\.md$/i, ''),
                    allowed: allowedFiles.has(file) || req.user.role >= ROLE.SUPER_ADMIN
                }));
            }

            result.sort((a, b) => {
                if (a.allowed !== b.allowed) return a.allowed ? -1 : 1;
                return a.filename.localeCompare(b.filename);
            });

            res.json(result);
        });
    });
});

router.get('/api/documents/read/:filename', authenticateToken, (req, res) => {
    const filename = req.params.filename;

    if (filename.includes('..') || filename.includes('/') || !filename.endsWith('.md')) {
        return res.status(400).json({ error: '非法的文件名' });
    }

    const checkPermission = () => {
        if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
        return new Promise((resolve) => {
            const sql = `
                SELECT 1 FROM character_document_permissions cdp
                JOIN characters c ON cdp.character_id = c.id
                WHERE c.user_id = ? AND cdp.filename = ?
                LIMIT 1
            `;
            db.get(sql, [req.user.userId, filename], (err, row) => resolve(!!row));
        });
    };

    checkPermission().then(allowed => {
        if (!allowed) return res.status(403).json({ error: '权限不足：无法访问此高墙文件' });

        const filePath = path.join(HIGH_SECURITY_DIR, filename);
        if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) return res.status(500).json({ error: '读取失败' });
            res.json({ content: data });
        });
    });
});

router.get('/api/admin/user/:id/permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const userId = req.params.id;
    
    fs.readdir(HIGH_SECURITY_DIR, (err, files) => {
        if (err) return res.json([]);
        const mdFiles = files.filter(f => f.endsWith('.md'));

        db.all('SELECT filename FROM document_permissions WHERE user_id = ?', [userId], (err, rows) => {
            const allowedSet = new Set(rows ? rows.map(r => r.filename) : []);
            const result = mdFiles.map(f => ({
                filename: f,
                hasPerm: allowedSet.has(f)
            }));
            res.json(result);
        });
    });
});

router.put('/api/admin/user/:id/permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const userId = req.params.id;
    const { permissions } = req.body;

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        
        db.run('DELETE FROM document_permissions WHERE user_id = ?', [userId]);
        
        const stmt = db.prepare('INSERT INTO document_permissions (user_id, filename, granted_at) VALUES (?, ?, ?)');
        permissions.forEach(file => {
            stmt.run(userId, file, Date.now());
        });
        stmt.finalize();

        db.run('COMMIT', (err) => {
            if (err) res.status(500).json({ success: false, message: err.message });
            else res.json({ success: true });
        });
    });
});

router.get('/api/manager/user/:userId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const targetUserId = req.params.userId;

        const isAuthorized = await checkManagerAuthorization(managerId, targetUserId);
        if (!isAuthorized) {
            return res.status(403).json({ error: '无权管理该用户的权限' });
        }

        fs.readdir(HIGH_SECURITY_DIR, (err, files) => {
            if (err) return res.json([]);
            const mdFiles = files.filter(f => f.endsWith('.md'));

            db.all('SELECT filename FROM document_permissions WHERE user_id = ?', [targetUserId], (err, rows) => {
                const allowedSet = new Set(rows ? rows.map(r => r.filename) : []);
                const result = mdFiles.map(f => ({
                    filename: f,
                    hasPerm: allowedSet.has(f)
                }));
                res.json(result);
            });
        });

    } catch (e) {
        res.status(500).json({ error: '服务器内部错误' });
    }
});

router.put('/api/manager/user/:userId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const targetUserId = req.params.userId;
        const { permissions } = req.body;

        const isAuthorized = await checkManagerAuthorization(managerId, targetUserId);
        if (!isAuthorized) {
            return res.status(403).json({ success: false, message: '无权管理该用户的权限' });
        }

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run('DELETE FROM document_permissions WHERE user_id = ?', [targetUserId]);
            
            const stmt = db.prepare('INSERT INTO document_permissions (user_id, filename, granted_at) VALUES (?, ?, ?)');
            permissions.forEach(file => {
                stmt.run(targetUserId, file, Date.now());
            });
            stmt.finalize();

            db.run('COMMIT', (err) => {
                if (err) res.status(500).json({ success: false, message: err.message });
                else res.json({ success: true });
            });
        });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

router.get('/api/manager/character/:charId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;

        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权管理该角色卡的权限' });
        }

        fs.readdir(HIGH_SECURITY_DIR, (err, files) => {
            if (err) return res.json([]);
            const mdFiles = files.filter(f => f.endsWith('.md'));

            db.all('SELECT filename FROM character_document_permissions WHERE character_id = ?', [charId], (err, rows) => {
                const allowedSet = new Set(rows ? rows.map(r => r.filename) : []);
                const result = mdFiles.map(f => ({
                    filename: f,
                    hasPerm: allowedSet.has(f)
                }));
                res.json(result);
            });
        });
    } catch (e) {
        res.status(500).json({ error: '服务器内部错误' });
    }
});

router.put('/api/manager/character/:charId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { permissions } = req.body;

        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权管理该角色卡的权限' });
        }

        const currentPerms = await new Promise((resolve) => {
            db.all('SELECT filename FROM character_document_permissions WHERE character_id = ?', [charId], (err, rows) => {
                resolve(new Set((rows || []).map(r => r.filename)));
            });
        });

        const newFiles = permissions.filter(f => !currentPerms.has(f));

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run('DELETE FROM character_document_permissions WHERE character_id = ?', [charId]);

            const stmt = db.prepare('INSERT INTO character_document_permissions (character_id, filename, granted_at) VALUES (?, ?, ?)');
            const now = Date.now();
            permissions.forEach(file => {
                stmt.run(charId, file, now);
            });
            stmt.finalize();

            if (newFiles.length > 0) {
                const msgStmt = db.prepare('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, hw_filename, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
                newFiles.forEach(file => {
                    const title = file.replace(/\.md$/i, '');
                    msgStmt.run(
                        charId,
                        managerId,
                        'OS',
                        '高墙文件授权通知',
                        `您已获得查看高墙文件「${title}」的权限。\n\n请在收件箱中点击查看文件详情。`,
                        'hw_auth',
                        file,
                        now
                    );
                });
                msgStmt.finalize();
            }

            db.run('COMMIT', (err) => {
                if (err) res.status(500).json({ success: false, message: err.message });
                else res.json({ success: true, newAuthCount: newFiles.length });
            });
        });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

module.exports = router;
