const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { db, DATA_DIR } = require('../db/init');
const { ROLE } = require('../constants');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');
const { isCosEnabled, isCosConfigured, uploadToCos, deleteFromCos, keyFromCosUrl } = require('../cos');

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const initDefaultFolder = () => {
    const def = path.join(UPLOADS_DIR, '默认');
    if (!fs.existsSync(def)) {
        fs.mkdirSync(path.join(def, 'NPC'), { recursive: true });
        fs.mkdirSync(path.join(def, 'MAP'), { recursive: true });
    }
};
initDefaultFolder();

// 统一使用 memoryStorage：COS 模式直接拿 buffer 上传，本地模式落盘
const storage = multer.memoryStorage();
const upload = multer({
    storage, limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg'];
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, allowed.includes(ext));
    }
});

router.post('/api/image-library/upload', authenticateToken, requireRole(ROLE.MANAGER), upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, message: '请选择文件' });
        const id = uuidv4();
        const category = req.body.category || 'npc';
        const folder = req.body.folder || '默认';
        const catDir = category === 'map' ? 'MAP' : 'NPC';
        // 修复中文文件名乱码：multer/busboy 默认按 latin1 解码 originalname
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        const ext = path.extname(originalName);
        const basename = Date.now() + '-' + Math.round(Math.random() * 1E9) + ext;
        const relPath = folder + '/' + catDir + '/' + basename;

        // COS 模式：上传到对象存储，DB 存完整 URL
        if (isCosEnabled()) {
            if (!isCosConfigured()) {
                return res.status(400).json({ success: false, message: 'COS 已启用但凭证未配置完整，请在系统设置中填写' });
            }
            const cosKey = folder + '/' + catDir + '/' + basename;
            const { Url } = await uploadToCos(cosKey, req.file.buffer);
            db.prepare('INSERT INTO image_library (id, filename, original_name, category, folder, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
                .run(id, Url, originalName, category, folder, req.user.userId, Date.now());
            return res.json({ success: true, id, filename: basename, folder, category });
        }

        // 本地模式：把 buffer 落盘（保持原有目录结构）
        const dir = path.join(UPLOADS_DIR, folder, catDir);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, basename), req.file.buffer);
        db.prepare('INSERT INTO image_library (id, filename, original_name, category, folder, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(id, relPath, originalName, category, folder, req.user.userId, Date.now());
        res.json({ success: true, id, filename: basename, folder, category });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message || '上传失败' });
    }
});

router.delete('/api/image-library/:id', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const row = db.prepare('SELECT filename FROM image_library WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).json({ success: false, message: '图片不存在' });
        const filename = row.filename || '';

        // COS 图片：filename 是完整 URL，从 COS 删除
        if (/^https?:\/\//i.test(filename)) {
            const cosKey = keyFromCosUrl(filename);
            if (cosKey) {
                try { await deleteFromCos(cosKey); }
                catch (e) { console.error('COS 删除失败:', e.message); }
            }
        } else {
            // 本地图片：从磁盘删除
            const filePath = path.join(UPLOADS_DIR, filename);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        db.prepare('DELETE FROM image_library WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.put('/api/image-library/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: '缺少名称' });
    try {
        db.prepare('UPDATE image_library SET original_name = ? WHERE id = ?').run(name, req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.get('/api/image-library', authenticateToken, (req, res) => {
    try {
        const folder = req.query.folder || '';
        const category = req.query.category || '';
        let sql = 'SELECT * FROM image_library WHERE 1=1';
        const params = [];
        if (folder) { sql += ' AND folder = ?'; params.push(folder); }
        if (category) {
            sql += ' AND category = ?';
            params.push(category === 'map' ? 'map' : 'npc');
        }
        sql += ' ORDER BY created_at DESC';
        const rows = db.prepare(sql).all(...params);
        res.json(rows || []);
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/image-library/folders', authenticateToken, (req, res) => {
    try {
        const entries = fs.readdirSync(UPLOADS_DIR, { withFileTypes: true });
        const folders = entries
            .filter(e => e.isDirectory())
            .filter(e => {
                const npc = path.join(UPLOADS_DIR, e.name, 'NPC');
                const map = path.join(UPLOADS_DIR, e.name, 'MAP');
                return fs.existsSync(npc) && fs.existsSync(map);
            })
            .map(e => e.name)
            .sort();
        res.json(folders);
    } catch(e) { res.status(500).json({ success: false }); }
});

router.post('/api/image-library/folders', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ success: false, message: '缺少名称' });
    const safeName = name.replace(/[<>:"/\\|?*]/g, '_').trim();
    if (safeName.length === 0) return res.status(400).json({ success: false, message: '名称无效' });
    const dir = path.join(UPLOADS_DIR, safeName);
    if (fs.existsSync(dir)) return res.status(400).json({ success: false, message: '文件夹已存在' });
    try {
        fs.mkdirSync(path.join(dir, 'NPC'), { recursive: true });
        fs.mkdirSync(path.join(dir, 'MAP'), { recursive: true });
        res.json({ success: true, name: safeName });
    } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

router.put('/api/image-library/folders', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { oldName, newName } = req.body;
    if (!oldName || !newName) return res.status(400).json({ success: false, message: '缺少名称' });
    const safeNew = newName.replace(/[<>:"/\\|?*]/g, '_').trim();
    if (safeNew === '默认') return res.status(400).json({ success: false, message: '不能重命名默认文件夹' });
    const oldDir = path.join(UPLOADS_DIR, oldName);
    const newDir = path.join(UPLOADS_DIR, safeNew);
    if (!fs.existsSync(oldDir)) return res.status(404).json({ success: false, message: '文件夹不存在' });
    if (fs.existsSync(newDir)) return res.status(400).json({ success: false, message: '目标已存在' });
    try {
        fs.renameSync(oldDir, newDir);
        db.prepare('UPDATE image_library SET folder = ? WHERE folder = ?').run(safeNew, oldName);
        res.json({ success: true, name: safeNew });
    } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

router.delete('/api/image-library/folders', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: '缺少名称' });
    if (name === '默认') return res.status(400).json({ success: false, message: '不能删除默认文件夹' });
    const dir = path.join(UPLOADS_DIR, name);
    if (!fs.existsSync(dir)) return res.status(404).json({ success: false, message: '文件夹不存在' });
    const npcDir = path.join(dir, 'NPC');
    const mapDir = path.join(dir, 'MAP');
    const npcFiles = fs.existsSync(npcDir) ? fs.readdirSync(npcDir) : [];
    const mapFiles = fs.existsSync(mapDir) ? fs.readdirSync(mapDir) : [];
    if (npcFiles.length > 0 || mapFiles.length > 0)
        return res.status(400).json({ success: false, message: '文件夹不为空，请先删除所有图片' });
    try {
        fs.rmdirSync(npcDir);
        fs.rmdirSync(mapDir);
        fs.rmdirSync(dir);
        res.json({ success: true });
    } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

module.exports = router;
