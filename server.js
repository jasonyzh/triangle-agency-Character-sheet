const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3333;

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

const DB_PATH = path.join(__dirname, 'data', 'database.db');

if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}

const db = new sqlite3.Database(DB_PATH);
db.run("PRAGMA foreign_keys = ON");

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT, is_admin INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS characters (id TEXT PRIMARY KEY, user_id INTEGER, data TEXT, created_at INTEGER, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
        if (!row) {
            db.run('INSERT INTO users VALUES (?, ?, ?, ?, ?)', [999, 'admin', 'admin', '管理员', 1]); //修改账号：admin，在生成database.db之前修改。
            db.get('SELECT * FROM users WHERE username = ?', ['111'], (err2, row2) => {
                if(!row2) db.run('INSERT INTO users VALUES (?, ?, ?, ?, ?)', [1, '111', '111', '测试员', 0]);
            });
        }
    });
});



// 档案列表接口 ===
app.get('/api/characters', (req, res) => {
    db.all('SELECT id, data FROM characters WHERE user_id = ?', [req.query.userId], (err, rows) => {
        const list = (rows || []).map(row => {
            const d = JSON.parse(row.data);
            return { 
                id: row.id, 
                name: d.pName || "未命名干员", 
                func: d.pFunc || "---",      // 职能
                anom: d.pAnom || "---",      // 异常能力
                real: d.pReal || "---"       // 现实身份
            };
        });
        res.json(list);
    });
});



app.get('/api/character/:id', (req, res) => {
    db.get('SELECT data FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (row) res.json(JSON.parse(row.data));
        else res.status(404).json({});
    });
});

app.post('/api/character', (req, res) => {
    const newId = Date.now().toString();
    const data = JSON.stringify({ pName: "新进干员" });
    db.run('INSERT INTO characters (id, user_id, data, created_at) VALUES (?, ?, ?, ?)', 
        [newId, req.body.userId, data, Date.now()], 
        function(err) { res.json({ success: true, id: newId }); }
    );
});

app.put('/api/character/:id', (req, res) => {
    db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(req.body), req.params.id], function(err) {
        if (err) res.status(500).json({ success: false });
        else res.json({ success: true });
    });
});

app.delete('/api/character/:id', (req, res) => {
    db.run('DELETE FROM characters WHERE id = ?', [req.params.id], function(err) {
        res.json({ success: true });
    });
});


app.post('/api/login', (req, res) => {
    db.get('SELECT * FROM users WHERE username = ? AND password = ?', [req.body.username, req.body.password], (err, row) => {
        if (err) return res.status(500).json({ success: false });
        if (row) res.json({ success: true, userId: row.id, isAdmin: !!row.is_admin });
        else res.status(401).json({ success: false, message: "账号或密码错误" });
    });
});

app.get('/api/users', (req, res) => {
    db.all('SELECT id, username, password, name, is_admin FROM users', [], (err, users) => {
        if (err) return res.json([]);
        if (users.length === 0) return res.json([]);
        let processed = 0; const result = [];
        users.forEach(u => {
            db.get('SELECT COUNT(*) as count FROM characters WHERE user_id = ?', [u.id], (err, row) => {
                result.push({ id: u.id, username: u.username, password: u.password, name: u.name, isAdmin: !!u.is_admin, charCount: row ? row.count : 0 });
                processed++; if(processed === users.length) res.json(result);
            });
        });
    });
});
app.post('/api/users', (req, res) => {
    db.run('INSERT INTO users (id, username, password, name, is_admin) VALUES (?, ?, ?, ?, ?)', [Date.now(), req.body.username, req.body.password, req.body.name || "新职员", 0], function(err) {
        if (err) res.json({ success: false, message: "账号已存在" }); else res.json({ success: true });
    });
});
app.delete('/api/users/:id', (req, res) => {
    db.get('SELECT is_admin FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (row && row.is_admin) return res.json({ success: false, message: "不能删除管理员" });
        db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err) { res.json({ success: true }); });
    });
});
app.put('/api/users/:id', (req, res) => {
    db.run('UPDATE users SET password = ? WHERE id = ?', [req.body.password, req.params.id], function(err) { res.json({ success: true }); });
});
app.get('/api/admin/monitor', (req, res) => {
    db.all('SELECT id, name, username, is_admin FROM users', [], (err, users) => {
        if(err || !users) return res.json([]);
        if(users.length === 0) return res.json([]);
        let completed = 0; const result = [];
        users.forEach(u => {
            db.all('SELECT id, data FROM characters WHERE user_id = ?', [u.id], (err, chars) => {
                const userChars = (chars || []).map(c => { let d = {}; try { d = JSON.parse(c.data); } catch(e) {} return { id: c.id, name: d.pName || "未命名", func: d.pFunc || "未知" }; });
                result.push({ userId: u.id, userName: u.name, userAccount: u.username, isAdmin: !!u.is_admin, characters: userChars });
                completed++; if(completed === users.length) res.json(result);
            });
        });
    });
});

app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(PORT, () => {
    console.log(`服务器运行中: http://localhost:${PORT}`);
});