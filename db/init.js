const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { ROLE, BCRYPT_ROUNDS } = require('../constants');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'database.db');
const HIGH_SECURITY_DIR = path.join(DATA_DIR, 'high-security');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

const db = new sqlite3.Database(DB_PATH);
db.run("PRAGMA foreign_keys = ON");

if (!fs.existsSync(HIGH_SECURITY_DIR)) {
    fs.mkdirSync(HIGH_SECURITY_DIR, { recursive: true });
    fs.writeFileSync(path.join(HIGH_SECURITY_DIR, 'welcome.md'), '# 欢迎访问高墙数据库\n\n此区域存放绝密档案。\n\n- 请遵守保密协议\n- 违者将被抹除');
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        password_hash TEXT,
        name TEXT,
        is_admin INTEGER,
        role INTEGER DEFAULT 0,
        email TEXT,
        email_verified INTEGER DEFAULT 0,
        created_at INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS characters (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        data TEXT,
        created_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        type TEXT,
        expires_at INTEGER,
        used INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS character_authorizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT,
        manager_id INTEGER,
        auth_code TEXT UNIQUE,
        created_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS character_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT,
        share_code TEXT UNIQUE,
        password_hash TEXT,
        created_at INTEGER,
        expires_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS document_permissions (
        user_id INTEGER,
        filename TEXT,
        granted_at INTEGER,
        PRIMARY KEY (user_id, filename),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS character_document_permissions (
        character_id TEXT,
        filename TEXT,
        granted_at INTEGER,
        PRIMARY KEY (character_id, filename),
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS character_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT,
        sender_id INTEGER,
        sender_name TEXT,
        subject TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'mail',
        hw_filename TEXT,
        read INTEGER DEFAULT 0,
        created_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS field_missions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'active',
        created_by INTEGER,
        created_at INTEGER,
        updated_at INTEGER,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS field_mission_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id TEXT NOT NULL,
        character_id TEXT NOT NULL,
        member_status TEXT DEFAULT '待命',
        joined_at INTEGER,
        FOREIGN KEY(mission_id) REFERENCES field_missions(id) ON DELETE CASCADE,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        UNIQUE(mission_id, character_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS manager_inbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manager_id INTEGER NOT NULL,
        sender_character_id TEXT,
        sender_name TEXT,
        subject TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'mail',
        report_data TEXT,
        read INTEGER DEFAULT 0,
        created_at INTEGER,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS branches (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_by INTEGER,
        created_at INTEGER,
        updated_at INTEGER,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS requisitions (
        id TEXT PRIMARY KEY,
        manager_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        pd TEXT,
        effect TEXT,
        type TEXT DEFAULT 'basic',
        price INTEGER DEFAULT 0,
        prices TEXT,
        created_at INTEGER,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('创建 requisitions 表失败:', err);
        } else {
            db.all("PRAGMA table_info(requisitions)", (err, columns) => {
                if (err) {
                    console.error('查询表结构失败:', err);
                    return;
                }
                
                const hasType = columns.some(col => col.name === 'type');
                const hasPrice = columns.some(col => col.name === 'price');
                const hasOnce = columns.some(col => col.name === 'once');
                
                if (!hasType) {
                    console.log('正在添加 type 字段到 requisitions 表...');
                    db.run("ALTER TABLE requisitions ADD COLUMN type TEXT DEFAULT 'basic'", (err) => {
                        if (err) console.error('添加 type 字段失败:', err);
                        else console.log('✓ type 字段添加成功');
                    });
                }
                
                if (!hasPrice) {
                    console.log('正在添加 price 字段到 requisitions 表...');
                    db.run("ALTER TABLE requisitions ADD COLUMN price INTEGER DEFAULT 0", (err) => {
                        if (err) console.error('添加 price 字段失败:', err);
                        else console.log('✓ price 字段添加成功');
                    });
                }

                if (!hasOnce) {
                    console.log('正在添加 once 字段到 requisitions 表...');
                    db.run("ALTER TABLE requisitions ADD COLUMN once INTEGER DEFAULT 0", (err) => {
                        if (err) console.error('添加 once 字段失败:', err);
                        else console.log('✓ once 字段添加成功');
                    });
                }
            });
        }
    });
    
    db.run(`CREATE TABLE IF NOT EXISTS requisition_purchases (
        id TEXT PRIMARY KEY,
        character_id TEXT NOT NULL,
        requisition_id TEXT NOT NULL,
        price INTEGER NOT NULL,
        purchased_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(requisition_id) REFERENCES requisitions(id) ON DELETE CASCADE
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS user_requisition_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        requisition_id TEXT NOT NULL,
        granted_at INTEGER,
        UNIQUE(user_id, requisition_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(requisition_id) REFERENCES requisitions(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS branch_managers (
        branch_id TEXT NOT NULL,
        manager_id INTEGER NOT NULL,
        assigned_at INTEGER,
        PRIMARY KEY(branch_id, manager_id),
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS mission_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id TEXT NOT NULL,
        submitted_by TEXT,
        original_data TEXT,
        revised_data TEXT,
        annotations TEXT,
        rating TEXT,
        scatter_value INTEGER DEFAULT 0,
        status TEXT DEFAULT 'submitted',
        submitted_at INTEGER,
        reviewed_at INTEGER,
        sent_at INTEGER,
        FOREIGN KEY(mission_id) REFERENCES field_missions(id) ON DELETE CASCADE,
        FOREIGN KEY(submitted_by) REFERENCES characters(id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS mission_inbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id TEXT NOT NULL,
        sender_character_id TEXT,
        sender_name TEXT,
        subject TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'mail',
        report_id INTEGER,
        read INTEGER DEFAULT 0,
        created_at INTEGER,
        FOREIGN KEY(mission_id) REFERENCES field_missions(id) ON DELETE CASCADE,
        FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE SET NULL,
        FOREIGN KEY(report_id) REFERENCES mission_reports(id) ON DELETE SET NULL
    )`);

    db.all("PRAGMA table_info(field_missions)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('mission_type')) {
            db.run("ALTER TABLE field_missions ADD COLUMN mission_type TEXT DEFAULT 'containment'");
        }
        if (!columnNames.includes('chaos_value')) {
            db.run("ALTER TABLE field_missions ADD COLUMN chaos_value INTEGER DEFAULT 0");
        }
        if (!columnNames.includes('scatter_value')) {
            db.run("ALTER TABLE field_missions ADD COLUMN scatter_value INTEGER DEFAULT 0");
        }
        if (!columnNames.includes('branch_id')) {
            db.run("ALTER TABLE field_missions ADD COLUMN branch_id TEXT");
        }
        if (!columnNames.includes('report_status')) {
            db.run("ALTER TABLE field_missions ADD COLUMN report_status TEXT DEFAULT 'none'");
        }
    });

    db.all("PRAGMA table_info(character_messages)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('message_type')) {
            db.run("ALTER TABLE character_messages ADD COLUMN message_type TEXT DEFAULT 'mail'");
        }
        if (!columnNames.includes('hw_filename')) {
            db.run("ALTER TABLE character_messages ADD COLUMN hw_filename TEXT");
        }
        if (!columnNames.includes('from_character_id')) {
            db.run("ALTER TABLE character_messages ADD COLUMN from_character_id TEXT");
        }
        if (!columnNames.includes('recipient_name')) {
            db.run("ALTER TABLE character_messages ADD COLUMN recipient_name TEXT");
        }
    });

    const defaultConfigs = [
        ['registration_enabled', 'true'],
        ['email_registration_enabled', 'false'],
        ['smtp_host', ''],
        ['smtp_port', '587'],
        ['smtp_user', ''],
        ['smtp_pass', ''],
        ['smtp_from', ''],
        ['smtp_secure', 'false']
    ];

    defaultConfigs.forEach(([key, value]) => {
        db.run('INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)', [key, value]);
    });

    db.all("PRAGMA table_info(users)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);

        if (!columnNames.includes('password_hash')) {
            db.run('ALTER TABLE users ADD COLUMN password_hash TEXT');
        }
        if (!columnNames.includes('role')) {
            db.run('ALTER TABLE users ADD COLUMN role INTEGER DEFAULT 0');
        }
        if (!columnNames.includes('email')) {
            db.run('ALTER TABLE users ADD COLUMN email TEXT');
        }
        if (!columnNames.includes('email_verified')) {
            db.run('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0');
        }
        if (!columnNames.includes('created_at')) {
            db.run('ALTER TABLE users ADD COLUMN created_at INTEGER');
        }

        db.all('SELECT id, password, password_hash, is_admin, role FROM users WHERE password_hash IS NULL AND password IS NOT NULL', [], async (err, users) => {
            if (err || !users) return;
            for (const user of users) {
                try {
                    const hash = await bcrypt.hash(user.password, BCRYPT_ROUNDS);
                    const newRole = user.is_admin ? ROLE.SUPER_ADMIN : (user.role || ROLE.PLAYER);
                    db.run('UPDATE users SET password_hash = ?, role = ? WHERE id = ?', [hash, newRole, user.id]);
                } catch (e) {
                    console.error('密码迁移失败:', e);
                }
            }
        });
    });

    db.run(`CREATE TABLE IF NOT EXISTS siphon_products (
        id TEXT PRIMARY KEY,
        manager_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        price INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS siphon_purchases (
        id TEXT PRIMARY KEY,
        character_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        price INTEGER NOT NULL,
        purchased_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(product_id) REFERENCES siphon_products(id) ON DELETE CASCADE
    )`);

const NEW_ADMIN_USERNAME = 'admin'; 
const NEW_ADMIN_PASSWORD = 'admin123';

db.get('SELECT * FROM users WHERE username = ?', [NEW_ADMIN_USERNAME], async (err, row) => {
    if (!row) {
        const adminHash = await bcrypt.hash(NEW_ADMIN_PASSWORD, BCRYPT_ROUNDS);
        const testHash = await bcrypt.hash('111', BCRYPT_ROUNDS);
        db.run('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [999, NEW_ADMIN_USERNAME, NEW_ADMIN_PASSWORD, adminHash, '管理员', 1, ROLE.SUPER_ADMIN, null, 0, Date.now()]);
        db.run('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [1, '111', '111', testHash, '测试员', 0, ROLE.PLAYER, null, 0, Date.now()]);
    }
});

// === 分部系统迁移 ===
db.run(`CREATE TABLE IF NOT EXISTS user_branches (
    user_id INTEGER NOT NULL,
    branch_id TEXT NOT NULL,
    assigned_at INTEGER,
    PRIMARY KEY(user_id, branch_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE
)`);

const BRANCH_MIGRATION_KEY = 'branch_migration_v2';
db.get('SELECT value FROM system_config WHERE key = ?', [BRANCH_MIGRATION_KEY], (err, row) => {
    if (row) return;

    console.log('=== 开始分部系统迁移 ===');
    const HEADQUARTERS_ID = 'hq-sanlian';
    const now = Date.now();

    const addBranchColumns = (table, callback) => {
        db.all(`PRAGMA table_info(${table})`, [], (err, columns) => {
            if (err) { if (callback) callback(err); return; }
            const names = columns.map(c => c.name);
            if (!names.includes('branch_id')) {
                db.run(`ALTER TABLE ${table} ADD COLUMN branch_id TEXT`, (err) => {
                    if (err && !err.message.includes('duplicate')) console.error(`添加 ${table}.branch_id 失败:`, err);
                    if (callback) callback();
                });
            } else {
                if (callback) callback();
            }
        });
    };

    let pending = 4;
    const done = () => { if (--pending === 0) migrateData(); };

    addBranchColumns('characters', done);
    addBranchColumns('requisitions', done);
    addBranchColumns('siphon_products', done);
    addBranchColumns('manager_inbox', done);

    function migrateData() {
        db.run(`INSERT OR IGNORE INTO branches (id, name, description, created_by, created_at, updated_at)
            VALUES (?, '三联城本部', '系统默认分部，迁移自原有数据', 999, ?, ?)`,
            [HEADQUARTERS_ID, now, now], (err) => {
                if (err) console.error('创建本部分部失败:', err);

                db.run('UPDATE characters SET branch_id = ? WHERE branch_id IS NULL', [HEADQUARTERS_ID]);
                db.run('UPDATE requisitions SET branch_id = ? WHERE branch_id IS NULL', [HEADQUARTERS_ID]);
                db.run('UPDATE siphon_products SET branch_id = ? WHERE branch_id IS NULL', [HEADQUARTERS_ID]);
                db.run('UPDATE field_missions SET branch_id = ? WHERE branch_id IS NULL', [HEADQUARTERS_ID]);
                db.run('UPDATE manager_inbox SET branch_id = ? WHERE branch_id IS NULL', [HEADQUARTERS_ID]);

                db.all('SELECT id FROM users', [], (err, users) => {
                    if (!users) return;
                    const stmt = db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)');
                    users.forEach(u => stmt.run(u.id, HEADQUARTERS_ID, now));
                    stmt.finalize();

                    db.all('SELECT DISTINCT manager_id FROM character_authorizations', [], (err, auths) => {
                        if (auths) {
                            const stmt2 = db.prepare('INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)');
                            auths.forEach(a => stmt2.run(a.manager_id, HEADQUARTERS_ID, now));
                            stmt2.finalize();
                        }

                        db.run(`INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)`, [BRANCH_MIGRATION_KEY, String(now)]);
                        console.log('✓ 分部系统迁移完成：三联城本部已创建，所有数据已归入');
                    });
                });
            });
    }
});

db.run(`CREATE TABLE IF NOT EXISTS branch_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    branch_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER,
    reviewed_by INTEGER,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
)`);

});

module.exports = { db, DATA_DIR, HIGH_SECURITY_DIR };
