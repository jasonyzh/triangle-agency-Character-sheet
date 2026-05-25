const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const { ROLE, BCRYPT_ROUNDS } = require('../constants');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'database.db');
const HIGH_SECURITY_DIR = path.join(DATA_DIR, 'high-security');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

if (!fs.existsSync(HIGH_SECURITY_DIR)) {
    fs.mkdirSync(HIGH_SECURITY_DIR, { recursive: true });
    fs.writeFileSync(
        path.join(HIGH_SECURITY_DIR, 'welcome.md'),
        '# 欢迎访问高墙数据库\n\n此区域存放绝密档案。\n\n- 请遵守保密协议\n- 违者将被抹除'
    );
}

db.exec(`CREATE TABLE IF NOT EXISTS users (
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

db.exec(`CREATE TABLE IF NOT EXISTS characters (
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    data TEXT,
    created_at INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT
)`);

db.exec(`CREATE TABLE IF NOT EXISTS verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    code TEXT,
    type TEXT,
    expires_at INTEGER,
    used INTEGER DEFAULT 0
)`);

db.exec(`CREATE TABLE IF NOT EXISTS character_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    character_id TEXT,
    manager_id INTEGER,
    auth_code TEXT UNIQUE,
    created_at INTEGER,
    FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
    FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS character_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    character_id TEXT,
    share_code TEXT UNIQUE,
    password_hash TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
)`);
db.exec(`CREATE TABLE IF NOT EXISTS document_permissions (
    user_id INTEGER,
    filename TEXT,
    granted_at INTEGER,
    PRIMARY KEY (user_id, filename),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS character_document_permissions (
    character_id TEXT,
    filename TEXT,
    granted_at INTEGER,
    PRIMARY KEY (character_id, filename),
    FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS character_messages (
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

db.exec(`CREATE TABLE IF NOT EXISTS field_missions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'active',
    created_by INTEGER,
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS field_mission_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    character_id TEXT NOT NULL,
    member_status TEXT DEFAULT '待命',
    joined_at INTEGER,
    FOREIGN KEY(mission_id) REFERENCES field_missions(id) ON DELETE CASCADE,
    FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
    UNIQUE(mission_id, character_id)
)`);

db.exec(`CREATE TABLE IF NOT EXISTS manager_inbox (
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

db.exec(`CREATE TABLE IF NOT EXISTS branches (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_by INTEGER,
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS requisitions (
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
)`);

const requisitionsColumns = db.pragma('table_info(requisitions)');
const hasType = requisitionsColumns.some(col => col.name === 'type');
const hasPrice = requisitionsColumns.some(col => col.name === 'price');
const hasOnce = requisitionsColumns.some(col => col.name === 'once');

if (!hasType) {
    console.log('正在添加 type 字段到 requisitions 表...');
    try {
        db.exec("ALTER TABLE requisitions ADD COLUMN type TEXT DEFAULT 'basic'");
        console.log('✓ type 字段添加成功');
    } catch (err) {
        console.error('添加 type 字段失败:', err);
    }
}

if (!hasPrice) {
    console.log('正在添加 price 字段到 requisitions 表...');
    try {
        db.exec('ALTER TABLE requisitions ADD COLUMN price INTEGER DEFAULT 0');
        console.log('✓ price 字段添加成功');
    } catch (err) {
        console.error('添加 price 字段失败:', err);
    }
}

if (!hasOnce) {
    console.log('正在添加 once 字段到 requisitions 表...');
    try {
        db.exec('ALTER TABLE requisitions ADD COLUMN once INTEGER DEFAULT 0');
        console.log('✓ once 字段添加成功');
    } catch (err) {
        console.error('添加 once 字段失败:', err);
    }
}

db.exec(`CREATE TABLE IF NOT EXISTS requisition_purchases (
    id TEXT PRIMARY KEY,
    character_id TEXT NOT NULL,
    requisition_id TEXT NOT NULL,
    price INTEGER NOT NULL,
    purchased_at INTEGER,
    FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
    FOREIGN KEY(requisition_id) REFERENCES requisitions(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS user_requisition_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    requisition_id TEXT NOT NULL,
    granted_at INTEGER,
    UNIQUE(user_id, requisition_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(requisition_id) REFERENCES requisitions(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS branch_managers (
    branch_id TEXT NOT NULL,
    manager_id INTEGER NOT NULL,
    assigned_at INTEGER,
    PRIMARY KEY(branch_id, manager_id),
    FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
    FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS mission_reports (
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

db.exec(`CREATE TABLE IF NOT EXISTS mission_inbox (
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

const fieldMissionsColumns = db.pragma('table_info(field_missions)');
const fieldMissionsColNames = fieldMissionsColumns.map(c => c.name);
if (!fieldMissionsColNames.includes('mission_type')) {
    db.exec("ALTER TABLE field_missions ADD COLUMN mission_type TEXT DEFAULT 'containment'");
}
if (!fieldMissionsColNames.includes('chaos_value')) {
    db.exec('ALTER TABLE field_missions ADD COLUMN chaos_value INTEGER DEFAULT 0');
}
if (!fieldMissionsColNames.includes('scatter_value')) {
    db.exec('ALTER TABLE field_missions ADD COLUMN scatter_value INTEGER DEFAULT 0');
}
if (!fieldMissionsColNames.includes('branch_id')) {
    db.exec('ALTER TABLE field_missions ADD COLUMN branch_id TEXT');
}
if (!fieldMissionsColNames.includes('report_status')) {
    db.exec("ALTER TABLE field_missions ADD COLUMN report_status TEXT DEFAULT 'none'");
}

const charMessagesColumns = db.pragma('table_info(character_messages)');
const charMessagesColNames = charMessagesColumns.map(c => c.name);
if (!charMessagesColNames.includes('message_type')) {
    db.exec("ALTER TABLE character_messages ADD COLUMN message_type TEXT DEFAULT 'mail'");
}
if (!charMessagesColNames.includes('hw_filename')) {
    db.exec('ALTER TABLE character_messages ADD COLUMN hw_filename TEXT');
}
if (!charMessagesColNames.includes('from_character_id')) {
    db.exec('ALTER TABLE character_messages ADD COLUMN from_character_id TEXT');
}
if (!charMessagesColNames.includes('recipient_name')) {
    db.exec('ALTER TABLE character_messages ADD COLUMN recipient_name TEXT');
}

const defaultConfigs = [
    ['registration_enabled', 'true'],
    ['email_registration_enabled', 'false'],
    ['smtp_host', ''],
    ['smtp_port', '587'],
    ['smtp_user', ''],
    ['smtp_pass', ''],
    ['smtp_from', ''],
    ['smtp_secure', 'false'],
];

defaultConfigs.forEach(([key, value]) => {
    db.prepare('INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)').run(key, value);
});

const usersColumns = db.pragma('table_info(users)');
const usersColNames = usersColumns.map(c => c.name);

if (!usersColNames.includes('password_hash')) {
    db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
}
if (!usersColNames.includes('role')) {
    db.exec('ALTER TABLE users ADD COLUMN role INTEGER DEFAULT 0');
}
if (!usersColNames.includes('email')) {
    db.exec('ALTER TABLE users ADD COLUMN email TEXT');
}
if (!usersColNames.includes('email_verified')) {
    db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0');
}
if (!usersColNames.includes('created_at')) {
    db.exec('ALTER TABLE users ADD COLUMN created_at INTEGER');
}

const plainPasswordUsers = db
    .prepare(
        'SELECT id, password, password_hash, is_admin, role FROM users WHERE password_hash IS NULL AND password IS NOT NULL'
    )
    .all();
if (plainPasswordUsers) {
    for (const user of plainPasswordUsers) {
        try {
            const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);
            const newRole = user.is_admin ? ROLE.SUPER_ADMIN : user.role || ROLE.PLAYER;
            db.prepare('UPDATE users SET password_hash = ?, role = ? WHERE id = ?').run(hash, newRole, user.id);
        } catch (e) {
            console.error('密码迁移失败:', e);
        }
    }
}

db.exec(`CREATE TABLE IF NOT EXISTS siphon_products (
    id TEXT PRIMARY KEY,
    manager_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    price INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER,
    FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS siphon_purchases (
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

const adminRow = db.prepare('SELECT * FROM users WHERE username = ?').get(NEW_ADMIN_USERNAME);
if (!adminRow) {
    const adminHash = bcrypt.hashSync(NEW_ADMIN_PASSWORD, BCRYPT_ROUNDS);
    const testHash = bcrypt.hashSync('111', BCRYPT_ROUNDS);
    db.prepare('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        999,
        NEW_ADMIN_USERNAME,
        NEW_ADMIN_PASSWORD,
        adminHash,
        '管理员',
        1,
        ROLE.SUPER_ADMIN,
        null,
        0,
        Date.now()
    );
    db.prepare('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        1,
        '111',
        '111',
        testHash,
        '测试员',
        0,
        ROLE.PLAYER,
        null,
        0,
        Date.now()
    );
}

db.exec(`CREATE TABLE IF NOT EXISTS user_branches (
    user_id INTEGER NOT NULL,
    branch_id TEXT NOT NULL,
    assigned_at INTEGER,
    PRIMARY KEY(user_id, branch_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE
)`);

const BRANCH_MIGRATION_KEY = 'branch_migration_v2';
const branchMigrationRow = db.prepare('SELECT value FROM system_config WHERE key = ?').get(BRANCH_MIGRATION_KEY);
if (!branchMigrationRow) {
    console.log('=== 开始分部系统迁移 ===');
    const HEADQUARTERS_ID = 'hq-sanlian';
    const now = Date.now();

    const addBranchColumns = table => {
        const columns = db.pragma(`table_info(${table})`);
        const names = columns.map(c => c.name);
        if (!names.includes('branch_id')) {
            try {
                db.exec(`ALTER TABLE ${table} ADD COLUMN branch_id TEXT`);
            } catch (err) {
                if (!err.message.includes('duplicate')) console.error(`添加 ${table}.branch_id 失败:`, err);
            }
        }
    };

    addBranchColumns('characters');
    addBranchColumns('requisitions');
    addBranchColumns('siphon_products');
    addBranchColumns('manager_inbox');

    try {
        db.prepare(
            `INSERT OR IGNORE INTO branches (id, name, description, created_by, created_at, updated_at)
            VALUES (?, '三联城本部', '系统默认分部，迁移自原有数据', 999, ?, ?)`
        ).run(HEADQUARTERS_ID, now, now);
    } catch (err) {
        console.error('创建本部分部失败:', err);
    }

    db.prepare('UPDATE characters SET branch_id = ? WHERE branch_id IS NULL').run(HEADQUARTERS_ID);
    db.prepare('UPDATE requisitions SET branch_id = ? WHERE branch_id IS NULL').run(HEADQUARTERS_ID);
    db.prepare('UPDATE siphon_products SET branch_id = ? WHERE branch_id IS NULL').run(HEADQUARTERS_ID);
    db.prepare('UPDATE field_missions SET branch_id = ? WHERE branch_id IS NULL').run(HEADQUARTERS_ID);
    db.prepare('UPDATE manager_inbox SET branch_id = ? WHERE branch_id IS NULL').run(HEADQUARTERS_ID);

    const allUsers = db.prepare('SELECT id FROM users').all();
    if (allUsers) {
        const insertUserBranch = db.prepare(
            'INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)'
        );
        for (const u of allUsers) insertUserBranch.run(u.id, HEADQUARTERS_ID, now);
    }

    const allAuths = db.prepare('SELECT DISTINCT manager_id FROM character_authorizations').all();
    if (allAuths) {
        const insertAuthBranch = db.prepare(
            'INSERT OR IGNORE INTO user_branches (user_id, branch_id, assigned_at) VALUES (?, ?, ?)'
        );
        for (const a of allAuths) insertAuthBranch.run(a.manager_id, HEADQUARTERS_ID, now);
    }

    db.prepare(`INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)`).run(BRANCH_MIGRATION_KEY, String(now));
    console.log('✓ 分部系统迁移完成：三联城本部已创建，所有数据已归入');
}

db.exec(`CREATE TABLE IF NOT EXISTS branch_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    branch_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER,
    reviewed_by INTEGER,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS anomaly_templates (
    id TEXT PRIMARY KEY,
    branch_id TEXT NOT NULL,
    name TEXT NOT NULL,
    trig TEXT DEFAULT '',
    qual TEXT DEFAULT '',
    succ TEXT DEFAULT '',
    fail TEXT DEFAULT '',
    chk INTEGER DEFAULT 0,
    tdesc TEXT DEFAULT '',
    t1 TEXT DEFAULT '',
    t1v TEXT DEFAULT '',
    t2 TEXT DEFAULT '',
    t2v TEXT DEFAULT '',
    p1 TEXT DEFAULT '[]',
    p2 TEXT DEFAULT '[]',
    doc_filename TEXT DEFAULT '',
    created_at INTEGER,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS image_library (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    original_name TEXT DEFAULT '',
    category TEXT DEFAULT 'npc',
    uploaded_by INTEGER,
    created_at INTEGER
)`);

try {
    db.exec(`ALTER TABLE image_library ADD COLUMN folder TEXT DEFAULT '默认'`);
} catch {}

db.exec(`CREATE TABLE IF NOT EXISTS mission_boards (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    name TEXT DEFAULT '',
    show_connections INTEGER DEFAULT 1,
    created_at INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS board_images (
    id TEXT PRIMARY KEY,
    board_id TEXT NOT NULL,
    image_lib_id TEXT NOT NULL,
    name TEXT DEFAULT '',
    m_x REAL DEFAULT 100,
    m_y REAL DEFAULT 100,
    m_w REAL DEFAULT 120,
    m_h REAL DEFAULT 120,
    p_x REAL DEFAULT 100,
    p_y REAL DEFAULT 100,
    p_w REAL DEFAULT 120,
    p_h REAL DEFAULT 120,
    is_map_node INTEGER DEFAULT 0,
    z_index INTEGER DEFAULT 0,
    created_at INTEGER,
    FOREIGN KEY (board_id) REFERENCES mission_boards(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS board_connections (
    id TEXT PRIMARY KEY,
    board_id TEXT NOT NULL,
    node_a TEXT NOT NULL,
    node_b TEXT NOT NULL,
    label TEXT DEFAULT '',
    created_at INTEGER,
    FOREIGN KEY (board_id) REFERENCES mission_boards(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS player_npc_connections (
    id TEXT PRIMARY KEY,
    board_id TEXT NOT NULL,
    node_a TEXT NOT NULL,
    node_b TEXT NOT NULL,
    conn_type TEXT DEFAULT 'neutral',
    label TEXT DEFAULT '',
    created_at INTEGER,
    FOREIGN KEY (board_id) REFERENCES mission_boards(id) ON DELETE CASCADE
)`);

db.exec(`CREATE TABLE IF NOT EXISTS destruction_tracks (
    branch_id TEXT NOT NULL,
    cell_index INTEGER NOT NULL,
    marked_at INTEGER,
    PRIMARY KEY (branch_id, cell_index)
)`);

module.exports = { db, DATA_DIR, HIGH_SECURITY_DIR };
