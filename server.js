const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const cors = require('cors');
const app = express();
app.use(cors());
const PORT = 3333;
const JWT_SECRET = process.env.JWT_SECRET || 'triangle-agency-secret-key-change-in-production';
const BCRYPT_ROUNDS = 10;


// 角色常量
const ROLE = {
    PLAYER: 0,
    MANAGER: 1,
    SUPER_ADMIN: 2
};

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'database.db');

// 确保 data 目录存在
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

const db = new sqlite3.Database(DB_PATH);
db.run("PRAGMA foreign_keys = ON");

const HIGH_SECURITY_DIR = path.join(DATA_DIR, 'high-security');

// 确保目录存在
if (!fs.existsSync(HIGH_SECURITY_DIR)) {
    fs.mkdirSync(HIGH_SECURITY_DIR, { recursive: true });
    // 创建一个示例文件，避免文件夹为空
    fs.writeFileSync(path.join(HIGH_SECURITY_DIR, 'welcome.md'), '# 欢迎访问高墙数据库\n\n此区域存放绝密档案。\n\n- 请遵守保密协议\n- 违者将被抹除');
}
// ==========================================
// 数据库初始化
// ==========================================
db.serialize(() => {
    // 用户表 - 添加新字段
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

    // 角色表
    db.run(`CREATE TABLE IF NOT EXISTS characters (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        data TEXT,
        created_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 系统配置表
    db.run(`CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    // 验证码表
    db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        type TEXT,
        expires_at INTEGER,
        used INTEGER DEFAULT 0
    )`);

    // 角色授权表
    db.run(`CREATE TABLE IF NOT EXISTS character_authorizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT,
        manager_id INTEGER,
        auth_code TEXT UNIQUE,
        created_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 角色分享表
    db.run(`CREATE TABLE IF NOT EXISTS character_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT,
        share_code TEXT UNIQUE,
        password_hash TEXT,
        created_at INTEGER,
        expires_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
    )`);
	    // 高墙文件权限表（旧版，按用户）
    db.run(`CREATE TABLE IF NOT EXISTS document_permissions (
        user_id INTEGER,
        filename TEXT,
        granted_at INTEGER,
        PRIMARY KEY (user_id, filename),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 高墙文件权限表（新版，按角色卡）
    db.run(`CREATE TABLE IF NOT EXISTS character_document_permissions (
        character_id TEXT,
        filename TEXT,
        granted_at INTEGER,
        PRIMARY KEY (character_id, filename),
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
    )`);

    // 角色卡站内信表
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

    // 外勤任务表
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

    // 外勤任务成员表
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

    // 经理收件箱表（保留用于非任务相关邮件）
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

    // 分部表
    db.run(`CREATE TABLE IF NOT EXISTS branches (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_by INTEGER,
        created_at INTEGER,
        updated_at INTEGER,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )`);

    // 分部经理关联表
    db.run(`CREATE TABLE IF NOT EXISTS branch_managers (
        branch_id TEXT NOT NULL,
        manager_id INTEGER NOT NULL,
        assigned_at INTEGER,
        PRIMARY KEY(branch_id, manager_id),
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 任务报告表
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

    // 任务收件箱表
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

    // 报告特工响应表（跟踪每个特工对初评的响应）
    db.run(`CREATE TABLE IF NOT EXISTS report_agent_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL,
        character_id TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        pending_rewards TEXT,
        appeal_reason TEXT,
        responded_at INTEGER,
        FOREIGN KEY(report_id) REFERENCES mission_reports(id) ON DELETE CASCADE,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        UNIQUE(report_id, character_id)
    )`);

    // 奖惩发放记录表
    db.run(`CREATE TABLE IF NOT EXISTS reward_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id TEXT NOT NULL,
        reward_type TEXT NOT NULL,
        amount INTEGER DEFAULT 1,
        reason TEXT,
        mission_id TEXT,
        report_id INTEGER,
        issued_by INTEGER,
        issued_at INTEGER,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(mission_id) REFERENCES field_missions(id) ON DELETE SET NULL,
        FOREIGN KEY(report_id) REFERENCES mission_reports(id) ON DELETE SET NULL,
        FOREIGN KEY(issued_by) REFERENCES users(id) ON DELETE SET NULL
    )`);

    // 申领物商店表
    db.run(`CREATE TABLE IF NOT EXISTS shop_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        created_by INTEGER NOT NULL,
        is_global INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at INTEGER,
        updated_at INTEGER,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 申领物标价选项表
    db.run(`CREATE TABLE IF NOT EXISTS shop_item_prices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        price_name TEXT NOT NULL,
        price_cost INTEGER NOT NULL,
        currency_type TEXT DEFAULT 'commendation',
        usage_type TEXT DEFAULT 'permanent',
        usage_count INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        FOREIGN KEY(item_id) REFERENCES shop_items(id) ON DELETE CASCADE
    )`);

    // 迁移: 为shop_item_prices添加字段
    db.all("PRAGMA table_info(shop_item_prices)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('usage_type')) {
            db.run("ALTER TABLE shop_item_prices ADD COLUMN usage_type TEXT DEFAULT 'permanent'");
        }
        if (!columnNames.includes('usage_count')) {
            db.run("ALTER TABLE shop_item_prices ADD COLUMN usage_count INTEGER DEFAULT 0");
        }
        if (!columnNames.includes('currency_type')) {
            db.run("ALTER TABLE shop_item_prices ADD COLUMN currency_type TEXT DEFAULT 'commendation'");
        }
    });

    // 申领物购买记录表
    db.run(`CREATE TABLE IF NOT EXISTS shop_purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        price_id INTEGER NOT NULL,
        character_id TEXT NOT NULL,
        cost_paid INTEGER NOT NULL,
        purchased_at INTEGER,
        approved_by INTEGER,
        approved_at INTEGER,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(item_id) REFERENCES shop_items(id) ON DELETE CASCADE,
        FOREIGN KEY(price_id) REFERENCES shop_item_prices(id) ON DELETE CASCADE,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(approved_by) REFERENCES users(id) ON DELETE SET NULL
    )`);

    // 为 field_missions 添加新字段的迁移
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

    // 为 character_messages 添加新字段的迁移
    db.all("PRAGMA table_info(character_messages)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('message_type')) {
            db.run("ALTER TABLE character_messages ADD COLUMN message_type TEXT DEFAULT 'mail'");
        }
        if (!columnNames.includes('hw_filename')) {
            db.run("ALTER TABLE character_messages ADD COLUMN hw_filename TEXT");
        }
        // 新增：发件人角色ID，用于追踪已发邮件
        if (!columnNames.includes('from_character_id')) {
            db.run("ALTER TABLE character_messages ADD COLUMN from_character_id TEXT");
        }
        // 新增：收件人名称，用于已发邮件显示
        if (!columnNames.includes('recipient_name')) {
            db.run("ALTER TABLE character_messages ADD COLUMN recipient_name TEXT");
        }
        // 新增：关联的报告ID，用于评级通知
        if (!columnNames.includes('report_id')) {
            db.run("ALTER TABLE character_messages ADD COLUMN report_id INTEGER");
        }
    });

    // 为 characters 添加发信权限字段的迁移
    db.all("PRAGMA table_info(characters)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('can_send_messages')) {
            db.run("ALTER TABLE characters ADD COLUMN can_send_messages INTEGER DEFAULT 1");
        }
    });

    // 为 manager_inbox 添加 report_id 和 mission_id 字段的迁移
    db.all("PRAGMA table_info(manager_inbox)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('report_id')) {
            db.run("ALTER TABLE manager_inbox ADD COLUMN report_id INTEGER");
        }
        if (!columnNames.includes('mission_id')) {
            db.run("ALTER TABLE manager_inbox ADD COLUMN mission_id TEXT");
        }
    });

    // 为 mission_reports 添加申诉相关字段的迁移
    db.all("PRAGMA table_info(mission_reports)", [], (err, columns) => {
        if (err) return;
        const columnNames = columns.map(c => c.name);
        // 待结算奖惩（初评时存储）
        if (!columnNames.includes('pending_rewards')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN pending_rewards TEXT");
        }
        // 申诉理由
        if (!columnNames.includes('appeal_reason')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN appeal_reason TEXT");
        }
        // 申诉请求更改内容
        if (!columnNames.includes('appeal_requested_changes')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN appeal_requested_changes TEXT");
        }
        // 申诉时间
        if (!columnNames.includes('appeal_at')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN appeal_at INTEGER");
        }
        // 申诉回复
        if (!columnNames.includes('appeal_response')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN appeal_response TEXT");
        }
        // 最终奖惩（结算时存储）
        if (!columnNames.includes('final_rewards')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN final_rewards TEXT");
        }
        // 提交报告的角色ID
        if (!columnNames.includes('character_id')) {
            db.run("ALTER TABLE mission_reports ADD COLUMN character_id TEXT");
        }
    });

    // 初始化默认配置
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

    // 迁移：添加新列（如果不存在）
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

        // 迁移现有密码为哈希
        db.all('SELECT id, password, password_hash, is_admin, role FROM users WHERE password_hash IS NULL AND password IS NOT NULL', [], async (err, users) => {
            if (err || !users) return;
            for (const user of users) {
                try {
                    const hash = await bcrypt.hash(user.password, BCRYPT_ROUNDS);
                    // 如果是旧的 is_admin，迁移到新的 role 系统
                    const newRole = user.is_admin ? ROLE.SUPER_ADMIN : (user.role || ROLE.PLAYER);
                    db.run('UPDATE users SET password_hash = ?, role = ? WHERE id = ?', [hash, newRole, user.id]);
                } catch (e) {
                    console.error('密码迁移失败:', e);
                }
            }
        });
    });

// 初始化默认用户，修改admin在此处。
const NEW_ADMIN_USERNAME = 'sss'; 
const NEW_ADMIN_PASSWORD = 'sss';

db.get('SELECT * FROM users WHERE username = ?', [NEW_ADMIN_USERNAME], async (err, row) => {
    if (!row) {
        const adminHash = await bcrypt.hash(NEW_ADMIN_PASSWORD, BCRYPT_ROUNDS);
        const testHash = await bcrypt.hash('111', BCRYPT_ROUNDS);
        // 参数顺序: id, username, password(旧兼容字段), password_hash, name, is_admin, role, email, email_verified, created_at
        db.run('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [999, NEW_ADMIN_USERNAME, NEW_ADMIN_PASSWORD, adminHash, '管理员', 1, ROLE.SUPER_ADMIN, null, 0, Date.now()]);
        db.run('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [1, '111', '111', testHash, '测试员', 0, ROLE.PLAYER, null, 0, Date.now()]);
		}
	}); 
}); 
// ==========================================
// 工具函数
// ==========================================
// 获取系统配置
function getConfig(key) {
    return new Promise((resolve, reject) => {
        db.get('SELECT value FROM system_config WHERE key = ?', [key], (err, row) => {
            if (err) reject(err);
            else resolve(row ? row.value : null);
        });
    });
}

// 获取所有配置
function getAllConfig() {
    return new Promise((resolve, reject) => {
        db.all('SELECT key, value FROM system_config', [], (err, rows) => {
            if (err) reject(err);
            else {
                const config = {};
                (rows || []).forEach(r => config[r.key] = r.value);
                resolve(config);
            }
        });
    });
}

// 设置配置
function setConfig(key, value) {
    return new Promise((resolve, reject) => {
        db.run('INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)', [key, value], (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

// 生成短码
function generateShortCode(length = 8) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// 生成6位数字验证码
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// 创建邮件传输器
async function createMailTransporter() {
    const config = await getAllConfig();
    if (!config.smtp_host || !config.smtp_user) {
        throw new Error('SMTP未配置');
    }

    return nodemailer.createTransport({
        host: config.smtp_host,
        port: parseInt(config.smtp_port) || 587,
        secure: config.smtp_secure === 'true',
        auth: {
            user: config.smtp_user,
            pass: config.smtp_pass
        }
    });
}

// 发送验证码邮件
async function sendVerificationEmail(email, code, type = 'register') {
    const transporter = await createMailTransporter();
    const config = await getAllConfig();

    const subject = type === 'register' ? '三角机构 - 注册验证码' : '三角机构 - 密码重置验证码';
    const templatePath = path.join(DATA_DIR, 'email-template.html');

    let html;
    if (fs.existsSync(templatePath)) {
        html = fs.readFileSync(templatePath, 'utf8')
            .replace(/{{CODE}}/g, code)
            .replace(/{{TYPE}}/g, type === 'register' ? '注册' : '密码重置');
    } else {
        // 默认邮件模板
        html = `
        <div style="background:#1a252f;padding:40px;font-family:Arial,sans-serif;">
            <div style="max-width:500px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;">
                <div style="background:#c0392b;padding:20px;text-align:center;">
                    <h1 style="margin:0;color:#fff;font-size:24px;letter-spacing:2px;">TRIANGLE AGENCY</h1>
                    <p style="margin:5px 0 0;color:rgba(255,255,255,0.8);font-size:12px;">三角机构</p>
                </div>
                <div style="padding:30px;text-align:center;">
                    <p style="color:#333;font-size:16px;margin-bottom:20px;">您的${type === 'register' ? '注册' : '密码重置'}验证码是：</p>
                    <div style="background:#f8f9fa;border:2px dashed #c0392b;border-radius:8px;padding:20px;margin:20px 0;">
                        <span style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#c0392b;">${code}</span>
                    </div>
                    <p style="color:#666;font-size:14px;">验证码有效期为 <strong>5分钟</strong></p>
                    <p style="color:#999;font-size:12px;margin-top:20px;">如果这不是您的操作，请忽略此邮件。</p>
                </div>
                <div style="background:#f8f9fa;padding:15px;text-align:center;border-top:1px solid #eee;">
                    <p style="margin:0;color:#999;font-size:11px;">© Triangle Agency - 此邮件由系统自动发送</p>
                </div>
            </div>
        </div>`;
    }

    // 处理发件人格式 - 确保格式正确
    let fromAddress = config.smtp_from || config.smtp_user;
    // 如果没有尖括号格式，添加名称
    if (!fromAddress.includes('<')) {
        fromAddress = `"Triangle Agency" <${config.smtp_user}>`;
    }

    await transporter.sendMail({
        from: fromAddress,
        to: email,
        subject: subject,
        html: html
    });
}

// ==========================================
// JWT 认证中间件
// ==========================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: '未登录' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: '登录已过期' });
        }
        req.user = user;
        next();
    });
}

function requireRole(minRole) {
    return (req, res, next) => {
        if (!req.user || req.user.role < minRole) {
            return res.status(403).json({ success: false, message: '权限不足' });
        }
        next();
    };
}

// 可选认证（不强制，但会解析token）
function optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) req.user = user;
            next();
        });
    } else {
        next();
    }
}

// ==========================================
// 配置选项接口
// ==========================================
app.get('/api/options', (req, res) => {
    try {
        const readJsonFile = (filename) => {
            const filePath = path.join(DATA_DIR, filename);
            if (fs.existsSync(filePath)) {
                try {
                    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
                } catch (e) {
                    console.error(`解析 ${filename} 失败:`, e);
                    return [];
                }
            }
            return [];
        };

        const anoms = readJsonFile('anoms.json');
        const realities = readJsonFile('realities.json');
        const functions = readJsonFile('functions.json');
        const bonuses = readJsonFile('bonuses.json');

        res.json({
            anoms: anoms,
            realities: realities,
            functions: functions,
            bonuses: bonuses
        });
    } catch (error) {
        console.error("获取配置选项失败:", error);
        res.status(500).json({ anoms: [], realities: [], functions: [], bonuses: [] });
    }
});

// ==========================================
// 注册状态检查
// ==========================================
app.get('/api/register/status', async (req, res) => {
    try {
        const regEnabled = await getConfig('registration_enabled');
        const emailEnabled = await getConfig('email_registration_enabled');
        res.json({
            registrationEnabled: regEnabled === 'true',
            emailRequired: emailEnabled === 'true'
        });
    } catch (e) {
        res.json({ registrationEnabled: false, emailRequired: false });
    }
});

// ==========================================
// 发送验证码
// ==========================================
app.post('/api/register/send-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '邮箱不能为空' });
        }

        const emailEnabled = await getConfig('email_registration_enabled');
        if (emailEnabled !== 'true') {
            return res.status(400).json({ success: false, message: '邮箱注册未启用' });
        }

        // 检查邮箱是否已注册
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: '该邮箱已被注册' });
        }

        // 生成验证码
        const code = generateVerificationCode();
        const expiresAt = Date.now() + 5 * 60 * 1000; // 5分钟

        // 保存验证码
        db.run('INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)',
            [email, code, 'register', expiresAt]);

        // 发送邮件
        await sendVerificationEmail(email, code, 'register');

        res.json({ success: true, message: '验证码已发送' });
    } catch (e) {
        console.error('发送验证码失败:', e);
        res.status(500).json({ success: false, message: '发送失败: ' + e.message });
    }
});

// ==========================================
// 验证并注册
// ==========================================
app.post('/api/register/verify', async (req, res) => {
    try {
        const { username, password, name, email, code } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: '账号和密码必填' });
        }

        const regEnabled = await getConfig('registration_enabled');
        if (regEnabled !== 'true') {
            return res.status(400).json({ success: false, message: '注册功能已关闭' });
        }

        const emailEnabled = await getConfig('email_registration_enabled');

        // 如果启用了邮箱注册，验证验证码
        if (emailEnabled === 'true') {
            if (!email || !code) {
                return res.status(400).json({ success: false, message: '邮箱和验证码必填' });
            }

            const validCode = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ? AND type = ? AND used = 0 AND expires_at > ?',
                    [email, code, 'register', Date.now()], (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    });
            });

            if (!validCode) {
                return res.status(400).json({ success: false, message: '验证码无效或已过期' });
            }

            // 标记验证码已使用
            db.run('UPDATE verification_codes SET used = 1 WHERE id = ?', [validCode.id]);
        }

        // 检查用户名是否已存在
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: '账号已存在' });
        }

        // 创建用户 - 不存储明文密码
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = Date.now();

        db.run('INSERT INTO users (id, username, password_hash, name, is_admin, role, email, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, username, passwordHash, name || '新职员', 0, ROLE.PLAYER, email || null, emailEnabled === 'true' ? 1 : 0, Date.now()],
            function(err) {
                if (err) {
                    return res.status(500).json({ success: false, message: '注册失败' });
                }
                res.json({ success: true, message: '注册成功' });
            });
    } catch (e) {
        console.error('注册失败:', e);
        res.status(500).json({ success: false, message: '注册失败: ' + e.message });
    }
});

// ==========================================
// 登录接口
// ==========================================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!user) {
            return res.status(401).json({ success: false, message: '账号或密码错误' });
        }

        // 验证密码（优先使用哈希，兼容旧密码）
        let validPassword = false;
        if (user.password_hash) {
            validPassword = await bcrypt.compare(password, user.password_hash);
        } else if (user.password === password) {
            // 旧密码匹配，迁移到新哈希
            validPassword = true;
            const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
            db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, user.id]);
        }

        if (!validPassword) {
            return res.status(401).json({ success: false, message: '账号或密码错误' });
        }

        // 确定角色
        const role = user.role !== undefined ? user.role : (user.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER);

        // 生成 JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            userId: user.id,
            isAdmin: role >= ROLE.SUPER_ADMIN,
            isManager: role >= ROLE.MANAGER,
            role: role,
            token: token
        });
    } catch (e) {
        console.error('登录失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// ==========================================
// 系统配置 API（超管）
// ==========================================
app.get('/api/admin/config', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const config = await getAllConfig();
        // 不返回密码明文
        if (config.smtp_pass) {
            config.smtp_pass_set = true;
            config.smtp_pass = '********';
        }
        res.json(config);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/admin/config', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const updates = req.body;
        for (const [key, value] of Object.entries(updates)) {
            // 跳过空密码更新
            if (key === 'smtp_pass' && value === '********') continue;
            await setConfig(key, value);
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/admin/test-smtp', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const transporter = await createMailTransporter();
        await transporter.verify();
        res.json({ success: true, message: 'SMTP连接成功' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'SMTP连接失败: ' + e.message });
    }
});

// 切换全局私信开关
app.post('/api/admin/toggle-messaging', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const config = await getAllConfig();
        const currentState = config.messaging_enabled !== 'false'; // 默认开启
        const newState = !currentState;
        await setConfig('messaging_enabled', newState ? 'true' : 'false');
        res.json({
            success: true,
            enabled: newState,
            message: newState ? '私信功能已开启' : '私信功能已关闭'
        });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 获取私信开关状态
app.get('/api/admin/messaging-status', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const config = await getAllConfig();
        const enabled = config.messaging_enabled !== 'false';
        res.json({ success: true, enabled });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// ==========================================
// 用户管理 API
// ==========================================
app.get('/api/users', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    // 不查询密码字段
    db.all('SELECT id, username, name, is_admin, role, email, email_verified, created_at FROM users', [], (err, users) => {
        if (err || !users || users.length === 0) return res.json([]);
        let processed = 0;
        const result = [];
        users.forEach(u => {
            db.get('SELECT COUNT(*) as count FROM characters WHERE user_id = ?', [u.id], (err, row) => {
                result.push({
                    id: u.id,
                    username: u.username,
                    // 不返回密码，只显示是否已设置
                    hasPassword: true,
                    name: u.name,
                    isAdmin: u.role >= ROLE.SUPER_ADMIN || !!u.is_admin,
                    role: u.role || (u.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER),
                    email: u.email,
                    emailVerified: !!u.email_verified,
                    charCount: row ? row.count : 0
                });
                processed++;
                if (processed === users.length) res.json(result);
            });
        });
    });
});

app.post('/api/users', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const { username, password, name, role } = req.body;
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userRole = role !== undefined ? role : ROLE.PLAYER;

        // 不存储明文密码，只存储哈希
        db.run('INSERT INTO users (id, username, password_hash, name, is_admin, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [Date.now(), username, passwordHash, name || '新职员', userRole >= ROLE.SUPER_ADMIN ? 1 : 0, userRole, Date.now()],
            function(err) {
                if (err) res.json({ success: false, message: '账号已存在' });
                else res.json({ success: true });
            });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.delete('/api/users/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.get('SELECT role, is_admin FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (row && (row.role >= ROLE.SUPER_ADMIN || row.is_admin)) {
            return res.json({ success: false, message: '不能删除超级管理员' });
        }
        db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err) {
            res.json({ success: true });
        });
    });
});

app.put('/api/users/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), async (req, res) => {
    try {
        const { password, role } = req.body;

        if (password) {
            const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
            // 只更新哈希，清空明文密码字段
            db.run('UPDATE users SET password = NULL, password_hash = ? WHERE id = ?',
                [passwordHash, req.params.id]);
        }

        if (role !== undefined) {
            db.run('UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
                [role, role >= ROLE.SUPER_ADMIN ? 1 : 0, req.params.id]);
        }

        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 修改用户角色
app.put('/api/admin/users/:id/role', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const { role } = req.body;
    if (role === undefined) {
        return res.status(400).json({ success: false, message: '角色不能为空' });
    }

    db.run('UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
        [role, role >= ROLE.SUPER_ADMIN ? 1 : 0, req.params.id],
        function(err) {
            if (err) res.status(500).json({ success: false });
            else res.json({ success: true });
        });
});

// ==========================================
// 角色卡 API
// ==========================================
app.get('/api/characters', (req, res) => {
    db.all('SELECT id, data FROM characters WHERE user_id = ?', [req.query.userId], (err, rows) => {
        const list = (rows || []).map(row => {
            let d = {};
            try { d = JSON.parse(row.data); } catch(e) {}
            return {
                id: row.id,
                name: d.pName || "未命名干员",
                func: d.pFunc || "---",
                anom: d.pAnom || "---",
                real: d.pReal || "---"
            };
        });
        res.json(list);
    });
});

// ==========================================
// 角色卡 API - 获取单个角色 (修正版)
// ==========================================
app.get('/api/character/:id', optionalAuth, (req, res) => {
    db.get('SELECT * FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (err) {
            console.error('查询角色失败:', err);
            return res.status(500).json({ error: '数据库查询失败' });
        }
        if (!row) return res.status(404).json({});

        // 检查访问权限 (这部分逻辑保持不变)
        const checkAccess = () => {
            if (req.user && req.user.role >= ROLE.SUPER_ADMIN) return true;
            if (req.user && req.user.userId === row.user_id) return true;
            return new Promise((resolve) => {
                if (!req.user || req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [req.params.id, req.user.userId], (err, auth) => resolve(!!auth));
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess && req.user) {
                return res.status(403).json({ error: '无权访问此角色卡' });
            }

            db.get('SELECT name, username FROM users WHERE id = ?', [row.user_id], (err, owner) => {
                try {
                    const data = JSON.parse(row.data);

                    // ==================== 核心修正 START ====================
                    // 处理 rewards 和 reprimands 可能是数组或数字的情况
                    let totalRewards = 0;
                    let totalReprimands = 0;

                    if (Array.isArray(data.rewards)) {
                        totalRewards = data.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
                    } else if (typeof data.rewards === 'number') {
                        totalRewards = data.rewards;
                    }

                    if (Array.isArray(data.reprimands)) {
                        totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                    } else if (typeof data.reprimands === 'number') {
                        totalReprimands = data.reprimands;
                    }

                    // 累加任务结算的数值
                    totalRewards += parseInt(data.commendations) || 0;
                    totalReprimands += parseInt(data.reprimands) || 0;

                    data.mvpCount = data.mvpCount || 0;
                    data.watchCount = data.probationCount || 0;
                    data.commendations = totalRewards;
                    data.reprimandsCount = totalReprimands;
                    // ===================== 核心修正 END ======================

                    data._ownerId = row.user_id;
                    data._canEdit = hasAccess;
                    data.ownerName = owner ? (owner.name || owner.username) : '未知';
                    data.anomSlots = data.anomSlots || 3;
                    data.realSlots = data.realSlots || 3;
                    data.canSendMessages = row.can_send_messages !== 0; // 默认允许发信

                    res.json(data);
                } catch (e) {
                    console.error('处理角色数据失败:', e);
                    res.status(500).json({ error: e.message });
                }
            });
        });
    });
});

app.post('/api/character', (req, res) => {
    const newId = Date.now().toString();
    const data = JSON.stringify({ pName: "新进职员" });
    db.run('INSERT INTO characters (id, user_id, data, created_at) VALUES (?, ?, ?, ?)',
        [newId, req.body.userId, data, Date.now()],
        function(err) { res.json({ success: true, id: newId }); }
    );
});

app.put('/api/character/:id', optionalAuth, (req, res) => {
    // 检查编辑权限
    db.get('SELECT user_id FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false });

        const checkEditAccess = () => {
            if (req.user && req.user.role >= ROLE.SUPER_ADMIN) return true;
            if (req.user && req.user.userId === row.user_id) return true;

            return new Promise((resolve) => {
                if (!req.user || req.user.role < ROLE.MANAGER) {
                    resolve(false);
                    return;
                }
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [req.params.id, req.user.userId], (err, auth) => {
                        resolve(!!auth);
                    });
            });
        };

        Promise.resolve(checkEditAccess()).then(canEdit => {
            if (!canEdit) {
                return res.status(403).json({ success: false, message: '无权编辑此角色卡' });
            }

            // 先获取现有数据，保留嘉奖和申诫记录
            db.get('SELECT data FROM characters WHERE id = ?', [req.params.id], (err, existingRow) => {
                let existingData = {};
                try {
                    if (existingRow && existingRow.data) {
                        existingData = JSON.parse(existingRow.data);
                    }
                } catch (e) {}

                // 合并数据，保留嘉奖/申诫记录
                const newData = {
                    ...req.body,
                    rewards: existingData.rewards || [],
                    reprimands: existingData.reprimands || []
                };

                db.run('UPDATE characters SET data = ? WHERE id = ?',
                    [JSON.stringify(newData), req.params.id],
                    function(err) {
                        if (err) res.status(500).json({ success: false });
                        else res.json({ success: true });
                    });
            });
        });
    });
});

app.delete('/api/character/:id', (req, res) => {
    db.run('DELETE FROM characters WHERE id = ?', [req.params.id], function(err) {
        res.json({ success: true });
    });
});

// ==========================================
// 授权管理 API
// ==========================================

// 生成授权码
app.post('/api/character/:id/auth-code', authenticateToken, (req, res) => {
    const charId = req.params.id;

    // 验证是所有者
    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '只有所有者可以生成授权码' });
        }

        const authCode = uuidv4();
        db.run('INSERT INTO character_authorizations (character_id, auth_code, created_at) VALUES (?, ?, ?)',
            [charId, authCode, Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true, authCode: authCode });
            });
    });
});

// 获取角色的授权列表
app.get('/api/character/:id/authorizations', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json([]);
        }

        db.all(`SELECT ca.id, ca.auth_code, ca.manager_id, ca.created_at, u.name as manager_name, u.username as manager_username
                FROM character_authorizations ca
                LEFT JOIN users u ON ca.manager_id = u.id
                WHERE ca.character_id = ?`, [charId], (err, rows) => {
            res.json(rows || []);
        });
    });
});

// 经理认领授权
app.post('/api/auth/claim', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { authCode } = req.body;

    if (!authCode) {
        return res.status(400).json({ success: false, message: '授权码不能为空' });
    }

    db.get('SELECT * FROM character_authorizations WHERE auth_code = ?', [authCode], (err, auth) => {
        if (!auth) {
            return res.status(404).json({ success: false, message: '授权码无效' });
        }

        if (auth.manager_id) {
            return res.status(400).json({ success: false, message: '该授权码已被使用' });
        }

        // 检查是否已有该角色的授权
        db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
            [auth.character_id, req.user.userId], (err, existing) => {
                if (existing) {
                    return res.status(400).json({ success: false, message: '您已拥有该角色的授权' });
                }

                // 绑定经理
                db.run('UPDATE character_authorizations SET manager_id = ? WHERE id = ?',
                    [req.user.userId, auth.id],
                    function(err) {
                        if (err) return res.status(500).json({ success: false });
                        res.json({ success: true, message: '授权成功' });
                    });
            });
    });
});

// 经理获取已授权的角色列表
// MODIFIED: 超级管理员可看到全部角色卡
app.get('/api/manager/characters', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    // 解析角色数据的辅助函数
    const parseCharData = (row, authId = null) => {
        let d = {};
        try { d = JSON.parse(row.data); } catch(e) {}

        // 计算嘉奖总数（从rewards数组）
        let totalCommendations = 0;
        if (Array.isArray(d.rewards)) {
            totalCommendations = d.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
        }
        totalCommendations += parseInt(d.commendations) || 0;

        // 计算申诫总数（从reprimands数组）
        let totalReprimands = 0;
        if (Array.isArray(d.reprimands)) {
            totalReprimands = d.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
        }

        return {
            id: row.id,
            name: d.pName || "未命名干员",
            func: d.pFunc || "---",
            anom: d.pAnom || "---",
            real: d.pReal || "---",
            commendations: totalCommendations,
            reprimands: totalReprimands,
            mvpCount: parseInt(d.mvpCount) || 0,
            probationCount: parseInt(d.probationCount) || 0,
            ownerName: row.owner_name,
            ownerId: row.user_id,
            authId: authId,
            canSendMessages: row.can_send_messages !== 0, // 默认允许发信
            reprimandShopAccess: d.reprimandShopAccess === true // 申诫商店权限，默认关闭
        };
    };

    // 超级管理员可看到全部角色卡
    if (req.user.role >= ROLE.SUPER_ADMIN) {
        db.all(`SELECT c.id, c.data, c.user_id, c.can_send_messages, u.name as owner_name
                FROM characters c
                JOIN users u ON c.user_id = u.id`, [], (err, rows) => {
            const list = (rows || []).map(row => parseCharData(row));
            res.json(list);
        });
    } else {
        // 普通经理只能看到已授权的角色卡
        db.all(`SELECT c.id, c.data, c.user_id, c.can_send_messages, u.name as owner_name, ca.id as auth_id
                FROM characters c
                JOIN character_authorizations ca ON c.id = ca.character_id
                JOIN users u ON c.user_id = u.id
                WHERE ca.manager_id = ?`, [req.user.userId], (err, rows) => {
            const list = (rows || []).map(row => parseCharData(row, row.auth_id));
            res.json(list);
        });
    }
});

// 撤销授权
app.delete('/api/auth/:authId', authenticateToken, (req, res) => {
    db.get(`SELECT ca.*, c.user_id FROM character_authorizations ca
            JOIN characters c ON ca.character_id = c.id
            WHERE ca.id = ?`, [req.params.authId], (err, auth) => {
        if (!auth) return res.status(404).json({ success: false });

        // 角色所有者、超管、或被授权的经理本人可以撤销
        const canRevoke = auth.user_id === req.user.userId ||
                          req.user.role >= ROLE.SUPER_ADMIN ||
                          auth.manager_id === req.user.userId;
        if (!canRevoke) {
            return res.status(403).json({ success: false, message: '无权撤销此授权' });
        }

        db.run('DELETE FROM character_authorizations WHERE id = ?', [req.params.authId],
            function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
    });
});

// ==========================================
// 槽位管理 API（经理/超管）
// ==========================================

// 获取角色槽位信息
app.get('/api/character/:id/slots', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ error: '角色不存在' });

        // 检查权限：经理需要有授权，或者是超管
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);

            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) {
                    resolve(false);
                    return;
                }
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [charId, req.user.userId], (err, auth) => {
                        resolve(!!auth);
                    });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ error: '无权访问' });
            }

            try {
                const data = JSON.parse(row.data);
                res.json({
                    anomSlots: data.anomSlots || 3,  // 默认3个槽位
                    realSlots: data.realSlots || 3,  // 默认3个槽位
                    currentAnoms: (data.anoms || []).length,
                    currentReals: (data.reals || []).length
                });
            } catch (e) {
                res.json({ anomSlots: 3, realSlots: 3, currentAnoms: 0, currentReals: 0 });
            }
        });
    });
});

// 经理增加槽位
app.put('/api/character/:id/slots', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { anomSlots, realSlots } = req.body;

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // 检查权限：需要有授权或是超管
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);

            return new Promise((resolve) => {
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [charId, req.user.userId], (err, auth) => {
                        resolve(!!auth);
                    });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ success: false, message: '无权修改此角色' });
            }

            try {
                const data = JSON.parse(row.data);

                // 更新槽位数量（只能增加，不能减少现有数量以下）
                if (anomSlots !== undefined) {
                    const currentAnomSlots = data.anomSlots || 3;
                    const currentAnomCount = (data.anoms || []).length;
                    // 新槽位数不能低于当前已有数量，且不能低于默认值3
                    data.anomSlots = Math.max(anomSlots, currentAnomCount, 3);
                }

                if (realSlots !== undefined) {
                    const currentRealSlots = data.realSlots || 3;
                    const currentRealCount = (data.reals || []).length;
                    data.realSlots = Math.max(realSlots, currentRealCount, 3);
                }

                db.run('UPDATE characters SET data = ? WHERE id = ?',
                    [JSON.stringify(data), charId],
                    function(err) {
                        if (err) return res.status(500).json({ success: false });
                        res.json({
                            success: true,
                            anomSlots: data.anomSlots,
                            realSlots: data.realSlots
                        });
                    });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

// ==========================================
// 嘉奖/申诫 API（经理）
// ==========================================

// 获取角色的嘉奖/申诫记录
app.get('/api/character/:id/records', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ error: '角色不存在' });

        // 检查权限：经理需要有授权或任务成员关系，或者是超管，或者是角色所有者
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);

            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) {
                    resolve(false);
                    return;
                }
                // 首先检查授权表
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [charId, req.user.userId], (err, auth) => {
                        if (auth) return resolve(true);

                        // 然后检查任务成员关系 - 角色是否在该经理创建的任务中
                        db.get(`SELECT 1 FROM field_mission_members fmm
                            JOIN field_missions fm ON fmm.mission_id = fm.id
                            WHERE fmm.character_id = ? AND fm.created_by = ? AND fm.status = 'active'`,
                            [charId, req.user.userId], (err, member) => {
                                resolve(!!member);
                            });
                    });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ error: '无权访问' });
            }

            try {
                const data = JSON.parse(row.data);
                res.json({
                    rewards: data.rewards || [],
                    reprimands: data.reprimands || []
                });
            } catch (e) {
                res.json({ rewards: [], reprimands: [] });
            }
        });
    });
});

// 添加嘉奖记录

// 添加嘉奖记录
app.post('/api/character/:id/reward', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { reason, count } = req.body;
    const recordCount = Math.max(1, Math.min(99, parseInt(count) || 1));

    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '请填写嘉奖原因' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // ... (权限检查代码保持不变) ...
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?', [charId, req.user.userId], (err, auth) => {
                    if (auth) return resolve(true);
                    db.get(`SELECT 1 FROM field_mission_members fmm JOIN field_missions fm ON fmm.mission_id = fm.id WHERE fmm.character_id = ? AND fm.created_by = ? AND fm.status = 'active'`, [charId, req.user.userId], (err, member) => resolve(!!member));
                });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ success: false, message: '无权修改此角色' });
            }

            try {
                const data = JSON.parse(row.data);
                if (!data.rewards) data.rewards = [];

                data.rewards.push({
                    id: Date.now().toString(),
                    reason: reason.trim(),
                    count: recordCount,
                    date: Date.now(),
                    addedByName: req.user.username // 记录操作者
                });

                // 核心修正：重新计算总数
                const totalRewards = data.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
                data.mvpCount = totalRewards;

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    res.json({ success: true, message: `已添加 ${recordCount} 个嘉奖` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

// 添加申诫记录
app.post('/api/character/:id/reprimand', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const { reason, count } = req.body;
    const recordCount = Math.max(1, Math.min(99, parseInt(count) || 1));

    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '请填写申诫原因' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // ... (权限检查代码保持不变) ...
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?', [charId, req.user.userId], (err, auth) => {
                    if (auth) return resolve(true);
                    db.get(`SELECT 1 FROM field_mission_members fmm JOIN field_missions fm ON fmm.mission_id = fm.id WHERE fmm.character_id = ? AND fm.created_by = ? AND fm.status = 'active'`, [charId, req.user.userId], (err, member) => resolve(!!member));
                });
            });
        };
        
        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ success: false, message: '无权修改此角色' });
            }

            try {
                const data = JSON.parse(row.data);
                if (!data.reprimands) data.reprimands = [];

                data.reprimands.push({
                    id: Date.now().toString(),
                    reason: reason.trim(),
                    count: recordCount,
                    date: Date.now(),
                    addedByName: req.user.username
                });

                // 核心修正：重新计算总数
                const totalReprimands = data.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                data.watchCount = totalReprimands;

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    res.json({ success: true, message: `已添加 ${recordCount} 个申诫` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

// 删除嘉奖/申诫记录
app.delete('/api/character/:id/record/:recordId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const charId = req.params.id;
    const recordId = req.params.recordId;
    const { type } = req.query;

    if (!type || !['reward', 'reprimand'].includes(type)) {
        return res.status(400).json({ success: false, message: '无效的记录类型' });
    }

    db.get('SELECT data, user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false, message: '角色不存在' });

        // ... (权限检查代码保持不变) ...
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) return resolve(false);
                db.get('SELECT id FROM character_authorizations WHERE character_id = ? AND manager_id = ?', [charId, req.user.userId], (err, auth) => {
                    if (auth) return resolve(true);
                    db.get(`SELECT 1 FROM field_mission_members fmm JOIN field_missions fm ON fmm.mission_id = fm.id WHERE fmm.character_id = ? AND fm.created_by = ? AND fm.status = 'active'`, [charId, req.user.userId], (err, member) => resolve(!!member));
                });
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) {
                return res.status(403).json({ success: false, message: '无权修改此角色' });
            }

            try {
                const data = JSON.parse(row.data);
                const arrayKey = type === 'reward' ? 'rewards' : 'reprimands';
                const countKey = type === 'reward' ? 'mvpCount' : 'watchCount';

                if (!data[arrayKey]) return res.status(404).json({ success: false, message: '记录不存在' });

                // 核心修正：删除后重新计算总数
                data[arrayKey] = data[arrayKey].filter(r => r.id !== recordId);
                const newTotal = data[arrayKey].reduce((sum, r) => sum + (r.count || 1), 0);
                data[countKey] = newTotal;

                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(data), charId], function(err) {
                    if (err) return res.status(500).json({ success: false });
                    res.json({ success: true, message: `记录已删除` });
                });
            } catch (e) {
                res.status(500).json({ success: false, message: '数据解析失败' });
            }
        });
    });
});

// 分享 API
// ==========================================

// 创建分享链接
app.post('/api/character/:id/share', authenticateToken, async (req, res) => {
    try {
        const charId = req.params.id;
        const { password, expiresIn } = req.body; // expiresIn: 小时数，null为永久

        // 验证是所有者
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '只有所有者可以分享' });
        }

        // 删除旧的分享
        await new Promise((resolve) => {
            db.run('DELETE FROM character_shares WHERE character_id = ?', [charId], resolve);
        });

        const shareCode = generateShortCode(8);
        const passwordHash = password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null;
        const expiresAt = expiresIn ? Date.now() + expiresIn * 60 * 60 * 1000 : null;

        db.run('INSERT INTO character_shares (character_id, share_code, password_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            [charId, shareCode, passwordHash, Date.now(), expiresAt],
            function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({
                    success: true,
                    shareCode: shareCode,
                    hasPassword: !!password,
                    expiresAt: expiresAt
                });
            });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 获取分享的角色数据
app.post('/api/share/:code', async (req, res) => {
    try {
        const { password } = req.body;

        const share = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM character_shares WHERE share_code = ?', [req.params.code], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!share) {
            return res.status(404).json({ success: false, message: '分享链接不存在' });
        }

        // 检查是否过期
        if (share.expires_at && share.expires_at < Date.now()) {
            return res.status(410).json({ success: false, message: '分享链接已过期' });
        }

        // 检查密码
        if (share.password_hash) {
            if (!password) {
                return res.json({ success: false, needPassword: true });
            }
            const valid = await bcrypt.compare(password, share.password_hash);
            if (!valid) {
                return res.status(401).json({ success: false, message: '密码错误' });
            }
        }

        // 获取角色数据
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT data FROM characters WHERE id = ?', [share.character_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) {
            return res.status(404).json({ success: false, message: '角色不存在' });
        }

        res.json({ success: true, data: JSON.parse(char.data) });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 检查分享状态（是否需要密码）
app.get('/api/share/:code/status', async (req, res) => {
    const share = await new Promise((resolve, reject) => {
        db.get('SELECT password_hash, expires_at FROM character_shares WHERE share_code = ?', [req.params.code], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });

    if (!share) {
        return res.status(404).json({ exists: false });
    }

    if (share.expires_at && share.expires_at < Date.now()) {
        return res.status(410).json({ exists: false, expired: true });
    }

    res.json({
        exists: true,
        needPassword: !!share.password_hash
    });
});

// 删除分享
app.delete('/api/character/:id/share', authenticateToken, (req, res) => {
    db.get('SELECT user_id FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ success: false });
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false });
        }

        db.run('DELETE FROM character_shares WHERE character_id = ?', [req.params.id],
            function(err) {
                res.json({ success: true });
            });
    });
});

// 获取角色的分享状态
app.get('/api/character/:id/share', authenticateToken, (req, res) => {
    db.get('SELECT user_id FROM characters WHERE id = ?', [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ exists: false });
        if (row.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ exists: false });
        }

        db.get('SELECT share_code, password_hash, created_at, expires_at FROM character_shares WHERE character_id = ?',
            [req.params.id], (err, share) => {
                if (!share) return res.json({ exists: false });
                res.json({
                    exists: true,
                    shareCode: share.share_code,
                    hasPassword: !!share.password_hash,
                    createdAt: share.created_at,
                    expiresAt: share.expires_at
                });
            });
    });
});

// ==========================================
// 监控 API（管理员）
// ==========================================
app.get('/api/admin/monitor', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    db.all('SELECT id, name, username, is_admin, role FROM users', [], (err, users) => {
        if (err || !users || users.length === 0) return res.json([]);
        let completed = 0;
        const result = [];
        users.forEach(u => {
            db.all('SELECT id, data FROM characters WHERE user_id = ?', [u.id], (err, chars) => {
                const userChars = (chars || []).map(c => {
                    let d = {};
                    try { d = JSON.parse(c.data); } catch(e) {}
                    return { id: c.id, name: d.pName || "未命名", func: d.pFunc || "未知" };
                });
                result.push({
                    userId: u.id,
                    userName: u.name,
                    userAccount: u.username,
                    isAdmin: u.role >= ROLE.SUPER_ADMIN || !!u.is_admin,
                    role: u.role || (u.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER),
                    characters: userChars
                });
                completed++;
                if (completed === users.length) res.json(result);
            });
        });
    });
});

// ==========================================
// 验证 Token
// ==========================================
app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        userId: req.user.userId,
        username: req.user.username,
        role: req.user.role
    });
});

// ==========================================
// 首页重定向
// ==========================================
app.get('/', (req, res) => res.redirect('/login.html'));

// ==========================================
// 高墙文件 API
// ==========================================

// 1. 获取当前用户的文件列表（包含权限状态）
// 支持按特定角色卡筛选：?charId=xxx 只显示该角色卡授权的文件
app.get('/api/documents/list', authenticateToken, (req, res) => {
    const charId = req.query.charId; // 可选参数：指定角色卡ID

    fs.readdir(HIGH_SECURITY_DIR, (err, files) => {
        if (err) return res.status(500).json({ error: '无法读取文件目录' });

        // 1. 只获取 .md 文件名
        const mdFiles = files.filter(f => f.endsWith('.md'));

        // 2. 根据是否指定角色卡，选择不同的查询方式
        let sql, params;
        if (charId) {
            // 指定角色卡：只查该角色卡的权限
            sql = `
                SELECT cdp.filename
                FROM character_document_permissions cdp
                JOIN characters c ON cdp.character_id = c.id
                WHERE cdp.character_id = ? AND c.user_id = ?
            `;
            params = [charId, req.user.userId];
        } else {
            // 未指定：合并用户所有角色卡的权限
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

            // 3. 构造返回数据
            let result;
            if (charId) {
                // 指定角色卡模式：只返回已授权的文件（不显示未授权的）
                result = mdFiles
                    .filter(file => allowedFiles.has(file) || req.user.role >= ROLE.SUPER_ADMIN)
                    .map(file => ({
                        filename: file,
                        title: file.replace(/\.md$/i, ''),
                        allowed: true
                    }));
            } else {
                // 常规模式：返回所有文件（标记授权状态）
                result = mdFiles.map(file => ({
                    filename: file,
                    title: file.replace(/\.md$/i, ''),
                    allowed: allowedFiles.has(file) || req.user.role >= ROLE.SUPER_ADMIN
                }));
            }

            // 4. 排序
            result.sort((a, b) => {
                if (a.allowed !== b.allowed) return a.allowed ? -1 : 1;
                return a.filename.localeCompare(b.filename);
            });

            res.json(result);
        });
    });
});

// 2. 读取文件内容 (需权限验证)
// 按角色卡授权：检查用户任一角色卡是否有权限
app.get('/api/documents/read/:filename', authenticateToken, (req, res) => {
    const filename = req.params.filename;

    // 安全检查：防止路径遍历
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

// 3. (管理员) 获取某用户的文件权限列表
app.get('/api/admin/user/:id/permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
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

// 4. (管理员) 更新某用户的权限
app.put('/api/admin/user/:id/permissions', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const userId = req.params.id;
    const { permissions } = req.body; // Array of filenames to grant

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        
        // 先删除该用户所有文件权限
        db.run('DELETE FROM document_permissions WHERE user_id = ?', [userId]);
        
        // 重新插入选中的权限
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


// ==========================================
// NEW: 高墙文件 API (经理专用)
// ==========================================

// 封装一个检查经理是否对某个用户有管理权限的函数
function checkManagerAuthorization(managerId, targetUserId) {
    return new Promise((resolve, reject) => {
        const sql = `
            SELECT 1 FROM character_authorizations ca
            JOIN characters c ON ca.character_id = c.id
            WHERE ca.manager_id = ? AND c.user_id = ?
            LIMIT 1
        `;
        db.get(sql, [managerId, targetUserId], (err, row) => {
            if (err) reject(err);
            else resolve(!!row);
        });
    });
}

// 5. (经理) 获取其下属用户的文件权限
app.get('/api/manager/user/:userId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const targetUserId = req.params.userId;

        // 安全检查：确认该经理有权管理此用户
        const isAuthorized = await checkManagerAuthorization(managerId, targetUserId);
        if (!isAuthorized) {
            return res.status(403).json({ error: '无权管理该用户的权限' });
        }

        // 权限检查通过，执行与管理员相同的逻辑
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

// 6. (经理) 更新其下属用户的权限
app.put('/api/manager/user/:userId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const targetUserId = req.params.userId;
        const { permissions } = req.body; // Array of filenames to grant

        // 安全检查：确认该经理有权管理此用户
        const isAuthorized = await checkManagerAuthorization(managerId, targetUserId);
        if (!isAuthorized) {
            return res.status(403).json({ success: false, message: '无权管理该用户的权限' });
        }

        // 权限检查通过，执行与管理员相同的逻辑
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


// ==========================================
// 高墙文件 API (按角色卡授权 - 新版)
// ==========================================

// 检查经理是否对某个角色卡有授权
function checkManagerCharacterAuth(managerId, charId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT 1 FROM character_authorizations WHERE manager_id = ? AND character_id = ?',
            [managerId, charId], (err, row) => {
                if (err) reject(err);
                else resolve(!!row);
            });
    });
}

// 获取角色卡的文件权限
app.get('/api/manager/character/:charId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;

        // 检查经理是否有该角色卡的授权
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

// 更新角色卡的文件权限
app.put('/api/manager/character/:charId/permissions', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { permissions } = req.body;

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权管理该角色卡的权限' });
        }

        // 获取当前权限，用于对比新增了哪些文件
        const currentPerms = await new Promise((resolve) => {
            db.all('SELECT filename FROM character_document_permissions WHERE character_id = ?', [charId], (err, rows) => {
                resolve(new Set((rows || []).map(r => r.filename)));
            });
        });

        // 找出新增的文件
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

            // 为每个新授权的文件创建通知邮件
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

// ==========================================
// 角色卡邮箱 API
// ==========================================

// 获取角色卡的高墙文件列表（已授权的）
app.get('/api/character/:id/highwall-files', authenticateToken, (req, res) => {
    const charId = req.params.id;

    // 检查访问权限
    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);

        // 只有角色所有者、授权的经理、超管可以访问
        const checkAccess = () => {
            if (req.user.role >= ROLE.SUPER_ADMIN) return Promise.resolve(true);
            if (req.user.userId === row.user_id) return Promise.resolve(true);

            return new Promise((resolve) => {
                if (req.user.role < ROLE.MANAGER) {
                    resolve(false);
                    return;
                }
                db.get('SELECT 1 FROM character_authorizations WHERE character_id = ? AND manager_id = ?',
                    [charId, req.user.userId], (err, auth) => resolve(!!auth));
            });
        };

        Promise.resolve(checkAccess()).then(hasAccess => {
            if (!hasAccess) return res.status(403).json([]);

            // 获取该角色卡的已授权高墙文件
            db.all('SELECT filename, granted_at FROM character_document_permissions WHERE character_id = ?',
                [charId], (err, rows) => {
                    if (err) return res.json([]);

                    const files = (rows || []).map(r => ({
                        filename: r.filename,
                        title: r.filename.replace(/\.md$/i, ''),
                        grantedAt: r.granted_at
                    }));

                    res.json(files);
                });
        });
    });
});

// 检查角色卡是否已解锁A1高墙文件（用于控制报告提交权限）
app.get('/api/character/:id/check-a1', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ unlocked: false });

        // 只有角色所有者可以查看
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ unlocked: false });
        }

        // 检查是否有A1.md的授权（不区分大小写）
        db.get(`SELECT 1 FROM character_document_permissions
                WHERE character_id = ? AND LOWER(filename) = 'a1.md'`,
            [charId], (err, perm) => {
                res.json({ unlocked: !!perm });
            });
    });
});

// 获取角色卡的站内信
app.get('/api/character/:id/messages', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);

        // 只有角色所有者可以查看
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json([]);
        }

        // 排除已发邮件（message_type = 'sent'），只返回收件箱
        db.all(`SELECT * FROM character_messages WHERE character_id = ? AND (message_type IS NULL OR message_type != 'sent') ORDER BY created_at DESC`,
            [charId], (err, rows) => {
                if (err) return res.json([]);
                // 转换字段名为驼峰命名
                const messages = (rows || []).map(r => ({
                    id: r.id,
                    characterId: r.character_id,
                    senderId: r.sender_id,
                    senderName: r.sender_name || '未知发件人',
                    subject: r.subject,
                    content: r.content,
                    messageType: r.message_type,
                    hwFilename: r.hw_filename,
                    reportId: r.report_id,
                    read: r.read,
                    createdAt: r.created_at
                }));
                res.json(messages);
            });
    });
});

// 获取角色卡已发邮件
app.get('/api/character/:id/sent-messages', authenticateToken, (req, res) => {
    const charId = req.params.id;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json([]);

        // 只有角色所有者可以查看
        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json([]);
        }

        // 只返回已发邮件（message_type = 'sent'）
        db.all(`SELECT * FROM character_messages WHERE character_id = ? AND message_type = 'sent' ORDER BY created_at DESC`,
            [charId], (err, rows) => {
                if (err) return res.json([]);
                const messages = (rows || []).map(r => ({
                    id: r.id,
                    characterId: r.character_id,
                    recipientName: r.recipient_name || '未知收件人',
                    subject: r.subject,
                    content: r.content,
                    createdAt: r.created_at
                }));
                res.json(messages);
            });
    });
});

// 经理发送站内信给角色卡
app.post('/api/manager/character/:charId/message', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { subject, content } = req.body;

        if (!subject || !content) {
            return res.status(400).json({ success: false, message: '标题和内容不能为空' });
        }

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权向该角色卡发送消息' });
        }

        // 获取发送者名称
        const sender = await new Promise((resolve) => {
            db.get('SELECT name, username FROM users WHERE id = ?', [managerId], (err, row) => {
                resolve(row ? (row.name || row.username) : '未知');
            });
        });

        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [charId, managerId, sender, subject, content, Date.now()],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                res.json({ success: true, messageId: this.lastID });
            });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// 标记站内信为已读
app.put('/api/character/:charId/message/:msgId/read', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const msgId = req.params.msgId;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, row) => {
        if (!row) return res.status(404).json({ success: false });

        if (req.user.userId !== row.user_id && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false });
        }

        db.run('UPDATE character_messages SET read = 1 WHERE id = ? AND character_id = ?',
            [msgId, charId], function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
    });
});

// 经理切换角色发信权限
app.put('/api/manager/character/:charId/message-permission', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { canSendMessages } = req.body;

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作该角色卡' });
        }

        const value = canSendMessages ? 1 : 0;
        db.run('UPDATE characters SET can_send_messages = ? WHERE id = ?', [value, charId], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, canSendMessages: !!value });
        });
    } catch (e) {
        console.error('切换发信权限失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 经理切换角色申诫商店权限
app.put('/api/manager/character/:charId/reprimand-shop-access', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { reprimandShopAccess } = req.body;

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作该角色卡' });
        }

        // 获取角色当前数据
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT data FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) {
            return res.status(404).json({ success: false, message: '角色不存在' });
        }

        // 更新charData中的reprimandShopAccess字段
        let charData = {};
        try { charData = JSON.parse(char.data); } catch(e) {}
        charData.reprimandShopAccess = !!reprimandShopAccess;

        db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(charData), charId], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, reprimandShopAccess: charData.reprimandShopAccess });
        });
    } catch (e) {
        console.error('切换申诫商店权限失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 经理直接发放奖惩
app.post('/api/manager/character/:charId/reward', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;
        const { rewardType, amount, reason } = req.body;

        // 验证奖惩类型
        const validTypes = ['commend', 'reprimand', 'mvp', 'probation'];
        if (!validTypes.includes(rewardType)) {
            return res.status(400).json({ success: false, message: '无效的奖惩类型' });
        }

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作该角色卡' });
        }

        // 获取角色当前数据
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM characters WHERE id = ?', [charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) {
            return res.status(404).json({ success: false, message: '角色不存在' });
        }

        let charData = {};
        try { charData = JSON.parse(char.data || '{}'); } catch(e) {}

        const now = Date.now();
        const rewardAmount = parseInt(amount) || 1;

        // 应用奖惩
        switch (rewardType) {
            case 'commend':
                charData.commendations = (parseInt(charData.commendations) || 0) + rewardAmount;
                break;
            case 'reprimand':
                charData.reprimands = (parseInt(charData.reprimands) || 0) + rewardAmount;
                break;
            case 'mvp':
                charData.mvpCount = (parseInt(charData.mvpCount) || 0) + 1;
                break;
            case 'probation':
                charData.probationCount = (parseInt(charData.probationCount) || 0) + 1;
                break;
        }

        // 更新角色数据
        await new Promise((resolve, reject) => {
            db.run('UPDATE characters SET data = ? WHERE id = ?',
                [JSON.stringify(charData), charId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 记录到奖惩记录表
        await new Promise((resolve, reject) => {
            db.run(`INSERT INTO reward_records (character_id, reward_type, amount, reason, issued_by, issued_at)
                VALUES (?, ?, ?, ?, ?, ?)`,
                [charId, rewardType, rewardAmount, reason || null, managerId, now], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 获取经理名称
        const manager = await new Promise((resolve) => {
            db.get('SELECT name, username FROM users WHERE id = ?', [managerId], (err, row) => {
                resolve(row ? (row.name || row.username) : '经理');
            });
        });

        // 发送通知给角色
        const typeNames = { commend: '嘉奖', reprimand: '申诫', mvp: 'MVP', probation: '观察期' };
        const typeName = typeNames[rewardType];
        const subject = `[奖惩通知] 您收到了${typeName}`;
        let content = `${manager} 向您发放了 ${typeName}`;
        if (rewardType === 'commend' || rewardType === 'reprimand') {
            content += ` x${rewardAmount}`;
        }
        if (reason) {
            content += `\n\n原因: ${reason}`;
        }

        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [charId, managerId, manager, subject, content, 'reward', now]);

        res.json({ success: true, message: `${typeName}已发放` });
    } catch (e) {
        console.error('发放奖惩失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 获取角色的奖惩记录
app.get('/api/manager/character/:charId/rewards', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    try {
        const managerId = req.user.userId;
        const charId = req.params.charId;

        // 检查经理是否有该角色卡的授权
        const isAuthorized = await checkManagerCharacterAuth(managerId, charId);
        if (!isAuthorized && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权查看该角色卡' });
        }

        const records = await new Promise((resolve, reject) => {
            db.all(`SELECT rr.*, u.name as issuer_name, u.username as issuer_username,
                    fm.name as mission_name
                FROM reward_records rr
                LEFT JOIN users u ON rr.issued_by = u.id
                LEFT JOIN field_missions fm ON rr.mission_id = fm.id
                WHERE rr.character_id = ?
                ORDER BY rr.issued_at DESC
                LIMIT 50`, [charId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        res.json({
            success: true,
            records: records.map(r => ({
                id: r.id,
                reward_type: r.reward_type,
                amount: r.amount,
                reason: r.reason,
                mission_name: r.mission_name,
                issuer: r.issuer_name || r.issuer_username || '系统',
                issued_at: r.issued_at
            }))
        });
    } catch (e) {
        console.error('获取奖惩记录失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// ==========================================
// 外勤任务 API
// ==========================================

// 创建外勤任务
app.post('/api/manager/mission', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { name, description, missionType, characterIds } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ success: false, message: '任务名称不能为空' });
    }

    // 任务类型: containment(收容) 或 sweep(清扫)
    const validType = ['containment', 'sweep'].includes(missionType) ? missionType : 'containment';

    const missionId = Date.now().toString();
    const now = Date.now();

    db.run(`INSERT INTO field_missions
        (id, name, description, mission_type, status, created_by, created_at, updated_at, report_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [missionId, name.trim(), description || '', validType, 'active', req.user.userId, now, now, 'none'],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });

            // 如果提供了角色卡ID列表，添加成员
            if (characterIds && characterIds.length > 0) {
                const stmt = db.prepare('INSERT OR IGNORE INTO field_mission_members (mission_id, character_id, member_status, joined_at) VALUES (?, ?, ?, ?)');
                characterIds.forEach(charId => {
                    stmt.run(missionId, charId, '待命', now);
                });
                stmt.finalize();
            }

            res.json({ success: true, missionId });
        });
});

// 获取经理的所有任务
// ==========================================
// 外勤任务 API - 获取经理的所有任务 (修正版)
// ==========================================
app.get('/api/manager/missions', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const managerId = req.user.userId;
    
    // 修正点 1：读取 status 参数
    const statusFilter = req.query.status; 

    // 构建基础 SQL 和参数
    let sql = 'SELECT * FROM field_missions';
    let params = [];
    const conditions = [];

    // 如果不是超管，则限制只能看自己创建的任务
    if (req.user.role < ROLE.SUPER_ADMIN) {
        conditions.push('created_by = ?');
        params.push(managerId);
    }
    
    // 修正点 2：如果 status 参数有效，则加入 SQL 查询条件
    if (statusFilter === 'active' || statusFilter === 'archived') {
        conditions.push('status = ?');
        params.push(statusFilter);
    }
    
    // 组合查询条件
    if (conditions.length > 0) {
        sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ' ORDER BY created_at DESC';

    db.all(sql, params, (err, missions) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }

        if (!missions || missions.length === 0) {
            return res.json([]);
        }

        // (下面的代码保持不变，用于获取任务成员)
        let completed = 0;
        const result = [];
        missions.forEach(mission => {
            db.all(`
                SELECT fmm.character_id, c.data, fmm.member_status, fmm.joined_at
                FROM field_mission_members fmm
                JOIN characters c ON fmm.character_id = c.id
                WHERE fmm.mission_id = ?
            `, [mission.id], (err, members) => {
                const memberList = (members || []).map(m => {
                    let d = {};
                    try { d = JSON.parse(m.data); } catch(e) {}

                    // 计算嘉奖/申诫总数
                    let commendations = 0;
                    if (Array.isArray(d.rewards)) {
                        commendations = d.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
                    }
                    commendations += parseInt(d.commendations) || 0;

                    let reprimands = 0;
                    if (Array.isArray(d.reprimands)) {
                        reprimands = d.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                    }

                    return {
                        character_id: m.character_id,
                        name: d.pName || '未命名',
                        member_status: m.member_status,
                        joined_at: m.joined_at,
                        commendations: commendations,
                        reprimands: reprimands,
                        mvpCount: parseInt(d.mvpCount) || 0,
                        probationCount: parseInt(d.probationCount) || 0
                    };
                });

                // 获取任务的已完成报告（用于归档任务展示）
                db.get(`SELECT id, rating, scatter_value, final_rewards, status, sent_at
                        FROM mission_reports
                        WHERE mission_id = ? AND status IN ('sent', 'finalized')
                        ORDER BY sent_at DESC LIMIT 1`, [mission.id], (err, report) => {

                    let reportInfo = null;
                    if (report) {
                        let rewards = {};
                        try { rewards = JSON.parse(report.final_rewards || '{}'); } catch(e) {}

                        // 统计奖惩
                        let totalCommend = 0, totalReprimand = 0, mvpCount = 0, probationCount = 0;
                        for (const [charId, r] of Object.entries(rewards)) {
                            totalCommend += r.commend || 0;
                            totalReprimand += r.reprimand || 0;
                            if (r.mvp) mvpCount++;
                            if (r.probation) probationCount++;
                        }

                        reportInfo = {
                            rating: report.rating,
                            scatterValue: report.scatter_value,
                            totalCommend,
                            totalReprimand,
                            mvpCount,
                            probationCount,
                            sentAt: report.sent_at
                        };
                    }

                    const missionData = {
                        ...mission,
                        members: memberList,
                        mission_type: mission.mission_type || 'containment',
                        reportInfo
                    };

                    result.push(missionData);
                    completed++;
                    if (completed === missions.length) {
                        result.sort((a, b) => b.created_at - a.created_at);
                        res.json(result);
                    }
                });
            });
        });
    });
});

// 更新任务信息
app.put('/api/manager/mission/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { name, description, status, missionType, chaosValue, scatterValue } = req.body;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        // 只有创建者或超管可以修改
        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        const updates = [];
        const params = [];

        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name.trim());
        }
        if (description !== undefined) {
            updates.push('description = ?');
            params.push(description);
        }
        if (status !== undefined && ['active', 'archived'].includes(status)) {
            updates.push('status = ?');
            params.push(status);
        }
        if (missionType !== undefined && ['containment', 'sweep'].includes(missionType)) {
            updates.push('mission_type = ?');
            params.push(missionType);
        }
        // 混沌值和逸散端（逸散端可以为负数）
        if (chaosValue !== undefined && !isNaN(parseInt(chaosValue))) {
            updates.push('chaos_value = ?');
            params.push(parseInt(chaosValue));
        }
        if (scatterValue !== undefined && !isNaN(parseInt(scatterValue))) {
            updates.push('scatter_value = ?');
            params.push(parseInt(scatterValue));
        }

        if (updates.length === 0) {
            return res.json({ success: true });
        }

        updates.push('updated_at = ?');
        params.push(Date.now());
        params.push(missionId);

        db.run(`UPDATE field_missions SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

// 删除任务
app.delete('/api/manager/mission/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权删除此任务' });
        }

        db.run('DELETE FROM field_missions WHERE id = ?', [missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

// 添加成员到任务
app.post('/api/manager/mission/:id/member', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { characterId } = req.body;

    if (!characterId) {
        return res.status(400).json({ success: false, message: '角色卡ID不能为空' });
    }

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        // 检查特工是否已在任何活跃任务中（一个特工只能在一个未归档任务中）
        db.get(`
            SELECT fm.id, fm.name FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.status = 'active'
        `, [characterId], (err, existing) => {
            if (existing) {
                return res.status(400).json({
                    success: false,
                    message: `该特工已在任务"${existing.name}"中，无法加入其他任务`
                });
            }

            db.run('INSERT OR IGNORE INTO field_mission_members (mission_id, character_id, member_status, joined_at) VALUES (?, ?, ?, ?)',
                [missionId, characterId, '待命', Date.now()],
                function(err) {
                    if (err) return res.status(500).json({ success: false });

                    // 更新任务更新时间
                    db.run('UPDATE field_missions SET updated_at = ? WHERE id = ?', [Date.now(), missionId]);

                    res.json({ success: true });
                });
        });
    });
});

// 移除成员从任务
app.delete('/api/manager/mission/:id/member/:charId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const charId = req.params.charId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        db.run('DELETE FROM field_mission_members WHERE mission_id = ? AND character_id = ?',
            [missionId, charId],
            function(err) {
                if (err) return res.status(500).json({ success: false });

                db.run('UPDATE field_missions SET updated_at = ? WHERE id = ?', [Date.now(), missionId]);

                res.json({ success: true });
            });
    });
});

// 更新成员状态
app.put('/api/manager/mission/:id/member/:charId/status', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const charId = req.params.charId;
    const { status } = req.body;

    if (!status) {
        return res.status(400).json({ success: false, message: '状态不能为空' });
    }

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权修改此任务' });
        }

        db.run('UPDATE field_mission_members SET member_status = ? WHERE mission_id = ? AND character_id = ?',
            [status, missionId, charId],
            function(err) {
                if (err) return res.status(500).json({ success: false });

                db.run('UPDATE field_missions SET updated_at = ? WHERE id = ?', [Date.now(), missionId]);

                res.json({ success: true });
            });
    });
});

// 获取任务中特工的完整数据
app.get('/api/manager/mission/:id/agent/:charId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const charId = req.params.charId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        // 获取角色数据
        db.get('SELECT * FROM characters WHERE id = ?', [charId], (err, char) => {
            if (!char) return res.status(404).json({ success: false, message: '角色不存在' });

            let charData = {};
            try { charData = JSON.parse(char.data); } catch(e) {}

            // 嘉奖和申诫数据从charData中获取（存储在JSON中）
            const rewards = charData.rewards || [];
            const reprimands = charData.reprimands || [];

            res.json({
                success: true,
                agent: {
                    id: char.id,
                    name: charData.pName || '未命名',
                    // 基础属性
                    physical: charData.physical || 3,
                    mental: charData.mental || 3,
                    social: charData.social || 3,
                    luck: charData.luck || 3,
                    hp: charData.hp || 10,
                    mp: charData.mp || 10,
                    san: charData.san || 50,
                    // 次级属性
                    str: charData.str || 0,
                    dex: charData.dex || 0,
                    con: charData.con || 0,
                    int: charData.intVal || 0,
                    wis: charData.wis || 0,
                    cha: charData.cha || 0,
                    // 异常能力
                    abilities: charData.anomAbilities || [],
                    abilitySlots: charData.anomSlots || 3,
                    // 关系网络
                    relations: charData.relations || [],
                    relationSlots: charData.realSlots || 3,
                    // GM备注
                    gmNotes: charData.gmNotes || '',
                    // 嘉奖和申诫（从charData中读取）
                    rewards: rewards,
                    reprimands: reprimands
                }
            });
        });
    });
});

// ==================== 任务收件箱API ====================

// 获取任务收件箱
app.get('/api/manager/mission/:id/inbox', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.all(`
            SELECT * FROM mission_inbox
            WHERE mission_id = ?
            ORDER BY created_at DESC
        `, [missionId], (err, messages) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, messages: messages || [] });
        });
    });
});

// 获取任务收件箱未读数
app.get('/api/manager/mission/:id/inbox/unread-count', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.get('SELECT COUNT(*) as count FROM mission_inbox WHERE mission_id = ? AND read = 0', [missionId], (err, row) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, count: row ? row.count : 0 });
        });
    });
});

// 标记任务收件箱邮件已读
app.put('/api/manager/mission/:id/inbox/:msgId/read', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const msgId = req.params.msgId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.run('UPDATE mission_inbox SET read = 1 WHERE id = ? AND mission_id = ?', [msgId, missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

// 删除任务收件箱邮件
app.delete('/api/manager/mission/:id/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const msgId = req.params.msgId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.run('DELETE FROM mission_inbox WHERE id = ? AND mission_id = ?', [msgId, missionId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
    });
});

// ==================== 任务报告API ====================

// 获取任务报告列表
app.get('/api/manager/mission/:id/reports', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权访问此任务' });
        }

        db.all(`
            SELECT mr.*, c.data as char_data
            FROM mission_reports mr
            LEFT JOIN characters c ON mr.submitted_by = c.id
            WHERE mr.mission_id = ?
            ORDER BY mr.submitted_at DESC
        `, [missionId], (err, reports) => {
            if (err) return res.status(500).json({ success: false });

            // 解析角色名称
            const result = (reports || []).map(r => {
                let charName = '未知特工';
                try {
                    const charData = JSON.parse(r.char_data || '{}');
                    charName = charData.pName || '未命名';
                } catch(e) {}

                return {
                    id: r.id,
                    missionId: r.mission_id,
                    submittedBy: r.submitted_by,
                    submitterName: charName,
                    originalData: r.original_data ? JSON.parse(r.original_data) : null,
                    revisedData: r.revised_data ? JSON.parse(r.revised_data) : null,
                    annotations: r.annotations ? JSON.parse(r.annotations) : [],
                    rating: r.rating,
                    scatterValue: r.scatter_value,
                    status: r.status,
                    submittedAt: r.submitted_at,
                    reviewedAt: r.reviewed_at,
                    sentAt: r.sent_at,
                    // 申诉相关字段
                    pending_rewards: r.pending_rewards ? JSON.parse(r.pending_rewards) : null,
                    appeal_reason: r.appeal_reason,
                    appeal_requested_changes: r.appeal_requested_changes,
                    appeal_at: r.appeal_at,
                    appeal_response: r.appeal_response,
                    final_rewards: r.final_rewards ? JSON.parse(r.final_rewards) : null
                };
            });

            res.json({ success: true, reports: result });
        });
    });
});

// 修订报告（经理）
app.put('/api/manager/mission/:id/report/:reportId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;
    const { revisedData, annotations, rating, scatterValue } = req.body;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        const updates = ['reviewed_at = ?', 'status = ?'];
        const params = [Date.now(), 'reviewed'];

        if (revisedData !== undefined) {
            updates.push('revised_data = ?');
            params.push(JSON.stringify(revisedData));
        }
        if (annotations !== undefined) {
            updates.push('annotations = ?');
            params.push(JSON.stringify(annotations));
        }
        if (rating !== undefined) {
            updates.push('rating = ?');
            params.push(rating);
        }
        if (scatterValue !== undefined) {
            updates.push('scatter_value = ?');
            params.push(parseInt(scatterValue) || 0);
        }

        params.push(reportId, missionId);

        db.run(`UPDATE mission_reports SET ${updates.join(', ')} WHERE id = ? AND mission_id = ?`, params, function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });

            // 更新任务状态
            db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?',
                ['reviewed', Date.now(), missionId]);

            res.json({ success: true });
        });
    });
});

// 发送评级给特工
app.post('/api/manager/mission/:id/report/:reportId/send', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        // 获取报告信息
        db.get('SELECT * FROM mission_reports WHERE id = ? AND mission_id = ?', [reportId, missionId], (err, report) => {
            if (!report) return res.status(404).json({ success: false, message: '报告不存在' });

            const now = Date.now();

            // 更新报告状态
            db.run('UPDATE mission_reports SET status = ?, sent_at = ? WHERE id = ?', ['sent', now, reportId], function(err) {
                if (err) return res.status(500).json({ success: false });

                // 更新任务状态
                db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['sent', now, missionId]);

                // 向提交者发送通知邮件
                if (report.submitted_by) {
                    const subject = '[评级通知] 您的任务报告已评审';
                    const content = `您提交的任务报告已被经理评审。\n\n评级: ${report.rating || '未评级'}\n逸散端: ${report.scatter_value || 0}`;

                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [report.submitted_by, req.user.userId, '任务系统', subject, content, 'system', now]);
                }

                res.json({ success: true });
            });
        });
    });
});

// 发送初评（所有参与特工都收到通知，各自决定接受或申诉）
app.post('/api/manager/mission/:id/report/:reportId/send-with-rewards', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;
    const { rating, agentRewards } = req.body;

    try {
        // 验证任务存在性和权限
        const mission = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM field_missions WHERE id = ?', [missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });
        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        // 获取报告信息
        const report = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM mission_reports WHERE id = ? AND mission_id = ?', [reportId, missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!report) return res.status(404).json({ success: false, message: '报告不存在' });
        if (report.status === 'sent' || report.status === 'finalized') {
            return res.status(400).json({ success: false, message: '报告已完成结算，无法重复操作' });
        }

        // 检查是否已有其他报告在初审或最终确认状态（一个任务只能有一个正式报告）
        const existingProcessedReport = await new Promise((resolve, reject) => {
            db.get(`SELECT id, status FROM mission_reports
                    WHERE mission_id = ? AND id != ? AND status IN ('initial', 'appealing', 'finalized')`,
                [missionId, reportId], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        if (existingProcessedReport) {
            const statusText = existingProcessedReport.status === 'finalized' ? '已有最终确认的报告' :
                existingProcessedReport.status === 'initial' ? '已有正在初审的报告' : '已有正在处理申诉的报告';
            return res.status(400).json({ success: false, message: `该任务${statusText}，无法对其他报告进行初审` });
        }

        // 获取所有任务成员
        const members = await new Promise((resolve, reject) => {
            db.all(`SELECT fmm.character_id, c.data as char_data
                    FROM field_mission_members fmm
                    JOIN characters c ON fmm.character_id = c.id
                    WHERE fmm.mission_id = ?`, [missionId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        if (members.length === 0) {
            return res.status(400).json({ success: false, message: '任务没有成员' });
        }

        const now = Date.now();

        // 存储待结算奖惩
        const pendingRewards = JSON.stringify(agentRewards || {});

        // 更新报告状态为"初评"
        await new Promise((resolve, reject) => {
            db.run(`UPDATE mission_reports SET
                status = 'initial',
                rating = ?,
                pending_rewards = ?,
                reviewed_at = ?
                WHERE id = ?`,
                [rating, pendingRewards, now, reportId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 解析报告详细数据
        let reportData = {};
        try { reportData = JSON.parse(report.original_data || '{}'); } catch(e) {}

        // 构建详细报告内容
        const buildDetailedReport = () => {
            const lines = [];
            lines.push(`【任务报告详情】\n`);
            if (reportData.summary) lines.push(`📋 任务概要: ${reportData.summary}`);
            if (reportData.chaos !== undefined) lines.push(`🌀 混沌池: ${reportData.chaos}`);
            if (reportData.scatter !== undefined) lines.push(`💫 逸散端: ${reportData.scatter}`);
            if (reportData.notes) lines.push(`📝 备注: ${reportData.notes}`);
            if (reportData.containmentReports && reportData.containmentReports.length > 0) {
                lines.push(`\n【收容报告】`);
                reportData.containmentReports.forEach((cr, i) => {
                    lines.push(`  ${i+1}. ${cr.targetName || '未知目标'}: ${cr.result || '无描述'}`);
                });
            }
            return lines.join('\n');
        };

        const detailedReport = buildDetailedReport();

        // 为每个成员创建响应记录并发送通知
        for (const member of members) {
            const charId = member.character_id;
            const rewards = agentRewards?.[charId] || { commend: 0, reprimand: 0, mvp: false, probation: false };

            // 创建响应记录
            await new Promise((resolve, reject) => {
                db.run(`INSERT OR REPLACE INTO report_agent_responses (report_id, character_id, status, pending_rewards)
                        VALUES (?, ?, 'pending', ?)`,
                    [reportId, charId, JSON.stringify(rewards)], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
            });

            // 构建个人奖惩预览
            let personalRewards = [];
            if (rewards.commend > 0) personalRewards.push(`嘉奖 +${rewards.commend}`);
            if (rewards.reprimand > 0) personalRewards.push(`申诫 +${rewards.reprimand}`);
            if (rewards.mvp) personalRewards.push(`获得 MVP`);
            if (rewards.probation) personalRewards.push(`进入查看期`);

            let charData = {};
            try { charData = JSON.parse(member.char_data || '{}'); } catch(e) {}
            const charName = charData.pName || '特工';

            const subject = '[任务初评] 请确认或申诉';
            const content = `${charName}，您参与的任务已完成初评。\n\n【任务评级】${rating}\n\n【您的预计奖惩】\n${personalRewards.join('\n') || '无'}\n\n${detailedReport}\n\n请选择「接受」确认评级，或「申诉」提出异议。所有特工确认后将自动完成结算。`;

            // 发送通知消息
            db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, report_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [charId, req.user.userId, '任务系统', subject, content, 'rating_notice', reportId, now]);
        }

        // 更新任务状态
        db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['initial', now, missionId]);

        res.json({ success: true, message: `初评已发送给 ${members.length} 位特工，等待确认` });
    } catch (e) {
        console.error('发送初评失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 玩家提交申诉
app.post('/api/character/:charId/appeal-rating/:reportId', authenticateToken, async (req, res) => {
    const { charId, reportId } = req.params;
    const { reason } = req.body;

    try {
        // 验证角色所有权
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.userId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) return res.status(403).json({ success: false, message: '无权操作此角色' });

        // 获取报告
        const report = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM mission_reports WHERE id = ?', [reportId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!report) return res.status(404).json({ success: false, message: '报告不存在' });
        if (report.status !== 'initial' && report.status !== 'appealing') {
            return res.status(400).json({ success: false, message: '当前状态无法申诉' });
        }

        // 检查该特工是否有响应记录
        const response = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM report_agent_responses WHERE report_id = ? AND character_id = ?', [reportId, charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!response) return res.status(404).json({ success: false, message: '您不是此任务的参与者' });
        if (response.status !== 'pending') {
            return res.status(400).json({ success: false, message: '您已经提交过响应' });
        }

        const now = Date.now();

        // 更新该特工的响应状态为申诉
        await new Promise((resolve, reject) => {
            db.run(`UPDATE report_agent_responses SET status = 'appealing', appeal_reason = ?, responded_at = ? WHERE report_id = ? AND character_id = ?`,
                [reason, now, reportId, charId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 更新报告状态为申诉中
        await new Promise((resolve, reject) => {
            db.run(`UPDATE mission_reports SET status = 'appealing' WHERE id = ?`, [reportId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // 获取任务信息
        const mission = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM field_missions WHERE id = ?', [report.mission_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        let charData = {};
        try { charData = JSON.parse(char.data || '{}'); } catch(e) {}
        const charName = charData.pName || '特工';

        // 通知经理有新申诉
        if (mission) {
            db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['appealing', now, report.mission_id]);

            // 获取该特工的待结算奖惩
            const pendingRewards = JSON.parse(response.pending_rewards || '{}');
            let rewardPreview = [];
            if (pendingRewards.commend > 0) rewardPreview.push(`嘉奖 +${pendingRewards.commend}`);
            if (pendingRewards.reprimand > 0) rewardPreview.push(`申诫 +${pendingRewards.reprimand}`);
            if (pendingRewards.mvp) rewardPreview.push(`获得 MVP`);
            if (pendingRewards.probation) rewardPreview.push(`进入查看期`);

            // 发送消息给经理的收件箱
            db.run(`INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_id, mission_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [mission.created_by, charId, charName, '[申诉] 评级申诉请求',
                    `特工 ${charName} 对初评提出申诉。\n\n当前待结算奖惩:\n${rewardPreview.join('\n') || '无'}\n\n申诉理由:\n${reason}`,
                    'appeal', reportId, report.mission_id, now]);
        }

        res.json({ success: true, message: '申诉已提交，请等待经理处理' });
    } catch (e) {
        console.error('提交申诉失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 玩家接受初评（记录接受状态，检查是否所有人都接受了）
app.post('/api/character/:charId/accept-rating/:reportId', authenticateToken, async (req, res) => {
    const { charId, reportId } = req.params;

    try {
        // 验证角色所有权
        const char = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.userId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!char) return res.status(403).json({ success: false, message: '无权操作此角色' });

        // 获取报告
        const report = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM mission_reports WHERE id = ?', [reportId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!report) return res.status(404).json({ success: false, message: '报告不存在' });
        if (report.status !== 'initial' && report.status !== 'appealing') {
            return res.status(400).json({ success: false, message: '当前状态无法接受评级' });
        }

        // 检查该特工是否有响应记录
        const response = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM report_agent_responses WHERE report_id = ? AND character_id = ?', [reportId, charId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!response) return res.status(404).json({ success: false, message: '您不是此任务的参与者' });
        if (response.status !== 'pending') {
            return res.status(400).json({ success: false, message: '您已经提交过响应' });
        }

        const now = Date.now();

        // 更新该特工的响应状态为接受
        await new Promise((resolve, reject) => {
            db.run(`UPDATE report_agent_responses SET status = 'accepted', responded_at = ? WHERE report_id = ? AND character_id = ?`,
                [now, reportId, charId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 检查是否所有特工都已响应
        const allResponses = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM report_agent_responses WHERE report_id = ?', [reportId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        const pendingCount = allResponses.filter(r => r.status === 'pending').length;
        const appealingCount = allResponses.filter(r => r.status === 'appealing').length;
        const allAccepted = pendingCount === 0 && appealingCount === 0;

        // 获取任务信息
        const mission = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM field_missions WHERE id = ?', [report.mission_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        let charData = {};
        try { charData = JSON.parse(char.data || '{}'); } catch(e) {}
        const charName = charData.pName || '特工';

        if (allAccepted) {
            // 所有人都接受了，自动进行最终结算
            const pendingRewards = JSON.parse(report.pending_rewards || '{}');

            // 应用奖惩到每个角色
            for (const [rewardCharId, rewards] of Object.entries(pendingRewards)) {
                const targetChar = await new Promise((resolve, reject) => {
                    db.get('SELECT data FROM characters WHERE id = ?', [rewardCharId], (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    });
                });

                if (targetChar) {
                    let targetCharData = {};
                    try { targetCharData = JSON.parse(targetChar.data || '{}'); } catch(e) {}

                    // 使用正确的字段名（与前端对应）
                    // mvpCount = 嘉奖数量, watchCount = 申诫数量, pComm = MVP, pRep = 查看期
                    const missionName = mission?.name || '任务';

                    // 更新数字统计
                    targetCharData.mvpCount = (parseInt(targetCharData.mvpCount) || 0) + (rewards.commend || 0);
                    targetCharData.watchCount = (parseInt(targetCharData.watchCount) || 0) + (rewards.reprimand || 0);
                    if (rewards.probation) {
                        targetCharData.pRep = (parseInt(targetCharData.pRep) || 0) + 1;
                    }
                    if (rewards.mvp) {
                        targetCharData.pComm = (parseInt(targetCharData.pComm) || 0) + 1;
                    }

                    // 同时添加记录到数组（用于查看历史）
                    if (!Array.isArray(targetCharData.rewards)) targetCharData.rewards = [];
                    if (!Array.isArray(targetCharData.reprimands)) targetCharData.reprimands = [];

                    if (rewards.commend > 0) {
                        targetCharData.rewards.push({
                            reason: `来自「${missionName}」任务结算`,
                            count: rewards.commend,
                            date: now,
                            addedByName: '任务系统'
                        });
                    }
                    if (rewards.reprimand > 0) {
                        targetCharData.reprimands.push({
                            reason: `来自「${missionName}」任务结算`,
                            count: rewards.reprimand,
                            date: now,
                            addedByName: '任务系统'
                        });
                    }

                    await new Promise((resolve, reject) => {
                        db.run('UPDATE characters SET data = ? WHERE id = ?',
                            [JSON.stringify(targetCharData), rewardCharId], (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                    });

                    // 发送最终结算通知
                    let rewardMsg = [];
                    if (rewards.commend > 0) rewardMsg.push(`嘉奖 +${rewards.commend}`);
                    if (rewards.reprimand > 0) rewardMsg.push(`申诫 +${rewards.reprimand}`);
                    if (rewards.mvp) rewardMsg.push(`获得MVP`);
                    if (rewards.probation) rewardMsg.push(`进入查看期`);

                    const subject = '[任务结算] 评级已确认';
                    const content = `所有特工已确认初评，任务报告已完成结算。\n\n最终评级: ${report.rating}\n\n您的奖惩结算:\n${rewardMsg.join('\n') || '无'}`;
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [rewardCharId, req.user.userId, '任务系统', subject, content, 'system', now]);
                }
            }

            // 更新报告状态为已结算
            await new Promise((resolve, reject) => {
                db.run(`UPDATE mission_reports SET
                    status = 'finalized',
                    final_rewards = pending_rewards,
                    sent_at = ?
                    WHERE id = ?`,
                    [now, reportId], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
            });

            // 更新任务状态
            db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['sent', now, report.mission_id]);

            // 通知经理
            if (mission) {
                db.run(`INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_id, mission_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [mission.created_by, null, '任务系统', '[任务结算] 所有特工已确认',
                        `所有参与特工都已接受初评，任务报告已自动完成结算。`,
                        'rating_finalized', reportId, report.mission_id, now]);
            }

            res.json({ success: true, message: '已接受评级，所有特工已确认，奖惩已自动结算', autoFinalized: true });
        } else {
            // 还有人未响应，只记录当前特工的接受状态
            // 通知经理有人接受了
            if (mission) {
                const acceptedCount = allResponses.filter(r => r.status === 'accepted').length + 1; // +1 因为当前用户刚接受
                const totalCount = allResponses.length;
                db.run(`INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_id, mission_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [mission.created_by, charId, charName, '[评级确认] 特工已接受初评',
                        `${charName} 已接受初评评级。\n\n当前进度: ${acceptedCount}/${totalCount} 特工已响应\n${appealingCount > 0 ? `申诉中: ${appealingCount} 人` : ''}`,
                        'rating_accepted', reportId, report.mission_id, now]);
            }

            res.json({ success: true, message: '已接受评级，等待其他特工响应', autoFinalized: false });
        }
    } catch (e) {
        console.error('接受评级失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 经理最终结算（只能在有申诉时使用，处理申诉后进行结算）
app.post('/api/manager/mission/:id/report/:reportId/finalize', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;
    const { rating, agentRewards, appealResponse } = req.body;

    try {
        // 验证任务存在性和权限
        const mission = await new Promise((resolve, reject) => {
            db.get('SELECT created_by, name FROM field_missions WHERE id = ?', [missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });
        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        // 获取报告信息
        const report = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM mission_reports WHERE id = ? AND mission_id = ?', [reportId, missionId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!report) return res.status(404).json({ success: false, message: '报告不存在' });
        if (report.status === 'finalized') {
            return res.status(400).json({ success: false, message: '报告已完成最终结算' });
        }
        // 只允许在有申诉时进行最终结算
        if (report.status !== 'appealing') {
            return res.status(400).json({ success: false, message: '只能在有申诉时进行最终结算。请等待所有特工响应，如果全部接受将自动结算。' });
        }

        const now = Date.now();
        const finalRewards = agentRewards || JSON.parse(report.pending_rewards || '{}');
        const finalRating = rating || report.rating;

        // 应用奖惩
        if (finalRewards && typeof finalRewards === 'object') {
            for (const [charId, rewards] of Object.entries(finalRewards)) {
                const char = await new Promise((resolve, reject) => {
                    db.get('SELECT data FROM characters WHERE id = ?', [charId], (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    });
                });

                if (char) {
                    let charData = {};
                    try { charData = JSON.parse(char.data || '{}'); } catch(e) {}

                    // 使用正确的字段名（与前端对应）
                    // mvpCount = 嘉奖数量, watchCount = 申诫数量, pComm = MVP, pRep = 查看期
                    const missionName = mission?.name || '任务';

                    // 更新数字统计
                    charData.mvpCount = (parseInt(charData.mvpCount) || 0) + (rewards.commend || 0);
                    charData.watchCount = (parseInt(charData.watchCount) || 0) + (rewards.reprimand || 0);
                    if (rewards.probation) {
                        charData.pRep = (parseInt(charData.pRep) || 0) + 1;
                    }
                    if (rewards.mvp) {
                        charData.pComm = (parseInt(charData.pComm) || 0) + 1;
                    }

                    // 同时添加记录到数组（用于查看历史）
                    if (!Array.isArray(charData.rewards)) charData.rewards = [];
                    if (!Array.isArray(charData.reprimands)) charData.reprimands = [];

                    if (rewards.commend > 0) {
                        charData.rewards.push({
                            reason: `来自「${missionName}」任务结算`,
                            count: rewards.commend,
                            date: now,
                            addedByName: '任务系统'
                        });
                    }
                    if (rewards.reprimand > 0) {
                        charData.reprimands.push({
                            reason: `来自「${missionName}」任务结算`,
                            count: rewards.reprimand,
                            date: now,
                            addedByName: '任务系统'
                        });
                    }

                    // 保存更新后的角色数据
                    await new Promise((resolve, reject) => {
                        db.run('UPDATE characters SET data = ? WHERE id = ?',
                            [JSON.stringify(charData), charId], (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                    });

                    // 发送最终结算通知
                    let rewardMsg = [];
                    if (rewards.commend > 0) rewardMsg.push(`嘉奖 +${rewards.commend}`);
                    if (rewards.reprimand > 0) rewardMsg.push(`申诫 +${rewards.reprimand}`);
                    if (rewards.mvp) rewardMsg.push(`获得MVP`);
                    if (rewards.probation) rewardMsg.push(`进入查看期`);

                    const subject = '[任务结算] 最终评级通知';
                    let content = `最终评级: ${finalRating}\n\n奖惩结算:\n${rewardMsg.join('\n') || '无'}`;
                    if (appealResponse) {
                        content += `\n\n申诉回复:\n${appealResponse}`;
                    }
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [charId, req.user.userId, '任务系统', subject, content, 'system', now]);
                }
            }
        }

        // 更新报告状态
        await new Promise((resolve, reject) => {
            db.run(`UPDATE mission_reports SET
                status = 'finalized',
                rating = ?,
                final_rewards = ?,
                appeal_response = ?,
                sent_at = ?
                WHERE id = ?`,
                [finalRating, JSON.stringify(finalRewards), appealResponse || null, now, reportId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // 更新任务状态
        db.run('UPDATE field_missions SET report_status = ?, updated_at = ? WHERE id = ?', ['sent', now, missionId]);

        res.json({ success: true, message: '已完成最终结算' });
    } catch (e) {
        console.error('最终结算失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 获取报告的特工响应状态
app.get('/api/manager/mission/:id/report/:reportId/agent-responses', authenticateToken, requireRole(ROLE.MANAGER), async (req, res) => {
    const missionId = req.params.id;
    const reportId = req.params.reportId;

    try {
        // 获取所有响应记录，包括角色信息
        const responses = await new Promise((resolve, reject) => {
            db.all(`SELECT
                    rar.*,
                    c.data as char_data
                FROM report_agent_responses rar
                JOIN characters c ON rar.character_id = c.id
                WHERE rar.report_id = ?`, [reportId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });

        // 格式化返回数据
        const formattedResponses = responses.map(r => {
            let charData = {};
            try { charData = JSON.parse(r.char_data || '{}'); } catch(e) {}
            let pendingRewards = {};
            try { pendingRewards = JSON.parse(r.pending_rewards || '{}'); } catch(e) {}

            return {
                character_id: r.character_id,
                character_name: charData.pName || '未知特工',
                status: r.status,
                pending_rewards: pendingRewards,
                appeal_reason: r.appeal_reason,
                responded_at: r.responded_at
            };
        });

        res.json({
            success: true,
            responses: formattedResponses,
            summary: {
                total: responses.length,
                pending: responses.filter(r => r.status === 'pending').length,
                accepted: responses.filter(r => r.status === 'accepted').length,
                appealing: responses.filter(r => r.status === 'appealing').length
            }
        });
    } catch (e) {
        console.error('获取特工响应状态失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 归档任务（需报告已发送）
app.post('/api/manager/mission/:id/archive', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;

    db.get('SELECT * FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        // 检查是否有已完成的报告（sent 或 finalized）
        db.get('SELECT COUNT(*) as count FROM mission_reports WHERE mission_id = ? AND status IN (?, ?)', [missionId, 'sent', 'finalized'], (err, finishedCount) => {
            // 检查是否有正在进行中的报告（initial 或 appealing，需要完成）
            db.get('SELECT COUNT(*) as count FROM mission_reports WHERE mission_id = ? AND status IN (?, ?)', [missionId, 'initial', 'appealing'], (err, inProgressCount) => {
                if (inProgressCount && inProgressCount.count > 0) {
                    return res.status(400).json({
                        success: false,
                        message: '存在正在评审中的报告，请先完成评审'
                    });
                }

                // 如果有已完成报告或者没有任何非草稿报告，可以归档
                // (草稿报告可以忽略)
                doArchive();
            });
        });

        function doArchive() {
            const now = Date.now();
            db.run('UPDATE field_missions SET status = ?, updated_at = ? WHERE id = ?', ['archived', now, missionId], function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
        }
    });
});

// 角色卡查询所属任务、队友和经理信息
app.get('/api/character/:charId/mission', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    // 验证访问权限
    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ error: '角色不存在' });

        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权访问' });
        }

        // 先获取该角色卡的负责经理
        db.all(`
            SELECT DISTINCT u.id, u.name, u.username
            FROM character_authorizations ca
            JOIN users u ON ca.manager_id = u.id
            WHERE ca.character_id = ?
        `, [charId], (err, managers) => {
            const managerList = (managers || []).map(m => ({
                id: m.id,
                name: m.name || m.username
            }));

            // 查找该角色所属的所有活跃任务
            db.all(`
                SELECT fm.*, fmm.member_status, u.name as creator_name, u.username as creator_username
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                LEFT JOIN users u ON fm.created_by = u.id
                WHERE fmm.character_id = ? AND fm.status = 'active'
                ORDER BY fm.created_at DESC
            `, [charId], (err, missions) => {
                if (!missions || missions.length === 0) {
                    return res.json({
                        inMission: false,
                        managers: managerList
                    });
                }

                // 获取所有任务的队友信息
                const missionIds = missions.map(m => m.id);
                const placeholders = missionIds.map(() => '?').join(',');

                db.all(`
                    SELECT fmm.mission_id, fmm.character_id, fmm.member_status, c.data
                    FROM field_mission_members fmm
                    JOIN characters c ON fmm.character_id = c.id
                    WHERE fmm.mission_id IN (${placeholders})
                `, missionIds, (err, allMembers) => {
                    // 按任务分组队友
                    const membersByMission = {};
                    (allMembers || []).forEach(m => {
                        if (!membersByMission[m.mission_id]) {
                            membersByMission[m.mission_id] = [];
                        }
                        let d = {};
                        try { d = JSON.parse(m.data); } catch(e) {}
                        membersByMission[m.mission_id].push({
                            characterId: m.character_id,
                            characterName: d.pName || '未命名',
                            status: m.member_status,
                            isMe: m.character_id === charId
                        });
                    });

                    // 构建任务列表
                    const missionList = missions.map(m => ({
                        missionId: m.id,
                        missionName: m.name,
                        missionDescription: m.description,
                        missionType: m.mission_type,
                        missionStatus: m.status,
                        myStatus: m.member_status,
                        creatorName: m.creator_name || m.creator_username || '未知',
                        creatorId: m.created_by,
                        teammates: membersByMission[m.id] || []
                    }));

                    res.json({
                        inMission: true,
                        missions: missionList,
                        // 兼容旧版本，返回第一个任务的信息
                        missionId: missionList[0].missionId,
                        missionName: missionList[0].missionName,
                        myStatus: missionList[0].myStatus,
                        teammates: missionList[0].teammates,
                        managers: managerList
                    });
                });
            });
        });
    });
});

// ==========================================
// 角色卡邮件发送 API
// ==========================================

// 获取可发送对象（经理+队友）
app.get('/api/character/:charId/send-targets', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    db.get('SELECT user_id FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ error: '角色不存在' });

        if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ error: '无权访问' });
        }

        // 获取授权该角色卡的经理
        db.all(`
            SELECT DISTINCT u.id, u.name, u.username
            FROM character_authorizations ca
            JOIN users u ON ca.manager_id = u.id
            WHERE ca.character_id = ?
        `, [charId], (err, managers) => {
            const managerList = (managers || []).map(m => ({
                id: m.id,
                name: m.name || m.username,
                type: 'manager'
            }));

            // 获取同任务的队友
            db.all(`
                SELECT c.id, c.data
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                JOIN field_mission_members fmm2 ON fmm.mission_id = fmm2.mission_id
                JOIN characters c ON fmm2.character_id = c.id
                WHERE fmm.character_id = ? AND fm.status = 'active' AND fmm2.character_id != ?
            `, [charId, charId], (err, teammates) => {
                const teammateList = (teammates || []).map(t => {
                    let d = {};
                    try { d = JSON.parse(t.data); } catch(e) {}
                    return {
                        id: t.id,
                        name: d.pName || '未命名',
                        type: 'character'
                    };
                });

                res.json({
                    managers: managerList,
                    teammates: teammateList
                });
            });
        });
    });
});

// 发送普通邮件
app.post('/api/character/:charId/send-mail', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    const { recipientType, recipientId, subject, content } = req.body;

    // 检查全局私信开关（管理员除外）
    if (req.user.role < ROLE.SUPER_ADMIN) {
        const config = await getAllConfig();
        if (config.messaging_enabled === 'false') {
            return res.status(403).json({ success: false, message: '私信功能已被管理员暂时关闭' });
        }
    }

    // 验证权限
    const char = await new Promise((resolve) => {
        db.get('SELECT user_id, data, can_send_messages FROM characters WHERE id = ?', [charId], (err, row) => resolve(row));
    });

    if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
    if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
        return res.status(403).json({ success: false, message: '无权操作' });
    }

    // 检查发信权限
    if (char.can_send_messages === 0) {
        return res.status(403).json({ success: false, message: '您的发信权限已被禁用' });
    }

    if (!subject || !content) {
        return res.status(400).json({ success: false, message: '标题和内容不能为空' });
    }

    let charData = {};
    try { charData = JSON.parse(char.data); } catch(e) {}
    const senderName = charData.pName || '未命名角色';

    const now = Date.now();

    // 获取收件人名称（用于已发邮件显示）
    let recipientName = '未知';
    if (recipientType === 'manager') {
        const manager = await new Promise(resolve => {
            db.get('SELECT name, username FROM users WHERE id = ?', [recipientId], (err, row) => resolve(row));
        });
        recipientName = manager ? (manager.name || manager.username) : '经理';
    } else if (recipientType === 'character') {
        const recipient = await new Promise(resolve => {
            db.get('SELECT data FROM characters WHERE id = ?', [recipientId], (err, row) => resolve(row));
        });
        if (recipient) {
            try {
                const rData = JSON.parse(recipient.data);
                recipientName = rData.pName || '未命名角色';
            } catch(e) {}
        }
    }

    if (recipientType === 'manager') {
        // 检查特工是否在某个任务中
        const activeMission = await new Promise((resolve) => {
            db.get(`
                SELECT fm.id as mission_id, fm.created_by as manager_id
                FROM field_mission_members fmm
                JOIN field_missions fm ON fmm.mission_id = fm.id
                WHERE fmm.character_id = ? AND fm.status = 'active'
            `, [charId], (err, row) => resolve(row));
        });

        if (activeMission) {
            // 特工在任务中，发送到任务收件箱
            db.run('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [activeMission.mission_id, charId, senderName, subject, content, 'mail', now],
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: err.message });
                    // 记录已发邮件
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                        [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                    res.json({ success: true, messageId: this.lastID, sentToMission: true });
                });
        } else {
            // 特工不在任务中，发送到经理全局收件箱
            db.run('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [recipientId, charId, senderName, subject, content, 'mail', now],
                function(err) {
                    if (err) return res.status(500).json({ success: false, message: err.message });
                    // 记录已发邮件
                    db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                        [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                    res.json({ success: true, messageId: this.lastID, sentToMission: false });
                });
        }
    } else if (recipientType === 'character') {
        // 发送给队友 - 存入 character_messages
        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [recipientId, req.user.userId, senderName, subject, content, 'mail', charId, recipientName, now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                // 记录已发邮件
                db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                    [charId, req.user.userId, senderName, subject, content, 'sent', charId, recipientName, now]);
                res.json({ success: true, messageId: this.lastID });
            });
    } else {
        return res.status(400).json({ success: false, message: '无效的收件人类型' });
    }
});

// 寄送收容物
app.post('/api/character/:charId/send-containment', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    const { recipientId, name: containmentName, description } = req.body;

    const char = await new Promise((resolve) => {
        db.get('SELECT user_id, data FROM characters WHERE id = ?', [charId], (err, row) => resolve(row));
    });

    if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
    if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
        return res.status(403).json({ success: false, message: '无权操作' });
    }

    if (!containmentName) {
        return res.status(400).json({ success: false, message: '收容物名称不能为空' });
    }

    let charData = {};
    try { charData = JSON.parse(char.data); } catch(e) {}
    const senderName = charData.pName || '未命名角色';

    const subject = `[收容物] ${containmentName}`;
    const content = `收容物名称: ${containmentName}\n\n描述:\n${description || '无'}`;
    const now = Date.now();

    // 检查特工是否在某个任务中
    const activeMission = await new Promise((resolve) => {
        db.get(`
            SELECT fm.id as mission_id, fm.created_by as manager_id
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.status = 'active'
        `, [charId], (err, row) => resolve(row));
    });

    if (activeMission) {
        // 发送到任务收件箱
        db.run('INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [activeMission.mission_id, charId, senderName, subject, content, 'containment', now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                // 记录到已发邮件
                db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                    [charId, req.user.userId, senderName, subject, content, 'sent', charId, '任务收件箱', now]);
                res.json({ success: true, messageId: this.lastID, sentToMission: true });
            });
    } else {
        // 发送到经理全局收件箱
        db.run('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [recipientId, charId, senderName, subject, content, 'containment', now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });
                // 记录到已发邮件
                db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                    [charId, req.user.userId, senderName, subject, content, 'sent', charId, '经理', now]);
                res.json({ success: true, messageId: this.lastID, sentToMission: false });
            });
    }
});

// 提交任务报告
app.post('/api/character/:charId/send-report', authenticateToken, async (req, res) => {
    const charId = req.params.charId;
    // 前端直接发送 reportData 作为 body，不是包装在对象中
    const reportData = req.body;
    const recipientId = req.body.recipientId; // 可能存在于旧版本请求中

    const char = await new Promise((resolve) => {
        db.get('SELECT user_id, data FROM characters WHERE id = ?', [charId], (err, row) => resolve(row));
    });

    if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
    if (char.user_id !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
        return res.status(403).json({ success: false, message: '无权操作' });
    }

    let charData = {};
    try { charData = JSON.parse(char.data); } catch(e) {}
    const senderName = charData.pName || '未命名角色';

    const subject = `[任务报告] 来自 ${senderName}`;
    const content = `任务报告已提交，详情请查看报告数据`;
    const now = Date.now();

    // 检查特工是否在某个任务中
    const activeMission = await new Promise((resolve) => {
        db.get(`
            SELECT fm.id as mission_id, fm.created_by as manager_id
            FROM field_mission_members fmm
            JOIN field_missions fm ON fmm.mission_id = fm.id
            WHERE fmm.character_id = ? AND fm.status = 'active'
        `, [charId], (err, row) => resolve(row));
    });

    if (activeMission) {
        // 检查是否已提交过报告
        const existingReport = await new Promise((resolve) => {
            db.get('SELECT id FROM mission_reports WHERE mission_id = ? AND submitted_by = ?',
                [activeMission.mission_id, charId], (err, row) => resolve(row));
        });

        if (existingReport) {
            return res.status(409).json({
                success: false,
                message: '您已在此任务中提交过报告，无法重复提交'
            });
        }

        // 创建任务报告记录
        db.run(`INSERT INTO mission_reports (mission_id, submitted_by, original_data, status, submitted_at)
                VALUES (?, ?, ?, 'submitted', ?)`,
            [activeMission.mission_id, charId, JSON.stringify(reportData), now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });

                const reportId = this.lastID;

                // 同时在任务收件箱创建通知
                db.run(`INSERT INTO mission_inbox (mission_id, sender_character_id, sender_name, subject, content, message_type, report_id, created_at)
                        VALUES (?, ?, ?, ?, ?, 'report', ?, ?)`,
                    [activeMission.mission_id, charId, senderName, subject, content, reportId, now],
                    function(err) {
                        if (err) return res.status(500).json({ success: false, message: err.message });

                        // 更新任务报告状态
                        db.run('UPDATE field_missions SET report_status = ? WHERE id = ?', ['submitted', activeMission.mission_id]);

                        // 记录到已发邮件 - 构建报告摘要
                        const reportSummary = buildReportSummary(reportData);
                        db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                            [charId, req.user.userId, senderName, subject, reportSummary, 'sent', charId, '任务收件箱', now]);

                        res.json({ success: true, reportId, messageId: this.lastID, sentToMission: true });
                    });
            });
    } else {
        // 发送到经理全局收件箱（无任务关联）
        db.run('INSERT INTO manager_inbox (manager_id, sender_character_id, sender_name, subject, content, message_type, report_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [recipientId, charId, senderName, subject, content, 'report', JSON.stringify(reportData), now],
            function(err) {
                if (err) return res.status(500).json({ success: false, message: err.message });

                // 记录到已发邮件
                const reportSummary = buildReportSummary(reportData);
                db.run('INSERT INTO character_messages (character_id, sender_id, sender_name, subject, content, message_type, from_character_id, recipient_name, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
                    [charId, req.user.userId, senderName, subject, reportSummary, 'sent', charId, '经理', now]);

                res.json({ success: true, messageId: this.lastID, sentToMission: false });
            });
    }
});

// 构建报告摘要用于已发邮件显示
function buildReportSummary(reportData) {
    if (!reportData) return '任务报告已提交';

    let summary = [];

    // 异常状态
    if (reportData.status) {
        const statusMap = {
            neutralized: '已中和',
            captured: '已捕获',
            escaped: '已逃脱'
        };
        const selected = reportData.status.selected;
        if (selected && statusMap[selected]) {
            summary.push(`异常状态: ${statusMap[selected]}`);
        } else if (reportData.status.other) {
            summary.push(`异常状态: ${reportData.status.other}`);
        }
    }

    // 异常分析
    if (reportData.analysis) {
        if (reportData.analysis.codename) summary.push(`代号: ${reportData.analysis.codename}`);
        if (reportData.analysis.behavior) summary.push(`行为: ${reportData.analysis.behavior}`);
    }

    // 评优信息
    if (reportData.evaluation) {
        if (reportData.evaluation.participants) summary.push(`参与者: ${reportData.evaluation.participants}`);
    }

    return summary.length > 0 ? summary.join('\n') : '任务报告已提交';
}

// ==========================================
// 经理收件箱 API
// ==========================================

// 获取经理收件箱
app.get('/api/manager/inbox', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.all('SELECT * FROM manager_inbox WHERE manager_id = ? ORDER BY created_at DESC',
        [req.user.userId], (err, messages) => {
            if (err) return res.status(500).json([]);
            res.json(messages || []);
        });
});

// 获取经理收件箱未读数
app.get('/api/manager/inbox/unread-count', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get('SELECT COUNT(*) as count FROM manager_inbox WHERE manager_id = ? AND read = 0',
        [req.user.userId], (err, row) => {
            if (err) return res.json({ count: 0 });
            res.json({ count: row ? row.count : 0 });
        });
});

// 获取单封邮件详情
app.get('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get('SELECT * FROM manager_inbox WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], (err, msg) => {
            if (!msg) return res.status(404).json({ error: '邮件不存在' });

            // 如果有报告数据，解析它
            if (msg.report_data) {
                try {
                    msg.reportData = JSON.parse(msg.report_data);
                } catch(e) {}
            }

            res.json(msg);
        });
});

// 标记经理邮件已读
app.put('/api/manager/inbox/:msgId/read', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('UPDATE manager_inbox SET read = 1 WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

// 删除经理邮件
app.delete('/api/manager/inbox/:msgId', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.run('DELETE FROM manager_inbox WHERE id = ? AND manager_id = ?',
        [req.params.msgId, req.user.userId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

// ==================== 分部系统API ====================

// 创建分部（超管）
app.post('/api/admin/branch', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const { name, description } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ success: false, message: '分部名称不能为空' });
    }

    const branchId = Date.now().toString();
    const now = Date.now();

    db.run(`INSERT INTO branches (id, name, description, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
        [branchId, name.trim(), description || '', req.user.userId, now, now],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, branchId });
        });
});

// 获取所有分部
app.get('/api/admin/branches', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.all(`
        SELECT b.*,
            (SELECT COUNT(*) FROM branch_managers WHERE branch_id = b.id) as manager_count,
            (SELECT COALESCE(SUM(fm.scatter_value), 0)
             FROM field_missions fm
             WHERE fm.branch_id = b.id AND fm.status = 'archived') as total_scatter
        FROM branches b
        ORDER BY b.created_at DESC
    `, [], (err, branches) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, branches: branches || [] });
    });
});

// 获取单个分部详情
app.get('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const branchId = req.params.id;

    db.get('SELECT * FROM branches WHERE id = ?', [branchId], (err, branch) => {
        if (!branch) return res.status(404).json({ success: false, message: '分部不存在' });

        // 获取分部经理
        db.all(`
            SELECT u.id, u.username, u.name
            FROM branch_managers bm
            JOIN users u ON bm.manager_id = u.id
            WHERE bm.branch_id = ?
        `, [branchId], (err, managers) => {
            // 获取分部统计
            db.get(`
                SELECT
                    COUNT(*) as mission_count,
                    COALESCE(SUM(scatter_value), 0) as total_scatter,
                    COALESCE(SUM(chaos_value), 0) as total_chaos
                FROM field_missions
                WHERE branch_id = ? AND status = 'archived'
            `, [branchId], (err, stats) => {
                res.json({
                    success: true,
                    branch: {
                        ...branch,
                        managers: managers || [],
                        stats: stats || { mission_count: 0, total_scatter: 0, total_chaos: 0 }
                    }
                });
            });
        });
    });
});

// 更新分部
app.put('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;
    const { name, description } = req.body;

    const updates = ['updated_at = ?'];
    const params = [Date.now()];

    if (name !== undefined) {
        updates.push('name = ?');
        params.push(name.trim());
    }
    if (description !== undefined) {
        updates.push('description = ?');
        params.push(description);
    }

    params.push(branchId);

    db.run(`UPDATE branches SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// 删除分部
app.delete('/api/admin/branch/:id', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;

    db.run('DELETE FROM branches WHERE id = ?', [branchId], function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// 添加经理到分部
app.post('/api/admin/branch/:id/manager', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;
    const { managerId } = req.body;

    if (!managerId) {
        return res.status(400).json({ success: false, message: '经理ID不能为空' });
    }

    db.run('INSERT OR IGNORE INTO branch_managers (branch_id, manager_id, assigned_at) VALUES (?, ?, ?)',
        [branchId, managerId, Date.now()],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true });
        });
});

// 从分部移除经理
app.delete('/api/admin/branch/:id/manager/:managerId', authenticateToken, requireRole(ROLE.SUPER_ADMIN), (req, res) => {
    const branchId = req.params.id;
    const managerId = req.params.managerId;

    db.run('DELETE FROM branch_managers WHERE branch_id = ? AND manager_id = ?',
        [branchId, managerId],
        function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true });
        });
});

// 经理获取自己所属分部信息
app.get('/api/manager/my-branch', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    db.get(`
        SELECT b.*,
            (SELECT COALESCE(SUM(fm.scatter_value), 0)
             FROM field_missions fm
             WHERE fm.branch_id = b.id AND fm.status = 'archived') as total_scatter
        FROM branch_managers bm
        JOIN branches b ON bm.branch_id = b.id
        WHERE bm.manager_id = ?
    `, [req.user.userId], (err, branch) => {
        if (!branch) {
            return res.json({ success: true, branch: null });
        }
        res.json({ success: true, branch });
    });
});

// 将任务分配到分部
app.put('/api/manager/mission/:id/branch', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const missionId = req.params.id;
    const { branchId } = req.body;

    db.get('SELECT created_by FROM field_missions WHERE id = ?', [missionId], (err, mission) => {
        if (!mission) return res.status(404).json({ success: false, message: '任务不存在' });

        if (mission.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权操作' });
        }

        db.run('UPDATE field_missions SET branch_id = ?, updated_at = ? WHERE id = ?',
            [branchId || null, Date.now(), missionId],
            function(err) {
                if (err) return res.status(500).json({ success: false });
                res.json({ success: true });
            });
    });
});

// ==================== 申领物商店API ====================

// 获取申领物列表（经理端）
app.get('/api/manager/shop/items', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    // 经理看到：自己创建的 + 全局的(admin创建的)
    const query = req.user.role >= ROLE.SUPER_ADMIN
        ? `SELECT si.*, u.name as creator_name FROM shop_items si
           LEFT JOIN users u ON si.created_by = u.id
           WHERE si.is_active = 1 ORDER BY si.created_at DESC`
        : `SELECT si.*, u.name as creator_name FROM shop_items si
           LEFT JOIN users u ON si.created_by = u.id
           WHERE si.is_active = 1 AND (si.created_by = ? OR si.is_global = 1)
           ORDER BY si.created_at DESC`;

    const params = req.user.role >= ROLE.SUPER_ADMIN ? [] : [req.user.userId];

    db.all(query, params, (err, items) => {
        if (err) return res.status(500).json({ success: false, message: '获取失败' });

        // 获取每个物品的标价选项
        const itemIds = items.map(i => i.id);
        if (itemIds.length === 0) {
            return res.json({ success: true, items: [] });
        }

        const placeholders = itemIds.map(() => '?').join(',');
        db.all(`SELECT * FROM shop_item_prices WHERE item_id IN (${placeholders}) ORDER BY sort_order`, itemIds, (err, prices) => {
            const pricesByItem = {};
            (prices || []).forEach(p => {
                if (!pricesByItem[p.item_id]) pricesByItem[p.item_id] = [];
                pricesByItem[p.item_id].push(p);
            });

            const result = items.map(item => ({
                ...item,
                prices: pricesByItem[item.id] || [],
                canEdit: item.created_by === req.user.userId || req.user.role >= ROLE.SUPER_ADMIN
            }));

            res.json({ success: true, items: result });
        });
    });
});

// 创建申领物
app.post('/api/manager/shop/items', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const { title, description, prices, isGlobal } = req.body;

    if (!title || !title.trim()) {
        return res.status(400).json({ success: false, message: '请填写物品标题' });
    }

    if (!prices || !Array.isArray(prices) || prices.length === 0) {
        return res.status(400).json({ success: false, message: '请至少添加一个标价选项' });
    }

    // 只有超管可以创建全局物品
    const global = (isGlobal && req.user.role >= ROLE.SUPER_ADMIN) ? 1 : 0;
    const now = Date.now();

    db.run(`INSERT INTO shop_items (title, description, created_by, is_global, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
        [title.trim(), description || '', req.user.userId, global, now, now],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: '创建失败' });

            const itemId = this.lastID;

            // 插入标价选项
            // usage_type: 'permanent'=永久, 'consumable'=一次性消耗, 'per_mission'=每任务可用次数
            // currency_type: 'commendation'=嘉奖, 'reprimand'=申诫
            const stmt = db.prepare('INSERT INTO shop_item_prices (item_id, price_name, price_cost, currency_type, usage_type, usage_count, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)');
            prices.forEach((p, idx) => {
                if (p.name && p.cost >= 0) {
                    const currencyType = p.currencyType || 'commendation';
                    const usageType = p.usageType || 'permanent';
                    const usageCount = parseInt(p.usageCount) || 0;
                    stmt.run(itemId, p.name.trim(), parseInt(p.cost) || 0, currencyType, usageType, usageCount, idx);
                }
            });
            stmt.finalize();

            res.json({ success: true, itemId, message: '申领物创建成功' });
        });
});

// 更新申领物
app.put('/api/manager/shop/items/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const itemId = req.params.id;
    const { title, description, prices, isGlobal } = req.body;

    db.get('SELECT * FROM shop_items WHERE id = ?', [itemId], (err, item) => {
        if (!item) return res.status(404).json({ success: false, message: '物品不存在' });

        // 只有创建者或超管可以编辑
        if (item.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权编辑此物品' });
        }

        const global = (isGlobal && req.user.role >= ROLE.SUPER_ADMIN) ? 1 : 0;
        const now = Date.now();

        db.run('UPDATE shop_items SET title = ?, description = ?, is_global = ?, updated_at = ? WHERE id = ?',
            [title.trim(), description || '', global, now, itemId],
            function(err) {
                if (err) return res.status(500).json({ success: false });

                // 删除旧标价，插入新标价
                db.run('DELETE FROM shop_item_prices WHERE item_id = ?', [itemId], () => {
                    if (prices && Array.isArray(prices)) {
                        const stmt = db.prepare('INSERT INTO shop_item_prices (item_id, price_name, price_cost, currency_type, usage_type, usage_count, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)');
                        prices.forEach((p, idx) => {
                            if (p.name && p.cost >= 0) {
                                const currencyType = p.currencyType || 'commendation';
                                const usageType = p.usageType || 'permanent';
                                const usageCount = parseInt(p.usageCount) || 0;
                                stmt.run(itemId, p.name.trim(), parseInt(p.cost) || 0, currencyType, usageType, usageCount, idx);
                            }
                        });
                        stmt.finalize();
                    }
                    res.json({ success: true, message: '更新成功' });
                });
            });
    });
});

// 删除申领物
app.delete('/api/manager/shop/items/:id', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const itemId = req.params.id;

    db.get('SELECT * FROM shop_items WHERE id = ?', [itemId], (err, item) => {
        if (!item) return res.status(404).json({ success: false, message: '物品不存在' });

        if (item.created_by !== req.user.userId && req.user.role < ROLE.SUPER_ADMIN) {
            return res.status(403).json({ success: false, message: '无权删除此物品' });
        }

        // 软删除
        db.run('UPDATE shop_items SET is_active = 0 WHERE id = ?', [itemId], function(err) {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, message: '删除成功' });
        });
    });
});

// 玩家获取可购买的申领物列表
app.get('/api/character/:charId/shop', authenticateToken, (req, res) => {
    const charId = req.params.charId;

    // 验证角色归属
    db.get('SELECT * FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId && req.user.role < ROLE.MANAGER) {
            return res.status(403).json({ success: false, message: '无权访问' });
        }

        let charData = {};
        try { charData = JSON.parse(char.data); } catch(e) {}

        // 检查申诫商店权限
        const hasReprimandAccess = charData.reprimandShopAccess === true;

        // 计算可用嘉奖数
        let availableCommendations = 0;
        if (Array.isArray(charData.rewards)) {
            availableCommendations = charData.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
        }
        availableCommendations += parseInt(charData.commendations) || 0;

        // 计算可用申诫数（仅在有权限时返回）
        let availableReprimands = 0;
        if (hasReprimandAccess && Array.isArray(charData.reprimands)) {
            availableReprimands = charData.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
        }

        // 获取该角色被哪些经理管理
        db.all(`SELECT DISTINCT manager_id FROM character_authorizations WHERE character_id = ?`, [charId], (err, auths) => {
            const managerIds = (auths || []).map(a => a.manager_id);

            // 获取全局物品 + 管理该角色的经理创建的物品
            let query, params;
            if (managerIds.length > 0) {
                const placeholders = managerIds.map(() => '?').join(',');
                query = `SELECT si.*, u.name as creator_name FROM shop_items si
                         LEFT JOIN users u ON si.created_by = u.id
                         WHERE si.is_active = 1 AND (si.is_global = 1 OR si.created_by IN (${placeholders}))
                         ORDER BY si.is_global DESC, si.created_at DESC`;
                params = managerIds;
            } else {
                query = `SELECT si.*, u.name as creator_name FROM shop_items si
                         LEFT JOIN users u ON si.created_by = u.id
                         WHERE si.is_active = 1 AND si.is_global = 1
                         ORDER BY si.created_at DESC`;
                params = [];
            }

            db.all(query, params, (err, items) => {
                if (err) return res.status(500).json({ success: false });

                const itemIds = items.map(i => i.id);
                if (itemIds.length === 0) {
                    const responseData = { success: true, items: [], availableCommendations };
                    if (hasReprimandAccess) responseData.availableReprimands = availableReprimands;
                    return res.json(responseData);
                }

                const placeholders = itemIds.map(() => '?').join(',');
                db.all(`SELECT * FROM shop_item_prices WHERE item_id IN (${placeholders}) ORDER BY sort_order`, itemIds, (err, prices) => {
                    const pricesByItem = {};
                    (prices || []).forEach(p => {
                        // 如果没有申诫商店权限，过滤掉申诫标价
                        if (!hasReprimandAccess && p.currency_type === 'reprimand') {
                            return;
                        }
                        if (!pricesByItem[p.item_id]) pricesByItem[p.item_id] = [];
                        pricesByItem[p.item_id].push(p);
                    });

                    const result = items.map(item => ({
                        ...item,
                        prices: pricesByItem[item.id] || []
                    }));

                    const responseData = { success: true, items: result, availableCommendations };
                    if (hasReprimandAccess) responseData.availableReprimands = availableReprimands;
                    res.json(responseData);
                });
            });
        });
    });
});

// 玩家购买申领物
app.post('/api/character/:charId/shop/purchase', authenticateToken, (req, res) => {
    const charId = req.params.charId;
    const { itemId, priceId } = req.body;

    db.get('SELECT * FROM characters WHERE id = ?', [charId], (err, char) => {
        if (!char) return res.status(404).json({ success: false, message: '角色不存在' });
        if (char.user_id !== req.user.userId) {
            return res.status(403).json({ success: false, message: '只能为自己的角色购买' });
        }

        let charData = {};
        try { charData = JSON.parse(char.data); } catch(e) {}

        // 获取标价信息
        db.get(`SELECT sip.*, si.title as item_title FROM shop_item_prices sip
                JOIN shop_items si ON sip.item_id = si.id
                WHERE sip.id = ? AND sip.item_id = ? AND si.is_active = 1`, [priceId, itemId], (err, price) => {
            if (!price) {
                return res.status(404).json({ success: false, message: '标价选项不存在' });
            }

            const currencyType = price.currency_type || 'commendation';
            const currencyName = currencyType === 'reprimand' ? '申诫' : '嘉奖';

            // 检查申诫商店权限
            if (currencyType === 'reprimand' && charData.reprimandShopAccess !== true) {
                return res.status(403).json({ success: false, message: '没有申诫商店权限' });
            }
            let available = 0;

            if (currencyType === 'reprimand') {
                // 计算可用申诫
                if (Array.isArray(charData.reprimands)) {
                    available = charData.reprimands.reduce((sum, r) => sum + (r.count || 1), 0);
                }
            } else {
                // 计算可用嘉奖
                if (Array.isArray(charData.rewards)) {
                    available = charData.rewards.reduce((sum, r) => sum + (r.count || 1), 0);
                }
                available += parseInt(charData.commendations) || 0;
            }

            if (available < price.price_cost) {
                return res.status(400).json({ success: false, message: `${currencyName}不足，需要 ${price.price_cost} ${currencyName}，当前只有 ${available} ${currencyName}` });
            }

            // 扣除货币
            let remaining = price.price_cost;

            if (currencyType === 'reprimand') {
                // 从 reprimands 数组扣
                if (Array.isArray(charData.reprimands)) {
                    const newReprimands = [];
                    for (const r of charData.reprimands) {
                        if (remaining <= 0) {
                            newReprimands.push(r);
                            continue;
                        }
                        const count = r.count || 1;
                        if (count <= remaining) {
                            remaining -= count;
                        } else {
                            r.count = count - remaining;
                            remaining = 0;
                            newReprimands.push(r);
                        }
                    }
                    charData.reprimands = newReprimands;
                }
            } else {
                // 先从 commendations 数值扣
                if (charData.commendations && charData.commendations > 0) {
                    const deduct = Math.min(charData.commendations, remaining);
                    charData.commendations -= deduct;
                    remaining -= deduct;
                }

                // 再从 rewards 数组扣
                if (remaining > 0 && Array.isArray(charData.rewards)) {
                    const newRewards = [];
                    for (const r of charData.rewards) {
                        if (remaining <= 0) {
                            newRewards.push(r);
                            continue;
                        }
                        const count = r.count || 1;
                        if (count <= remaining) {
                            remaining -= count;
                        } else {
                            r.count = count - remaining;
                            remaining = 0;
                            newRewards.push(r);
                        }
                    }
                    charData.rewards = newRewards;
                }
            }

            // 获取物品详细信息用于添加到角色物品列表
            db.get('SELECT title, description FROM shop_items WHERE id = ?', [itemId], (err, itemInfo) => {
                if (err) return res.status(500).json({ success: false });

                // 将物品添加到角色的物品列表
                if (!Array.isArray(charData.items)) charData.items = [];

                // 构建物品对象，包含可用次数信息
                const newItem = {
                    item: `${itemInfo.title} (${price.price_name})`,
                    pd: `通过申领获得 - ${price.price_cost}${currencyName}`,
                    eff: itemInfo.description || ''
                };

                // 根据使用类型设置可用次数
                const usageType = price.usage_type || 'permanent';
                if (usageType === 'consumable') {
                    newItem.usageType = 'consumable';
                    newItem.usageRemaining = 1;
                    newItem.pd += ' [一次性]';
                } else if (usageType === 'per_mission') {
                    newItem.usageType = 'per_mission';
                    newItem.usageCount = price.usage_count || 1;
                    newItem.usageRemaining = price.usage_count || 1;
                    newItem.pd += ` [每任务${price.usage_count || 1}次]`;
                }
                // permanent类型不需要额外标记

                charData.items.push(newItem);

                // 更新角色数据
                db.run('UPDATE characters SET data = ? WHERE id = ?', [JSON.stringify(charData), charId], (err) => {
                    if (err) return res.status(500).json({ success: false });

                    // 记录购买
                    const now = Date.now();
                    db.run(`INSERT INTO shop_purchases (item_id, price_id, character_id, cost_paid, purchased_at, status) VALUES (?, ?, ?, ?, ?, 'completed')`,
                        [itemId, priceId, charId, price.price_cost, now],
                        function(err) {
                            if (err) return res.status(500).json({ success: false });

                            res.json({
                                success: true,
                                message: `成功购买「${price.item_title}」- ${price.price_name}，消耗 ${price.price_cost} 嘉奖，物品已添加到您的物品列表`,
                                remainingCommendations: availableCommendations - price.price_cost
                            });
                        });
                });
            });
        });
    });
});

// 获取购买记录（经理端）
app.get('/api/manager/shop/purchases', authenticateToken, requireRole(ROLE.MANAGER), (req, res) => {
    const query = req.user.role >= ROLE.SUPER_ADMIN
        ? `SELECT sp.*, si.title as item_title, sip.price_name, c.data as char_data
           FROM shop_purchases sp
           JOIN shop_items si ON sp.item_id = si.id
           JOIN shop_item_prices sip ON sp.price_id = sip.id
           JOIN characters c ON sp.character_id = c.id
           ORDER BY sp.purchased_at DESC LIMIT 100`
        : `SELECT sp.*, si.title as item_title, sip.price_name, c.data as char_data
           FROM shop_purchases sp
           JOIN shop_items si ON sp.item_id = si.id
           JOIN shop_item_prices sip ON sp.price_id = sip.id
           JOIN characters c ON sp.character_id = c.id
           WHERE si.created_by = ? OR si.is_global = 1
           ORDER BY sp.purchased_at DESC LIMIT 100`;

    const params = req.user.role >= ROLE.SUPER_ADMIN ? [] : [req.user.userId];

    db.all(query, params, (err, purchases) => {
        if (err) return res.status(500).json({ success: false });

        const result = purchases.map(p => {
            let charData = {};
            try { charData = JSON.parse(p.char_data); } catch(e) {}
            return {
                id: p.id,
                itemTitle: p.item_title,
                priceName: p.price_name,
                costPaid: p.cost_paid,
                characterName: charData.pName || '未命名',
                characterId: p.character_id,
                purchasedAt: p.purchased_at,
                status: p.status
            };
        });

        res.json({ success: true, purchases: result });
    });
});

app.listen(PORT, () => {
    console.log(`服务器运行中: http://localhost:${PORT}`);
    console.log(`数据目录: ${DATA_DIR}`);
});
