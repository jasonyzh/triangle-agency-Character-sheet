const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { db, DATA_DIR, HIGH_SECURITY_DIR } = require('./db/init');
const { BCRYPT_ROUNDS } = require('./constants');

function getConfig(key) {
    return new Promise((resolve, reject) => {
        db.get('SELECT value FROM system_config WHERE key = ?', [key], (err, row) => {
            if (err) reject(err);
            else resolve(row ? row.value : null);
        });
    });
}

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

function setConfig(key, value) {
    return new Promise((resolve, reject) => {
        db.run('INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)', [key, value], (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

function generateShortCode(length = 8) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

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

    let fromAddress = config.smtp_from || config.smtp_user;
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

function checkManagerCharacterAuth(managerId, charId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT branch_id FROM characters WHERE id = ?', [charId], (err, charRow) => {
            if (err) return reject(err);
            if (!charRow || !charRow.branch_id) return resolve(false);
            db.get('SELECT 1 FROM user_branches WHERE user_id = ? AND branch_id = ?',
                [managerId, charRow.branch_id], (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                });
        });
    });
}

module.exports = {
    DATA_DIR,
    HIGH_SECURITY_DIR,
    getConfig,
    getAllConfig,
    setConfig,
    generateShortCode,
    generateVerificationCode,
    createMailTransporter,
    sendVerificationEmail,
    checkManagerAuthorization,
    checkManagerCharacterAuth
};
