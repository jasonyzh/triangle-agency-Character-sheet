const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { db } = require('../db/init');
const { ROLE, BCRYPT_ROUNDS, JWT_SECRET } = require('../constants');
const { getConfig, getAllConfig, generateVerificationCode, sendVerificationEmail } = require('../utils');
const jwt = require('jsonwebtoken');

router.get('/api/register/status', async (req, res) => {
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

router.post('/api/register/send-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '邮箱不能为空' });
        }

        const emailEnabled = await getConfig('email_registration_enabled');
        if (emailEnabled !== 'true') {
            return res.status(400).json({ success: false, message: '邮箱注册未启用' });
        }

        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: '该邮箱已被注册' });
        }

        const code = generateVerificationCode();
        const expiresAt = Date.now() + 5 * 60 * 1000;

        db.run('INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)',
            [email, code, 'register', expiresAt]);

        await sendVerificationEmail(email, code, 'register');

        res.json({ success: true, message: '验证码已发送' });
    } catch (e) {
        console.error('发送验证码失败:', e);
        res.status(500).json({ success: false, message: '发送失败: ' + e.message });
    }
});

router.post('/api/register/verify', async (req, res) => {
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

            db.run('UPDATE verification_codes SET used = 1 WHERE id = ?', [validCode.id]);
        }

        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: '账号已存在' });
        }

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

router.post('/api/login', async (req, res) => {
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

        let validPassword = false;
        if (user.password_hash) {
            validPassword = await bcrypt.compare(password, user.password_hash);
        } else if (user.password === password) {
            validPassword = true;
            const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
            db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, user.id]);
        }

        if (!validPassword) {
            return res.status(401).json({ success: false, message: '账号或密码错误' });
        }

        const role = user.role !== undefined ? user.role : (user.is_admin ? ROLE.SUPER_ADMIN : ROLE.PLAYER);

        const token = jwt.sign(
            { userId: user.id, username: user.username, role: role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        db.all(`SELECT b.* FROM user_branches ub JOIN branches b ON ub.branch_id = b.id WHERE ub.user_id = ?`, [user.id], (err, branches) => {
            res.json({
                success: true,
                userId: user.id,
                isAdmin: role >= ROLE.SUPER_ADMIN,
                isManager: role >= ROLE.MANAGER,
                role: role,
                token: token,
                branches: branches || []
            });
        });
    } catch (e) {
        console.error('登录失败:', e);
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

router.get('/api/verify-token', require('../middleware/auth').authenticateToken, (req, res) => {
    res.json({
        valid: true,
        userId: req.user.userId,
        username: req.user.username,
        role: req.user.role
    });
});

module.exports = router;
