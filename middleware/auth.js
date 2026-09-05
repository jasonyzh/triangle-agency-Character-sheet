const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../constants');
const { ROLE } = require('../constants');

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

module.exports = { authenticateToken, requireRole, optionalAuth };
