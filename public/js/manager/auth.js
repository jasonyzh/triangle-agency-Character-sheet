import { S } from './state.js';

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${S.token}`
    };
}

function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

function sanitizeObject(obj) {
    if (obj === null || obj === undefined) return obj;

    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }

    if (typeof obj === 'object') {
        const cleaned = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                cleaned[key] = sanitizeObject(obj[key]);
            }
        }
        return cleaned;
    }

    if (typeof obj === 'string') {
        return sanitizeString(obj);
    }

    return obj;
}

async function safeFetch(url, options = {}) {
    try {
        if (options.body) {
            try {
                const parsed = JSON.parse(options.body);
                console.log(`[SafeFetch] 发送到 ${url}:`, parsed);
            } catch (e) {
                console.error('[SafeFetch] JSON 解析失败:', e);
                console.error('[SafeFetch] 原始数据:', options.body);
                console.error('[SafeFetch] 数据前100个字符:', options.body.substring(0, 100));
                throw new Error('请求数据格式错误: ' + e.message);
            }
        }

        const response = await fetch(url, options);
        return response;
    } catch (error) {
        console.error('[SafeFetch] 请求失败:', error);
        throw error;
    }
}

function logout() {
    localStorage.removeItem('ta_uid');
    localStorage.removeItem('ta_token');
    localStorage.removeItem('ta_role');
    localStorage.removeItem('ta_is_admin');
    localStorage.removeItem('ta_is_manager');
    window.location.href = 'login.html';
}

function goAdmin() {
    createTransition('权限认证中', 'admin.html');
}

function goToDashboard() {
    createTransition('档案读取中', 'dashboard.html');
}

import { createTransition } from './ui.js';

export {
    getAuthHeaders,
    sanitizeString,
    sanitizeObject,
    safeFetch,
    logout,
    goAdmin,
    goToDashboard
};
