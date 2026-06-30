const COS = require('cos-nodejs-sdk-v5');
const { getConfig } = require('./utils');

// 是否启用 COS 上传
function isCosEnabled() {
    return getConfig('cos_enabled') === 'true';
}

// 读取全部 COS 配置
function getCosConfig() {
    return {
        SecretId: getConfig('cos_secret_id') || '',
        SecretKey: getConfig('cos_secret_key') || '',
        Bucket: getConfig('cos_bucket') || '',
        Region: getConfig('cos_region') || '',
        Domain: getConfig('cos_domain') || ''
    };
}

// COS 配置是否完整（凭证 + 桶 + 地域）
function isCosConfigured() {
    const cfg = getCosConfig();
    return !!(cfg.SecretId && cfg.SecretKey && cfg.Bucket && cfg.Region);
}

// 懒加载 cos 客户端（凭证变更后需手动调用 resetCosClient）
let _cos = null;
function getCosClient() {
    const cfg = getCosConfig();
    if (!cfg.SecretId || !cfg.SecretKey) return null;
    if (!_cos) {
        _cos = new COS({ SecretId: cfg.SecretId, SecretKey: cfg.SecretKey });
    }
    return _cos;
}

// 凭证变更后重置客户端（admin 保存配置后调用）
function resetCosClient() {
    _cos = null;
}

// 根据 Key 构造可访问的完整 URL
// 自定义域名优先，否则用默认 cos 域名（encodeURI 处理中文 Key）
function buildCosUrl(key) {
    const cfg = getCosConfig();
    const encKey = encodeURI(key);
    if (cfg.Domain) return cfg.Domain.replace(/\/+$/, '') + '/' + encKey;
    return `https://${cfg.Bucket}.cos.${cfg.Region}.myqcloud.com/` + encKey;
}

// 从 COS 完整 URL 反解出 Key（删除时使用）
function keyFromCosUrl(url) {
    try {
        const cfg = getCosConfig();
        const u = new URL(url);
        // 自定义域名场景：整个 pathname 即 Key（去前导 /）
        if (cfg.Domain) {
            const domainHost = new URL(cfg.Domain).host;
            if (u.host === domainHost) return decodeURI(u.pathname.replace(/^\/+/, ''));
        }
        // 默认域名场景：去掉前缀 /{Bucket}/
        const parts = u.pathname.replace(/^\/+/, '').split('/');
        parts.shift(); // 去掉 Bucket 段
        return decodeURI(parts.join('/'));
    } catch (e) {
        return null;
    }
}

// 上传 Buffer 到 COS，返回 { Key, Url }
function uploadToCos(key, body) {
    return new Promise((resolve, reject) => {
        const cfg = getCosConfig();
        const cos = getCosClient();
        if (!cos) return reject(new Error('COS 未配置凭证'));
        if (!cfg.Bucket || !cfg.Region) return reject(new Error('COS 缺少 Bucket/Region'));
        cos.putObject({
            Bucket: cfg.Bucket,
            Region: cfg.Region,
            Key: key,
            Body: body
        }, function (err, data) {
            if (err) return reject(err);
            resolve({ Key: key, Url: buildCosUrl(key) });
        });
    });
}

// 从 COS 删除对象
function deleteFromCos(key) {
    return new Promise((resolve, reject) => {
        const cfg = getCosConfig();
        const cos = getCosClient();
        if (!cos) return reject(new Error('COS 未配置凭证'));
        cos.deleteObject({
            Bucket: cfg.Bucket,
            Region: cfg.Region,
            Key: key
        }, function (err, data) {
            if (err) return reject(err);
            resolve(true);
        });
    });
}

module.exports = {
    isCosEnabled,
    isCosConfigured,
    getCosConfig,
    getCosClient,
    resetCosClient,
    buildCosUrl,
    keyFromCosUrl,
    uploadToCos,
    deleteFromCos
};
