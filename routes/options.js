const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('../utils');

router.get('/api/options', (req, res) => {
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

module.exports = router;
