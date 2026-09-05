// 清空异常能力模板表
// 用法：
//   node scripts/clear-anomaly-templates.js          # 删除全部分部的模板
//   node scripts/clear-anomaly-templates.js hq-sanlian  # 只删除指定分部
// 注意：只删除模板库，不影响已授予角色的异常能力（存在 characters.data 里）
const db = require('../db/init').db;

const branchId = process.argv[2];
const before = db.prepare('SELECT COUNT(*) as c FROM anomaly_templates').get().c;

let deleted;
if (branchId) {
    const result = db.prepare('DELETE FROM anomaly_templates WHERE branch_id = ?').run(branchId);
    deleted = result.changes;
    console.log('分部 [' + branchId + '] 删除前模板数: ' + before + '（全库）');
} else {
    const result = db.prepare('DELETE FROM anomaly_templates').run();
    deleted = result.changes;
    console.log('删除前模板总数: ' + before);
}

const after = db.prepare('SELECT COUNT(*) as c FROM anomaly_templates').get().c;
console.log('已删除: ' + deleted + ' 条');
console.log('剩余模板: ' + after + ' 条');
