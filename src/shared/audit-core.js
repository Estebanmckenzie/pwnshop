/* Núcleo de auditoría: ensureAuditTable() + auditLog().
   DUEÑO LÓGICO: M4 · Logs/Auditoría (Yerald Sánchez).
   Vive en shared/ solo porque TODOS los módulos llaman a auditLog(). */

const { db } = require('./db');

function ensureAuditTable(cb) {
    db.query(
        `CREATE TABLE IF NOT EXISTS audit_log (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            user_id    INT DEFAULT NULL,
            action     VARCHAR(60) NOT NULL,
            detail     TEXT,
            ip         VARCHAR(120),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        cb
    );
}

ensureAuditTable(() => {});

function auditLog(userId, action, detail, req) {

    const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();

    db.query(
        'INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)',
        [userId || null, action, String(detail).substring(0, 1000), ip]
    );
}

module.exports = { ensureAuditTable, auditLog };
