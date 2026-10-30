/* Núcleo de auditoría: ensureAuditTable() + auditLog().
   DUEÑO LÓGICO: M4 · Logs/Auditoría (Yerald Sánchez).
   Vive en shared/ solo porque TODOS los módulos llaman a auditLog(). */

const net = require('net');
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

// PWN-028: the client never chooses the logged IP, and detail cannot forge extra log lines.
const DETAIL_MAX_LENGTH = 1000;
const LOG_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

// req.ip is the TCP peer unless Express 'trust proxy' names a trusted proxy;
// X-Forwarded-For sent by the client is never read directly.
function clientIp(req) {
    const ip = String(req.ip || (req.socket && req.socket.remoteAddress) || '');
    return net.isIP(ip) ? ip : 'unknown';
}

function cleanDetail(detail) {
    return String(detail).replace(LOG_CONTROL_CHARS, ' ').substring(0, DETAIL_MAX_LENGTH);
}

function auditLog(userId, action, detail, req) {
    db.query(
        'INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)',
        [userId || null, action, cleanDetail(detail), clientIp(req)]
    );
}

module.exports = { ensureAuditTable, auditLog };
