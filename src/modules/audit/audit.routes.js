/* M4 · Logs/Auditoría — Responsable: Yerald Sánchez.
   auditLog()/ensureAuditTable() (también de M4) viven en src/shared/audit-core.js. */

const express = require('express');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { requireAdmin } = require('../../shared/helpers');
const bcrypt = require('bcryptjs');
const router = express.Router();

// PWN-005: the JSON feed exposes the same data as /admin/security, so it gets the same admin guard.
router.get('/api/v1/events', requireAdmin, (req, res) => {

    db.query(
        'SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 200',
        (err, logs) => {
            if (err) logs = [];
            res.json({ count: logs.length, logs });
        }
    );
});

// PWN-014 (SQLi): the search term travels as a bound parameter, never as SQL text.
const SEARCH_MAX_LENGTH = 100;

// Escapes LIKE wildcards so the term is matched literally.
function likePattern(term) {
    return '%' + term.replace(/[\\%_]/g, '\\$&') + '%';
}

router.get('/admin/security', requireAdmin, (req, res) => {
    const search = String(req.query.search || '').trim().slice(0, SEARCH_MAX_LENGTH);

    const sql = search
        ? 'SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE a.action LIKE ? OR a.detail LIKE ? ORDER BY a.created_at DESC LIMIT 200'
        : 'SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 200';
    const params = search ? [likePattern(search), likePattern(search)] : [];

    db.query(sql, params, (err, auditLogs) => {
        if (err) auditLogs = [];
        res.render('admin', {
            user: req.session.user,
            tab: 'security',
            users: [], orders: [], products: [], reviews: [],
            auditLogs,
            success: req.query.success || null,
            error:   req.query.error   || null,
            search
        });
    });
});

// LOG-04: clearing the log never destroys evidence. Rows are moved to audit_log_archive
// (no app route reads or deletes it) inside one transaction, and ids are not reset.
function ensureAuditArchiveTable(cb) {
    db.query(
        `CREATE TABLE IF NOT EXISTS audit_log_archive (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            original_id INT NOT NULL,
            user_id     INT DEFAULT NULL,
            action      VARCHAR(60) NOT NULL,
            detail      TEXT,
            ip          VARCHAR(120),
            created_at  TIMESTAMP NULL DEFAULT NULL,
            archived_by INT NOT NULL,
            archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        cb
    );
}

ensureAuditArchiveTable(() => {});

function securityRedirect(res, key, message) {
    res.redirect(`/admin/security?${key}=` + encodeURIComponent(message));
}

// Copies every row up to maxId into the archive, then deletes exactly those rows.
function archiveAndClearLog(adminId, cb) {
    db.getConnection((connErr, conn) => {
        if (connErr) return cb(connErr);
        const fail = (err) => conn.rollback(() => { conn.release(); cb(err); });

        conn.beginTransaction((txErr) => {
            if (txErr) { conn.release(); return cb(txErr); }
            conn.query('SELECT COALESCE(MAX(id), 0) AS maxId FROM audit_log', (err, rows) => {
                if (err) return fail(err);
                const maxId = rows[0].maxId;
                conn.query(
                    `INSERT INTO audit_log_archive (original_id, user_id, action, detail, ip, created_at, archived_by)
                     SELECT id, user_id, action, detail, ip, created_at, ? FROM audit_log WHERE id <= ?`,
                    [adminId, maxId],
                    (err, archived) => {
                        if (err) return fail(err);
                        conn.query('DELETE FROM audit_log WHERE id <= ?', [maxId], (err, deleted) => {
                            if (err) return fail(err);
                            if (deleted.affectedRows !== archived.affectedRows) {
                                return fail(new Error('archive/delete row count mismatch'));
                            }
                            conn.commit((err) => {
                                if (err) return fail(err);
                                conn.release();
                                cb(null, archived.affectedRows);
                            });
                        });
                    }
                );
            });
        });
    });
}

router.post('/admin/reset-log', requireAdmin, (req, res) => {
    const admin = req.session.user;
    const password = String(req.body.password || '');
    if (!password) return securityRedirect(res, 'error', 'Enter your password to clear the log');

    // Destructive action: re-authenticate the admin before touching the log.
    db.query('SELECT password FROM users WHERE id = ? AND role = ?', [admin.id, 'admin'], (err, rows) => {
        if (err || !rows.length) return securityRedirect(res, 'error', 'Could not verify your password');
        bcrypt.compare(password, rows[0].password, (bcryptErr, match) => {
            if (bcryptErr || !match) {
                auditLog(admin.id, 'AUDIT_LOG_RESET_DENIED', `admin: ${admin.username} | reason: incorrect password`, req);
                return securityRedirect(res, 'error', 'Incorrect password');
            }

            archiveAndClearLog(admin.id, (err, archivedCount) => {
                if (err) return securityRedirect(res, 'error', 'Failed to reset log');
                auditLog(admin.id, 'AUDIT_LOG_RESET',
                    `admin: ${admin.username} | archived: ${archivedCount} entries`, req);
                securityRedirect(res, 'success', `Audit log cleared (${archivedCount} entries archived)`);
            });
        });
    });
});

module.exports = router;
