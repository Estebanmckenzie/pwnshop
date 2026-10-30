/* M4 · Logs/Auditoría — Responsable: Yerald Sánchez.
   auditLog()/ensureAuditTable() (también de M4) viven en src/shared/audit-core.js. */

const express = require('express');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { requireAdmin } = require('../../shared/helpers');
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

router.post('/admin/reset-log', requireAdmin, (req, res) => {
    db.query('DELETE FROM audit_log WHERE 1=1', (err) => {
        if (err) return res.redirect('/admin/security?error=Failed to reset log');


        db.query('ALTER TABLE audit_log AUTO_INCREMENT = 1', () => {
            auditLog(req.session.user.id, 'AUDIT_LOG_RESET',
                `admin: ${req.session.user.username} - log cleared`, req);
            res.redirect('/admin/security?success=Audit log cleared');
        });
    });
});

module.exports = router;
