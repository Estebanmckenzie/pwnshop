/* Lab: tracking de visitas + auto-healer + endpoints de reset — FUERA DEL ALCANCE.
   Se mantiene junto porque comparte estado mutable (labIsDirty, lastActivityMs). */

const express = require('express');
const { execFile } = require('child_process');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { requireAdmin } = require('../../shared/helpers');
const router = express.Router();

// visitor_stats uses the main db pool (metaDb pool caused a stall on Filess.io)

// Smart healer + visitor tracking
let labIsDirty = false;
let lastActivityMs = 0;

const trackedRoutes = [
    '/', '/search', '/login', '/register', '/verify-otp',
    '/forgot-password', '/reset-password', '/cart', '/checkout',
    '/chat', '/chat/init', '/mail', '/track', '/vulnerabilities',
    '/debug/info', '/seller/preview'
];

function isTrackedRoute(path) {
    if (trackedRoutes.includes(path)) return true;
    if (path.startsWith('/product/')) return true;
    if (path.startsWith('/category/')) return true;
    if (path.startsWith('/mail/')) return true;
    if (path.startsWith('/wishlist/')) return true;
    if (path.startsWith('/track/')) return true;
    return false;
}

router.use((req, res, next) => {
    lastActivityMs = Date.now();

    // Mark dirty on POST/PUT/DELETE/PATCH
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        labIsDirty = true;
    }

    // Only track meaningful routes
    if (isTrackedRoute(req.path)) {
        const rawIp = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
        if (rawIp) {
            db.query(
                `INSERT INTO visitor_stats (ip, visit_count) VALUES (?, 1)
                 ON DUPLICATE KEY UPDATE last_seen = NOW(), visit_count = visit_count + 1`,
                [rawIp],
                (err) => { if (err) console.error('[visitor] insert error:', err.message); }
            );
        }
    }

    next();
});

let labResetInProgress = false;
let lastLabResetAtMs = 0;
const LAB_RESET_COOLDOWN_MS = 10 * 60 * 1000;

function runLabReset(req, done) {
    const resetScript = process.env.LAB_RESET_SCRIPT || '/usr/src/app/scripts/reset-lab-inside.sh';

    const now = Date.now();
    const elapsed = now - lastLabResetAtMs;
    if (lastLabResetAtMs > 0 && elapsed < LAB_RESET_COOLDOWN_MS) {
        const remainingMs = LAB_RESET_COOLDOWN_MS - elapsed;
        const remainingSeconds = Math.ceil(remainingMs / 1000);
        return done(new Error(`Cooldown active. Try again in ${remainingSeconds}s`));
    }

    if (labResetInProgress) {
        return done(new Error('Lab reset already in progress'));
    }

    labResetInProgress = true;
    execFile('/bin/bash', [resetScript], { timeout: 180000 }, (err, stdout, stderr) => {
        labResetInProgress = false;
        if (!err) {
            lastLabResetAtMs = Date.now();
        }
        done(err, stdout, stderr, resetScript);
    });
}

router.post('/admin/lab-reset', requireAdmin, (req, res) => {
    runLabReset(req, (err, stdout, stderr, resetScript) => {
        if (err) {
            auditLog(req.session.user?.id || null, 'LAB_RESET_FAILED', `script: ${resetScript} | error: ${err.message}`, req);
            return res.redirect('/admin/security?error=' + encodeURIComponent('Lab reset failed: ' + (stderr || err.message || 'Unknown error')));
        }

        auditLog(req.session.user?.id || null, 'LAB_RESET_SUCCESS', `script: ${resetScript}`, req);
        return res.redirect('/admin/security?success=' + encodeURIComponent('Lab reset completed successfully'));
    });
});

router.post('/lab/reset', (req, res) => {
    const configuredToken = process.env.LAB_RESET_TOKEN;
    const providedToken = req.get('x-lab-reset-token') || req.body?.token || '';

    if (!configuredToken) {
        return res.status(503).json({ ok: false, error: 'LAB_RESET_TOKEN is not configured' });
    }

    if (providedToken !== configuredToken) {
        return res.status(403).json({ ok: false, error: 'Invalid reset token' });
    }

    runLabReset(req, (err, stdout, stderr, resetScript) => {
        if (err) {
            auditLog(req.session.user?.id || null, 'LAB_RESET_FAILED', `script: ${resetScript} | error: ${err.message}`, req);
            return res.status(500).json({
                ok: false,
                error: err.message,
                details: (stderr || err.message || '').toString().substring(0, 500)
            });
        }

        auditLog(req.session.user?.id || null, 'LAB_RESET_SUCCESS', `script: ${resetScript}`, req);
        return res.json({
            ok: true,
            message: 'Lab reset completed',
            output: (stdout || '').toString().substring(0, 300)
        });
    });
});

// Admin lab-stats endpoint
router.get('/admin/lab-stats', requireAdmin, (req, res) => {
    db.query(
        'SELECT COUNT(*) AS uniqueVisitors, SUM(visit_count) AS totalVisits FROM visitor_stats',
        (err, rows) => {
            if (err) console.error('[visitor] stats query error:', err.message);
            const stats = (!err && rows[0]) ? rows[0] : { uniqueVisitors: 0, totalVisits: 0 };
            res.json({
                uniqueVisitors: parseInt(stats.uniqueVisitors) || 0,
                totalVisits: parseInt(stats.totalVisits) || 0,
                labIsDirty,
                lastActivityMinsAgo: lastActivityMs
                    ? Math.floor((Date.now() - lastActivityMs) / 60000)
                    : null
            });
        }
    );
});

// Smart auto-healer
const HEAL_EVERY_MINUTES = parseInt(process.env.HEAL_EVERY_MINUTES || '20', 10);
setInterval(() => {
    if (!labIsDirty) {
        console.log('[healer] App is clean, skipping reset');
        return;
    }
    const inactiveMins = lastActivityMs
        ? (Date.now() - lastActivityMs) / 60000
        : HEAL_EVERY_MINUTES + 1;
    if (inactiveMins < HEAL_EVERY_MINUTES) {
        console.log(`[healer] Activity ${Math.floor(inactiveMins)}m ago, skipping reset`);
        return;
    }
    console.log('[healer] Dirty + inactive, triggering auto-reset...');
    labIsDirty = false;
    runLabReset(null, (err) => {
        if (err) {
            labIsDirty = true;
            console.error('[healer] Auto-reset failed:', err.message);
        } else {
            console.log('[healer] Auto-reset complete at', new Date().toISOString());
        }
    });
}, HEAL_EVERY_MINUTES * 60 * 1000);

console.log(`[healer] Auto-reset active - fires after ${HEAL_EVERY_MINUTES}m inactivity`);

module.exports = router;
