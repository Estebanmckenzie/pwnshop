/* M2 · Gestión de Usuarios — Responsable: Roberto Chacón. */

const express = require('express');
const multer = require('multer');
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { VULNBANK_LAB_VULN } = require('../../shared/config');
const { isVulnbankConfigured } = require('../../shared/vulnbank');
const { avatarLimiter, registerSellerLimiter, accountDeleteLimiter, mailReadLimiter } = require('../../shared/rate-limiters');
const { requireAdmin } = require('../../shared/helpers');
const bcrypt = require('bcryptjs');
const router = express.Router();

// PWN-026 (CSRF): per-session synchronizer token + same-origin check on every M2 POST.
function csrfToken(req) {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    return req.session.csrfToken;
}

// Browsers send Origin (or at least Referer) on cross-site POSTs; when present it must be this host.
function isSameOrigin(req) {
    const source = req.get('origin') || req.get('referer');
    if (!source) return true;
    try {
        return new URL(source).host === req.get('host');
    } catch (_) {
        return false;
    }
}

function rejectCsrf(req, res) {
    auditUserEvent(req.session.user?.id || null, 'CSRF_REJECTED',
        { method: req.method, path: req.originalUrl, origin: req.get('origin') || req.get('referer') || 'none' }, req);
    if (req.get('x-csrf-token') !== undefined || req.is('json') || req.is('multipart/form-data')) {
        return res.status(403).json({ ok: false, error: 'Invalid or missing CSRF token. Reload the page and try again.' });
    }
    res.status(403).send('Invalid or missing CSRF token. Reload the page and try again.');
}

function verifyCsrf(req, res, next) {
    if (!isSameOrigin(req)) return rejectCsrf(req, res);
    const sent     = String(req.get('x-csrf-token') || (req.body && req.body._csrf) || '');
    const expected = String(req.session.csrfToken || '');
    if (!expected || sent.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))) {
        return rejectCsrf(req, res);
    }
    next();
}

// Admin forms live in the shared admin.ejs view, so these routes rely on the origin check.
function verifySameOrigin(req, res, next) {
    if (!isSameOrigin(req)) return rejectCsrf(req, res);
    next();
}

// USR-06 (audit poisoning): M2 never hands raw user input to auditLog().
// Values are stripped of control characters / line breaks, length-capped and stored as
// separate JSON fields, plus defensive tracing data taken from the server side.
const LOG_VALUE_MAX = 200;

// Control characters (C0, DEL, C1) and the Unicode line/paragraph separators (0x2028, 0x2029).
function isLogControlChar(code) {
    return code < 0x20 || (code >= 0x7F && code <= 0x9F) || code === 0x2028 || code === 0x2029;
}

function cleanLogValue(value) {
    const text = String(value === undefined || value === null ? '' : value);
    let clean = '';
    for (const char of text) clean += isLogControlChar(char.charCodeAt(0)) ? ' ' : char;
    return clean.slice(0, LOG_VALUE_MAX);
}

function auditUserEvent(userId, action, fields, req) {
    const detail = { trace: crypto.randomUUID() };
    Object.keys(fields).forEach((key) => { detail[key] = cleanLogValue(fields[key]); });
    // Who and from where, according to the server — not to the request body or headers.
    detail.actor = req.session.user?.id || req.session.pendingUserId || null;
    detail.peer  = cleanLogValue(req.socket && req.socket.remoteAddress);
    // The spoofable header is kept apart, so a forged IP shows up as a mismatch with `peer`.
    if (req.get('x-forwarded-for')) detail.claimed_xff = cleanLogValue(req.get('x-forwarded-for'));
    auditLog(userId, action, JSON.stringify(detail), req);
}

// PWN-012 (stored XSS): SVG can carry scripts, so only raster formats are accepted.
const ALLOWED_AVATAR_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_AVATAR_EXTS  = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

// Detects the real image type from the file's first bytes (magic numbers).
function detectImageType(buffer) {
    if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'jpg';
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
    const head = buffer.subarray(0, 12).toString('latin1');
    if (head.startsWith('GIF87a') || head.startsWith('GIF89a')) return 'gif';
    if (head.startsWith('RIFF') && head.slice(8, 12) === 'WEBP') return 'webp';
    return null;
}

const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => {
        // The stored name never reuses the client's file name, only a validated extension.
        const ext = file.originalname.split('.').pop().toLowerCase();
        cb(null, 'avatar_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex') + '.' + ext);
    }
});

const avatarUpload = multer({
    storage: avatarStorage,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = file.originalname.split('.').pop().toLowerCase();
        if (!ALLOWED_AVATAR_MIMES.includes(file.mimetype) || !ALLOWED_AVATAR_EXTS.includes(ext)) {
            return cb(new Error('Only image files are allowed (jpg, png, gif, webp)'));
        }
        cb(null, true);
    }
});

router.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId = req.session.user.id;


    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, users) => {
        if (!err && users.length) {
            req.session.user = users[0];
        }

        db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, orders) => {
            if (err) return res.send('Database error');
            db.query(
                'SELECT w.*, p.name, p.price, p.image, p.category, p.id AS product_id FROM wishlists w JOIN products p ON w.product_id = p.id WHERE w.user_id = ?',
                [userId],
                (err, wishlist) => {
                    if (err) wishlist = [];
                    res.render('profile', {
                        user: req.session.user,
                        orders,
                        wishlist,
                        walletError:    req.query.wallet_error    || null,
                        walletSuccess:  req.query.wallet_success  || null,
                        addressSuccess: req.query.address_success || null,
                        addressError:   req.query.address_error   || null,
                        deleteError:    req.query.delete_error    || null,
                        vulnbankEnabled: isVulnbankConfigured(),
                        vulnbankLabVuln: VULNBANK_LAB_VULN,
                        csrfToken:      csrfToken(req)
                    });
                }
            );
        });
    });
});

router.post('/profile/address', verifyCsrf, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId  = req.session.user.id;
    const address = String(req.body.default_shipping_address || '').trim();
    const zone    = ['lagos','others','remote'].includes(req.body.default_zone) ? req.body.default_zone : 'others';
    if (!address) return res.redirect('/profile?address_error=Address cannot be empty');
    db.query(
        'UPDATE users SET default_shipping_address = ?, default_zone = ? WHERE id = ?',
        [address, zone, userId],
        (err) => {
            if (err) return res.redirect('/profile?address_error=Failed to save address');
            req.session.user.default_shipping_address = address;
            req.session.user.default_zone = zone;
            res.redirect('/profile?address_success=Default address saved');
        }
    );
});

// PWN-029 (SSRF): only public destinations may be fetched for an avatar URL.
// BlockList also matches IPv4-mapped IPv6 forms such as ::ffff:7f00:1.
const blockedNetworks = new net.BlockList();
[
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
    ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]
].forEach(([base, bits]) => blockedNetworks.addSubnet(base, bits, 'ipv4'));
[
    ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
].forEach(([base, bits]) => blockedNetworks.addSubnet(base, bits, 'ipv6'));

function isBlockedAddress(ip) {
    const family = net.isIP(ip);
    if (!family) return true;
    return blockedNetworks.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

// Checks the address actually used for the connection, so DNS rebinding cannot swap it.
function safeLookup(hostname, options, callback) {
    dns.lookup(hostname, options, (err, address, family) => {
        if (err) return callback(err);
        const list = Array.isArray(address) ? address : [{ address, family }];
        if (list.some(entry => isBlockedAddress(entry.address))) {
            return callback(new Error('Blocked destination'));
        }
        callback(null, address, family);
    });
}

router.post('/profile/update-avatar', avatarLimiter, verifyCsrf, (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false, error: 'Not logged in' });
    const { avatar_url } = req.body;
    if (!avatar_url || typeof avatar_url !== 'string') return res.status(400).json({ ok: false, error: 'No URL provided' });

    let answered = false;
    const reply = (status, body) => {
        if (answered) return;
        answered = true;
        res.status(status).json(body);
    };
    // USR-06: rejected URLs are recorded (with the internal reason) so SSRF attempts are detectable.
    const rejectUrl = (error, internalReason) => {
        if (answered) return;
        auditUserEvent(req.session.user.id, 'AVATAR_URL_REJECTED', { url: avatar_url, reason: internalReason || error }, req);
        reply(400, { ok: false, error });
    };

    let target;
    try {
        target = new URL(avatar_url);
    } catch (_) {
        return rejectUrl('Invalid URL');
    }
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
        return rejectUrl('Only http/https image URLs are allowed');
    }
    if (target.port && !['80', '443'].includes(target.port)) {
        return rejectUrl('Only default ports are allowed');
    }
    const host = target.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && isBlockedAddress(host)) {
        return rejectUrl('URL not allowed', 'Blocked destination');
    }

    const proto = target.protocol === 'https:' ? https : http;

    const request = proto.get(target, { lookup: safeLookup }, (response) => {
        const contentType = String(response.headers['content-type'] || '').toLowerCase();
        response.resume();
        if (response.statusCode !== 200 || !contentType.startsWith('image/')) {
            request.destroy();
            return rejectUrl('URL does not point to an image', `status ${response.statusCode}, type ${contentType || 'none'}`);
        }

        db.query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500) DEFAULT NULL",
            () => {
                db.query(
                    'UPDATE users SET avatar_url = ? WHERE id = ?',
                    [avatar_url, req.session.user.id],
                    (err) => {
                        if (err) return reply(500, { ok: false, error: 'Could not save avatar' });
                        db.query('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, users) => {
                            if (!err && users.length) req.session.user = users[0];
                        });

                        auditUserEvent(req.session.user.id, 'AVATAR_URL_SET', { url: avatar_url }, req);
                        reply(200, { ok: true, url: avatar_url });
                    }
                );
            }
        );
    });

    request.on('error', (err) => {
        rejectUrl('Could not fetch image from that URL', err.message);
    });

    request.setTimeout(5000, () => {
        rejectUrl('Request timed out');
        request.destroy();
    });
});

router.post('/profile/upload-avatar', avatarLimiter, verifyCsrf, (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false, error: 'Not logged in' });

    avatarUpload.single('avatar')(req, res, (uploadErr) => {
        if (uploadErr) {
            auditUserEvent(req.session.user.id, 'AVATAR_UPLOAD_REJECTED', { reason: uploadErr.message }, req);
            return res.json({ ok: false, error: uploadErr.message });
        }
        if (!req.file)  return res.json({ ok: false, error: 'No file received' });

        const fs      = require('fs');
        const ext     = req.file.originalname.split('.').pop().toLowerCase();
        const fileUrl = '/uploads/' + req.file.filename;

        // Extension and MIME type come from the client; the content must really be that image.
        let detected = null;
        try {
            const fd = fs.openSync(req.file.path, 'r');
            const header = Buffer.alloc(12);
            const bytesRead = fs.readSync(fd, header, 0, 12, 0);
            fs.closeSync(fd);
            detected = detectImageType(header.subarray(0, bytesRead));
        } catch (_) { }
        const expected = ext === 'jpeg' ? 'jpg' : ext;
        if (detected !== expected) {
            fs.unlink(req.file.path, () => {});
            auditUserEvent(req.session.user.id, 'AVATAR_UPLOAD_REJECTED', {
                reason: 'content does not match extension', file: req.file.originalname,
                mime: req.file.mimetype, detected: detected || 'unknown'
            }, req);
            return res.json({ ok: false, error: 'File content is not a valid ' + ext + ' image' });
        }


        db.query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500) DEFAULT NULL",
            () => {

                db.query('UPDATE users SET avatar_url = ? WHERE id = ?',
                    [fileUrl, req.session.user.id],
                    (dbErr) => {
                        if (dbErr) return res.json({ ok: false, error: 'DB error: ' + dbErr.message });
                        db.query('SELECT * FROM users WHERE id = ?', [req.session.user.id], (e2, users) => {
                            if (!e2 && users.length) req.session.user = users[0];
                        });
                        auditUserEvent(req.session.user.id, 'AVATAR_UPLOADED',
                            { file: req.file.originalname, stored: req.file.filename, mime: req.file.mimetype }, req);
                        res.json({ ok: true, url: fileUrl });
                    }
                );
            }
        );
    });
});

router.post('/account/delete', accountDeleteLimiter, verifyCsrf, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId = req.session.user.id;
    const password = String(req.body.password || '');
    if (!password) return res.redirect('/profile?delete_error=' + encodeURIComponent('Enter your password to delete your account'));

    // Destructive action: re-authenticate with the current password before deleting.
    db.query('SELECT password FROM users WHERE id = ?', [userId], (err, rows) => {
        if (err || !rows.length) return res.redirect('/profile?delete_error=' + encodeURIComponent('Could not verify your password'));
        bcrypt.compare(password, rows[0].password, (bcryptErr, match) => {
            if (bcryptErr || !match) {
                auditUserEvent(userId, 'ACCOUNT_DELETE_DENIED', { reason: 'incorrect password' }, req);
                return res.redirect('/profile?delete_error=' + encodeURIComponent('Incorrect password'));
            }

            db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
                if (err) return res.send('Error deleting account: ' + err.message);
                auditUserEvent(userId, 'ACCOUNT_DELETED', { username: req.session.user.username }, req);
                req.session.destroy(() => res.redirect('/'));
            });
        });
    });
});

router.get('/mail', (req, res) => {
    const id = req.session.user?.id || req.session.pendingUserId;
    if (!id) return res.redirect('/login');

    db.query('SELECT inbox_token FROM users WHERE id = ?', [id], (err, rows) => {
        if (err || !rows.length || !rows[0].inbox_token) return res.redirect('/login');
        res.redirect('/mail/' + rows[0].inbox_token);
    });
});

router.get('/mail/:token', (req, res) => {
    const token = req.params.token;



    const loggedInId = req.session.user?.id;
    const pendingId  = req.session.pendingUserId;
    if (!loggedInId && !pendingId) return res.redirect('/login');

    db.query('SELECT id, username, email, inbox_token FROM users WHERE inbox_token = ?', [token], (err, users) => {
        if (err) return res.send('Database error');
        if (!users.length) return res.status(404).render('404', { user: req.session.user });

        const owner  = users[0];
        const userId = owner.id;

        // PWN-004 (IDOR): only the mailbox owner may read it — the logged-in user,
        // or the user who already passed the password step and is waiting for the OTP.
        const isOwner = loggedInId ? userId === loggedInId : userId === pendingId;
        if (!isOwner) return res.status(404).render('404', { user: req.session.user });

        db.query(
            'SELECT * FROM mail_inbox WHERE to_user_id = ? ORDER BY created_at DESC',
            [userId],
            (err, mails) => {
                if (err) return res.send('Database error');
                const unread = mails.filter(m => !m.is_read).length;
                res.render('mail', {
                    user: req.session.user,
                    mails,
                    mailOwner: owner,
                    userId,
                    unread,
                    csrfToken: csrfToken(req)
                });
            }
        );
    });
});

router.post('/mail/:id/read', mailReadLimiter, verifyCsrf, (req, res) => {
    const ownerId = req.session.user?.id || req.session.pendingUserId;
    if (!ownerId) return res.status(401).json({ ok: false });

    const mailId = Number(req.params.id);
    if (!Number.isInteger(mailId) || mailId <= 0) return res.status(400).json({ ok: false });

    // PWN-004 (IDOR): the UPDATE only touches mail addressed to the session's user.
    db.query('UPDATE mail_inbox SET is_read = TRUE WHERE id = ? AND to_user_id = ?', [mailId, ownerId], (err, result) => {
        if (err) return res.status(500).json({ ok: false });
        if (!result.affectedRows) return res.status(404).json({ ok: false });
        res.json({ ok: true });
    });
});

// USR-03 (privilege escalation): a user can only *request* the seller role.
// The role is granted by an admin through /admin/make-seller.
const sellerRequestSubject = (userId) => `Seller request: user #${userId}`;

// Returns 'already' (seller/admin), 'pending' (unread request in an admin inbox) or null.
function sellerRequestState(userId, callback) {
    db.query('SELECT role, isSeller FROM users WHERE id = ?', [userId], (err, rows) => {
        if (err || !rows.length) return callback(err || new Error('User not found'));
        if (rows[0].isSeller || rows[0].role === 'seller' || rows[0].role === 'admin') return callback(null, 'already');
        db.query(
            'SELECT id FROM mail_inbox WHERE subject = ? AND is_read = FALSE LIMIT 1',
            [sellerRequestSubject(userId)],
            (err, pending) => {
                if (err) return callback(err);
                callback(null, pending.length ? 'pending' : null);
            }
        );
    });
}

router.get('/register-seller', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    sellerRequestState(req.session.user.id, (err, notice) => {
        if (err) return res.status(500).send('Error');
        res.render('register-seller', { user: req.session.user, notice, csrfToken: csrfToken(req) });
    });
});

router.post('/register-seller', registerSellerLimiter, verifyCsrf, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const user = req.session.user;

    sellerRequestState(user.id, (err, notice) => {
        if (err) return res.status(500).send('Error');
        if (notice) return res.render('register-seller', { user, notice, csrfToken: csrfToken(req) });

        db.query(
            "INSERT INTO mail_inbox (to_user_id, to_email, subject, body) SELECT id, email, ?, ? FROM users WHERE role = 'admin'",
            [
                sellerRequestSubject(user.id),
                `User ${user.username} (${user.email}) has requested a seller account.\n\n` +
                `To approve it, go to /admin/users and promote ${user.email} with "Make Seller".\n\n- Pwnshop`
            ],
            (err) => {
                if (err) return res.status(500).send('Error');
                auditUserEvent(user.id, 'SELLER_REQUESTED', { username: user.username }, req);
                res.render('register-seller', { user, notice: 'sent', csrfToken: csrfToken(req) });
            }
        );
    });
});

router.get('/admin/users', requireAdmin, (req, res) => {
    db.query('SELECT * FROM users ORDER BY created_at DESC', (err, users) => {
        if (err) return res.send('Database error');
        res.render('admin', {
            user: req.session.user,
            tab: 'users',
            users,
            orders: [], products: [], reviews: [],
            success: req.query.success || null,
            error:   req.query.error   || null,
            auditLogs: [], coupons: [],
            search:  req.query.search  || ''
        });
    });
});

router.post('/admin/make-seller', requireAdmin, verifySameOrigin, (req, res) => {
    db.query('UPDATE users SET isSeller = TRUE, role = "seller" WHERE email = ?', [req.body.email], (err, r) => {
        if (err || !r.affectedRows) return res.redirect('/admin/users?error=' + (err ? 'Database error' : 'Email not found'));
        auditUserEvent(req.session.user.id, 'SELLER_PROMOTED',
            { admin: req.session.user.username, email: req.body.email }, req);
        res.redirect('/admin/users?success=User promoted to seller');
    });
});

router.post('/admin/remove-seller', requireAdmin, verifySameOrigin, (req, res) => {
    db.query('UPDATE users SET isSeller = FALSE, role = "user" WHERE id = ?', [req.body.user_id], (err) => {
        if (err) return res.redirect('/admin/users?error=Database error');
        auditUserEvent(req.session.user.id, 'SELLER_DEMOTED',
            { admin: req.session.user.username, user_id: req.body.user_id }, req);
        res.redirect('/admin/users?success=Seller role removed');
    });
});

router.post('/admin/delete-user', requireAdmin, verifySameOrigin, (req, res) => {
    const targetId = parseInt(req.body.user_id);
    if (targetId === req.session.user.id) return res.redirect('/admin/users?error=Cannot delete your own account');

    const steps = [
        `DELETE te FROM tracking_events te JOIN orders o ON te.order_id = o.id WHERE o.user_id = ${targetId}`,
        `DELETE oi FROM order_items oi JOIN orders o ON oi.order_id = o.id WHERE o.user_id = ${targetId}`,
        `DELETE se FROM seller_earnings se JOIN orders o ON se.order_id = o.id WHERE o.user_id = ${targetId}`,
        `DELETE FROM orders          WHERE user_id = ${targetId}`,
        `DELETE FROM cart_items      WHERE user_id = ${targetId}`,
        `DELETE FROM wishlists       WHERE user_id = ${targetId}`,
        `DELETE FROM reviews         WHERE user_id = ${targetId}`,
        `DELETE FROM otp_codes       WHERE user_id = ${targetId}`,
        `DELETE FROM mail_inbox      WHERE to_user_id = ${targetId}`,
        `DELETE FROM password_resets WHERE user_id = ${targetId}`,
        `DELETE FROM coupon_uses     WHERE user_id = ${targetId}`,
        `DELETE FROM seller_earnings WHERE seller_id = ${targetId}`,
        `DELETE FROM products        WHERE seller_id = ${targetId}`,
        `DELETE FROM users           WHERE id = ${targetId}`
    ];

    let i = 0;
    function runNext(err) {
        if (err) return res.redirect('/admin/users?error=' + encodeURIComponent('Delete failed: ' + err.message));
        if (i >= steps.length) {
            auditUserEvent(req.session.user.id, 'USER_DELETED',
                { admin: req.session.user.username, deleted_user_id: targetId }, req);
            return res.redirect('/admin/users?success=User and all related data deleted');
        }
        db.query(steps[i++], runNext);
    }
    runNext(null);
});

module.exports = router;
