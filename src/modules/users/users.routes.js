/* M2 · Gestión de Usuarios — Responsable: Roberto Chacón. */

const express = require('express');
const multer = require('multer');
const http = require('http');
const https = require('https');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { VULNBANK_LAB_VULN } = require('../../shared/config');
const { isVulnbankConfigured } = require('../../shared/vulnbank');
const { avatarLimiter, registerSellerLimiter, accountDeleteLimiter, mailReadLimiter } = require('../../shared/rate-limiters');
const { requireAdmin } = require('../../shared/helpers');
const router = express.Router();

const ALLOWED_AVATAR_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
const ALLOWED_AVATAR_EXTS  = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'];

const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => {

        const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, 'avatar_' + Date.now() + '_' + safe);
    }
});

const avatarUpload = multer({
    storage: avatarStorage,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = file.originalname.split('.').pop().toLowerCase();



        if (!ALLOWED_AVATAR_MIMES.includes(file.mimetype) || !ALLOWED_AVATAR_EXTS.includes(ext)) {
            return cb(new Error('Only image files are allowed (jpg, png, gif, webp, svg)'));
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
                        vulnbankEnabled: isVulnbankConfigured(),
                        vulnbankLabVuln: VULNBANK_LAB_VULN
                    });
                }
            );
        });
    });
});

router.post('/profile/address', (req, res) => {
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

router.post('/profile/update-avatar', avatarLimiter, (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false, error: 'Not logged in' });
    const { avatar_url } = req.body;
    if (!avatar_url) return res.status(400).json({ ok: false, error: 'No URL provided' });

    const proto = avatar_url.startsWith('https') ? https : http;


    const request = proto.get(avatar_url, (response) => {
        let data = '';
        response.on('data', chunk => { data += chunk; });
        response.on('end', () => {

            db.query(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500) DEFAULT NULL",
                () => {
                    db.query(
                        'UPDATE users SET avatar_url = ? WHERE id = ?',
                        [avatar_url, req.session.user.id],
                        (err) => {
                            if (err) return res.json({ ok: false, error: 'DB error: ' + err.message });
                            db.query('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, users) => {
                                if (!err && users.length) req.session.user = users[0];
                            });

                            auditLog(req.session.user.id, 'AVATAR_URL_SET', `url: ${avatar_url}`, req);
            res.json({ ok: true, fetched: data.substring(0, 2000), url: avatar_url });
                        }
                    );
                }
            );
        });
    });

    request.on('error', (err) => {
        res.json({ ok: false, error: err.message });
    });

    request.setTimeout(5000, () => {
        request.destroy();
        res.json({ ok: false, error: 'Request timed out' });
    });
});

router.post('/profile/upload-avatar', avatarLimiter, (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false, error: 'Not logged in' });

    avatarUpload.single('avatar')(req, res, (uploadErr) => {
        if (uploadErr) return res.json({ ok: false, error: uploadErr.message });
        if (!req.file)  return res.json({ ok: false, error: 'No file received' });

        const fs      = require('fs');
        const ext     = req.file.originalname.split('.').pop().toLowerCase();
        const fileUrl = '/uploads/' + req.file.filename;





        if (ext === 'svg') {
            try {
                let svg = fs.readFileSync(req.file.path, 'utf8');
                svg = svg.replace(/<script[\s\S]*?<\/script>/gi, '');
                svg = svg.replace(/javascript:/gi, '');
                fs.writeFileSync(req.file.path, svg);
            } catch (_) {  }
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
                        auditLog(req.session.user.id, 'AVATAR_UPLOADED', `file: ${req.file.originalname} | stored: ${req.file.filename} | mime: ${req.file.mimetype}`, req);
                        res.json({ ok: true, url: fileUrl });
                    }
                );
            }
        );
    });
});

router.post('/account/delete', accountDeleteLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId = req.session.user.id;


    db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) return res.send('Error deleting account: ' + err.message);
        auditLog(userId, 'ACCOUNT_DELETED', `username: ${req.session.user.username}`, req);
        req.session.destroy(() => res.redirect('/'));
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



    const loggedInId  = req.session.user?.id;
    const pendingId   = req.session.pendingUserId;
    const resetMailId = req.session.resetMailUserId;


    db.query('SELECT id, username, email, inbox_token FROM users WHERE inbox_token = ?', [token], (err, users) => {
        if (err) return res.send('Database error');
        if (!users.length) return res.status(404).render('404', { user: req.session.user });

        const owner  = users[0];
        const userId = owner.id;


        if (!loggedInId && userId !== pendingId && userId !== resetMailId)
            return res.redirect('/login');

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
                    unread
                });
            }
        );
    });
});

router.post('/mail/:id/read', mailReadLimiter, (req, res) => {
    if (!req.session.user && !req.session.pendingUserId) return res.status(401).json({ ok: false });
    db.query('UPDATE mail_inbox SET is_read = TRUE WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
});

router.get('/register-seller', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.render('register-seller', { user: req.session.user });
});

router.post('/register-seller', registerSellerLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    db.query('UPDATE users SET isSeller = TRUE WHERE id = ?', [req.session.user.id], (err) => {
        if (err) return res.status(500).send('Error');
        req.session.user.isSeller = true;
        req.session.user.role = 'seller';
        res.redirect('/');
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

router.post('/admin/make-seller', requireAdmin, (req, res) => {
    db.query('UPDATE users SET isSeller = TRUE, role = "seller" WHERE email = ?', [req.body.email], (err, r) => {
        if (err || !r.affectedRows) return res.redirect('/admin/users?error=' + (err ? 'Database error' : 'Email not found'));
        auditLog(req.session.user.id, 'SELLER_PROMOTED',
            `admin: ${req.session.user.username} | email: ${req.body.email}`, req);
        res.redirect('/admin/users?success=User promoted to seller');
    });
});

router.post('/admin/remove-seller', requireAdmin, (req, res) => {
    db.query('UPDATE users SET isSeller = FALSE, role = "user" WHERE id = ?', [req.body.user_id], (err) => {
        if (err) return res.redirect('/admin/users?error=Database error');
        auditLog(req.session.user.id, 'SELLER_DEMOTED',
            `admin: ${req.session.user.username} | user_id: ${req.body.user_id}`, req);
        res.redirect('/admin/users?success=Seller role removed');
    });
});

router.post('/admin/delete-user', requireAdmin, (req, res) => {
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
            auditLog(req.session.user.id, 'USER_DELETED',
                `admin: ${req.session.user.username} | deleted_user_id: ${targetId}`, req);
            return res.redirect('/admin/users?success=User and all related data deleted');
        }
        db.query(steps[i++], runNext);
    }
    runNext(null);
});

module.exports = router;
