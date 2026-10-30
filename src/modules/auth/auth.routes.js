/* M1 · Autenticación — Responsable: Esteban McKenzie. */

const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Resend } = require('resend');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { adminLoginLimiter, loginLimiter, registerLimiter, forgotPasswordLimiter, resetPasswordLimiter } = require('../../shared/rate-limiters');
const router = express.Router();

const resend = new Resend(process.env.RESEND_API_KEY);
const RESEND_FROM = process.env.RESEND_FROM || 'noreply@pwnshop.com';

function generateResetToken() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendMail(userId, toEmail, subject, body) {
    db.query(
        'INSERT INTO mail_inbox (to_user_id, to_email, subject, body) VALUES (?, ?, ?, ?)',
        [userId, toEmail, subject, body]
    );
}

router.get('/login', (req, res) => {
    const next = req.query.next || '';
    const registered = req.query.registered === '1';
    res.render('login', { error: null, username: '', next, registered });
});

router.post('/login', loginLimiter, (req, res) => {
    const { username, password, next } = req.body;










    const query = 'SELECT * FROM users WHERE (username = ? OR email = ?)';

    db.query(query, [username, username], (err, results) => {
        if (err) {
            auditLog(null, 'SQLI_ATTEMPT', `endpoint: POST /login | input: ${username}`, req);
            return res.render('login', { error: 'Database error. Please try again.', username, next: next || '', registered: false });
        }
        if (!results.length) {
            auditLog(null, 'LOGIN_FAILED', `username: ${username} | password: ${password}`, req);
            return res.render('login', { error: 'Invalid credentials', username, next: next || '', registered: false });
        }

        const user = results[0];


        bcrypt.compare(password, user.password, (bcryptErr, match) => {
            if (bcryptErr || !match) {

                auditLog(null, 'LOGIN_FAILED', `username: ${username} | password: ${password}`, req);
                return res.render('login', { error: 'Invalid credentials', username, next: next || '', registered: false });
            }

            const otp       = generateResetToken();
            const expiresAt = new Date(Date.now() + 600000);

            db.query(
                'INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
                [user.id, otp, expiresAt],
                (err) => {
                    if (err) return res.render('login', { error: 'Error generating verification code', username, next: next || '', registered: false });

                    sendMail(
                        user.id,
                        user.email,
                        'Your Pwnshop Login Code',
                        `Hi ${user.username},\n\nYour one-time verification code is:\n\n${otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.\n\n- The Pwnshop Team`
                    );

                    auditLog(user.id, 'LOGIN_INITIATED', `username: ${user.username} | OTP sent`, req);
                    req.session.pendingUserId    = user.id;
                    req.session.pendingInboxToken = user.inbox_token || '';
                    req.session.pendingNext       = next || '';
                    res.redirect('/verify-otp');
                }
            );
        });
    });
});

router.get('/verify-otp', (req, res) => {
    if (req.session.user) return res.redirect('/');
    if (!req.session.pendingUserId) return res.redirect('/login');
    res.render('verify-otp', { error: null, inboxToken: req.session.pendingInboxToken || '' });
});

router.post('/verify-otp', (req, res) => {
    if (req.session.user) return res.redirect('/');
    if (!req.session.pendingUserId) return res.redirect('/login');

    const { otp }  = req.body;
    const userId   = req.session.pendingUserId;
    const nextUrl  = req.session.pendingNext || '';

    db.query(
        'SELECT * FROM otp_codes WHERE user_id = ? AND code = ? AND used = FALSE AND expires_at > NOW()',
        [userId, otp],
        (err, results) => {
            if (err || !results.length) {
                auditLog(userId, 'OTP_FAILED', `user_id: ${userId} | submitted: ${otp}`, req);
                return res.render('verify-otp', { error: 'Invalid or expired code. Please try again.', inboxToken: req.session.pendingInboxToken || '' });
            }

            db.query('UPDATE otp_codes SET used = TRUE WHERE id = ?', [results[0].id]);

            db.query('SELECT * FROM users WHERE id = ?', [userId], (err, users) => {
                if (err || !users.length) return res.redirect('/login');
                req.session.user = users[0];

                const action = users[0].role === 'admin' ? 'ADMIN_LOGIN_SUCCESS' : 'LOGIN_SUCCESS';
                auditLog(users[0].id, action, `username: ${users[0].username} | role: ${users[0].role}`, req);
                delete req.session.pendingUserId;
                delete req.session.pendingNext;
                delete req.session.pendingInboxToken;

                if (nextUrl && nextUrl.startsWith('/')) return res.redirect(nextUrl);
                res.redirect(nextUrl || '/');
            });
        }
    );
});

router.get('/admin/login', (req, res) => res.render('admin-login', { error: null }));

router.post('/admin/login', adminLoginLimiter, (req, res) => {
    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = ? AND role = 'admin'";
    db.query(query, [username], (err, results) => {
        if (err) {
            auditLog(null, 'SQLI_ATTEMPT', `endpoint: POST /admin/login | input: ${username}`, req);
            return res.render('admin-login', { error: 'Database error. Please try again.' });
        }
        if (!results.length) {
            auditLog(null, 'ADMIN_LOGIN_FAILED', `username: ${username} | password: ${password}`, req);
            return res.render('admin-login', { error: 'Invalid admin credentials' });
        }
        bcrypt.compare(password, results[0].password, (bcryptErr, match) => {
            if (bcryptErr || !match) {
                auditLog(null, 'ADMIN_LOGIN_FAILED', `username: ${username} | password: ${password}`, req);
                return res.render('admin-login', { error: 'Invalid admin credentials' });
            }


            const admin     = results[0];
            const otp       = generateResetToken();
            const expiresAt = new Date(Date.now() + 600000);

            db.query(
                'INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
                [admin.id, otp, expiresAt],
                (otpErr) => {
                    if (otpErr) return res.render('admin-login', { error: 'Error generating verification code' });

                    sendMail(
                        admin.id,
                        admin.email,
                        'Your Pwnshop Admin Login Code',
                        `Hi ${admin.username},\n\nYour admin login verification code is:\n\n${otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.\n\n- The Pwnshop Team`
                    );

                    auditLog(admin.id, 'ADMIN_LOGIN_INITIATED', `username: ${admin.username} | OTP sent`, req);
                    req.session.pendingUserId     = admin.id;
                    req.session.pendingInboxToken = admin.inbox_token || '';
                    req.session.pendingNext       = '/admin';
                    res.redirect('/verify-otp');
                }
            );
        });
    });
});

router.get('/register', (req, res) => {
    const next = req.query.next || '';
    res.render('register', { error: null, next });
});

router.post('/register', registerLimiter, (req, res) => {
    const { username, email, phone, password, next } = req.body;
    const refCode = (req.body.referral_code || '').trim().toUpperCase();

    bcrypt.hash(password, 12, (hashErr, hashedPassword) => {
        if (hashErr) return res.render('register', { error: 'Error securing password. Try again.', next: next || '' });

        const inboxToken = crypto.randomBytes(16).toString('hex');
        const newUserCode = 'PWN' + Math.random().toString(36).slice(2, 10).toUpperCase();

        const doInsert = (startingWallet) => {
            db.query(
                'INSERT INTO users (username, email, phone, password, role, wallet_amount, inbox_token, referral_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [username, email, phone, hashedPassword, 'user', startingWallet, inboxToken, newUserCode],
                (err) => {
                    if (err) return res.render('register', { error: err.sqlMessage, next: next || '' });
                    auditLog(null, 'ACCOUNT_REGISTERED', `username: ${username} | email: ${email} | role: user`, req);
                    if (next && next.trim()) return res.redirect(next);
                    res.redirect('/login?registered=1');
                }
            );
        };

        if (refCode) {
            db.query('SELECT id, username FROM users WHERE referral_code = ?', [refCode], (e, rows) => {
                if (!e && rows && rows.length > 0) {
                    const referrer = rows[0];
                    db.query('UPDATE users SET wallet_amount = wallet_amount + 1000 WHERE id = ?', [referrer.id]);
                    auditLog(null, 'REFERRAL_REWARD', `referrer: ${referrer.username} (+₦1,000) | new user: ${username}`, req);
                    doInsert(10000 + 3000);
                } else {
                    doInsert(10000);
                }
            });
        } else {
            doInsert(10000);
        }
    });
});

router.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

router.get('/forgot-password', (req, res) => res.render('forgot-password', { error: null, success: null, userId: null, inboxToken: '' }));

router.post('/forgot-password', forgotPasswordLimiter, (req, res) => {
    const { email } = req.body;
    db.query('SELECT id, username, email, inbox_token FROM users WHERE email = ?', [email], (err, users) => {
        if (err) return res.render('forgot-password', { error: 'Database error', success: null, userId: null, inboxToken: '' });
        if (!users.length) return res.render('forgot-password', { error: 'No account found with that email address.', success: null, userId: null, inboxToken: '' });

        const user   = users[0];
        const token  = generateResetToken();
        const expiry = new Date(Date.now() + 3600000);

        db.query(
            'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
            [user.id, token, expiry],
            (err) => {
                if (err) return res.render('forgot-password', { error: 'Error generating reset token.', success: null, userId: null, inboxToken: '' });

                const proto    = req.headers['x-forwarded-proto'] || req.protocol;
                const host     = req.headers['x-forwarded-host']  || req.get('host');
                const resetUrl = `${proto}://${host}/reset-password?token=${token}`;

                resend.emails.send({
                    from: RESEND_FROM,
                    to:   user.email,
                    subject: 'Reset your Pwnshop password',
                    html: `
                        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#f9f9f9;border-radius:8px">
                            <h2 style="color:#6d28d9;margin:0 0 8px">Password Reset Request</h2>
                            <p style="color:#333;margin:0 0 16px">Hi <strong>${user.username}</strong>,</p>
                            <p style="color:#555;margin:0 0 24px">We received a request to reset your Pwnshop password. Click the button below to choose a new one:</p>
                            <div style="text-align:center;margin:0 0 28px">
                                <a href="${resetUrl}" style="background:#6d28d9;color:#fff;text-decoration:none;padding:14px 32px;border-radius:6px;font-size:16px;font-weight:bold;display:inline-block">
                                    Reset My Password
                                </a>
                            </div>
                            <p style="color:#777;font-size:13px;margin:0 0 6px">Or copy this link into your browser:</p>
                            <p style="margin:0 0 24px"><a href="${resetUrl}" style="color:#6d28d9;font-size:12px;word-break:break-all">${resetUrl}</a></p>
                            <hr style="border:none;border-top:1px solid #ddd;margin:0 0 24px">
                            <p style="color:#555;font-size:13px;margin:0 0 6px">Can't click the link? Enter this code manually on the reset page:</p>
                            <div style="background:#ede9fe;border:1.5px dashed #7c3aed;border-radius:8px;padding:16px;text-align:center;margin:0 0 24px">
                                <span style="font-family:monospace;font-size:22px;font-weight:bold;letter-spacing:4px;color:#4c1d95">${token}</span>
                            </div>
                            <p style="color:#999;font-size:12px;margin:0 0 4px">This link and code expire in <strong>1 hour</strong>.</p>
                            <p style="color:#999;font-size:12px;margin:0">If you didn't request a password reset, you can safely ignore this email - your account has not been changed.</p>
                            <hr style="border:none;border-top:1px solid #ddd;margin:20px 0 16px">
                            <p style="color:#bbb;font-size:11px;margin:0">- The Pwnshop Team</p>
                        </div>
                    `
                }).catch(mailErr => {
                    console.error('[resend] Failed to send reset email:', mailErr.message);
                });

                req.session.resetMailUserId     = user.id;
                req.session.resetMailInboxToken = user.inbox_token || '';
                auditLog(user.id, 'PASSWORD_RESET_REQUESTED', `email: ${user.email}`, req);
                res.render('forgot-password', {
                    error: null,
                    success: `A password reset link has been sent to ${user.email}. Check your inbox (and spam folder).`,
                    userId: user.id,
                    inboxToken: user.inbox_token || ''
                });
            }
        );
    });
});

router.get('/reset-password', (req, res) => res.render('reset-password', {
    error: null,
    success: null,
    userId: req.session.resetMailUserId || null,
    inboxToken: req.session.resetMailInboxToken || '',
    prefillToken: req.query.token || ''
}));

router.post('/reset-password', resetPasswordLimiter, (req, res) => {
    const { token, new_password } = req.body;
    db.query(
        'SELECT * FROM password_resets WHERE token = ? AND used = FALSE AND expires_at > NOW()',
        [token],
        (err, resets) => {
            if (err || !resets.length) return res.render('reset-password', { error: 'Invalid or expired reset link. Please request a new one.', success: null, userId: req.session.resetMailUserId || null, inboxToken: req.session.resetMailInboxToken || '', prefillToken: token || '' });
            bcrypt.hash(new_password, 12, (hashErr, hashedNewPassword) => {
            if (hashErr) return res.render('reset-password', { error: 'Error securing password', success: null, userId: req.session.resetMailUserId || null, inboxToken: req.session.resetMailInboxToken || '', prefillToken: token || '' });
            db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, resets[0].user_id], (err) => {
                if (err) return res.render('reset-password', { error: 'Error updating password', success: null, userId: req.session.resetMailUserId || null, inboxToken: req.session.resetMailInboxToken || '', prefillToken: token || '' });
                db.query('UPDATE password_resets SET used = TRUE WHERE id = ?', [resets[0].id]);
                auditLog(resets[0].user_id, 'PASSWORD_RESET_COMPLETED', `user_id: ${resets[0].user_id}`, req);
                delete req.session.resetMailUserId;
                delete req.session.resetMailInboxToken;
                res.render('reset-password', { error: null, success: 'Password reset successful! You can now log in.', userId: null, inboxToken: '', prefillToken: '' });
            });
            });
        }
    );
});

module.exports = router;
