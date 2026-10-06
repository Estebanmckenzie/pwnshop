/* Catálogo/tienda — FUERA DEL ALCANCE de los 4 módulos del proyecto. */

const express = require('express');
const path = require('path');
const _       = require('lodash');
const PDFDocument = require('pdfkit');
const multer = require('multer');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { searchLimiter, addProductLimiter, reviewLimiter, wishlistLimiter, trackLimiter, sellerPreviewLimiter } = require('../../shared/rate-limiters');
const { resolveDeals, requireAdmin } = require('../../shared/helpers');
const router = express.Router();

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename:    (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

const SEED_USER_IDS    = [1, 2, 3, 4, 5];
const SEED_PRODUCT_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

const SEED_COUPON_IDS  = [1, 2, 3, 4, 5];

router.get('/', (req, res) => {
    db.query('SELECT * FROM products WHERE available = TRUE', (err, products) => {
        if (err) return res.status(500).send('Database error: ' + err.message);
        db.query(
            `SELECT p.*, u.username AS seller_name, u.seller_tagline
             FROM products p JOIN users u ON p.seller_id = u.id
             WHERE p.available = TRUE ORDER BY RAND() LIMIT 4`,
            (err, featuredProducts) => {
                if (err) return res.status(500).send('Database error: ' + err.message);
                res.render('home', { user: req.session.user, products: resolveDeals(products), featuredProducts: resolveDeals(featuredProducts) });
            }
        );
    });
});

router.get('/search', searchLimiter, (req, res) => {
    const query = req.query.q;
    const sqlQuery = `SELECT * FROM products WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'`;
    db.query(sqlQuery, (err, products) => {
        if (err) return res.send('Database error: ' + err.sqlMessage);
        res.render('search-results', { user: req.session.user, products: resolveDeals(products), query });
    });
});

router.get('/category/:category', (req, res) => {
    const category = req.params.category;
    const sort = req.query.sort;

    let orderBy = '';
    if (sort === 'high') orderBy = ' ORDER BY price DESC';
    else if (sort === 'low') orderBy = ' ORDER BY price ASC';

    const sql = (category === 'all'
        ? 'SELECT * FROM products WHERE available = TRUE'
        : 'SELECT * FROM products WHERE category = ? AND available = TRUE') + orderBy;

    const params = category === 'all' ? [] : [category];
    db.query(sql, params, (err, products) => {
        if (err) return res.send('Database error');
        res.render('category', { user: req.session.user, products: resolveDeals(products), currentCategory: category, currentSort: sort || 'relevance' });
    });
});

router.get('/product/:id', (req, res) => {
    const productId = req.params.id;
    db.query(
        'SELECT p.*, u.username AS seller_username FROM products p JOIN users u ON p.seller_id = u.id WHERE p.id = ?',
        [productId],
        (err, products) => {
            if (err) return res.send('Database error');
            if (!products.length) return res.send('Product not found');

            db.query(
                'SELECT r.*, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = ? ORDER BY r.created_at DESC',
                [productId],
                (err, reviews) => {
                    if (err) reviews = [];

                    const product = resolveDeals(products[0]);
                    if (req.session.user) {
                        db.query(
                            'SELECT id FROM wishlists WHERE user_id = ? AND product_id = ?',
                            [req.session.user.id, productId],
                            (err, wl) => {
                                res.render('product-details', {
                                    user: req.session.user,
                                    product,
                                    reviews,
                                    wishlisted: wl && wl.length > 0
                                });
                            }
                        );
                    } else {
                        res.render('product-details', {
                            user: null,
                            product,
                            reviews,
                            wishlisted: false
                        });
                    }
                }
            );
        }
    );
});

router.post('/review', reviewLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { product_id, rating, comment } = req.body;
    db.query(
        'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
        [product_id, req.session.user.id, parseInt(rating) || 5, comment],
        () => {
            auditLog(req.session.user.id, 'REVIEW_POSTED', `product_id: ${product_id} | rating: ${rating} | comment: ${comment}`, req);
            res.redirect('/product/' + product_id);
        }
    );
});

router.post('/wishlist/add', wishlistLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { product_id } = req.body;


    const shareToken = crypto.randomBytes(8).toString('hex');
    db.query(
        'INSERT IGNORE INTO wishlists (user_id, product_id, share_token) VALUES (?, ?, ?)',
        [req.session.user.id, product_id, shareToken],
        () => res.redirect('/product/' + product_id)
    );
});

router.post('/wishlist/remove', wishlistLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { product_id, redirect_to } = req.body;
    db.query(
        'DELETE FROM wishlists WHERE user_id = ? AND product_id = ?',
        [req.session.user.id, product_id],
        () => res.redirect(redirect_to || '/product/' + product_id)
    );
});

router.get('/wishlist/:token', (req, res) => {
    const token = req.params.token;

    db.query(
        'SELECT DISTINCT w.user_id FROM wishlists w WHERE w.share_token = ?',
        [token],
        (err, rows) => {
            if (err) return res.send('Database error');
            if (!rows.length) return res.status(404).render('404', { user: req.session.user });
            const userId = rows[0].user_id;
            db.query(
                'SELECT w.*, p.name, p.price, p.image, p.category, p.id AS product_id FROM wishlists w JOIN products p ON w.product_id = p.id WHERE w.user_id = ?',
                [userId],
                (err, items) => {
                    if (err) return res.send('Database error');
                    db.query('SELECT id, username FROM users WHERE id = ?', [userId], (err, users) => {
                        res.render('wishlist', {
                            user: req.session.user,
                            wishlistOwner: users && users[0] ? users[0] : null,
                            items
                        });
                    });
                }
            );
        }
    );
});

router.get('/add-product', (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');
    res.render('add-product', { error: null, user: req.session.user });
});

router.post('/add-product', addProductLimiter, upload.single('imageFile'), (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');
    const { name, description, price, category, image, available } = req.body;
    const sellerId = req.session.user.id;
    let imagePath  = image || '';

    const saveProduct = () => {
        db.query(
            'INSERT INTO products (name, description, price, category, image, seller_id, stock, available) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)',
            [name, description, price, category, imagePath, sellerId, available || 0],
            (err) => {
                if (err) return res.render('add-product', { error: 'Error: ' + err.message, user: req.session.user });
                auditLog(sellerId, 'PRODUCT_ADDED', `name: ${name} | price: ${price} | category: ${category}`, req);
                res.redirect('/');
            }
        );
    };

    if (req.file) {
        imagePath = '/uploads/' + req.file.filename;
        saveProduct();
    } else if (image && image.startsWith('http')) {
        const proto = image.startsWith('https') ? https : http;
        proto.get(image, () => { imagePath = image; saveProduct(); }).on('error', () => { imagePath = image; saveProduct(); });
    } else {
        saveProduct();
    }
});

router.get('/edit-product/:id', (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');
    const productId = req.params.id;
    db.query('SELECT * FROM products WHERE id = ? AND seller_id = ?', [productId, req.session.user.id], (err, products) => {
        if (err || !products.length) return res.redirect('/seller/dashboard');
        res.render('edit-product', { user: req.session.user, product: products[0], error: null, success: null });
    });
});

router.post('/edit-product/:id', upload.single('imageFile'), (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');
    const productId = req.params.id;
    const { name, description, price, category, image, available } = req.body;


    db.query('SELECT * FROM products WHERE id = ? AND seller_id = ?', [productId, req.session.user.id], (err, products) => {
        if (err || !products.length) return res.redirect('/seller/dashboard');

        let imagePath = image || products[0].image || '';

        const doUpdate = () => {
            db.query(
                'UPDATE products SET name=?, description=?, price=?, category=?, image=?, stock=? WHERE id=? AND seller_id=?',
                [name, description, price, category, imagePath, available || 0, productId, req.session.user.id],
                (err) => {
                    if (err) return res.render('edit-product', { user: req.session.user, product: products[0], error: 'Update failed: ' + err.message, success: null });
                    db.query('SELECT * FROM products WHERE id = ?', [productId], (err, updated) => {
                        auditLog(req.session.user.id, 'PRODUCT_EDITED', `product_id: ${productId} | name: ${name} | price: ${price}`, req);
                        res.render('edit-product', {
                            user: req.session.user,
                            product: updated[0] || products[0],
                            error: null,
                            success: 'Product updated successfully!'
                        });
                    });
                }
            );
        };

        if (req.file) {
            imagePath = '/uploads/' + req.file.filename;
            doUpdate();
        } else {
            doUpdate();
        }
    });
});

router.get('/admin', requireAdmin, (req, res) => res.redirect('/admin/users'));

router.get('/admin/products', requireAdmin, (req, res) => {
    const search = req.query.search || '';
    let sql = 'SELECT p.*, u.username AS seller_username FROM products p JOIN users u ON p.seller_id = u.id ORDER BY p.id DESC';
    let params = [];
    if (search) {
        sql = 'SELECT p.*, u.username AS seller_username FROM products p JOIN users u ON p.seller_id = u.id WHERE p.name LIKE ? OR p.category LIKE ? OR u.username LIKE ? ORDER BY p.id DESC';
        params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }
    db.query(sql, params, (err, products) => {
        if (err) return res.send('Database error');
        res.render('admin', {
            user: req.session.user,
            tab: 'products',
            users: [], orders: [], reviews: [],
            products,
            success: req.query.success || null,
            error:   req.query.error   || null,
            auditLogs: [], coupons: [],
            search
        });
    });
});

router.get('/admin/reviews', requireAdmin, (req, res) => {
    db.query(
        'SELECT r.*, u.username AS reviewer, p.name AS product_name FROM reviews r JOIN users u ON r.user_id = u.id JOIN products p ON r.product_id = p.id ORDER BY r.created_at DESC',
        (err, reviews) => {
            if (err) reviews = [];
            res.render('admin', {
                user: req.session.user,
                tab: 'reviews',
                users: [], orders: [], products: [],
                reviews,
                success: req.query.success || null,
                error:   req.query.error   || null,
                auditLogs: [], coupons: [],
            search:  ''
            });
        }
    );
});

router.post('/admin/toggle-product', requireAdmin, (req, res) => {
    db.query('UPDATE products SET available = NOT available WHERE id = ?', [req.body.product_id], (err) => {
        if (err) return res.redirect('/admin/products?error=Database error');
        auditLog(req.session.user.id, 'PRODUCT_TOGGLED',
            `admin: ${req.session.user.username} | product_id: ${req.body.product_id}`, req);
        res.redirect('/admin/products?success=Product visibility toggled');
    });
});

router.post('/admin/delete-review', requireAdmin, (req, res) => {
    db.query('DELETE FROM reviews WHERE id = ?', [req.body.review_id], (err) => {
        if (err) return res.redirect('/admin/reviews?error=Database error');
        auditLog(req.session.user.id, 'REVIEW_DELETED',
            `admin: ${req.session.user.username} | review_id: ${req.body.review_id}`, req);
        res.redirect('/admin/reviews?success=Review removed');
    });
});

router.get('/vulnerabilities', (req, res) => res.render('vulnerabilities', { user: req.session.user }));

router.get('/debug/info', (req, res) => {
    auditLog(req.session.user ? req.session.user.id : null, 'DEBUG_ENDPOINT_ACCESSED',
        `user: ${req.session.user ? req.session.user.username : 'unauthenticated'}`, req);
    res.json({
        nodeVersion: process.version,
        platform: process.platform,
        env: 'development',
        sessionSecret: 'weak-secret-123',
        dbConfig: { host: 'localhost', user: 'root', database: 'pwnshop' },
        CHAT_OVERRIDE_TOKEN: process.env.CHAT_OVERRIDE_TOKEN || 'PSH-INT-ADM-9X7K',
    });
});

router.get('/track', (req, res) => {
    res.render('track', {
        user: req.session.user,
        error: null
    });
});

router.post('/track', trackLimiter, (req, res) => {
    const { order_id, email } = req.body;
    if (!order_id) return res.render('track', { user: req.session.user, error: 'Please enter an order number.' });



    db.query('SELECT * FROM orders WHERE id = ?', [order_id], (err, orders) => {
        if (err || !orders.length) {
            return res.render('track', { user: req.session.user, error: 'Order not found. Please check your order number.' });
        }
        res.redirect('/track/' + order_id);
    });
});

router.get('/track/:order_id', (req, res) => {
    const orderId = req.params.order_id;


    db.query('SELECT o.*, u.username, u.email FROM orders o LEFT JOIN users u ON o.user_id = u.id WHERE o.id = ?', [orderId], (err, orders) => {
        if (err || !orders.length) return res.status(404).render('404', { user: req.session.user });

        const order = orders[0];

        db.query(
            'SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
            [orderId],
            (err, items) => {
                if (err) items = [];

                db.query(
                    'SELECT * FROM tracking_events WHERE order_id = ? ORDER BY created_at ASC',
                    [orderId],
                    (err, events) => {
                        if (err) events = [];
                        res.render('track-result', {
                            user:   req.session.user,
                            order,
                            items,
                            events
                        });
                    }
                );
            }
        );
    });
});

router.get('/reset', (req, res) => {
    res.render('reset', { user: req.session.user, done: false, error: null });
});

router.post('/reset', (req, res) => {
    const su = SEED_USER_IDS.length    ? SEED_USER_IDS.join(',')    : '0';
    const sp = SEED_PRODUCT_IDS.length ? SEED_PRODUCT_IDS.join(',') : '0';
    const sc = SEED_COUPON_IDS.length  ? SEED_COUPON_IDS.join(',')  : '0';


    const steps = [

        `DELETE te FROM tracking_events te
             JOIN orders o ON te.order_id = o.id
             WHERE o.user_id NOT IN (${su})`,

        `DELETE oi FROM order_items oi
             JOIN orders o ON oi.order_id = o.id
             WHERE o.user_id NOT IN (${su})`,

        `DELETE se FROM seller_earnings se
             JOIN orders o ON se.order_id = o.id
             WHERE o.user_id NOT IN (${su})`,
        `DELETE FROM orders          WHERE user_id    NOT IN (${su})`,
        `DELETE FROM cart_items      WHERE user_id    NOT IN (${su})`,
        `DELETE FROM wishlists       WHERE user_id    NOT IN (${su})`,
        `DELETE FROM reviews         WHERE user_id    NOT IN (${su})`,
        `DELETE FROM otp_codes       WHERE user_id    NOT IN (${su})`,
        `DELETE FROM mail_inbox      WHERE 1=1`,
        `DELETE FROM password_resets WHERE user_id    NOT IN (${su})`,



        `DELETE FROM coupon_uses WHERE 1=1`,


        `DELETE FROM coupons WHERE id NOT IN (${sc})`,


        `UPDATE coupons SET total_used = 0 WHERE id IN (${sc})`,


        `DELETE FROM products
             WHERE id NOT IN (${sp})
               AND seller_id NOT IN (${su})`,


        `DELETE FROM users
             WHERE id NOT IN (${su})`,


        `UPDATE products SET stock = 10 WHERE id IN (${sp})`,


        `UPDATE users SET seller_tagline = NULL WHERE id IN (${su})`,


        `UPDATE users SET avatar_url = NULL WHERE id IN (${su})`,





        `ALTER TABLE users    AUTO_INCREMENT = 6`,
        `ALTER TABLE products AUTO_INCREMENT = 12`,
    ];





    const dynamicTables = [
        'orders', 'order_items', 'cart_items', 'reviews',
        'wishlists', 'otp_codes', 'mail_inbox',
        'password_resets', 'tracking_events', 'seller_earnings',
        'coupons', 'coupon_uses'
    ];

    let i = 0;
    function runNext(err) {
        if (err) return res.render('reset', { user: req.session.user, done: false, error: 'Reset failed at step ' + i + ': ' + err.message });
        if (i >= steps.length) return resetDynamicCounters();
        db.query(steps[i++], runNext);
    }



    let d = 0;
    function resetDynamicCounters(err) {
        if (err) return res.render('reset', { user: req.session.user, done: false, error: 'Counter reset failed: ' + err.message });
        if (d >= dynamicTables.length) return res.render('reset', { user: req.session.user, done: true, error: null });

        const table = dynamicTables[d++];
        db.query('SELECT COALESCE(MAX(id), 0) + 1 AS next FROM `' + table + '`', (err, rows) => {
            if (err) return resetDynamicCounters(err);
            const next = (rows && rows[0]) ? rows[0].next : 1;
            db.query('ALTER TABLE `' + table + '` AUTO_INCREMENT = ' + next, (err) => {
                resetDynamicCounters(err);
            });
        });
    }

    runNext(null);
});

router.post('/seller/preview', sellerPreviewLimiter, (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');

    const template = req.body.template || '';
    let rendered = null;
    let saveError = null;

    if (template) {
        try {
            const ejs = require('ejs');

            rendered = ejs.render(template, {
                username:    req.session.user.username,
                shopName:    req.session.user.username + "'s Store",
                tagline:     'Quality products, great prices',
                memberSince: new Date(req.session.user.created_at).getFullYear()
            });
            auditLog(req.session.user.id, 'SSTI_TEMPLATE_RENDERED',
                `template: ${template.substring(0, 200)}`, req);
        } catch (err) {
            rendered = null;
            saveError = 'Template error: ' + err.message;
        }
    }


    const taglineToSave = rendered !== null ? rendered : (template || '');

    db.query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS seller_tagline TEXT DEFAULT NULL",
        () => {
            db.query(
                'UPDATE users SET seller_tagline = ? WHERE id = ?',
                [taglineToSave, req.session.user.id],
                (err) => {
                    if (err) saveError = 'Save failed: ' + err.message;

                    db.query('SELECT * FROM users WHERE id = ?', [req.session.user.id], (e2, rows) => {
                        if (!e2 && rows.length) req.session.user = rows[0];
                    });
                    db.query(
                        'SELECT COUNT(*) AS cnt FROM products WHERE seller_id = ? AND available = TRUE',
                        [req.session.user.id],
                        (e3, rows2) => {
                            const productCount = (!e3 && rows2.length) ? rows2[0].cnt : 0;
                            res.redirect('/seller/preview?template=' + encodeURIComponent(template) + (saveError ? '&error=1' : '&saved=1'));
                        }
                    );
                }
            );
        }
    );
});

router.get('/seller/preview', (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');

    const template = req.query.template || '';
    let rendered = null;
    let rawOutput = null;

    if (template) {
        try {
            const ejs = require('ejs');

            rendered = ejs.render(template, {
                username:     req.session.user.username,
                shopName:     req.session.user.username + "'s Store",
                tagline:      'Quality products, great prices',
                memberSince:  new Date(req.session.user.created_at).getFullYear()
            });
            if (rendered && rendered.length < 4000) rawOutput = rendered;
            auditLog(req.session.user.id, 'SSTI_TEMPLATE_RENDERED',
                `template: ${template.substring(0, 200)}`, req);
        } catch (err) {
            rendered = null;
            rawOutput = 'Error: ' + err.message;
        }
    }


    db.query(
        'SELECT COUNT(*) AS cnt FROM products WHERE seller_id = ? AND available = TRUE',
        [req.session.user.id],
        (err, rows) => {
            const productCount = (!err && rows.length) ? rows[0].cnt : 0;
            const saved   = req.query.saved  === '1';
            const saveErr = req.query.error  === '1';
            const currentTagline = req.session.user.seller_tagline || '';
            res.render('preview', {
                user: req.session.user,
                template,
                rendered,
                rawOutput,
                productCount,
                currentTagline,
                saved,
                saveErr
            });
        }
    );
});

const DEFAULT_FILTERS = {
    category:  'all',
    minPrice:  0,
    maxPrice:  10000000,
    sort:      'relevance',
    inStock:   true
};

router.post('/search/filters', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Login required' });

    const userPrefs = req.body;


    const merged = _.merge({}, DEFAULT_FILTERS, userPrefs);

    auditLog(
        req.session.user.id,
        'FILTER_PREFS_SAVED',
        `user: ${req.session.user.username} | prefs: ${JSON.stringify(userPrefs).substring(0, 200)}`,
        req
    );

    res.json({
        success:       true,
        filters:       merged,
        message:       'Filter preferences saved',
        _proto_isAdmin: Object.prototype.isAdmin
    });
});

router.get('/search/filters', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Login required' });

    const currentFilters = Object.assign({}, DEFAULT_FILTERS);

    res.json({
        success: true,
        filters: currentFilters,


        _proto_isAdmin: Object.prototype.isAdmin
    });
});

router.get('/download', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const file = req.query.file;
    if (!file) return res.redirect('/profile');

    const fs      = require('fs');
    const baseDir = path.join(__dirname, '../../../public', 'storage');

    const filePath = path.join(baseDir, file);


    const invoiceMatch = file.match(/^invoices\/([0-9]+)\.pdf$/);
    const orderId      = invoiceMatch ? invoiceMatch[1] : null;

    if (orderId) {

        db.query(
            `SELECT o.*, u.username, u.email, u.phone
             FROM orders o
             JOIN users u ON o.user_id = u.id
             WHERE o.id = ? AND o.user_id = ?`,
            [orderId, req.session.user.id],
            (err, orders) => {
                if (err || !orders.length) {


                    return fs.readFile(filePath, 'utf8', (ferr, data) => {
                        auditLog(req.session.user.id, 'INVOICE_FILE_READ',
                            `file: ${file} | path: ${filePath} | found: ${!ferr}`, req);
                        res.send(ferr
                            ? '<h3>File not found</h3>'
                            : `<pre style="font-family:monospace;padding:20px;">${data}</pre>`
                        );
                    });
                }

                const o = orders[0];
                db.query(
                    'SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
                    [o.id],
                    (err2, items) => {
                        if (err2) items = [];


                        const subtotal = items.reduce((s, i) => s + parseFloat(i.price) * i.quantity, 0);
                        const discount = parseFloat(o.discount_amount || 0);
                        const total    = parseFloat(o.total_amount);
                        const date     = new Date(o.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

                        const itemRows = items.map(i =>
                            `<tr>
                                <td style="padding:10px 14px;border-bottom:1px solid #EDE9F6;">${i.name}</td>
                                <td style="padding:10px 14px;border-bottom:1px solid #EDE9F6;text-align:center;">${i.quantity}</td>
                                <td style="padding:10px 14px;border-bottom:1px solid #EDE9F6;text-align:right;">&#8358;${parseFloat(i.price).toLocaleString('en-NG', { minimumFractionDigits: 2 })}</td>
                                <td style="padding:10px 14px;border-bottom:1px solid #EDE9F6;text-align:right;font-weight:700;color:#6D28D9;">&#8358;${(parseFloat(i.price) * i.quantity).toLocaleString('en-NG', { minimumFractionDigits: 2 })}</td>
                            </tr>`
                        ).join('');


                        auditLog(req.session.user.id, 'INVOICE_DOWNLOADED',
                            `order_id: ${o.id} | format: pdf`, req);

                        const doc = new PDFDocument({ margin: 50, size: 'A4' });
                        res.setHeader('Content-Type', 'application/pdf');
                        res.setHeader('Content-Disposition', `attachment; filename="invoice-${o.id}.pdf"`);
                        doc.pipe(res);


                        doc.rect(0, 0, doc.page.width, 90).fill('#3B0764');
                        doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(22)
                           .text('Pwnshop', 50, 28);
                        doc.fontSize(11)
                           .text(`Invoice #INV-${String(o.id).padStart(4,'0')}`, 50, 54);
                        doc.fontSize(9).fillColor('rgba(255,255,255,0.65)')
                           .text(new Date(o.created_at).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}), 50, 70);


                        doc.fillColor('#6B7280').font('Helvetica').fontSize(8).text('BILLED TO', 50, 112);
                        doc.fillColor('#0D0D0D').font('Helvetica-Bold').fontSize(10).text(o.username, 50, 124);
                        doc.font('Helvetica').fontSize(9).fillColor('#374151')
                           .text(o.email, 50, 138)
                           .text(o.phone || '', 50, 151)
                           .text(o.shipping_address, 50, 164);


                        doc.fillColor('#6B7280').font('Helvetica').fontSize(8).text('ORDER DETAILS', 320, 112);
                        doc.fillColor('#0D0D0D').font('Helvetica-Bold').fontSize(10).text(`Order #${o.id}`, 320, 124);
                        doc.font('Helvetica').fontSize(9).fillColor('#374151')
                           .text(`Status: ${o.status.toUpperCase()}`, 320, 138);


                        doc.moveTo(50, 200).lineTo(545, 200).strokeColor('#EDE9F6').lineWidth(1).stroke();


                        doc.rect(50, 210, 495, 22).fill('#F8F5FF');
                        doc.fillColor('#6B7280').font('Helvetica-Bold').fontSize(8)
                           .text('ITEM',       60,  217)
                           .text('QTY',       340,  217, { width: 50, align: 'center' })
                           .text('UNIT PRICE',390,  217, { width: 80, align: 'right' })
                           .text('TOTAL',     470,  217, { width: 70, align: 'right' });


                        let rowY = 242;
                        items.forEach(item => {
                            doc.fillColor('#0D0D0D').font('Helvetica').fontSize(9)
                               .text(item.name, 60, rowY, { width: 270 });
                            doc.text(String(item.quantity), 340, rowY, { width: 50, align: 'center' });
                            doc.text(`N${parseFloat(item.price).toLocaleString('en-NG',{minimumFractionDigits:2})}`, 390, rowY, { width: 80, align: 'right' });
                            doc.fillColor('#6D28D9')
                               .text(`N${(parseFloat(item.price)*item.quantity).toLocaleString('en-NG',{minimumFractionDigits:2})}`, 470, rowY, { width: 70, align: 'right' });
                            rowY += 22;
                            doc.moveTo(50, rowY-4).lineTo(545, rowY-4).strokeColor('#EDE9F6').lineWidth(0.5).stroke();
                        });


                        rowY += 10;
                        const sub  = items.reduce((s,i)=>s+parseFloat(i.price)*i.quantity,0);
                        const disc = parseFloat(o.discount_amount||0);
                        const tot  = parseFloat(o.total_amount);

                        const tLine = (label, val, bold, col) => {
                            doc.font(bold?'Helvetica-Bold':'Helvetica').fontSize(bold?10:9)
                               .fillColor(col||'#6B7280')
                               .text(label, 370, rowY, { width: 100 })
                               .text(val,   470, rowY, { width: 70, align: 'right' });
                            rowY += 18;
                        };
                        tLine('Subtotal', `N${sub.toLocaleString('en-NG',{minimumFractionDigits:2})}`);
                        if (disc > 0) tLine('Discount', `-N${disc.toLocaleString('en-NG',{minimumFractionDigits:2})}`, false, '#16a34a');
                        tLine('Shipping', 'FREE', false, '#16a34a');
                        doc.moveTo(370, rowY-2).lineTo(545, rowY-2).strokeColor('#374151').lineWidth(1).stroke();
                        rowY += 6;
                        tLine('Total Paid', `N${tot.toLocaleString('en-NG',{minimumFractionDigits:2})}`, true, '#3B0764');


                        doc.moveTo(50, rowY+20).lineTo(545, rowY+20).strokeColor('#EDE9F6').lineWidth(0.5).stroke();
                        doc.fillColor('#9CA3AF').font('Helvetica').fontSize(8)
                           .text('Thank you for shopping with Pwnshop. This is a computer-generated invoice.', 50, rowY+30, { align: 'center', width: 495 });

                        doc.end();

                    }
                );
            }
        );
    } else {


        fs.readFile(filePath, 'utf8', (ferr, data) => {
            auditLog(req.session.user.id, 'PATH_TRAVERSAL_ATTEMPT',
                `file: ${file} | path: ${filePath} | found: ${!ferr}`, req);
            res.send(ferr
                ? '<h3 style="font-family:monospace;padding:20px;">File not found</h3>'
                : `<pre style="font-family:monospace;padding:20px;white-space:pre-wrap;">${data}</pre>`
            );
        });
    }
});

module.exports = router;
