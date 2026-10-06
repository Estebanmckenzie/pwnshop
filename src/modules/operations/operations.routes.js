/* M3 · Operaciones/Transacciones — Responsable: Geiner Barrantes. */

const express = require('express');
const path = require('path');
const { db } = require('../../shared/db');
const { auditLog } = require('../../shared/audit-core');
const { VULNBANK_CHARGE_PATH, VULNBANK_LAB_VULN } = require('../../shared/config');
const { isVulnbankConfigured, getVulnbankReference, getVulnbankAmount, extractVulnbankErrorMessage, isVulnbankSuccess, buildVulnbankVerifyPath, vulnbankRequest } = require('../../shared/vulnbank');
const { checkoutLimiter, cartLimiter, couponLimiter } = require('../../shared/rate-limiters');
const { resolveDeals, requireAdmin } = require('../../shared/helpers');
const router = express.Router();

function seedDeals() {
    const targets = [
        { pattern: '%iphone 14%',  label: 'Flash Sale', discount: 0.72 },
        { pattern: '%levi%',       label: 'Hot Deal',   discount: 0.68 },
        { pattern: '%macbook%',    label: 'Clearance',  discount: 0.75 }
    ];
    targets.forEach(({ pattern, label, discount }) => {
        db.query(
            'SELECT id, price FROM products WHERE LOWER(name) LIKE ? AND (deal_price IS NULL OR deal_label != ?) LIMIT 1',
            [pattern, label],
            (e, rows) => {
                if (!e && rows && rows.length > 0) {
                    const dp = Math.round(parseFloat(rows[0].price) * discount * 100) / 100;
                    db.query('UPDATE products SET deal_price = ?, deal_label = ?, deal_expires_at = ? WHERE id = ?',
                        [dp, label, '2036-01-01', rows[0].id]);
                }
            }
        );
    });
}
setTimeout(seedDeals, 3000);
setInterval(seedDeals, 30 * 60 * 1000);

/* Commission rates by product category (master plan v2) */
const CATEGORY_COMMISSION = {
    'computers':   0.06,
    'phones':      0.08,
    'electronics': 0.08,
    'fashion':     0.12,
    'home':        0.10,
    'kids':        0.10,
    'beauty':      0.12,
};
const DEFAULT_COMMISSION = 0.08;
const VAT_ON_COMMISSION  = 0.075;

/* Logistics fee by delivery zone */
const ZONE_FEE = {
    lagos:  800,
    others: 1500,
    remote: 2500,
};
const DEFAULT_ZONE_FEE = 1500;

/* Legacy constants kept for seller-earnings admin view compatibility */
const PLATFORM_FEE_PCT    = 0.08;   /* not used in new orders, kept for old earnings display */
const SHIPPING_DEDUCTION  = 1500;   /* not used in new orders */

const WITHDRAWAL_FEE = 100;         /* ₦100 per seller withdrawal */

const PICKUP_STORES = [
    { id: 'lag-island',  name: 'Pwnshop Lagos Island',    address: '14 Broad Street, Lagos Island, Lagos',           zone: 'lagos'  },
    { id: 'lag-lekki',   name: 'Pwnshop Lekki Phase 1',   address: '25 Admiralty Way, Lekki Phase 1, Lagos',         zone: 'lagos'  },
    { id: 'lag-ikeja',   name: 'Pwnshop Ikeja',           address: '3 Obafemi Awolowo Way, Ikeja, Lagos',            zone: 'lagos'  },
    { id: 'abj-wuse',    name: 'Pwnshop Abuja (Wuse II)', address: 'Plot 291 Herbert Macaulay Way, Wuse II, Abuja',  zone: 'others' },
    { id: 'ph-stadium',  name: 'Pwnshop Port Harcourt',   address: '12 Stadium Road, Port Harcourt, Rivers State',   zone: 'others' },
    { id: 'ibd-ring',    name: 'Pwnshop Ibadan',          address: '67 Ring Road, Ibadan, Oyo State',                zone: 'others' },
    { id: 'kan-bompai',  name: 'Pwnshop Kano',            address: '15 Bompai Road, Kano, Kano State',               zone: 'others' },
    { id: 'enu-ogui',    name: 'Pwnshop Enugu',           address: '5 Ogui Road GRA, Enugu, Enugu State',            zone: 'others' },
    { id: 'ben-akp',     name: 'Pwnshop Benin City',      address: '22 Akpakpava Road, Benin City, Edo State',       zone: 'others' },
    { id: 'aba-exp',     name: 'Pwnshop Aba Express',     address: 'Aba-Owerri Road, Aba, Abia State',               zone: 'others' },
];

function getCommissionRate(category) {
    if (!category) return DEFAULT_COMMISSION;
    return CATEGORY_COMMISSION[category.toLowerCase().trim()] || DEFAULT_COMMISSION;
}
function getZoneFee(zone) {
    if (!zone) return DEFAULT_ZONE_FEE;
    return ZONE_FEE[zone.toLowerCase().trim()] || DEFAULT_ZONE_FEE;
}

router.get('/order/:id', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const orderId = req.params.id;
    db.query(
        'SELECT o.*, u.inbox_token FROM orders o LEFT JOIN users u ON o.user_id = u.id WHERE o.id = ?',
        [orderId],
        (err, orders) => {
            if (err) return res.send('Database error');
            if (!orders.length) return res.send('Order not found');
            db.query(
                'SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
                [orderId],
                (err, items) => {
                    if (err) return res.send('Database error');
                    res.render('order-details', { user: req.session.user, order: orders[0], items });
                }
            );
        }
    );
});

router.post('/wallet/topup/vulnbank', checkoutLimiter, async (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    if (!isVulnbankConfigured()) {
        return res.redirect('/profile?wallet_error=' + encodeURIComponent('Vulnbank is not configured on this lab instance'));
    }

    const userId = req.session.user.id;
    const amount = parseFloat(req.body.amount || '0');
    const cardNumber = String(req.body.card_number || '').trim();
    const cardExpiry = String(req.body.card_expiry || '').trim();
    const cardCvv = String(req.body.card_cvv || '').trim();
    const cardName = String(req.body.card_name || req.session.user.username || '').trim();

    if (isNaN(amount)) {
        return res.redirect('/profile?wallet_error=' + encodeURIComponent('Invalid top-up amount'));
    }

    // VULNERABILITY (negative amount): In lab vuln mode the positive-amount
    // guard is skipped. A learner can send amount=0.001 - Vulnbank charges
    // essentially nothing - then pair it with credited_amount to credit any
    // value they want. In strict mode the > 0 guard blocks this entirely.
    if (!VULNBANK_LAB_VULN && amount <= 0) {
        return res.redirect('/profile?wallet_error=' + encodeURIComponent('Amount must be greater than zero'));
    }

    if (!cardNumber || !cardExpiry || !cardCvv) {
        return res.redirect('/profile?wallet_error=' + encodeURIComponent('Vulnbank card details are required'));
    }

    const txRef = 'pwnshop_topup_' + userId + '_' + Date.now();
    const normalizedCardNumber = cardNumber.replace(/\s+/g, '');
    const payload = {
        // VULNERABILITY (negative amount): In lab vuln mode, amount is sent
        // as-is with no rounding or clamping - so 0.001 goes to Vulnbank
        // exactly as 0.001 rather than being normalised to a safe minimum.
        amount: VULNBANK_LAB_VULN ? amount : parseFloat(amount.toFixed(2)),
        currency: 'NGN',
        merchant_order_id: txRef,
        description: 'Pwnshop wallet top-up',
        card_number: normalizedCardNumber,
        cvv: cardCvv,
        expiry_date: cardExpiry,
        metadata: {
            user_id: userId,
            flow: 'wallet_topup',
            card_name: cardName
        }
    };

    try {
        const chargeResp = await vulnbankRequest(VULNBANK_CHARGE_PATH, 'POST', payload);
        const ref = VULNBANK_LAB_VULN
            ? (getVulnbankReference(chargeResp) || txRef)
            : txRef;

        let verifyResp = chargeResp;
        const verifyPath = buildVulnbankVerifyPath(ref);
        if (verifyPath) {
            try {
                verifyResp = await vulnbankRequest(verifyPath, 'GET');
            } catch (_) {
                // fall through - use charge response as-is
            }
        }

        const settled = isVulnbankSuccess(verifyResp);
        const remoteAmount = getVulnbankAmount(verifyResp);
        // VULNERABILITY (#3): remoteAmount === null bypasses amount check entirely
        const amountMatches = remoteAmount === null || Math.abs(remoteAmount - amount) < 0.01;

        if (!VULNBANK_LAB_VULN && (!settled || !amountMatches)) {
            return res.redirect('/profile?wallet_error=' + encodeURIComponent('Vulnbank charge was not settled'));
        }

        // VULNERABILITY (#1): credited_amount is read from the request body when lab vuln is on
        const creditedAmount = VULNBANK_LAB_VULN
            ? parseFloat(req.body.credited_amount || amount)
            : amount;

        if (isNaN(creditedAmount)) {
            return res.redirect('/profile?wallet_error=' + encodeURIComponent('Invalid credited amount'));
        }

        // VULNERABILITY (negative amount): In lab vuln mode the sign check on
        // creditedAmount is removed. Sending credited_amount=-5000 would
        // decrement the wallet. Combined with a tiny charge (amount=0.001)
        // and a large positive credited_amount, a learner can essentially
        // fund their wallet for free. In strict mode the <= 0 guard applies.
        if (!VULNBANK_LAB_VULN && creditedAmount <= 0) {
            return res.redirect('/profile?wallet_error=' + encodeURIComponent('Invalid credited amount'));
        }

        // VULNERABILITY (replay): In strict mode we check for duplicate references.
        // In lab vuln mode the check is skipped - replaying a valid reference credits
        // the wallet again without a new charge.
        const doCredit = () => {
            // VULNERABILITY (race condition): non-atomic SELECT then UPDATE creates a
            // TOCTOU window. Two concurrent top-up requests can both read the same
            // balance, both compute the same new value, and the second write wins -
            // effectively crediting the wallet only once instead of twice, or the
            // opposite: both succeed and the wallet is double-credited depending on timing.
            db.query('SELECT wallet_amount FROM users WHERE id = ?', [userId], (selErr, selRows) => {
                if (selErr || !selRows.length) {
                    return res.redirect('/profile?wallet_error=' + encodeURIComponent('Database error while funding wallet'));
                }
                const currentBalance = parseFloat(selRows[0].wallet_amount || 0);
                const newBalance = currentBalance + creditedAmount;

                db.query('UPDATE users SET wallet_amount = ? WHERE id = ?', [newBalance, userId], (updErr) => {
                    if (updErr) {
                        return res.redirect('/profile?wallet_error=' + encodeURIComponent('Database error while funding wallet'));
                    }

                    db.query('INSERT INTO vulnbank_tx_log (user_id, reference, amount, flow) VALUES (?, ?, ?, ?)',
                        [userId, ref, creditedAmount, 'wallet_topup'], () => {});

                    db.query('SELECT * FROM users WHERE id = ?', [userId], (uErr, rows) => {
                        if (!uErr && rows.length) req.session.user = rows[0];
                        auditLog(userId, 'WALLET_TOPUP_VULNBANK',
                            `ref: ${ref} | requested: ${amount.toFixed(2)} | credited: ${creditedAmount.toFixed(2)}`,
                            req);
                        res.redirect('/profile?wallet_success=' + encodeURIComponent('Wallet funded with Vulnbank: ₦' + creditedAmount.toFixed(2)));
                    });
                });
            });
        };

        if (!VULNBANK_LAB_VULN) {
            db.query('SELECT id FROM vulnbank_tx_log WHERE reference = ?', [ref], (chkErr, existing) => {
                if (!chkErr && existing.length > 0) {
                    return res.redirect('/profile?wallet_error=' + encodeURIComponent('Payment reference already used'));
                }
                doCredit();
            });
        } else {
            // Lab vuln mode: no duplicate reference check
            doCredit();
        }

    } catch (err) {
        const msg = extractVulnbankErrorMessage(err, 'Vulnbank request failed');
        res.redirect('/profile?wallet_error=' + encodeURIComponent(msg));
    }
});

router.get('/cart', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId = req.session.user.id;
    db.query(
        'SELECT c.*, p.name, p.price, p.deal_price, p.deal_label, p.deal_expires_at, p.image FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
        [userId],
        (err, items) => {
            if (err) return res.send('Database error');
            resolveDeals(items);
            items.forEach(i => {
                i.effective_price = i.deal_price != null ? parseFloat(i.deal_price) : parseFloat(i.price);
                i.subtotal = i.quantity * i.effective_price;
            });
            const total = items.reduce((s, i) => s + i.subtotal, 0);
            res.render('cart', { user: req.session.user, items, total: total.toFixed(2) });
        }
    );
});

router.post('/cart/add', cartLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { product_id, quantity } = req.body;
    db.query(
        'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?',
        [req.session.user.id, product_id, quantity || 1, quantity || 1],
        (err) => {
            if (err) return res.send('Error adding to cart');
            res.redirect('/cart');
        }
    );
});

router.post('/cart/remove/:id', cartLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    db.query('DELETE FROM cart_items WHERE id = ?', [req.params.id], () => res.redirect('/cart'));
});

router.post('/cart/update', cartLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { item_id, quantity } = req.body;
    const qty = parseInt(quantity);
    if (isNaN(qty) || qty < 1) {

        db.query('DELETE FROM cart_items WHERE id = ? AND user_id = ?',
            [item_id, req.session.user.id], () => res.redirect('/cart'));
    } else {
        db.query('UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?',
            [qty, item_id, req.session.user.id], () => res.redirect('/cart'));
    }
});

router.post('/apply-coupon', couponLimiter, (req, res) => {
    const { code, cart_total } = req.body;
    if (!code) return res.json({ valid: false, message: 'Enter a coupon code' });
    if (!req.session.user) return res.json({ valid: false, message: 'Please log in to use a coupon' });

    const userId = req.session.user.id;

    db.query(
        'SELECT * FROM coupons WHERE code = ? AND is_active = TRUE',
        [code.trim().toUpperCase()],
        (err, coupons) => {
            if (err || !coupons.length) return res.json({ valid: false, message: 'Invalid or expired coupon' });
            const coupon = coupons[0];


            if (coupon.max_total_uses !== null && coupon.total_used >= coupon.max_total_uses) {
                return res.json({ valid: false, message: 'This coupon has reached its maximum usage limit' });
            }




            db.query(
                'SELECT COUNT(*) AS cnt FROM coupon_uses WHERE coupon_id = ? AND user_id = ?',
                [coupon.id, userId],
                (err2, rows) => {
                    if (err2) return res.json({ valid: false, message: 'Database error' });
                    const usedCount = rows[0].cnt;
                    const maxPerUser = coupon.max_uses_per_user || 1;

                    if (usedCount >= maxPerUser) {
                        return res.json({ valid: false, message: `You have already used this coupon (limit: ${maxPerUser} per user)` });
                    }





                    if (coupon.allowed_category) {
                        db.query(
                            `SELECT ci.* FROM cart_items ci
                             JOIN products p ON ci.product_id = p.id
                             WHERE ci.user_id = ? AND p.category = ?`,
                            [userId, coupon.allowed_category],
                            (err3, matchingItems) => {
                                if (err3 || !matchingItems.length) {
                                    return res.json({
                                        valid:   false,
                                        message: `This coupon is only valid for ${coupon.allowed_category} products`
                                    });
                                }

                                applyDiscount(coupon, cart_total, userId, code, req, res);
                            }
                        );
                    } else {

                        applyDiscount(coupon, cart_total, userId, code, req, res);
                    }
                }
            );
        }
    );
});

function applyDiscount(coupon, cart_total, userId, code, req, res) {
    const original = parseFloat(cart_total);
    const discount = (original * coupon.discount_percent) / 100;
    const newTotal = Math.max(0, original - discount).toFixed(2);
    auditLog(userId, 'COUPON_APPLIED',
        `code: ${code.trim().toUpperCase()} | discount: ${coupon.discount_percent}% | user_id: ${userId}`, req);
    res.json({
        valid:             true,
        discount_percent:  coupon.discount_percent,
        discount_amount:   discount.toFixed(2),
        new_total:         newTotal,
        allowed_category:  coupon.allowed_category || null,
        message:           `${coupon.discount_percent}% discount applied!${coupon.allowed_category ? ' (valid for ' + coupon.allowed_category + ' items)' : ''}`
    });
}

router.get('/checkout', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const userId = req.session.user.id;

    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, users) => {
        if (!err && users.length) req.session.user = users[0];
        const savedAddress = req.session.user.default_shipping_address || '';
        const savedZone    = req.session.user.default_zone || 'others';
        const zone         = savedZone;

        db.query(
            'SELECT c.*, p.name, p.price, p.deal_price, p.deal_label, p.category, COALESCE(p.deal_price, p.price) AS effective_price, (c.quantity * COALESCE(p.deal_price, p.price)) AS subtotal FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
            [userId],
            (err, items) => {
                if (err) return res.send('Database error');
                const itemsTotal   = items.reduce((s, i) => s + parseFloat(i.subtotal), 0);
                const logisticsFee = items.length > 0 ? getZoneFee(zone) : 0;
                let totalCommission = 0, totalVat = 0;
                items.forEach(item => {
                    const rate = getCommissionRate(item.category);
                    const comm = parseFloat(item.subtotal) * rate;
                    totalCommission += comm;
                    totalVat        += comm * VAT_ON_COMMISSION;
                });
                const grandTotal = itemsTotal + logisticsFee;
                res.render('checkout', {
                    user: req.session.user,
                    items,
                    total:          itemsTotal.toFixed(2),
                    logisticsFee:   logisticsFee.toFixed(2),
                    commission:     totalCommission.toFixed(2),
                    vatAmt:         totalVat.toFixed(2),
                    grandTotal:     grandTotal.toFixed(2),
                    zone,
                    savedAddress,
                    savedZone,
                    pickupStores:   PICKUP_STORES,
                    platformFee:    totalCommission.toFixed(2),
                    shipping:       logisticsFee,
                    checkoutError:  null,
                    selectedPaymentMethod: 'wallet',
                    vulnbankEnabled: isVulnbankConfigured()
                });
            }
        );
    });
});

router.post('/checkout', checkoutLimiter, (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { shipping_address } = req.body;
    const userId = req.session.user.id;
    const zone   = String(req.body.delivery_zone || 'others').toLowerCase();
    const paymentMethod = String(req.body.payment_method || 'wallet').toLowerCase() === 'vulnbank_card'
        ? 'vulnbank_card'
        : 'wallet';

    const vbCardNumber = String(req.body.vb_card_number || '').trim();
    const vbCardExpiry = String(req.body.vb_card_expiry || '').trim();
    const vbCardCvv = String(req.body.vb_card_cvv || '').trim();
    const vbCardName = String(req.body.vb_card_name || req.session.user.username || '').trim();










    let coupon_code = req.body.coupon_code;
    if (Array.isArray(coupon_code)) {


        auditLog(userId, 'HPP_DETECTED', `coupon_code parameter pollution detected`, req);
        coupon_code = null;
    }

    db.query(
        'SELECT c.*, p.price, p.deal_price, p.category, p.seller_id, COALESCE(p.deal_price, p.price) AS effective_price FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
        [userId],
        async (err, items) => {
            if (err) return res.send('Database error');
            const itemsTotal   = items.reduce((s, i) => s + (i.quantity * parseFloat(i.effective_price)), 0);
            const logisticsFee = items.length > 0 ? getZoneFee(zone) : 0;
            const baseTotal    = itemsTotal + logisticsFee;   /* grand total charged to buyer */

            const renderCheckoutError = (total, walletBalance, message) => {
                db.query(
                    'SELECT c.*, p.name, p.price, p.deal_price, p.category, COALESCE(p.deal_price, p.price) AS effective_price, (c.quantity * COALESCE(p.deal_price, p.price)) AS subtotal FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
                    [userId],
                    (err2, fullItems) => {
                        const list = fullItems || [];
                        const lFee = list.length > 0 ? getZoneFee(zone) : 0;
                        let tComm = 0, tVat = 0;
                        list.forEach(item => {
                            const r = getCommissionRate(item.category);
                            const c = parseFloat(item.subtotal) * r;
                            tComm += c; tVat += c * VAT_ON_COMMISSION;
                        });
                        res.render('checkout', {
                            user: { ...req.session.user, wallet_amount: walletBalance },
                            items: list,
                            total:        (total - lFee).toFixed(2),
                            logisticsFee: lFee.toFixed(2),
                            commission:   tComm.toFixed(2),
                            vatAmt:       tVat.toFixed(2),
                            grandTotal:   total.toFixed(2),
                            zone,
                            savedAddress:  req.session.user.default_shipping_address || '',
                            savedZone:     req.session.user.default_zone || 'others',
                            pickupStores:  PICKUP_STORES,
                            platformFee:  tComm.toFixed(2),
                            shipping:     lFee,
                            checkoutError: message,
                            selectedPaymentMethod: paymentMethod,
                            vulnbankEnabled: isVulnbankConfigured()
                        });
                    }
                );
            };

            const finalizeOrder = (total, usedCoupon, discountAmt, paymentSummary, deductWallet) => {
                /* Pre-compute commission + VAT for this order */
                let totalCommission = 0, totalVat = 0;
                items.forEach(item => {
                    const rate = getCommissionRate(item.category);
                    const comm = (item.quantity * parseFloat(item.effective_price)) * rate;
                    totalCommission += comm;
                    totalVat        += comm * VAT_ON_COMMISSION;
                });
                const lFee = logisticsFee;

                db.query(
                    'INSERT INTO orders (user_id, total_amount, shipping_address, coupon_code, discount_amount, delivery_zone, logistics_fee, commission_amt, vat_amt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    [userId, total, shipping_address, usedCoupon, discountAmt, zone,
                     lFee.toFixed(2), totalCommission.toFixed(2), totalVat.toFixed(2)],
                    (insertErr, result) => {
                        if (insertErr) return res.send('Error creating order');
                        const orderId = result.insertId;

                        db.query(
                            'INSERT INTO tracking_events (order_id, status, note) VALUES (?, ?, ?)',
                            [orderId, 'pending', 'Order placed successfully (' + paymentSummary + ')']
                        );

                        let itemsInserted = 0;
                        const totalItems = items.length;

                        const creditSellerPending = () => {
                            /* Credit seller's pending_balance (held until delivery).
                               seller_earnings row is written at delivery time only - not here. */
                            const sellerTotals = {};
                            items.forEach(item => {
                                const sid   = item.seller_id;
                                const gross = item.quantity * parseFloat(item.effective_price);
                                const rate  = getCommissionRate(item.category);
                                const comm  = gross * rate;
                                const vat   = comm * VAT_ON_COMMISSION;
                                const net   = gross - comm - vat;
                                if (!sellerTotals[sid]) sellerTotals[sid] = 0;
                                sellerTotals[sid] += net;
                            });
                            Object.keys(sellerTotals).forEach(sellerId => {
                                db.query(
                                    'UPDATE users SET pending_balance = pending_balance + ? WHERE id = ?',
                                    [sellerTotals[sellerId].toFixed(2), sellerId]
                                );
                            });
                        };

                        const finish = () => {
                            creditSellerPending();

                            const afterPayment = () => {
                                db.query('DELETE FROM cart_items WHERE user_id = ?', [userId]);
                                db.query('SELECT * FROM users WHERE id = ?', [userId], (err2, updated) => {
                                    if (!err2 && updated.length) req.session.user = updated[0];
                                    auditLog(userId, 'ORDER_PLACED',
                                        `order_id: ${orderId} | amount: ${total.toFixed(2)} | zone: ${zone} | logistics: ${lFee} | coupon: ${usedCoupon || 'none'} | payment: ${paymentSummary}`,
                                        req);

                                    if (usedCoupon) {
                                        db.query(
                                            'SELECT id FROM coupons WHERE code = ?',
                                            [usedCoupon],
                                            (ce, cr) => {
                                                if (!ce && cr.length) {
                                                    db.query(
                                                        'INSERT INTO coupon_uses (coupon_id, user_id, order_id) VALUES (?, ?, ?)',
                                                        [cr[0].id, userId, orderId]
                                                    );
                                                    db.query(
                                                        'UPDATE coupons SET total_used = total_used + 1 WHERE id = ?',
                                                        [cr[0].id]
                                                    );
                                                }
                                            }
                                        );
                                    }
                                    res.redirect('/order/' + orderId);
                                });
                            };

                            if (!deductWallet) return afterPayment();

                            db.query('UPDATE users SET wallet_amount = wallet_amount - ? WHERE id = ?', [total, userId], (walletErr) => {
                                if (walletErr) return res.send('Error updating wallet');
                                afterPayment();
                            });
                        };

                        if (totalItems === 0) return finish();

                        items.forEach((item) => {
                            db.query(
                                'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                                [orderId, item.product_id, item.quantity, item.effective_price],
                                () => {
                                    db.query(
                                        'UPDATE products SET stock = stock - ? WHERE id = ?',
                                        [item.quantity, item.product_id]
                                    );
                                    itemsInserted++;
                                    if (itemsInserted === totalItems) finish();
                                }
                            );
                        });
                    }
                );
            };

            const proceedWithTotal = async (total, usedCoupon = null, discountAmt = 0) => {
                db.query('SELECT wallet_amount FROM users WHERE id = ?', [userId], (err, rows) => {
                    if (err) return res.send('Database error');

                    const wallet = parseFloat(rows[0].wallet_amount || 0);
                    if (paymentMethod === 'wallet') {
                        if (wallet < total) {
                            return renderCheckoutError(total, wallet, 'Insufficient wallet balance.');
                        }
                        return finalizeOrder(total, usedCoupon, discountAmt, 'wallet', true);
                    }

                    if (!isVulnbankConfigured()) {
                        return renderCheckoutError(total, wallet, 'Vulnbank is not configured yet.');
                    }

                    if (!vbCardNumber || !vbCardExpiry || !vbCardCvv) {
                        return renderCheckoutError(total, wallet, 'Card number, expiry and CVV are required for Vulnbank payment.');
                    }

                    const reference = 'pwnshop_order_' + userId + '_' + Date.now();
                    const normalizedCardNumber = vbCardNumber.replace(/\s+/g, '');
                    const payload = {
                        amount: parseFloat(total.toFixed(2)),
                        currency: 'NGN',
                        merchant_order_id: reference,
                        description: 'Pwnshop checkout',
                        card_number: normalizedCardNumber,
                        cvv: vbCardCvv,
                        expiry_date: vbCardExpiry,
                        metadata: {
                            user_id: userId,
                            flow: 'checkout',
                            card_name: vbCardName
                        }
                    };

                    vulnbankRequest(VULNBANK_CHARGE_PATH, 'POST', payload)
                        .then(async (chargeResp) => {
                            const ref = VULNBANK_LAB_VULN
                                ? (getVulnbankReference(chargeResp) || reference)
                                : reference;
                            let verifyResp = chargeResp;

                            const verifyPath = buildVulnbankVerifyPath(ref);
                            if (verifyPath) {
                                try {
                                    verifyResp = await vulnbankRequest(verifyPath, 'GET');
                                } catch (_) {
                                    // fall through - use charge response as-is
                                }
                            }

                            const settled = isVulnbankSuccess(verifyResp);
                            const remoteAmount = getVulnbankAmount(verifyResp);
                            // VULNERABILITY (#3): remoteAmount === null bypasses amount check
                            const amountMatches = remoteAmount === null || Math.abs(remoteAmount - total) < 0.01;

                            if (!VULNBANK_LAB_VULN && (!settled || !amountMatches)) {
                                return renderCheckoutError(total, wallet, 'Vulnbank payment could not be verified as settled.');
                            }

                            // VULNERABILITY (replay): In strict mode we reject a reference
                            // that already finalised an order. In lab vuln mode that check
                            // is skipped - the same successful reference can be submitted
                            // for multiple orders.
                            const doFinalize = () => {
                                db.query(
                                    'INSERT INTO vulnbank_tx_log (user_id, reference, amount, flow) VALUES (?, ?, ?, ?)',
                                    [userId, ref, total, 'checkout'], () => {}
                                );
                                finalizeOrder(total, usedCoupon, discountAmt, 'vulnbank:' + ref, false);
                            };

                            if (!VULNBANK_LAB_VULN) {
                                db.query('SELECT id FROM vulnbank_tx_log WHERE reference = ?', [ref], (chkErr, existing) => {
                                    if (!chkErr && existing.length > 0) {
                                        return renderCheckoutError(total, wallet, 'Payment reference has already been used for another order.');
                                    }
                                    doFinalize();
                                });
                            } else {
                                // Lab vuln mode: no duplicate reference check
                                doFinalize();
                            }
                        })
                        .catch((e) => {
                            const msg = extractVulnbankErrorMessage(e, 'Vulnbank payment failed');
                            renderCheckoutError(total, wallet, msg);
                        });
                });
            };

            if (coupon_code && coupon_code.trim()) {
                db.query(
                    'SELECT * FROM coupons WHERE code = ? AND is_active = TRUE',
                    [coupon_code.trim().toUpperCase()],
                    (err, coupons) => {
                        if (!err && coupons.length) {
                            const d        = (baseTotal * coupons[0].discount_percent) / 100;
                            const newTotal = Math.max(0, baseTotal - d);
                            proceedWithTotal(newTotal, coupon_code.trim().toUpperCase(), parseFloat(d.toFixed(2)));
                        } else {
                            proceedWithTotal(baseTotal, null, 0);
                        }
                    }
                );
            } else {
                proceedWithTotal(baseTotal);
            }
        }
    );
});

router.get('/seller/dashboard', (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/');
    const sellerId = req.session.user.id;

    db.query('SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC', [sellerId], (err, products) => {
        if (err) products = [];

        db.query(
            `SELECT se.*, o.created_at AS order_date, o.status AS order_status
             FROM seller_earnings se
             JOIN orders o ON se.order_id = o.id
             WHERE se.seller_id = ?
             ORDER BY se.created_at DESC LIMIT 50`,
            [sellerId],
            (err, earnings) => {
                if (err) earnings = [];

                const totalGross = earnings.reduce((s, e) => s + parseFloat(e.gross_amount || 0), 0);
                const totalFees  = earnings.reduce((s, e) => s + parseFloat(e.platform_fee || 0), 0);
                const totalNet   = earnings.reduce((s, e) => s + parseFloat(e.net_amount || 0), 0);

                db.query('SELECT wallet_amount, seller_wallet, pending_balance FROM users WHERE id = ?', [sellerId], (err, rows) => {
                    const row           = rows && rows[0] ? rows[0] : {};
                    const shopWallet    = parseFloat(row.wallet_amount   || 0);
                    const sellerWallet  = parseFloat(row.seller_wallet   || 0);
                    const pending       = parseFloat(row.pending_balance || 0);
                    res.render('seller-dashboard', {
                        user: req.session.user,
                        products,
                        earnings,
                        totalGross: totalGross.toFixed(2),
                        totalFees:  totalFees.toFixed(2),
                        totalNet:   totalNet.toFixed(2),
                        shopWallet:    shopWallet.toFixed(2),
                        sellerWallet:  sellerWallet.toFixed(2),
                        wallet:        sellerWallet.toFixed(2),   /* kept for withdrawal form max= */
                        pendingBalance: pending.toFixed(2),
                        platformFeePct: PLATFORM_FEE_PCT * 100,
                        shippingDeduction: SHIPPING_DEDUCTION,
                        withdrawSuccess: req.query.withdraw_success || null,
                        withdrawError:   req.query.withdraw_error   || null
                    });
                });
            }
        );
    });
});

router.post('/seller/withdraw', (req, res) => {
    if (!req.session.user || !req.session.user.isSeller) return res.redirect('/login');
    const sellerId = req.session.user.id;
    const amount   = parseFloat(req.body.amount);

    const redirectDash = (err, ok) => {
        const q = err ? `?withdraw_error=${encodeURIComponent(err)}` : `?withdraw_success=${encodeURIComponent(ok)}`;
        res.redirect('/seller/dashboard' + q);
    };

    if (isNaN(amount) || amount < 200)
        return redirectDash('Minimum transfer amount is ₦200.', null);

    db.query('SELECT seller_wallet FROM users WHERE id = ?', [sellerId], (err, rows) => {
        if (err || !rows.length) return redirectDash('Database error.', null);
        const balance = parseFloat(rows[0].seller_wallet || 0);
        if (balance < amount)
            return redirectDash(`Insufficient earnings balance. Available: ₦${balance.toFixed(2)}.`, null);

        const net = parseFloat((amount - WITHDRAWAL_FEE).toFixed(2));
        if (net <= 0) return redirectDash('Amount too small after processing fee.', null);

        db.query(
            'UPDATE users SET seller_wallet = seller_wallet - ?, wallet_amount = wallet_amount + ? WHERE id = ? AND seller_wallet >= ?',
            [amount, net, sellerId, amount],
            (updErr, result) => {
                if (updErr || result.affectedRows === 0)
                    return redirectDash('Transfer failed — balance may have changed. Please retry.', null);

                req.session.user.wallet_amount = parseFloat(req.session.user.wallet_amount || 0) + net;
                auditLog(sellerId, 'SELLER_WALLET_TRANSFER',
                    `amount: ₦${amount} | fee: ₦${WITHDRAWAL_FEE} | net credited to shopping wallet: ₦${net}`, req);
                redirectDash(null, `₦${net.toLocaleString('en-NG', {minimumFractionDigits:2})} has been added to your shopping wallet.`);
            }
        );
    });
});

/* ── Shared delivery earnings helper ────────────────────────────────────── */
function creditDeliveredOrder(order_id, cb) {
    db.query(
        `SELECT oi.product_id, oi.quantity, oi.price, p.seller_id, p.category
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         WHERE oi.order_id = ?`,
        [order_id],
        (err, items) => {
            if (err || !items.length) return cb && cb();
            const sellerNet = {};
            items.forEach(item => {
                const sid   = item.seller_id;
                const gross = parseFloat(item.price) * item.quantity;
                const rate  = getCommissionRate(item.category);
                const comm  = gross * rate;
                const vat   = comm * VAT_ON_COMMISSION;
                const net   = parseFloat((gross - comm - vat).toFixed(2));
                if (!sellerNet[sid]) sellerNet[sid] = { gross: 0, comm: 0, vat: 0, net: 0 };
                sellerNet[sid].gross += gross;
                sellerNet[sid].comm  += comm;
                sellerNet[sid].vat   += vat;
                sellerNet[sid].net   += net;
            });
            const sellerIds = Object.keys(sellerNet);
            let done = 0;
            sellerIds.forEach(sellerId => {
                const s = sellerNet[sellerId];
                db.query(
                    `INSERT INTO seller_earnings (seller_id, order_id, gross_amount, platform_fee, shipping_deduction, net_amount, vat_amount)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [sellerId, order_id, s.gross.toFixed(2), s.comm.toFixed(2), '0.00', s.net.toFixed(2), s.vat.toFixed(2)],
                    (insertErr) => {
                        if (insertErr) console.error('[earnings] INSERT failed', sellerId, insertErr.message);
                        db.query(
                            `UPDATE users
                             SET seller_wallet   = seller_wallet   + ?,
                                 pending_balance = GREATEST(0, pending_balance - ?)
                             WHERE id = ?`,
                            [s.net.toFixed(2), s.net.toFixed(2), sellerId],
                            () => { if (++done === sellerIds.length && cb) cb(); }
                        );
                    }
                );
            });
            if (!sellerIds.length && cb) cb();
        }
    );
}

/* ── Auto-progression background job ────────────────────────────────────── */
/* Timing (from order created_at):
     30s  → processing
     90s  → shipped
     3min → delivered                                                         */
function autoProgressOrders() {
    /* pending → processing */
    db.query(
        `SELECT id FROM orders WHERE status='pending' AND created_at <= DATE_SUB(NOW(), INTERVAL 30 SECOND)`,
        (err, rows) => {
            if (err || !rows.length) return;
            rows.forEach(({ id }) => {
                db.query(`UPDATE orders SET status='processing' WHERE id=?`, [id]);
                db.query(
                    `INSERT INTO tracking_events (order_id, status, note) VALUES (?, 'processing', 'Order confirmed and being prepared by seller')`,
                    [id]
                );
            });
        }
    );

    /* processing → shipped */
    db.query(
        `SELECT id FROM orders WHERE status='processing' AND created_at <= DATE_SUB(NOW(), INTERVAL 90 SECOND)`,
        (err, rows) => {
            if (err || !rows.length) return;
            rows.forEach(({ id }) => {
                db.query(`UPDATE orders SET status='shipped' WHERE id=?`, [id]);
                db.query(
                    `INSERT INTO tracking_events (order_id, status, note) VALUES (?, 'shipped', 'Order dispatched and on its way to you')`,
                    [id]
                );
            });
        }
    );

    /* shipped → delivered (3 min) */
    db.query(
        `SELECT id FROM orders WHERE status='shipped' AND created_at <= DATE_SUB(NOW(), INTERVAL 180 SECOND)`,
        (err, rows) => {
            if (err || !rows.length) return;
            rows.forEach(({ id }) => {
                db.query(`UPDATE orders SET status='delivered' WHERE id=?`, [id], (updErr) => {
                    if (updErr) return;
                    db.query(
                        `INSERT INTO tracking_events (order_id, status, note) VALUES (?, 'delivered', 'Order delivered successfully')`,
                        [id]
                    );
                    creditDeliveredOrder(id, () => {
                        console.log(`[auto] Order #${id} delivered - seller earnings credited`);
                    });
                });
            });
        }
    );
}

setInterval(autoProgressOrders, 30000);

router.get('/admin/orders', requireAdmin, (req, res) => {
    const search = req.query.search || '';
    let sql = 'SELECT * FROM orders ORDER BY created_at DESC LIMIT 100';
    let params = [];
    if (search) {
        sql = 'SELECT * FROM orders WHERE id LIKE ? OR user_id LIKE ? OR shipping_address LIKE ? ORDER BY created_at DESC LIMIT 100';
        params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }
    db.query(sql, params, (err, orders) => {
        if (err) return res.send('Database error');
        res.render('admin', {
            user: req.session.user,
            tab: 'orders',
            users: [], products: [], reviews: [],
            orders,
            success: req.query.success || null,
            error:   req.query.error   || null,
            auditLogs: [], coupons: [],
            search
        });
    });
});

router.get('/admin/stats', requireAdmin, (req, res) => {
    db.query('SELECT COUNT(*) AS cnt FROM users', (err, u) => {
        db.query('SELECT COUNT(*) AS cnt FROM orders', (err, o) => {
            db.query('SELECT COUNT(*) AS cnt FROM products', (err, p) => {
                db.query(
                    'SELECT SUM(commission_amt + logistics_fee) AS revenue, SUM(vat_amt) AS vat FROM orders WHERE status="delivered"',
                    (err, r) => {
                    db.query('SELECT COUNT(*) AS cnt FROM orders WHERE status="pending"', (err, pending) => {
                        db.query('SELECT COUNT(*) AS cnt FROM users WHERE isSeller=TRUE', (err, sellers) => {
                            db.query('SELECT COUNT(*) AS cnt FROM products WHERE available=TRUE', (err, active) => {
                                db.query(
                                    `SELECT o.id, o.total_amount, o.commission_amt, o.vat_amt, o.logistics_fee,
                                            o.discount_amount, o.coupon_code, o.status, o.created_at,
                                            u.username AS buyer
                                     FROM orders o
                                     JOIN users u ON o.user_id = u.id
                                     WHERE o.total_amount > 0
                                     ORDER BY o.created_at DESC LIMIT 50`,
                                    (err, recentOrders) => {
                                        const row = r && r[0] ? r[0] : {};
                                        res.render('admin', {
                                            user: req.session.user,
                                            tab: 'stats',
                                            stats: {
                                                users:        u && u[0] ? u[0].cnt : 0,
                                                orders:       o && o[0] ? o[0].cnt : 0,
                                                products:     p && p[0] ? p[0].cnt : 0,
                                                revenue:      parseFloat(row.revenue || 0).toFixed(0),
                                                vatCollected: parseFloat(row.vat     || 0).toFixed(0),
                                                pending:      pending && pending[0] ? pending[0].cnt : 0,
                                                sellers:      sellers && sellers[0] ? sellers[0].cnt : 0,
                                                active:       active  && active[0]  ? active[0].cnt  : 0
                                            },
                                            recentOrders: recentOrders || [],
                                            users: [], orders: [], products: [], reviews: [],
                                            auditLogs: [],
                                            success: null, error: null, search: ''
                                        });
                                    }
                                );
                            });
                        });
                    });
                });
            });
        });
    });
});

router.get('/admin/export-orders', requireAdmin, (req, res) => {
    db.query(
        `SELECT o.id, u.username, u.email, o.total_amount, o.status, o.shipping_address, o.created_at
         FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`,
        (err, orders) => {
            if (err) return res.send('Database error');


            let csv = 'Order ID,Username,Email,Amount,Status,Shipping Address,Date\n';
            orders.forEach(o => {

                const row = [
                    o.id,
                    o.username,
                    o.email,
                    o.total_amount,
                    o.status,
                    `"${(o.shipping_address || '').replace(/"/g, '""')}"`,
                    new Date(o.created_at).toISOString()
                ].join(',');
                csv += row + '\n';
            });

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename="pwnshop-orders.csv"');
            res.send(csv);
        }
    );
});

router.post('/admin/update-order-status', requireAdmin, (req, res) => {
    const { order_id, status, tracking_note } = req.body;
    if (!['pending','processing','shipped','delivered','cancelled'].includes(status)) return res.redirect('/admin/orders?error=Invalid status');


    db.query('SELECT status FROM orders WHERE id = ?', [order_id], (err, rows) => {
        if (err || !rows.length) return res.redirect('/admin/orders?error=Order not found');
        const previousStatus = rows[0].status;

        db.query('UPDATE orders SET status = ? WHERE id = ?', [status, order_id], (err) => {
            if (err) return res.redirect('/admin/orders?error=Database error');


            const defaultNotes = {
                pending:    'Order is pending confirmation',
                processing: 'Order is being prepared',
                shipped:    'Order has been shipped',
                delivered:  'Order delivered successfully',
                cancelled:  'Order has been cancelled'
            };
            const note = (tracking_note && tracking_note.trim())
                ? tracking_note.trim()
                : (defaultNotes[status] || status);
            db.query(
                'INSERT INTO tracking_events (order_id, status, note) VALUES (?, ?, ?)',
                [order_id, status, note]
            );


            if (status === 'delivered' && previousStatus !== 'delivered') {
                creditDeliveredOrder(order_id, () => {
                    auditLog(req.session.user.id, 'ORDER_DELIVERED',
                        `order_id: ${order_id} | manual admin delivery`, req);
                    res.redirect('/admin/orders?success=Order delivered - seller earnings credited');
                });
            } else {
                auditLog(req.session.user.id, 'ORDER_STATUS_CHANGED',
                    `order_id: ${order_id} | ${previousStatus} → ${status}`, req);
                res.redirect('/admin/orders?success=Order status updated');
            }
        });
    });
});

router.post('/admin/topup-wallet', requireAdmin, (req, res) => {
    const parsed = parseFloat(req.body.amount);
    if (isNaN(parsed) || parsed <= 0) return res.redirect('/admin/users?error=Invalid amount');
    db.query('UPDATE users SET wallet_amount = wallet_amount + ? WHERE id = ?', [parsed, req.body.user_id], (err) => {
        if (err) return res.redirect('/admin/users?error=Database error');
        auditLog(req.session.user.id, 'WALLET_TOPUP',
            `admin: ${req.session.user.username} | target_user_id: ${req.body.user_id} | amount: ₦${parsed.toFixed(2)}`, req);
        res.redirect('/admin/users?success=Shopping wallet topped up - added ₦' + parsed.toFixed(2));
    });
});

router.post('/admin/topup-seller-wallet', requireAdmin, (req, res) => {
    const parsed = parseFloat(req.body.amount);
    const reason = String(req.body.reason || '').trim();
    if (isNaN(parsed) || parsed <= 0) return res.redirect('/admin/users?error=Invalid amount');
    if (!reason) return res.redirect('/admin/users?error=Reason is required for seller wallet credit');
    db.query('SELECT isSeller, username FROM users WHERE id = ?', [req.body.user_id], (err, rows) => {
        if (err || !rows.length) return res.redirect('/admin/users?error=User not found');
        if (!rows[0].isSeller) return res.redirect('/admin/users?error=User is not a seller');
        db.query('UPDATE users SET seller_wallet = seller_wallet + ? WHERE id = ?', [parsed, req.body.user_id], (err2) => {
            if (err2) return res.redirect('/admin/users?error=Database error');
            auditLog(req.session.user.id, 'SELLER_WALLET_CREDIT',
                `admin: ${req.session.user.username} | target_user_id: ${req.body.user_id} | seller: ${rows[0].username} | amount: ₦${parsed.toFixed(2)} | reason: ${reason}`, req);
            res.redirect('/admin/users?success=Seller earnings wallet credited - added ₦' + parsed.toFixed(2) + ' to ' + rows[0].username);
        });
    });
});

router.get('/invoice', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const order = req.query.order;
    if (!order) return res.redirect('/profile');

    const fs = require('fs');





    if (order.startsWith('..')) {
        return res.render('invoice', {
            user: req.session.user,
            orderId: order,
            order: null,
            items: [],
            fileContent: null,
            filePath: null
        });
    }

    const isNumeric = /^\d+$/.test(order);
    const baseDir   = path.join(__dirname, '../../../public', 'invoices');
    const filePath  = isNumeric
        ? path.join(baseDir, order + '.txt')
        : path.join(baseDir, order);

    db.query(
        `SELECT o.*, u.username, u.email, u.phone
         FROM orders o
         JOIN users u ON o.user_id = u.id
         WHERE o.id = ? AND o.user_id = ?`,
        [order, req.session.user.id],
        (err, orders) => {
            if (!err && orders.length) {
                const o = orders[0];
                db.query(
                    'SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
                    [o.id],
                    (err2, items) => {
                        if (err2) items = [];
                        auditLog(req.session.user.id, 'INVOICE_DOWNLOADED', `order_id: ${o.id}`, req);
                        res.render('invoice', {
                            user: req.session.user,
                            orderId: order,
                            order: o,
                            items,
                            fileContent: null,
                            filePath: null
                        });
                    }
                );
            } else {
                fs.readFile(filePath, 'utf8', (ferr, data) => {
                    auditLog(req.session.user.id, 'INVOICE_FILE_READ',
                        `order: ${order} | path: ${filePath} | found: ${!ferr}`, req);
                    res.render('invoice', {
                        user: req.session.user,
                        orderId: order,
                        order: null,
                        items: [],
                        fileContent: ferr ? null : data,
                        filePath: null
                    });
                });
            }
        }
    );
});

router.get('/admin/coupons', requireAdmin, (req, res) => {
    db.query(
        `SELECT c.*,
            (SELECT COUNT(DISTINCT user_id) FROM coupon_uses WHERE coupon_id = c.id) AS unique_users
         FROM coupons c ORDER BY c.id DESC`,
        (err, coupons) => {
            if (err) coupons = [];
            res.render('admin', {
                user:      req.session.user,
                tab:       'coupons',
                users:     [], orders: [], products: [], reviews: [],
                auditLogs: [], coupons,
                search:    '',
                success:   req.query.success || null,
                error:     req.query.error   || null
            });
        }
    );
});

router.post('/admin/coupons/create', requireAdmin, (req, res) => {
    const { code, discount_percent, max_uses_per_user, max_total_uses, allowed_category } = req.body;
    if (!code || !discount_percent) return res.redirect('/admin/coupons?error=Code and discount are required');

    const cat = allowed_category && allowed_category.trim() ? allowed_category.trim().toLowerCase() : null;
    const maxTotal = max_total_uses && parseInt(max_total_uses) > 0 ? parseInt(max_total_uses) : null;
    const maxPer   = max_uses_per_user && parseInt(max_uses_per_user) > 0 ? parseInt(max_uses_per_user) : 1;

    db.query(
        `INSERT INTO coupons (code, discount_percent, is_active, max_uses_per_user, max_total_uses, allowed_category, total_used)
         VALUES (?, ?, TRUE, ?, ?, ?, 0)`,
        [code.trim().toUpperCase(), parseInt(discount_percent), maxPer, maxTotal, cat],
        (err) => {
            if (err) return res.redirect('/admin/coupons?error=' + encodeURIComponent(err.sqlMessage || 'Failed to create coupon'));
            auditLog(req.session.user.id, 'COUPON_CREATED',
                `code: ${code.trim().toUpperCase()} | discount: ${discount_percent}% | max_per_user: ${maxPer} | max_total: ${maxTotal || 'unlimited'} | category: ${cat || 'all'}`, req);
            res.redirect('/admin/coupons?success=Coupon created');
        }
    );
});

router.post('/admin/coupons/toggle', requireAdmin, (req, res) => {
    const { coupon_id } = req.body;
    db.query(
        'UPDATE coupons SET is_active = NOT is_active WHERE id = ?',
        [coupon_id],
        (err) => {
            if (err) return res.redirect('/admin/coupons?error=Failed to update coupon');
            res.redirect('/admin/coupons?success=Coupon updated');
        }
    );
});

router.post('/admin/coupons/delete', requireAdmin, (req, res) => {
    const { coupon_id } = req.body;
    db.query('DELETE FROM coupon_uses WHERE coupon_id = ?', [coupon_id], () => {
        db.query('DELETE FROM coupons WHERE id = ?', [coupon_id], (err) => {
            if (err) return res.redirect('/admin/coupons?error=Failed to delete coupon');
            auditLog(req.session.user.id, 'COUPON_DELETED', `coupon_id: ${coupon_id}`, req);
            res.redirect('/admin/coupons?success=Coupon deleted');
        });
    });
});

// ── Deals management ─────────────────────────────────────────────────────────
router.get('/admin/deals', requireAdmin, (req, res) => {
    db.query(
        'SELECT p.*, u.username AS seller_username FROM products p JOIN users u ON p.seller_id = u.id ORDER BY p.deal_price IS NULL ASC, p.id DESC',
        (err, products) => {
            if (err) products = [];
            res.render('admin', {
                user: req.session.user, tab: 'deals',
                products, users: [], orders: [], reviews: [], auditLogs: [], coupons: [],
                success: req.query.success || null, error: req.query.error || null, search: ''
            });
        }
    );
});

router.post('/admin/deals/set', requireAdmin, (req, res) => {
    const { product_id, deal_price, deal_label, deal_expires_at } = req.body;
    const price = parseFloat(deal_price);
    if (isNaN(price) || price <= 0) return res.redirect('/admin/deals?error=Invalid deal price');
    const expires = deal_expires_at || null;
    db.query(
        'UPDATE products SET deal_price = ?, deal_label = ?, deal_expires_at = ? WHERE id = ?',
        [price, (deal_label || 'Sale').trim(), expires, product_id],
        (err) => {
            if (err) return res.redirect('/admin/deals?error=Database error');
            auditLog(req.session.user.id, 'DEAL_SET', `product_id: ${product_id} | price: ${price} | label: ${deal_label} | expires: ${expires}`, req);
            res.redirect('/admin/deals?success=Deal saved');
        }
    );
});

router.post('/admin/deals/remove', requireAdmin, (req, res) => {
    const { product_id } = req.body;
    db.query('UPDATE products SET deal_price = NULL, deal_label = NULL WHERE id = ?', [product_id], (err) => {
        if (err) return res.redirect('/admin/deals?error=Database error');
        auditLog(req.session.user.id, 'DEAL_REMOVED', `product_id: ${product_id}`, req);
        res.redirect('/admin/deals?success=Deal removed');
    });
});

module.exports = router;
