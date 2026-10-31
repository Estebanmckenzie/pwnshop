/* Cliente Vulnbank (billetera externa). Usado por M2 (/profile) y M3 (wallet/checkout). */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { VULNBANK_BASE_URL, VULNBANK_MERCHANT_API_KEY, VULNBANK_MERCHANT_JWT, VULNBANK_AUTH_MODE, VULNBANK_VERIFY_PATH, VULNBANK_TIMEOUT_MS, VULNBANK_WEBHOOK_SECRET } = require('./config');

function isVulnbankConfigured() {
    const hasAuth = VULNBANK_AUTH_MODE === 'jwt'
        ? !!VULNBANK_MERCHANT_JWT
        : !!VULNBANK_MERCHANT_API_KEY;
    return !!(VULNBANK_BASE_URL && hasAuth);
}

function vulnbankUnwrap(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (payload.data && typeof payload.data === 'object') return payload.data;
    return payload;
}

function getVulnbankStatus(payload) {
    const flat = vulnbankUnwrap(payload);
    const inner = payload.payment || {};
    return String(
        flat.status || flat.payment_status ||
        inner.status || inner.payment_status ||
        payload.status || ''
    ).toLowerCase();
}

function getVulnbankReference(payload) {
    const flat = vulnbankUnwrap(payload);
    const inner = payload.payment || {};
    return flat.reference || flat.tx_ref || flat.transaction_reference || flat.id ||
           inner.id || inner.reference || inner.tx_ref || '';
}

function getVulnbankAmount(payload) {
    const flat = vulnbankUnwrap(payload);
    const inner = payload.payment || {};
    const candidates = [
        flat.amount, flat.amount_charged, flat.paid_amount, flat.value,
        payload.amount, payload.amount_charged,
        inner.amount, inner.amount_charged
    ];
    for (const c of candidates) {
        const n = parseFloat(c);
        if (!isNaN(n)) return n;
    }
    return null;
}

function extractVulnbankErrorMessage(err, fallback = 'Vulnbank request failed', maxLen = 220) {
    const payload = err && err.payload && typeof err.payload === 'object' ? err.payload : null;
    if (payload) {
        const candidates = [
            payload.message,
            payload.error,
            payload.detail,
            payload.reason,
            payload.error_message,
            payload.user_message,
            payload.debug_info && payload.debug_info.message,
            payload.debug_info && payload.debug_info.error
        ];

        const direct = candidates.find((v) => typeof v === 'string' && v.trim());
        if (direct) return direct.trim().slice(0, maxLen);

        if (Array.isArray(payload.errors) && payload.errors.length) {
            const first = payload.errors[0];
            if (typeof first === 'string' && first.trim()) return first.trim().slice(0, maxLen);
            if (first && typeof first === 'object') {
                const nested = [first.message, first.error, first.detail].find((v) => typeof v === 'string' && v.trim());
                if (nested) return nested.trim().slice(0, maxLen);
            }
        }
    }

    if (err && typeof err.message === 'string' && err.message.trim()) {
        return err.message.trim().slice(0, maxLen);
    }
    return fallback;
}

function isVulnbankSuccess(payload) {
    const status = getVulnbankStatus(payload);
    return ['success', 'succeeded', 'approved', 'completed', 'paid'].includes(status);
}

function normalizeVulnbankPath(relativePath) {
    if (!relativePath) return '/';
    if (relativePath.startsWith('/')) return relativePath;
    return '/' + relativePath;
}

function buildVulnbankVerifyPath(referenceOrId) {
    if (!VULNBANK_VERIFY_PATH) return null;
    if (!referenceOrId) return null;
    if (!(VULNBANK_VERIFY_PATH.includes('{reference}') || VULNBANK_VERIFY_PATH.includes('{payment_id}'))) {
        return null;
    }

    return VULNBANK_VERIFY_PATH
        .replace('{reference}', encodeURIComponent(referenceOrId))
        .replace('{payment_id}', encodeURIComponent(referenceOrId));
}

function verifyVulnbankSignature(rawBody, signatureHeader) {
    if (!VULNBANK_WEBHOOK_SECRET || !signatureHeader) return false;
    const expected = crypto.createHmac('sha256', VULNBANK_WEBHOOK_SECRET).update(rawBody).digest('hex');
    try {
        return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(signatureHeader)));
    } catch (_) {
        return false;
    }
}

function vulnbankRequest(relativePath, method = 'POST', payload = null) {
    return new Promise((resolve, reject) => {
        if (!isVulnbankConfigured()) {
            return reject(new Error('Vulnbank is not configured'));
        }

        let target;
        try {
            target = new URL(normalizeVulnbankPath(relativePath), VULNBANK_BASE_URL);
        } catch (_) {
            return reject(new Error('Invalid Vulnbank URL configuration'));
        }

        const body = payload ? JSON.stringify(payload) : null;
        const transport = target.protocol === 'http:' ? http : https;
        const options = {
            hostname: target.hostname,
            port: target.port || (target.protocol === 'http:' ? 80 : 443),
            path: target.pathname + target.search,
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (VULNBANK_AUTH_MODE === 'jwt') {
            options.headers['Authorization'] = 'Bearer ' + VULNBANK_MERCHANT_JWT;
        } else {
            options.headers['X-Merchant-Api-Key'] = VULNBANK_MERCHANT_API_KEY;
        }

        if (body) options.headers['Content-Length'] = Buffer.byteLength(body);

        const req = transport.request(options, (resp) => {
            let raw = '';
            resp.on('data', (chunk) => { raw += chunk; });
            resp.on('end', () => {
                let parsed = {};
                if (raw && raw.trim()) {
                    try {
                        parsed = JSON.parse(raw);
                    } catch (_) {
                        parsed = { raw };
                    }
                }

                if (!verifyVulnbankSignature(raw, resp.headers['x-vulnbank-signature'])) {
                    const sigErr = new Error('Vulnbank response signature invalid or missing');
                    sigErr.statusCode = 502;
                    return reject(sigErr);
                }

                if (resp.statusCode >= 200 && resp.statusCode < 300) {
                    return resolve(parsed);
                }
                const err = new Error('Vulnbank API error');
                err.statusCode = resp.statusCode;
                err.payload = parsed;
                reject(err);
            });
        });

        req.on('error', reject);
        req.setTimeout(VULNBANK_TIMEOUT_MS, () => {
            req.destroy(new Error('Vulnbank request timed out'));
        });

        if (body) req.write(body);
        req.end();
    });
}

module.exports = { isVulnbankConfigured, vulnbankUnwrap, getVulnbankStatus, getVulnbankReference, getVulnbankAmount, extractVulnbankErrorMessage, isVulnbankSuccess, normalizeVulnbankPath, buildVulnbankVerifyPath, vulnbankRequest };
