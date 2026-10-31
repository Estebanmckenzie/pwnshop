/* Configuración Vulnbank (env vars). Usada por M2 (/profile), M3 y shared/vulnbank.js. */

const VULNBANK_BASE_URL = process.env.VULNBANK_BASE_URL || '';
const VULNBANK_MERCHANT_API_KEY = process.env.VULNBANK_MERCHANT_API_KEY || '';
const VULNBANK_MERCHANT_JWT = process.env.VULNBANK_MERCHANT_JWT || '';
const VULNBANK_AUTH_MODE = (process.env.VULNBANK_AUTH_MODE || 'api_key_header').toLowerCase();
const VULNBANK_CHARGE_PATH = process.env.VULNBANK_CHARGE_PATH || '/api/v1/payments/charge';
const VULNBANK_VERIFY_PATH = process.env.VULNBANK_VERIFY_PATH || '/api/v1/payments/{payment_id}';
const VULNBANK_TIMEOUT_MS = parseInt(process.env.VULNBANK_TIMEOUT_MS || '12000', 10);
const VULNBANK_LAB_VULN = process.env.VULNBANK_LAB_VULN === '1';
const VULNBANK_WEBHOOK_SECRET = process.env.VULNBANK_WEBHOOK_SECRET || '';

module.exports = { VULNBANK_BASE_URL, VULNBANK_MERCHANT_API_KEY, VULNBANK_MERCHANT_JWT, VULNBANK_AUTH_MODE, VULNBANK_CHARGE_PATH, VULNBANK_VERIFY_PATH, VULNBANK_TIMEOUT_MS, VULNBANK_LAB_VULN, VULNBANK_WEBHOOK_SECRET };
