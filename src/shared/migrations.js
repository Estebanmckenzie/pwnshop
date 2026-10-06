/* Migraciones/tablas que la app crea al arrancar (movido tal cual desde src/app.js). */

const { db } = require('./db');

/* Safe migration helper for MySQL 5.7 - ignores error 1060 (duplicate column) */
function addCol(sql) { db.query(sql, (e) => { if (e && e.errno !== 1060) console.error('[migration]', e.message); }); }

/* New business logic columns */
addCol("ALTER TABLE users          ADD COLUMN pending_balance DECIMAL(12,2) DEFAULT 0");
addCol("ALTER TABLE users          ADD COLUMN referral_code   VARCHAR(16)   DEFAULT NULL");
addCol("ALTER TABLE orders         ADD COLUMN delivery_zone   VARCHAR(20)   DEFAULT 'others'");
addCol("ALTER TABLE orders         ADD COLUMN logistics_fee   DECIMAL(10,2) DEFAULT 0");
addCol("ALTER TABLE orders         ADD COLUMN commission_amt  DECIMAL(10,2) DEFAULT 0");
addCol("ALTER TABLE orders         ADD COLUMN vat_amt         DECIMAL(10,2) DEFAULT 0");
addCol("ALTER TABLE seller_earnings ADD COLUMN vat_amount              DECIMAL(10,2) DEFAULT 0");
addCol("ALTER TABLE users          ADD COLUMN default_shipping_address TEXT          DEFAULT NULL");
addCol("ALTER TABLE users          ADD COLUMN default_zone             VARCHAR(20)   DEFAULT 'others'");
addCol("ALTER TABLE users          ADD COLUMN seller_wallet            DECIMAL(12,2) DEFAULT 0");
/* Seed referral codes for existing users that don't have one */
db.query("UPDATE users SET referral_code = CONCAT('PWN', UPPER(SUBSTRING(MD5(id), 1, 8))) WHERE referral_code IS NULL", () => {});

addCol("ALTER TABLE coupons ADD COLUMN max_uses_per_user INT DEFAULT 1");
addCol("ALTER TABLE coupons ADD COLUMN max_total_uses    INT DEFAULT NULL");
addCol("ALTER TABLE coupons ADD COLUMN allowed_category  VARCHAR(50) DEFAULT NULL");
addCol("ALTER TABLE coupons ADD COLUMN total_used        INT DEFAULT 0");
addCol("ALTER TABLE products ADD COLUMN deal_price      DECIMAL(10,2) DEFAULT NULL");
addCol("ALTER TABLE products ADD COLUMN deal_label      VARCHAR(100)  DEFAULT NULL");
addCol("ALTER TABLE products ADD COLUMN deal_expires_at DATE          DEFAULT NULL");

db.query(`CREATE TABLE IF NOT EXISTS coupon_uses (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    coupon_id  INT NOT NULL,
    user_id    INT NOT NULL,
    order_id   INT DEFAULT NULL,
    used_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, () => {});

// Tracks Vulnbank payment references - used to prevent replay attacks in strict mode
db.query(`CREATE TABLE IF NOT EXISTS vulnbank_tx_log (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    reference  VARCHAR(255) NOT NULL,
    amount     DECIMAL(12,2) NOT NULL,
    flow       VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, () => {});
