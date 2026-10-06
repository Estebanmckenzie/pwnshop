/* Pool MySQL compartido por todos los módulos (movido tal cual desde src/app.js). */

const mysql = require('mysql2');

const db = mysql.createPool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '3306', 10),
    user:     process.env.DB_USER     || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME     || 'pwnshop',
    waitForConnections: true,
    connectionLimit: parseInt(process.env.DB_POOL_LIMIT || '2', 10),
    queueLimit: 0
});

db.getConnection((err, conn) => {
    if (err) {
        console.error('Database pool init failed:', err.stack);
        return;
    }
    console.log('Connected to database pool.');
    conn.release();
});

module.exports = { db };
