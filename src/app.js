require('dotenv').config();
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();

const { db } = require('./shared/db');
require('./shared/audit-core');   // ejecuta ensureAuditTable() al arrancar
require('./shared/migrations');   // migraciones al arrancar
const { globalGetLimiter } = require('./shared/rate-limiters');

const labRoutes = require('./modules/catalog/lab.routes');
const authRoutes = require('./modules/auth/auth.routes');
const usersRoutes = require('./modules/users/users.routes');
const operationsRoutes = require('./modules/operations/operations.routes');
const auditRoutes = require('./modules/audit/audit.routes');
const catalogRoutes = require('./modules/catalog/catalog.routes');
const chatbotRoutes = require('./modules/chatbot/chatbot.routes');


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'weak-secret-123',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, '../public')));
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

app.locals.fmtPrice = (v) =>
    parseFloat(v || 0).toLocaleString('en-NG', { minimumFractionDigits: 0, maximumFractionDigits: 0 });


app.use((req, res, next) => {
    res.locals.cartCount = 0;
    if (req.session.user) {
        db.query(
            'SELECT SUM(quantity) AS count FROM cart_items WHERE user_id = ?',
            [req.session.user.id],
            (err, rows) => {
                res.locals.cartCount = (!err && rows[0].count) ? parseInt(rows[0].count) : 0;
                next();
            }
        );
    } else {
        next();
    }
});


// Global GET rate limit - protects against directory fuzzing
app.use((req, res, next) => {
    if (req.method === 'GET') return globalGetLimiter(req, res, next);
    next();
});


// Routers por módulo (montados después de todos los middlewares globales, igual que las rutas originales)
app.use(labRoutes);
app.use(authRoutes);
app.use(usersRoutes);
app.use(operationsRoutes);
app.use(auditRoutes);
app.use(catalogRoutes);
app.use(chatbotRoutes);


app.use((req, res) => res.status(404).render('404', { user: req.session.user }));
app.use((err, req, res, next) => res.status(500).send(`<h1>Error occurred</h1><pre>${err.stack}</pre>`));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Pwnshop running → http://localhost:${PORT}`));
