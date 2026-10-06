/* Helpers usados por más de un módulo (movido tal cual desde src/app.js). */

function resolveDeals(products) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const list = Array.isArray(products) ? products : [products];
    list.forEach(p => {
        if (p && p.deal_expires_at && new Date(p.deal_expires_at) < today) {
            p.deal_price = null;
            p.deal_label = null;
        }
    });
    return products;
}

function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/admin/login');
    next();
}

module.exports = { resolveDeals, requireAdmin };
