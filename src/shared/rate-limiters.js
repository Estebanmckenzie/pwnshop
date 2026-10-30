/* createRateLimiter() y todas las instancias de rate limiters (movido tal cual desde src/app.js). */

// Rate limiter factory - hybrid IP + user ID
const rateLimitMaps = new Map();

function createRateLimiter(maxRequests, windowMs = 60 * 1000) {
    const store = new Map();

    // Clean up expired entries every 5 mins
    setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of store.entries()) {
            if (now - entry.windowStart > windowMs) store.delete(key);
        }
    }, 5 * 60 * 1000);

    return function rateLimiter(req, res, next) {
        // Hybrid key: use user ID if logged in, otherwise IP
        const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
        const key = req.session && req.session.user ? `user:${req.session.user.id}` : `ip:${ip}`;
        const now = Date.now();

        if (!store.has(key)) {
            store.set(key, { count: 1, windowStart: now });
            return next();
        }

        const entry = store.get(key);

        if (now - entry.windowStart > windowMs) {
            entry.count = 1;
            entry.windowStart = now;
            return next();
        }

        entry.count++;
        if (entry.count > maxRequests) {
            const retryAfter = Math.ceil((windowMs - (now - entry.windowStart)) / 1000);
            if (req.xhr || req.headers.accept?.includes('application/json')) {
                return res.status(429).json({ error: 'Too many requests', retryAfter });
            }
            return res.status(429).send(`<h2>Too many requests. Please wait ${retryAfter} seconds.</h2>`);
        }

        next();
    };
}

// Rate limiter instances
const globalGetLimiter      = createRateLimiter(60);
const adminLoginLimiter     = createRateLimiter(10);
const loginLimiter          = createRateLimiter(30);
const registerLimiter       = createRateLimiter(10);
const checkoutLimiter       = createRateLimiter(20);
const searchLimiter         = createRateLimiter(30);
const addProductLimiter     = createRateLimiter(10);
const reviewLimiter         = createRateLimiter(10);
const avatarLimiter         = createRateLimiter(10);
const forgotPasswordLimiter = createRateLimiter(10);
const resetPasswordLimiter  = createRateLimiter(10);
const otpLimiter            = createRateLimiter(10);
const wishlistLimiter       = createRateLimiter(30);
const cartLimiter           = createRateLimiter(50);
const couponLimiter         = createRateLimiter(20);
const trackLimiter          = createRateLimiter(20);
const sellerPreviewLimiter  = createRateLimiter(15);
const registerSellerLimiter = createRateLimiter(5);
const accountDeleteLimiter  = createRateLimiter(5);
const mailReadLimiter       = createRateLimiter(30);

module.exports = { rateLimitMaps, globalGetLimiter, adminLoginLimiter, loginLimiter, registerLimiter, checkoutLimiter, searchLimiter, addProductLimiter, reviewLimiter, avatarLimiter, forgotPasswordLimiter, resetPasswordLimiter, otpLimiter, wishlistLimiter, cartLimiter, couponLimiter, trackLimiter, sellerPreviewLimiter, registerSellerLimiter, accountDeleteLimiter, mailReadLimiter, createRateLimiter };
