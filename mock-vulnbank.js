/* Mock mínimo de Vulnbank, solo para pruebas locales de PWN-042 a PWN-045.
 * Simula las dos rutas que shared/vulnbank.js llama:
 *   POST /merchant/charges              (VULNBANK_CHARGE_PATH)
 *   GET  /merchant/charges/:reference   (VULNBANK_VERIFY_PATH)
 *
 * Comportamiento por defecto: aprueba cualquier cargo con el monto exacto
 * que se pidió, para que el flujo "normal" (sin ninguna vulnerabilidad)
 * también sea reproducible como línea base.
 *
 * Gatillo especial: si el monto cobrado es exactamente 0.45, la verificación
 * responde SIN campo de monto -> dispara PWN-045 (null amount fallback).
 *
 * Uso:
 *   node mock-vulnbank.js
 *   (escucha en http://localhost:4001)
 *
 * En tu .env, dentro del contenedor de Pwnshop, usa:
 *   VULNBANK_BASE_URL=http://host.docker.internal:4001
 *   (NO uses "localhost" ahi -- el contenedor tiene su propio localhost,
 *    distinto al de tu máquina. host.docker.internal es como Docker Desktop
 *    en Windows/Mac deja que un contenedor llame de vuelta al host.)
 */

const http = require('http');

const charges = {}; // reference -> { amount }

const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
        console.log(`[mock-vulnbank] ${req.method} ${req.url}`);

        // POST /merchant/charges
        if (req.method === 'POST' && req.url === '/merchant/charges') {
            let payload = {};
            try { payload = JSON.parse(body); } catch (_) {}
            const amount = parseFloat(payload.amount);
            const reference = payload.merchant_order_id || ('vb_' + Date.now());
            charges[reference] = { amount };
            console.log(`[mock-vulnbank] charge recorded: reference=${reference} amount=${amount}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                status: 'success',
                reference,
                amount,
            }));
        }

        // GET /merchant/charges/:reference
        if (req.method === 'GET' && req.url.startsWith('/merchant/charges/')) {
            const reference = decodeURIComponent(req.url.split('/merchant/charges/')[1]);
            const charge = charges[reference];

            if (!charge) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ status: 'not_found' }));
            }

            // Gatillo de PWN-045: monto 0.45 -> responder sin campo de monto
            if (charge.amount === 0.45) {
                console.log('[mock-vulnbank] trigger PWN-045: responding WITHOUT amount field');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ status: 'paid' })); // sin "amount"
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                status: 'paid',
                reference,
                amount: charge.amount,
            }));
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'not found' }));
    });
});

const PORT = 4001;
server.listen(PORT, () => {
    console.log(`[mock-vulnbank] escuchando en http://localhost:${PORT}`);
    console.log('[mock-vulnbank] desde el contenedor de Pwnshop, usa VULNBANK_BASE_URL=http://host.docker.internal:' + PORT);
});
