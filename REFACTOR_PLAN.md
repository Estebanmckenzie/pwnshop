# REFACTOR_PLAN.md — Plan de separación de `src/app.js`

> ✅ **PLAN YA EJECUTADO. NO LO VUELVAS A APLICAR.** La separación se completó en
> la rama `refactor/module-separation` (septiembre 2026). `src/app.js` ya es solo
> el orquestador y el código vive en `src/modules/` y `src/shared/`. Este archivo
> queda como **registro histórico** del plan. Lo que realmente se hizo, incluidas
> las desviaciones del plan (lab en `catalog/lab.routes.js`, constantes de negocio
> en M3, `shared/migrations.js`, los dos ajustes de `__dirname`), está en
> `SEPARATION_RESULT.md`. Las reglas de trabajo actuales están en `CLAUDE.md` §4.

> Requisito previo: haber leído `CLAUDE.md`. Recordá la regla de oro: **solo se
> mueve código, no se modifica.** Las vulnerabilidades se quedan vivas.

Este documento te dice **exactamente** qué bloques de `app.js` van a cada módulo,
qué estructura de archivos crear, y cómo manejar el código compartido.

Los números de línea son una **referencia aproximada** del estado actual del
archivo (~3780 líneas). Úsalos como guía; localiza cada bloque por su firma
(nombre de ruta o de función), no confíes ciegamente en el número, porque a
medida que muevas cosas los números cambian.

---

## 1. Estructura de archivos objetivo

Crear una carpeta `src/modules/` con un archivo por módulo, más una carpeta
`src/shared/` para lo transversal. Cada módulo exporta un `express.Router()`.

```
src/
  app.js                     ← queda como "orquestador": imports, setup, monta routers
  shared/
    db.js                    ← el pool MySQL y su init
    config.js                ← constantes de negocio y config Vulnbank (env vars)
    helpers.js               ← helpers genéricos usados por >1 módulo
    rate-limiters.js         ← createRateLimiter + todas las instancias de limiters
    vulnbank.js              ← cliente Vulnbank (funciones vulnbank*, http/https)
  modules/
    auth/
      auth.routes.js         ← M1 · Autenticación (Esteban)
    users/
      users.routes.js        ← M2 · Gestión de Usuarios (Roberto)
    operations/
      operations.routes.js   ← M3 · Operaciones/Transacciones (Geiner)
    audit/
      audit.routes.js        ← M4 · Logs/Auditoría (Yerald)
    catalog/
      catalog.routes.js      ← código de tienda que NO pertenece a ningún módulo del proyecto
    chatbot/
      chatbot.routes.js      ← chatbot/LLM (fuera del alcance de los 4 módulos)
```

> **Por qué `catalog` y `chatbot`:** el repo tiene mucho código (home, búsqueda,
> productos, vistas de vendedor, chatbot LLM) que **no cae** en ninguno de los 4
> módulos del proyecto académico. No lo borres ni lo fuerces dentro de un módulo:
> agrúpalo aparte para que la app siga completa y los 4 dueños tengan su módulo
> limpio. Anota en el reporte que esto quedó "fuera de alcance del proyecto".

---

## 2. Mapeo endpoint → módulo

Clasificá cada `app.<método>('/ruta', ...)` según esta tabla. **Mové el handler
completo tal cual** (incluyendo el/los rate limiter que recibe como middleware).

### M1 · Autenticación → `modules/auth/auth.routes.js`
- `GET  /login`, `POST /login`
- `GET  /verify-otp`, `POST /verify-otp`
- `GET  /admin/login`, `POST /admin/login`
- `GET  /register`, `POST /register`
- `GET  /logout`
- `GET  /forgot-password`, `POST /forgot-password`
- `GET  /reset-password`, `POST /reset-password`
- Helper asociado: `generateResetToken()` (si solo lo usa auth, muévelo aquí; si
  no, ver sección 3).

### M2 · Gestión de Usuarios → `modules/users/users.routes.js`
- `GET  /profile`
- `POST /profile/address`
- `POST /profile/update-avatar`, `POST /profile/upload-avatar`
- `POST /account/delete`
- `GET  /mail`, `GET /mail/:token`, `POST /mail/:id/read`
- `GET  /admin/users`
- `POST /admin/make-seller`, `POST /admin/remove-seller`
- `POST /admin/delete-user`
- `GET  /register-seller`, `POST /register-seller`
- Config de `multer` para avatares (`avatarStorage`, `avatarUpload`,
  `ALLOWED_AVATAR_*`) → esto lo usa el perfil; muévelo con Users **si no lo usa
  nadie más**. Verifícalo con un grep antes de mover.

### M3 · Operaciones/Transacciones → `modules/operations/operations.routes.js`
- `GET  /cart`, `POST /cart/add`, `POST /cart/remove/:id`, `POST /cart/update`
- `POST /apply-coupon`
- `GET  /checkout`, `POST /checkout`
- `POST /wallet/topup/vulnbank`
- `GET  /order/:id`
- Vendedor / earnings / retiros (son operaciones de transacción):
  `GET /seller/dashboard`, `POST /seller/withdraw`,
  `GET /admin/orders`, `POST /admin/update-order-status`,
  `POST /admin/topup-wallet`, `POST /admin/topup-seller-wallet`,
  `GET /admin/export-orders`, `GET /admin/stats`
- Cupones y deals (admin de transacciones):
  `GET /admin/coupons`, `POST /admin/coupons/create`,
  `POST /admin/coupons/toggle`, `POST /admin/coupons/delete`,
  `GET /admin/deals`, `POST /admin/deals/set`, `POST /admin/deals/remove`
- `GET  /invoice`
- Helpers asociados: `applyDiscount()`, `creditDeliveredOrder()`,
  `autoProgressOrders()`, `getCommissionRate()`, `getZoneFee()`, `resolveDeals()`,
  `seedDeals()`. **Ojo:** algunos de estos (p.ej. `resolveDeals`) también los usa
  `catalog` (home/productos). Si un helper lo usan varios módulos, va a
  `shared/helpers.js` (sección 3), NO duplicado.

### M4 · Logs/Auditoría → `modules/audit/audit.routes.js`
- `GET  /admin/security` (visor de logs)
- `POST /admin/reset-log`
- `GET  /api/v1/events`
- La función `auditLog()` y `ensureAuditTable()` son el **corazón de este
  módulo**, pero las llaman TODOS los demás módulos. → van a `shared/` PERO
  déjalas claramente identificadas como "propiedad lógica de M4". Ver sección 3.

### Fuera de alcance → `modules/catalog/` y `modules/chatbot/`
- **catalog:** `GET /`, `GET /search`, `GET /category/:category`,
  `GET /product/:id`, `POST /review`, `POST /wishlist/add`,
  `POST /wishlist/remove`, `GET /wishlist/:token`, `GET /add-product`,
  `POST /add-product`, `GET /edit-product/:id`, `POST /edit-product/:id`,
  `GET /admin`, `GET /admin/products`, `GET /admin/reviews`,
  `POST /admin/toggle-product`, `POST /admin/delete-review`,
  `GET /track`, `POST /track`, `GET /track/:order_id`,
  `POST /seller/preview`, `GET /seller/preview`,
  `POST /search/filters`, `GET /search/filters`,
  `GET /vulnerabilities`, `GET /debug/info`, `GET /download`,
  `GET /reset`, `POST /reset`, y los endpoints de lab
  (`/admin/lab-reset`, `/lab/reset`, `/admin/lab-stats`).
- **chatbot:** `POST /chat/init`, `POST /chat`, `GET /chat/transcript`,
  `GET /kb/search`, y las funciones `buildSystemPrompt()`, `chatRateLimit()`,
  `kbTokenize()`, `kbNormalizeQuery()`, `kbScoreDocs()`, `KB_STOPWORDS`.

> Si encuentras algún endpoint que no está en esta lista, **no lo inventes ni lo
> borres**: colócalo en `catalog` por defecto y anótalo en el reporte para que
> el grupo decida.

---

## 3. Código compartido (lo más delicado)

Hay elementos que usan varios módulos. Regla: **si lo usa más de un módulo, va a
`src/shared/` y se importa; nunca se duplica.** No cambies su implementación.

Candidatos a `shared/`:

- **`shared/db.js`** — el `db = mysql.createPool({...})` y su `getConnection`
  de arranque. Exporta `db`. Lo importa prácticamente todo.
- **`shared/rate-limiters.js`** — `createRateLimiter()` y TODAS las instancias
  (`loginLimiter`, `checkoutLimiter`, etc.). Cada router importa las que use.
- **`shared/config.js`** — constantes de negocio (`CATEGORY_COMMISSION`,
  `ZONE_FEE`, `PICKUP_STORES`, `WITHDRAWAL_FEE`, `SEED_*_IDS`…) y las env/const
  de Vulnbank (`VULNBANK_*`).
- **`shared/vulnbank.js`** — todas las funciones `vulnbank*`,
  `isVulnbankConfigured`, `getVulnbankStatus/Reference/Amount`,
  `extractVulnbankErrorMessage`, `normalizeVulnbankPath`,
  `buildVulnbankVerifyPath`, `vulnbankRequest`. Lo usa M3 (checkout/wallet).
  Si SOLO lo usa M3, puedes dejarlo dentro de `operations/` en vez de `shared/`
  — decide según el grep y anótalo.
- **`shared/helpers.js`** — helpers genéricos usados por >1 módulo:
  `sendMail()`, `resolveDeals()` (si lo comparten catalog y operations), etc.
- **`auditLog()` + `ensureAuditTable()`** — pertenecen conceptualmente a M4 pero
  las invocan todos. Ponlas en `shared/audit-core.js` (o dentro de
  `shared/helpers.js`) y **documenta explícitamente en el reporte** que su dueño
  para efectos del proyecto es Yerald (M4), aunque físicamente estén en shared
  porque el resto de módulos las llaman. Esto le importa mucho al grupo para la
  trazabilidad de Fase 3.

**Cómo decidir dónde va cada helper/const:** antes de mover, corré un grep del
identificador sobre `app.js` para ver cuántos handlers lo usan.
- Usado por 1 módulo → va dentro de ese módulo.
- Usado por 2+ módulos → va a `shared/`.

No muevas nada a `shared/` "por si acaso": solo si el grep confirma uso múltiple.

---

## 4. Qué queda en `app.js`

`app.js` debe quedar como orquestador delgado:
1. `require(...)` de librerías.
2. `require(...)` de `shared/*` y de cada router de `modules/*`.
3. El setup de Express que hoy está arriba: `bodyParser`, `session(...)`,
   `app.set('views'...)`, `express.static`, el middleware de `Cache-Control`,
   el middleware de `cartCount`, el de `visitor_stats`/healer, `app.locals.fmtPrice`.
   → Déjalo aquí **tal cual** (o muévelo a `shared/`/`app.setup.js` solo si es
   trivial y no cambia comportamiento; ante la duda, déjalo en `app.js`).
4. El montaje de routers: `app.use(authRoutes)`, `app.use(usersRoutes)`, etc.
5. Al final: el handler 404 `app.use((req,res)=>...)` y el handler de errores
   `app.use((err,req,res,next)=>...)`. **Deben quedar de últimos**, después de
   montar todos los routers, igual que ahora.

> **Orden de middlewares = comportamiento.** Express ejecuta middlewares y rutas
> en el orden en que se registran. Mantén el mismo orden relativo: primero los
> middlewares globales, luego las rutas de los módulos, y al final 404 + errores.
> Si al partir cambia el orden, cambia el comportamiento (aunque el código sea
> idéntico). Este es el único punto donde "solo mover" requiere cuidado real.

---

## 5. Andamiaje permitido (la única excepción a "no escribir código")

Para que el código movido corra, SÍ puedes escribir el mínimo pegamento:
- `const express = require('express'); const router = express.Router();` y
  `module.exports = router;` en cada archivo de módulo.
- Cambiar `app.get(...)` → `router.get(...)` (mismo método, misma ruta, mismo
  handler y middlewares). Esto es reescritura mecánica, no cambio de lógica.
- Los `require(...)` necesarios para traer `db`, limiters, helpers, etc. a cada
  archivo.
- Los `module.exports` de las funciones/constantes que ahora viven en `shared/`.

Nada más. No agregues logging, validación, comentarios "de mejora", try/catch
nuevos, ni nada que no exista ya en el código original.

---

## 6. Procedimiento sugerido (para minimizar riesgo)

1. Crea las carpetas y archivos vacíos con su esqueleto (`router`, `exports`).
2. Extrae primero `shared/` (db, limiters, config, helpers, vulnbank). Ajusta
   imports en `app.js`. Verifica que arranca.
3. Mueve un módulo a la vez, en este orden: audit → auth → users → operations →
   catalog → chatbot. Tras **cada** módulo: `npm start` y prueba que la app
   levanta. Así, si algo se rompe, sabes exactamente qué bloque fue.
4. Cuando todo esté movido y la app corra igual, escribe `SEPARATION_RESULT.md`.

Haz commits por módulo (p.ej. `refactor: extract auth module`) para que el
`git diff` de cada paso sea revisable. Recuerda: el diff debe mostrar líneas
movidas, no reescritas.
