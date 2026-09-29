# SEPARATION_RESULT.md — Resultado de la separación de `app.js`

> Registro de la separación descrita en `REFACTOR_PLAN.md`. Rama:
> `refactor/module-separation` (7 commits, uno por etapa). Todos los números de
> línea corresponden al estado final de cada archivo.

---

## 1. Árbol de archivos final

```
src/
├── app.js                          ← orquestador (83 líneas; antes 3780)
├── shared/
│   ├── db.js                       ← pool MySQL + getConnection de arranque
│   ├── audit-core.js               ← ensureAuditTable() + auditLog()  (dueño lógico: M4)
│   ├── migrations.js               ← ALTER/CREATE TABLE que corren al arrancar
│   ├── config.js                   ← constantes VULNBANK_* (env vars)
│   ├── vulnbank.js                 ← cliente Vulnbank (funciones vulnbank*)
│   ├── rate-limiters.js            ← createRateLimiter() + las 19 instancias
│   └── helpers.js                  ← resolveDeals(), requireAdmin()
├── modules/
│   ├── auth/auth.routes.js         ← M1 · Autenticación        (Esteban)
│   ├── users/users.routes.js       ← M2 · Gestión de Usuarios  (Roberto)
│   ├── operations/operations.routes.js ← M3 · Operaciones     (Geiner)
│   ├── audit/audit.routes.js       ← M4 · Logs/Auditoría       (Yerald)
│   ├── catalog/catalog.routes.js   ← fuera de alcance (tienda)
│   ├── catalog/lab.routes.js       ← fuera de alcance (tracking + healer + reset de lab)
│   └── chatbot/chatbot.routes.js   ← fuera de alcance (LLM)
├── views/ … (sin cambios)
├── public/ … (sin cambios)
├── config/db.js                    ┐
├── controllers/userController.js   │
├── middlewares/auth.js             ├ huérfanos, SIN TOCAR (ver §6)
├── models/user.js                  │
├── routes/userRoutes.js            │
└── utils/helpers.js                ┘
```

Rutas por archivo: auth 13 · users 14 · operations 25 · audit 3 · catalog 29 ·
lab 3 · chatbot 4 = **91** (idéntico al `app.js` original, sin rutas duplicadas).

---

## 2. Dónde quedó cada módulo

### M1 · Autenticación — Esteban McKenzie
- **Archivo:** `src/modules/auth/auth.routes.js`
- **Endpoints movidos:** `GET/POST /login` (26, 32), `GET/POST /verify-otp` (93, 99),
  `GET/POST /admin/login` (135, 137), `GET/POST /register` (185, 190),
  `GET /logout` (230), `GET/POST /forgot-password` (232, 234),
  `GET/POST /reset-password` (299, 307).
- **Helpers/constantes movidos:** cliente `resend` + `RESEND_FROM` (12-13),
  `generateResetToken()` (15), `sendMail()` (19).
- **Notas:** el grep confirmó que `generateResetToken`, `sendMail`, `resend` y
  `bcrypt` solo los usa este módulo, por eso quedaron aquí y no en `shared/`
  (el plan sugería `sendMail` como candidato a shared, pero no se usa en ningún
  otro lado). Rate limiters que importa: `loginLimiter`, `adminLoginLimiter`,
  `registerLimiter`, `forgotPasswordLimiter`, `resetPasswordLimiter`.

### M2 · Gestión de Usuarios — Roberto Chacón
- **Archivo:** `src/modules/users/users.routes.js`
- **Endpoints movidos:** `GET /profile` (42), `POST /profile/address` (76),
  `POST /profile/update-avatar` (94), `POST /profile/upload-avatar` (138),
  `POST /account/delete` (183), `GET /mail` (195), `GET /mail/:token` (205),
  `POST /mail/:id/read` (244), `GET/POST /register-seller` (250, 255),
  `GET /admin/users` (265), `POST /admin/make-seller` (281),
  `POST /admin/remove-seller` (290), `POST /admin/delete-user` (299).
- **Helpers/constantes movidos:** `ALLOWED_AVATAR_MIMES`, `ALLOWED_AVATAR_EXTS`,
  `avatarStorage`, `avatarUpload` (15-40). El grep confirmó que solo los usa el
  perfil.
- **Notas:** `/profile` usa `isVulnbankConfigured()` y `VULNBANK_LAB_VULN`; por
  eso Vulnbank quedó en `shared/` (lo usan M2 y M3).

### M3 · Operaciones/Transacciones — Geiner Barrantes
- **Archivo:** `src/modules/operations/operations.routes.js`
- **Endpoints movidos:** `GET /order/:id` (85), `POST /wallet/topup/vulnbank` (106),
  `GET /cart` (252), `POST /cart/add` (271), `POST /cart/remove/:id` (284),
  `POST /cart/update` (289), `POST /apply-coupon` (303), `GET/POST /checkout`
  (384, 432), `GET /seller/dashboard` (731), `POST /seller/withdraw` (779),
  `GET /admin/orders` (926), `GET /admin/stats` (949), `GET /admin/export-orders`
  (998), `POST /admin/update-order-status` (1028), `POST /admin/topup-wallet`
  (1072), `POST /admin/topup-seller-wallet` (1083), `GET /invoice` (1100),
  `GET /admin/coupons` (1172), `POST /admin/coupons/create|toggle|delete`
  (1192, 1213, 1225), `GET /admin/deals` (1237), `POST /admin/deals/set|remove`
  (1251, 1267).
- **Helpers/constantes movidos:** `seedDeals()` + sus timers (13-34),
  `CATEGORY_COMMISSION`, `DEFAULT_COMMISSION`, `VAT_ON_COMMISSION`, `ZONE_FEE`,
  `DEFAULT_ZONE_FEE`, `PLATFORM_FEE_PCT`, `SHIPPING_DEDUCTION`, `WITHDRAWAL_FEE`,
  `PICKUP_STORES` (37-74), `getCommissionRate()` (76), `getZoneFee()` (80),
  `applyDiscount()` (368), `creditDeliveredOrder()` (818),
  `autoProgressOrders()` + su `setInterval` (872-924).
- **Notas:** las constantes de negocio iban a `shared/config.js` según el plan,
  pero el grep mostró que **solo las usa M3**, así que siguiendo la regla de la
  §3 del plan ("usado por 1 módulo → dentro del módulo") quedaron aquí.
  `/invoice` tiene uno de los dos cambios de texto forzados (ver §5).

### M4 · Logs/Auditoría — Yerald Sánchez
- **Archivo:** `src/modules/audit/audit.routes.js`
- **Endpoints movidos:** `GET /api/v1/events` (10), `GET /admin/security` (21),
  `POST /admin/reset-log` (42).
- **Helpers/constantes movidos:** ninguno dentro del router; ver abajo.
- **Notas sobre `auditLog()`/`ensureAuditTable()`:** están físicamente en
  `src/shared/audit-core.js` (`ensureAuditTable` línea 7 y su llamada de arranque;
  `auditLog` línea 23) porque **todos** los módulos llaman a `auditLog()`.
  **Su dueño lógico para el proyecto es Yerald (M4)**: el encabezado del archivo
  lo indica explícitamente. Las correcciones anti *Audit Poisoning* de Fase 3
  (IP desde `x-forwarded-for`, contraseñas en `detail`, etc.) se hacen en ese
  archivo.

### Fuera de alcance del proyecto
- **catalog** (`src/modules/catalog/catalog.routes.js`): `GET /`, `GET /search`,
  `GET /category/:category`, `GET /product/:id`, `POST /review`,
  `POST /wishlist/add`, `POST /wishlist/remove`, `GET /wishlist/:token`,
  `GET/POST /add-product`, `GET/POST /edit-product/:id`, `GET /admin`,
  `GET /admin/products`, `GET /admin/reviews`, `POST /admin/toggle-product`,
  `POST /admin/delete-review`, `GET /vulnerabilities`, `GET /debug/info`,
  `GET/POST /track`, `GET /track/:order_id`, `GET/POST /reset`,
  `POST/GET /seller/preview`, `POST/GET /search/filters`, `GET /download`.
  También: `storage`/`upload` (multer de productos), `SEED_*_IDS`, `DEFAULT_FILTERS`.
- **catalog/lab** (`src/modules/catalog/lab.routes.js`): middleware de tracking de
  visitas (`labIsDirty`, `lastActivityMs`, `trackedRoutes`, `isTrackedRoute`),
  `runLabReset()`, `POST /admin/lab-reset`, `POST /lab/reset`,
  `GET /admin/lab-stats` y el auto-healer (`setInterval`). Ver §5 por qué es un
  archivo aparte.
- **chatbot** (`src/modules/chatbot/chatbot.routes.js`): `POST /chat/init`,
  `POST /chat`, `GET /chat/transcript`, `GET /kb/search`, y `chatRateMap`,
  `chatRateLimit()` + su limpieza con `setInterval`, `buildSystemPrompt()`,
  `KB_STOPWORDS`, `kbTokenize()`, `kbNormalizeQuery()`, `kbScoreDocs()`.

No apareció ningún endpoint fuera de la tabla del plan.

---

## 3. Código compartido (`src/shared/`)

| Archivo shared | Contiene | Usado por (módulos) | Por qué es compartido |
|---|---|---|---|
| `shared/db.js` | `db = mysql.createPool(...)` + `getConnection` de arranque | app.js, auth, users, operations, audit, catalog, lab, chatbot, audit-core, migrations | todos consultan la BD |
| `shared/rate-limiters.js` | `rateLimitMaps`, `createRateLimiter()`, las 19 instancias | app.js (`globalGetLimiter`), auth, users, operations, catalog | cada router importa solo las suyas; una sola fábrica/estado |
| `shared/config.js` | `VULNBANK_*` (8 constantes de env) | users (`VULNBANK_LAB_VULN`), operations, shared/vulnbank | M2 y M3 leen la config de Vulnbank |
| `shared/vulnbank.js` | `isVulnbankConfigured`, `vulnbankUnwrap`, `getVulnbankStatus/Reference/Amount`, `extractVulnbankErrorMessage`, `isVulnbankSuccess`, `normalizeVulnbankPath`, `buildVulnbankVerifyPath`, `vulnbankRequest` | users (`/profile`), operations | `/profile` (M2) llama `isVulnbankConfigured()`; checkout/wallet (M3) usan el resto |
| `shared/helpers.js` | `resolveDeals()`, `requireAdmin()` | `resolveDeals`: catalog + operations. `requireAdmin`: users, operations, audit, catalog, lab | uso en 2+ módulos |
| `shared/audit-core.js` | `ensureAuditTable()` (+ su llamada al arrancar), `auditLog()` | todos | **dueño lógico: M4 (Yerald)** |
| `shared/migrations.js` | `addCol()` + los `ALTER TABLE`, el `UPDATE` de `referral_code`, `CREATE TABLE coupon_uses` y `vulnbank_tx_log` | efecto de arranque (lo requiere app.js) | no es de ningún módulo: es el esquema que la app crea al iniciar |

---

## 4. Qué quedó en `app.js`

`src/app.js` (83 líneas), en este orden:

1. `require('dotenv').config()` y las librerías que usa (`path`, `express`,
   `body-parser`, `express-session`), `const app = express()`.
2. `require` de `shared/db`, `shared/audit-core` (ejecuta `ensureAuditTable()`),
   `shared/migrations` y `globalGetLimiter`; luego los 7 routers.
3. Middlewares globales **tal cual y en el mismo orden original**:
   `bodyParser.urlencoded` → `bodyParser.json` → `session(...)` (sigue con
   `'weak-secret-123'`) → `views`/`view engine` → `express.static` →
   `Cache-Control: no-store` → `app.locals.fmtPrice` → middleware de `cartCount`
   → rate limit global de GET.
4. Montaje de routers: `labRoutes` **primero** (contiene el middleware de tracking
   de visitas, que en el original iba justo después del rate limit global y antes
   de todas las rutas), luego auth, users, operations, audit, catalog, chatbot.
5. Al final, igual que antes: handler 404, handler de errores 500 y `app.listen`.

**Orden de middlewares preservado.** Entre las 91 rutas no hay dos con el mismo
método + path ni rutas que llamen a `next()` para caer en otra, así que el orden
relativo entre routers no cambia qué handler responde; aun así todos se montan
después de los middlewares globales y antes del 404/errores, igual que antes.

---

## 5. Decisiones y desviaciones

- **Único cambio de texto en líneas existentes (forzado): dos rutas relativas a
  `__dirname`.** Al mover el código de `src/` a `src/modules/<m>/`, `__dirname`
  cambia y `'../public'` apuntaría a otra carpeta. Se ajustó el literal para que
  resuelva a **la misma ruta absoluta** que antes (`<repo>/public/...`):
  - `operations.routes.js:1124` (`/invoice`): `path.join(__dirname, '../public', 'invoices')` → `path.join(__dirname, '../../../public', 'invoices')`
  - `catalog.routes.js:651` (`/download`): `path.join(__dirname, '../public', 'storage')` → `path.join(__dirname, '../../../public', 'storage')`

  No se podía evitar sin tocar la línea (redeclarar `__dirname` en un módulo
  CommonJS es un `SyntaxError`). El path traversal de ambos endpoints **sigue
  funcionando igual**: se verificó que `/invoice?order=x/../../../package.json` y
  `/download?file=../../package.json` devuelven el mismo archivo antes y después.
- **Lab en archivo propio (`catalog/lab.routes.js`).** El plan ponía los endpoints
  de lab en `catalog` y el middleware de visitas + healer en `app.js`. Pero los
  tres comparten variables `let` mutables (`labIsDirty`, `lastActivityMs`) que no
  se pueden compartir entre archivos CommonJS sin reescribir lógica (p.ej. pasar
  a un objeto). Para no tocar lógica, todo ese bloque quedó junto en un router
  que se monta en la posición exacta del middleware original. Sigue dentro de la
  carpeta `catalog/` (fuera de alcance).
- **Constantes de negocio en M3 y no en `shared/config.js`**, y **`sendMail()` en
  M1 y no en `shared/helpers.js`**: el grep mostró uso en un solo módulo (regla §3
  del plan).
- **`shared/migrations.js`** es un archivo que el plan no listaba: agrupa las
  migraciones de arranque que no pertenecen a ningún módulo. Se requiere después
  de `audit-core` para conservar el orden original de las queries de arranque.
- **Andamiaje añadido** (lo único escrito a mano): `require`/`module.exports`,
  `express.Router()`, `app.X(` → `router.X(`, los `app.use(<router>)` y un
  comentario de encabezado por archivo con módulo y responsable. Las funciones
  exportadas desde `shared/` no se modificaron.
- **Orden de arranque:** los timers (`seedDeals`, `autoProgressOrders`, limpieza
  de rate limiters, chat y healer) se registran al cargar su archivo, con los
  mismos intervalos, unos milisegundos antes que en el original. Los logs de
  arranque salen en el mismo orden que antes (`[healer] ...`, `Pwnshop running`,
  `Connected to database pool.`).
- **Método:** la separación se hizo con un script que copia rangos de líneas
  exactos del `app.js` original, sin retipear código. Después se comprobó que el
  multiconjunto de líneas no vacías del original es idéntico al de los archivos
  nuevos: las únicas líneas nuevas son andamiaje (require/exports/router/mount/
  encabezados) y las únicas modificadas son las dos de `__dirname`.
- **Documentación desfasada (no tocada):** `scripts/gen_docs.py` y `README.md`
  (línea 578: "all routes and logic") citan números de línea de `src/app.js`.
  Esas referencias ya no aplican; el grupo decide si actualizarlas.

## 6. Archivos huérfanos NO tocados

No están conectados a la app real (ningún `require` los alcanza desde `app.js`).
Quedan **sin modificar** para que el grupo decida:

- `src/config/db.js`
- `src/controllers/userController.js`
- `src/middlewares/auth.js`
- `src/models/user.js`
- `src/routes/userRoutes.js`
- `src/utils/helpers.js`

---

## 7. Verificación de que la app corre igual

- [x] `npm install` OK (`npm ci`: 237 paquetes, `package.json` y `package-lock.json` sin cambios)
- [x] `npm start` levanta sin errores
- [x] Rutas responden igual que antes: 91 peticiones comparadas, no solo el
      spot-check de `/`, `/login`, `/cart`, `/admin/security`
- [x] `git diff` revisado: el código se **movió**, no se reescribió

**Cómo se verificó.** Se levantó la app **original** en otro puerto contra el MySQL
del `docker-compose` (puerto 3307) y se grabó una línea base de 91 peticiones:
todas las rutas GET de forma anónima, varios POST inofensivos (login inválido,
SQLi `'` en `/login` y `/admin/login`, `/apply-coupon`, `/chat/init`,
`/lab/reset` sin token…) y luego, con sesión de admin, los paneles `/admin/*`,
`/profile`, `/cart`, `/checkout`, `/invoice`, `/download`, `/api/v1/events`, etc.
Por cada petición se guardó status, content-type, redirect y cuerpo. Después de
**cada** etapa (shared → audit → auth → users → operations → catalog → chatbot)
se repitió la misma batería y se comparó:

- status / content-type / redirect: **idénticos en las 91 peticiones, en las 7 etapas**.
- cuerpos: iguales salvo 5 respuestas con datos dinámicos: `/` (productos
  destacados con `ORDER BY RAND()`), `/api/v1/events` y `/admin/security` (el
  audit log crece con cada corrida) y `/admin/lab-stats` (contador de visitas).
  Se revisaron: solo cambian los datos, la estructura es la misma.
- Las vulnerabilidades siguen vivas: la SQLi de `/search?q='` devuelve el mismo
  error de MySQL y los path traversal de `/invoice` y `/download` leen
  `package.json` igual que antes.

**Comando(s) de verificación usados y su salida resumida:**

```
$ git log --oneline main..refactor/module-separation
043107c refactor: extract chatbot module (out of project scope)
87ce17b refactor: extract catalog and lab modules (out of project scope)
8c398ea refactor: extract operations module (M3)
21bca7a refactor: extract users module (M2)
76b02d5 refactor: extract auth module (M1)
a4e94f9 refactor: extract audit module (M4)
8efe994 refactor: extract shared db, audit-core, migrations, config, vulnbank, rate limiters and helpers

$ git diff --stat main..refactor/module-separation
 15 files changed, 3858 insertions(+), 3719 deletions(-)
 (+139 netas = andamiaje: requires, exports, routers, montaje y encabezados)

$ npm start
> pwnshop-app@1.0.0 start
> node src/app.js
[healer] Auto-reset active - fires after 20m inactivity
Pwnshop running → http://localhost:3000
Connected to database pool.

$ node --check  (los 15 archivos .js nuevos/modificados)  → OK
```

> Nota de entorno (no es cambio de código): al correr Node fuera de Docker contra
> el MySQL del contenedor hay que usar `TZ=UTC`, porque el OTP se guarda con la
> hora local de Node y MySQL compara con `NOW()` en UTC. Dentro de Docker no pasa.

---

## 8. Confirmación final

> Confirma explícitamente: **no se modificó lógica, no se corrigió ninguna
> vulnerabilidad, no se parametrizó ninguna query, no se cambió ningún string
> ni status code.** Solo se reubicó código y se añadió el andamiaje mínimo de
> routers/imports/exports.

- [x] Confirmado, con una salvedad documentada en §5: los dos literales de ruta
  relativa a `__dirname` (`'../public'` → `'../../../public'`) se ajustaron para
  que sigan resolviendo exactamente la misma carpeta que antes.
