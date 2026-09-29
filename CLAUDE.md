# CLAUDE.md — Contexto del proyecto Pwnshop (IC-8071 Seguridad del Software)

> **Lee este documento completo antes de tocar una sola línea de código.**
>
> ✅ **LA SEPARACIÓN EN MÓDULOS YA ESTÁ HECHA.** `src/app.js` ya no es un
> monolito: el código está repartido en `src/modules/` y `src/shared/`. La hizo
> la rama `refactor/module-separation` (septiembre 2026) y el detalle está en
> `SEPARATION_RESULT.md`. **No vuelvas a separar ni a reorganizar módulos.**
> `REFACTOR_PLAN.md` queda solo como registro histórico de cómo se hizo.
> Para saber cómo trabajar ahora, ve a la sección 4.

---

## 1. Qué es este repositorio

`pwnshop` (https://github.com/r007sec/pwnshop) es una aplicación e-commerce
**intencionalmente vulnerable**, hecha para entrenamiento en pentesting web.
Contiene ~58 vulnerabilidades conocidas mapeadas al OWASP Top 10.

- **Stack:** Node.js + Express + EJS + MySQL. Sesiones con `express-session`.
- **El backend está separado por módulo** (antes todo vivía en `src/app.js`, de unas
  3780 líneas). Ahora `src/app.js` solo orquesta: middlewares globales y montaje de
  routers. El código de cada módulo está en `src/modules/<modulo>/*.routes.js` y lo
  compartido en `src/shared/`. Mapa completo en la sección 4 y en
  `SEPARATION_RESULT.md`.
- Hay unos pocos archivos sueltos (`src/controllers/userController.js`,
  `src/models/user.js`, `src/routes/userRoutes.js`, `src/middlewares/auth.js`,
  `src/config/db.js`, `src/utils/helpers.js`) que **NO están enganchados a la app
  real**: son restos o ejemplos. Siguen sin tocar hasta que el grupo decida.
- Vistas en `src/views/*.ejs`, estáticos en `public/`.

### ⚠️ Regla de oro sobre las vulnerabilidades
Las vulnerabilidades de este repo son **deliberadas** y son la materia prima del
proyecto. **NO son bugs que arreglar.** Cualquier "mejora de seguridad",
parametrización de query, sanitización, validación extra, etc. que introduzcas
por iniciativa propia **arruina el proyecto**. Se parcheará después, a mano,
persona por persona, en fases controladas (ver sección 3).

---

## 2. Contexto académico

Curso **IC-8071 Seguridad del Software** (TEC). Proyecto final grupal, 20%,
entrega 9 de noviembre. El grupo eligió `pwnshop` como el sistema vulnerable.

El sistema se divide en **4 módulos**, y **cada integrante es dueño de uno**.
El reparto ya está definido (ver la Matriz de Gobernanza del grupo):

| Módulo | Responsable | Endpoints / activos representativos |
|---|---|---|
| **M1 · Autenticación** | Esteban McKenzie | `/login`, `/admin/login`, `/verify-otp`, `/register`, `/logout`, forgot/reset password, tokens de sesión, tabla de credenciales |
| **M2 · Gestión de Usuarios** | Roberto Chacón | `/profile`, `/admin/users`, `/account/delete`, `/admin/make-seller`, roles, PII, avatar |
| **M3 · Operaciones/Transacciones** | Geiner Barrantes | `/cart`, `/checkout`, `/apply-coupon`, `/wallet/topup/vulnbank`, carrito, cupones, billetera externa (JWT/Vulnbank) |
| **M4 · Logs/Auditoría** | Yerald Sánchez | tabla `audit_log`, función `auditLog()`, visor `/admin/security` |

### Detalle de cada módulo (según la Matriz General de Gobernanza del grupo)
Esto viene del entregable de Fase 1 y te ayuda a ubicar qué activos/endpoints
"pesan" en cada módulo cuando clasifiques código dudoso:

- **M1 · Autenticación (Esteban)** — Activos: tabla de credenciales (MySQL),
  tokens de sesión, endpoints `/login`, `/admin/login`, `/verify-otp`,
  `/register`. Función NIST: *PROTECT* (PR.AA-01 identidad, PR.AA-03
  credenciales). Riesgo inherente **Alto** (OTP predecible/no invalidado,
  credenciales en texto plano en logs).
- **M2 · Gestión de Usuarios (Roberto)** — Activos: PII, perfiles y roles,
  endpoints `/profile`, `/admin/users`, `/account/delete`, `/admin/make-seller`.
  NIST: *PROTECT/GOVERN* (PR.AA-05 RBAC, GV.RM). Riesgo **Alto** (IDOR
  confirmado, autoasignación de rol admin vía mass assignment, CSRF de
  autoeliminación).
- **M3 · Operaciones/Transacciones (Geiner)** — Activos: carrito, checkout,
  cupones, billetera externa (JWT), endpoints `/cart`, `/checkout`,
  `/apply-coupon`, `/wallet/topup/vulnbank`. NIST: *PROTECT* (PR.DS-01,
  PR.AA-01 confianza entre servicios). Riesgo **Alto** (SQLi confirmada, bypass
  de verificación de monto entre servicios, HTTP Parameter Pollution).
- **M4 · Logs/Auditoría (Yerald)** — Activos: tabla `audit_log`, función
  `auditLog()`, visor `/admin/security`. NIST: *DETECT/PROTECT* (DE.CM-01,
  PR.DS-01 integridad de registros). Riesgo **Crítico** (SQLi de 2º orden en el
  visor, IPs falsificables, contraseñas en texto plano en logs, endpoint que
  permite borrar todo el `audit_log`).

> Estas vulnerabilidades listadas son las que el grupo va a **explotar y luego
> parchear**. En la separación se dejaron **exactamente como estaban**, y así
> siguen hasta que su dueño las parchee en la Fase 3.

### Por qué el código está separado por módulo (ya resuelto)
Cuando todo estaba en `app.js`, si los 4 integrantes trabajaban a la vez sobre ese
archivo iban a chocar con **conflictos de merge constantes** en Git. Por eso el
código **ya se separó** en un archivo por módulo, para que cada persona trabaje
en el suyo sin pisar a los demás. Este problema ya está resuelto.

---

## 3. El proyecto completo (para que entiendas hacia dónde va esto)

Esto **NO es tu tarea ahora**, pero necesitas el panorama completo para no
"adelantarte" ni tomar decisiones que compliquen las fases siguientes.

### Objetivos de aprendizaje del proyecto
1. Evaluar, explotar y remediar vulnerabilidades en una arquitectura
   cliente-servidor aplicando **OWASP Top 10 + NIST CSF 2.0** + técnicas de
   manipulación de entradas.
2. Diagnosticar la seguridad mapeando las vulnerabilidades críticas contra los
   controles de gobernanza y gestión de riesgos de **NIST CSF 2.0** (línea base
   de impacto técnico y de negocio).
3. Demostrar los vectores de ataque con **PoCs reproducibles** (cliente y
   servidor): escalación de privilegios, inyecciones (A03), XSS, y alteración de
   registros de auditoría (*Audit Poisoning*).
4. Implementar las correcciones a nivel de código fuente con codificación segura
   **sin alterar la operación del sistema**.

### Requisito estructural (por qué son exactamente 4 módulos)
El sistema debe dividirse en **4 módulos**: Autenticación, Gestión de Usuarios,
Operaciones/Transacciones y Logs/Auditoría. **Cada integrante es dueño individual
de un módulo.** Por eso la separación que harás hoy tiene que dejar esos 4
módulos limpios y sin solaparse: es el andamiaje sobre el que se monta todo el
resto del proyecto y la trazabilidad individual en Git.

---

### Fase 1 — Diagnóstico y Marco Normalizado (NIST CSF 2.0)
Cada integrante, sobre **su** módulo:
- **Mapea** sus componentes/endpoints/lógica contra las subcategorías de NIST
  CSF 2.0.
- **Inventario de activos e impacto** (funciones *GOVERN* e *IDENTIFY*):
  identifica activos críticos (datos, servicios, BD) y el impacto operacional/de
  negocio ante un incidente.
- **Línea base de controles** (*PROTECT*, *DETECT*): define los controles
  mínimos requeridos antes de auditar y explotar.
- **Consolidación grupal** → **entregable: "Matriz General de Gobernanza del
  Sistema"** (un solo documento que integra los 4 módulos).

### Fase 2 — Evaluación Ofensiva y Explotación (OWASP)
Cada integrante documenta, vía **PoC**, los hallazgos de su módulo en 3 vectores:
1. **Servidor:** inyección SQL/Command (A03) y escalación de privilegios / roto
   control de acceso (A01), incluida desconfianza en JWT/microservicios.
2. **Cliente:** XSS Stored/Reflected (robo de cookies/sesión, manipulación del
   DOM, ejecución no autorizada en el navegador).
3. **Alteración de entrada y detección:** CSRF / manipulación de parámetros HTTP
   (A08) y *Audit Poisoning* (log injection para evadir la detección de intrusos).
- **Entregable: "Documento de PoCs" estandarizado** con las PoC de todos los
  integrantes; cada PoC cubre los 3 vectores para su módulo.
- **Aquí las vulnerabilidades TIENEN que seguir vivas.** Si tú las "arreglas" al
  separar, esta fase se vuelve imposible.

### Fase 3 — Remediación, Hardening y Respuesta (NIST Protect & Detect)
Cada integrante asume la **autoría e implementación** de las correcciones de su
módulo, con trazabilidad individual en el repo:
- **Protect:** parametrización de queries, sanitización estricta, CSP, cookies
  seguras (`HttpOnly`/`SameSite`), menor privilegio en sus endpoints.
- **Detect:** corregir la lógica de auditoría (anti *Audit Poisoning*):
  desinfección de headers/parámetros, firmas o *tracing* defensivo.

Entregables de Fase 3:
- **Matriz de Riesgos NIST CSF consolidada y actualizada** con el **riesgo
  residual** post-remediación por módulo. Escala:
  - **Alto/Crítico (no aceptable):** el parche cura el síntoma, no la causa; o se
    puede saltar la validación con codificación alternativa. Re-trabajo inmediato.
  - **Medio (tolerable):** la vulnerabilidad principal se eliminó pero quedan
    configuraciones laxas (ej. falta de rate limiting en el login remediado).
  - **Bajo (aceptado):** vector completamente neutralizado, la PoC original ya no
    corre y el control cumple la subcategoría NIST correspondiente.
- **Reporte Técnico de Parches** (evidencia de PRs/commits individuales), con
  esta estructura por sección:
  1. **Ficha del integrante y trazabilidad Git:** responsable, módulo, enlace al
     PR, IDs de commit, rama.
  2. **Mapeo de la vulnerabilidad y parche:** fallo ↔ OWASP Top 10, NIST CSF 2.0,
     archivos/líneas afectadas.
  3. **Comparativa de código (diff de remediación):** bloque visual antes vs
     después.
  4. **Verificación de no-reincidencia (prueba de regresión):** validar que la
     PoC ya no funciona + evidencias.

### Regla de evaluación del video (importante para el diseño del repo)
Cada integrante graba un video (máx. 5 min) explicando **exclusivamente sobre el
repositorio y el IDE** los parches de su módulo. **Cualquier video con
diapositivas, lectura de documentos o teoría = nota cero** en ese rubro: debe ser
100% técnico sobre las líneas modificadas. → Esto refuerza por qué la separación
por módulo importa tanto: cada quien tiene que poder mostrar *su* archivo con
*sus* cambios, sin ruido de los demás.

### Consideraciones especiales del enunciado
- La profesora dará plantillas de ejemplo, pero el grupo puede crear las suyas.
- Si un integrante no hace su parte no se penaliza al grupo, **pero** cuando la
  incorpore, una solución no integral afecta la nota de todos.
- **El proyecto se entrega como uno solo**, no se aceptan documentos separados
  por persona. (Por eso el repo debe quedar coherente y unificado, aunque el
  trabajo sea por módulo.)

---

Por todo lo anterior, la separación en módulos fue **puramente mecánica**: se
movió código para que cada dueño tenga su espacio limpio y trazable. Explotar
(Fase 2) y parchear (Fase 3) lo hacen las personas, cada una en su módulo.

---

## 4. ESTADO ACTUAL: separación COMPLETADA (no la repitas)

La separación de `src/app.js` en módulos **ya se hizo y se verificó**: la app
responde igual que antes y las vulnerabilidades siguen intactas. Detalle completo
(qué se movió, a dónde, por qué y cómo se verificó) en `SEPARATION_RESULT.md`.
`REFACTOR_PLAN.md` es solo el registro histórico del plan que se siguió.

### Mapa del código

| Archivo | Módulo / responsable |
|---|---|
| `src/modules/auth/auth.routes.js` | **M1 · Autenticación — Esteban McKenzie** |
| `src/modules/users/users.routes.js` | **M2 · Gestión de Usuarios — Roberto Chacón** |
| `src/modules/operations/operations.routes.js` | **M3 · Operaciones/Transacciones — Geiner Barrantes** |
| `src/modules/audit/audit.routes.js` | **M4 · Logs/Auditoría — Yerald Sánchez** |
| `src/shared/audit-core.js` (`auditLog()`, `ensureAuditTable()`) | **Dueño lógico: M4 (Yerald)**. Está en `shared/` solo porque todos los módulos llaman a `auditLog()` |
| `src/shared/db.js`, `rate-limiters.js`, `config.js`, `vulnbank.js`, `helpers.js`, `migrations.js` | Compartido: lo usan 2 o más módulos |
| `src/modules/catalog/catalog.routes.js`, `src/modules/catalog/lab.routes.js`, `src/modules/chatbot/chatbot.routes.js` | Fuera del alcance de los 4 módulos del proyecto |
| `src/app.js` | Orquestador: middlewares globales + montaje de routers + 404/errores |

### Cómo trabajar ahora (reglas para cualquier agente o integrante)
- ❌ **NO** vuelvas a separar, fusionar ni mover código entre módulos. Si crees que
  algo está en el módulo equivocado, dilo y deja que el grupo decida.
- ✅ Trabaja **solo en el archivo del módulo de la persona que te lo pide**. No
  toques los archivos de otros módulos: rompería la trazabilidad individual en
  Git que exige la Fase 3.
- ⚠️ Cambiar algo en `src/shared/` afecta a todos los módulos. Hazlo solo si la
  persona lo pide explícitamente, y avisa qué otros módulos lo usan (la tabla de
  la §3 de `SEPARATION_RESULT.md` lo detalla). Excepción: los parches
  anti *Audit Poisoning* en `shared/audit-core.js` los hace M4.
- ❌ **NO** cambies el orden de los middlewares ni del montaje de routers en
  `src/app.js`: ese orden es parte del comportamiento de la app.
- ❌ La **regla de oro sigue vigente**: las vulnerabilidades se quedan tal cual
  hasta que el dueño de cada módulo las parchee en la Fase 3. No "arregles" nada
  por iniciativa propia, ni siquiera lo obvio.
- ❌ **NO** actualices dependencias, no toques `package.json` y no agregues
  linters ni formateadores que reescriban el código.
- Los archivos huérfanos (`src/controllers/`, `src/models/`, `src/routes/`,
  `src/middlewares/`, `src/config/`, `src/utils/`) siguen sin tocar hasta que el
  grupo decida qué hacer con ellos.
- Los números de línea que citan `README.md` y `scripts/gen_docs.py` son del
  `app.js` monolítico original y ya no aplican.

---

## 5. Verificación (antes de decir "listo" en cualquier cambio)

1. `npm start` debe levantar sin errores de `require` ni rutas rotas.
2. Si corres Node fuera de Docker contra el MySQL del `docker-compose` (puerto
   3307), usa `TZ=UTC`. Si no, los OTP de login salen expirados por la diferencia
   de zona horaria entre Node y MySQL.
3. En la Fase 3, cada parche va en commits propios del dueño del módulo, con la
   PoC original como prueba de regresión.
