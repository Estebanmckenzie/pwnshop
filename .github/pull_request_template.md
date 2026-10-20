<!--
Plantilla de PR — Fase 3 (Remediación, Hardening y Respuesta)
Un PR por vulnerabilidad (PWN-XXX). Vincula el issue con "Closes #<issue>".
-->

Closes #<issue>

## 1. Ficha del Integrante y Trazabilidad de Git

| Campo | Detalle |
|---|---|
| Estudiante Responsable | |
| Módulo Asignado | <!-- Ej. Módulo 4: Auditoría y Logs --> |
| Rama de Trabajo (Branch) | |
| ID de Commit(s) de la Solución | <!-- se completa al final, con los hashes definitivos --> |

## 2. Mapeo de la Vulnerabilidad y Parche

| Campo | Detalle Técnico |
|---|---|
| ID interno | PWN-XXX |
| Vulnerabilidad Corregida | |
| Categoría OWASP Top 10 | |
| Subcategoría NIST CSF 2.0 | |
| Archivo(s) Modificado(s) | |
| Líneas de Código Impactadas | |

## 3. Comparativa de Código (Diff de Remediación)

<!-- Bloque visual antes/después del cambio principal. -->

```diff
# Archivo: ruta/al/archivo
- código vulnerable
+ código remediado
```

## 4. Verificación de No-Reincidencia (Prueba de Regresión)

**Comprobación de la PoC Original:** <!-- se re-ejecutó el script/payload de la Fase 2 contra el código parcheado -->

**Comportamiento Anterior:**

**Comportamiento Actual:**

**Evidencia Adjunta:** <!-- captura de pantalla / salida de consola / log -->

## 5. Riesgo Residual

- [ ] Alto / Crítico (No Aceptable)
- [ ] Medio (Tolerable)
- [ ] Bajo (Aceptado)

Justificación:

## Checklist antes de pedir revisión

- [ ] La PoC original de este PWN-XXX ya no es ejecutable
- [ ] No se modificaron archivos de módulos de otros integrantes ni `src/shared/` sin aprobación
- [ ] El parche no altera la operación normal del sistema
- [ ] Matriz de Riesgos NIST CSF actualizada con el riesgo residual de este hallazgo
