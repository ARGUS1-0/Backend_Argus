# ArgusTEC — Backend (Java Quarkus)

Plataforma de gestión de vulnerabilidades para Lyft. Reduce la fatiga de alertas del SOC: escanea activos con Nessus, les agrega contexto de negocio (CMDB iTop) y explotabilidad (EPSS), un agente Claude decide la prioridad y se avisa directamente al custodio del activo por Slack. El SOC supervisa desde un dashboard web.

Equipo: Josué (backend, infraestructura, PM), Samu (agente IA y algoritmo de riesgo), Ivana y Carlos (iTop/CMDB, frontend, Slack Block Kit). Plazo: 4 semanas.

## Pipeline
1. Nessus Essentials escanea periódicamente los activos (contenedores en la VM `argus1` de GCP). **No hay web scraping.**
2. Se carga el CSV de Nessus → `NessusParserService` → objetos STIX 2.1 (`vulnerability`, `infrastructure`).
3. Los eventos se firman con HMAC-SHA3-256 → Kafka.
4. Enriquecimiento:
   - CMDB iTop: criticidad, datos alojados (PII, financieros) y custodio (email/Slack ID).
   - EPSS desde FIRST.org.
5. Evaluación de riesgo (algoritmo de Samu + agente Claude) → JSON con prioridad y acción.
6. Si se supera el umbral → Slack (Block Kit) al custodio. El SOC **no** recibe alertas individuales.
7. Se guarda en MySQL → dashboard React.

## Stack
- Java Quarkus (REST Client Reactive, SmallRye Reactive Messaging para Kafka).
- Apache Kafka (+ Zookeeper).
- MySQL (Cloud SQL o contenedor).
- iTop como CMDB (API REST, consultas OQL). Jira para tickets.
- Anthropic Claude: modelo Sonnet actual (`claude-3-5-sonnet` ya está retirado), temperatura 0–0.1, salida JSON estricta.
- Slack App con bot token (`chat.postMessage`, no Incoming Webhook) para mandar DM o etiquetar a custodios.
- Firebase Authentication (ya implementado) para proteger endpoints.
- Frontend aparte: React + Vite + Tailwind, con login Firebase.
- Infraestructura: GCP, VM `argus1` (Ubuntu 22.04), Docker Compose.

## Estado actual
- [x] Entities de la base de datos
- [x] Parser Nessus CSV → STIX 2.1
- [x] Autenticación Firebase
- [ ] Tópicos Kafka y productor/consumidor (no hay ninguno implementado)
- [ ] Cliente EPSS (FIRST.org) con caché en MySQL
- [ ] Cliente CMDB iTop y relación hallazgo ↔ activo
- [ ] Interfaz `RiskEvaluator` (la lógica de criticidad la entrega Samu)
- [ ] `AgentOrchestratorService` (API de Claude)
- [ ] `SlackNotifierClient`
- [ ] Endpoints REST para el dashboard

## Decisiones de diseño
- **Tópicos Kafka propuestos:** `nessus-raw-events` → `enriched-vulns` → `analyzed-risks` → `notifications`.
- **RabbitMQ:** opcional. Preferimos usar el tópico `notifications` de Kafka para no agregar otro servicio.
- **Relación hallazgo ↔ activo:** todos los contenedores comparten IP en `argus1`, así que la llave es **IP + puerto**. Cada activo simulado en iTop representa un activo de Lyft (ej. Redis 6379 = "Redis Sesiones – Transporte").
- **EPSS:** `GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` en lotes, con caché en MySQL. Hallazgos sin CVE → EPSS null. Viene de FIRST, no de la NVD.
- **Prioridad:** la debe calcular código determinista (`RiskEvaluator`). Claude valida, justifica y redacta la recomendación; no hace las cuentas.
- **Arquitecturas de Lyft que se analizan:** Transporte, Analítica, CRM y ERP.

## Salida esperada del agente
```json
{
  "prioridad": "CRITICA | ALTA | MEDIA | BAJA",
  "accion": "Parchear | Monitorear | Ignorar",
  "justificacion_tecnica": "string",
  "recomendacion_mitigacion": "string",
  "slack_target_user": "@custodio_id"
}
```

## SLA de remediación
| Prioridad | Plazo |
|---|---|
| Crítica | 24–48 h |
| Alta | 7 días |
| Media / Baja | 15–30 días o monitoreo |

## Activos vulnerables de prueba (argus1)
- Redis 3.2.0 / 4.0.14 — puerto 6379, sin contraseña (CVSS 9.8)
- MySQL 5.5 / 5.7 — puerto 3306
- MongoDB — puerto 27017, certificado autofirmado
- Juice Shop — app web vulnerable

## Seguridad
- TLS 1.3 (ECDHE + AES-256-GCM) en toda comunicación REST y Kafka.
- HMAC-SHA3-256 sobre cada payload STIX antes de enviarlo a Kafka.
- Cifrado en reposo AES-256-XTS (disco de GCP).
- Secretos (API key de Anthropic, token de Slack, credenciales de iTop, llave HMAC) solo en variables de entorno. Nunca en el repo.

## Estructura del proyecto
TODO: describir paquetes (ej. `entity/`, `service/`, `client/`, `resource/`, `messaging/`).

## Comandos
- Dev: `./mvnw quarkus:dev` (TODO: confirmar si es Maven o Gradle)
- Tests: `./mvnw test`
- Build: `./mvnw package`
- Infraestructura: `docker compose up -d`

## Convenciones
- Código en inglés; documentación y comentarios para el equipo en español.
- Clientes externos con REST Client Reactive y timeouts explícitos.
- TODO: estilo de commits, ramas, etc.