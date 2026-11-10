# Contrato Kafka: `vulnerabilities-ingest`

Flujo: `POST /api/v1/ingest/nessus` (CSV) → `NessusParserService` → `VulnerabilityEventFactory` → `NessusKafkaProducer` → tópico `vulnerabilities-ingest` → **Agente de IA** (consumer group propio).

## Tópicos

| Tópico | Particiones | Retención | Uso |
|---|---|---|---|
| `vulnerabilities-ingest` | 3 | 7 días | Un mensaje por hallazgo Nessus con riesgo Medium/High/Critical |
| `vulnerabilities-ingest-dlq` | 1 | 30 días | El agente publica aquí los mensajes que no pueda procesar |

Bootstrap: `localhost:9092` desde el host, `kafka:29092` desde contenedores de la misma red de Docker Compose.

## Registro

- **Key** (string): `nessus:{plugin_id}:{host_ip}:{port}`. Es estable por hallazgo: los re-escaneos del mismo hallazgo caen en la misma partición, en orden, y el agente puede deduplicar por key.
- **Headers** (UTF-8), para filtrar sin deserializar:

| Header | Valor |
|---|---|
| `content-type` | `application/json` |
| `argus-schema-version` | `1.0` |
| `argus-event-type` | `argus.vulnerability.ingested` |
| `stix-spec-version` | `2.1` |
| `argus-source` | `nessus` |
| `argus-scan-id` | UUID compartido por todos los eventos del mismo CSV |

- **Value**: JSON con este formato (los campos sin valor se omiten, nunca se envían como `null`). Ejemplo real: Redis sin contraseña en `argus1`:

```json
{
  "schema_version": "1.0",
  "event_type": "argus.vulnerability.ingested",
  "event_id": "7d1f…",
  "scan_id": "c0a8…",
  "ingested_at": "2026-11-10T01:07:56.123Z",
  "source":  { "scanner": "nessus", "file_name": "argus1_scan.csv", "plugin_id": "100634" },
  "finding": {
    "host_ip": "10.128.0.10", "port": 6379, "protocol": "tcp",
    "risk": "Critical", "cvss_score": 9.8, "cvss_version": "3.0",
    "synopsis": "The remote Redis server does not require authentication.",
    "solution": "Enable the 'requirepass' directive in the redis.conf configuration file.",
    "evidence": "Nessus was able to execute the 'INFO' command without authentication:\n\n  redis_version:4.0.14 …",
    "asset": { "resolution": "MATCHED", "id": 3, "name": "Redis Sesiones – Transporte", "criticality": "CRITICAL", "responsible_team": "Transporte" }
  },
  "stix": {
    "type": "bundle",
    "id": "bundle--…",
    "objects": [
      { "type": "identity", "id": "identity--6968fd0a-…", "name": "Argus Nessus Ingestor", "identity_class": "system", … },
      { "type": "vulnerability", "id": "vulnerability--…", "created_by_ref": "identity--6968fd0a-…",
        "name": "Redis Server Unprotected by Password Authentication", "description": "…",
        "external_references": [
          { "source_name": "nessus-plugin", "external_id": "100634", "url": "https://www.tenable.com/plugins/nessus/100634" },
          { "source_name": "advisory", "url": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/" }
        ] },
      { "type": "infrastructure", "id": "infrastructure--…", "name": "10.128.0.10:6379/tcp",
        "description": "Servicio expuesto detectado por Nessus en 10.128.0.10:6379/tcp", "last_seen": "…" },
      { "type": "relationship", "relationship_type": "has",
        "source_ref": "infrastructure--…", "target_ref": "vulnerability--…" },
      { "type": "ipv4-addr", "id": "ipv4-addr--2088db49-fed0-5905-8b3f-5a009a59b4c3", "value": "10.128.0.10" },
      { "type": "relationship", "relationship_type": "consists-of",
        "source_ref": "infrastructure--…", "target_ref": "ipv4-addr--2088db49-…" }
    ]
  }
}
```

(Todos los objetos llevan `spec_version: "2.1"`. Los SDO y SRO también llevan `created`/`modified` con precisión de milisegundos y `created_by_ref`; se omiten arriba por brevedad.)

### Modelo STIX 2.1

```
infrastructure (IP:puerto/protocolo) --has---------> vulnerability (plugin Nessus + CVEs)
infrastructure                       --consists-of-> ipv4-addr / ipv6-addr
```

- **`vulnerability`**: un objeto por hallazgo. Nessus exporta **una fila por CVE**, y el parser las agrupa por (plugin, host, puerto, protocolo), así que un MySQL 5.5 con 3 CVEs genera **un** evento con 3 `external_references` de tipo `cve`. Los hallazgos sin CVE (Redis sin contraseña, certificado SSL autofirmado) quedan identificados por el plugin de Nessus.
- **`infrastructure`**: el servicio expuesto. Como los contenedores de `argus1` comparten IP, el `name` (`IP:puerto/protocolo`) es la llave con el activo de iTop. En los hallazgos a nivel de host (puerto 0) el `name` es solo la IP.
- **`ipv4-addr` / `ipv6-addr`**: su id es determinista (UUIDv5 de STIX), así que la misma IP tiene el mismo id en todos los escaneos y sirve para correlacionar. No se genera si el host es un FQDN sin IP.
- Los SDO y SRO usan UUIDv4 nuevos en cada escaneo. Para correlacionar entre escaneos, usa la key de Kafka.
- `stix` es un bundle STIX 2.1 válido: se puede pasar tal cual a `stix2.parse(...)` en Python.

### Campos de `finding`

Es el contexto del escaneo que STIX no modela. Es lo que el agente necesita para priorizar.

| Campo | Notas |
|---|---|
| `cve_id`, `cve_ids` | `cve_ids` trae todos los CVEs del hallazgo, y `cve_id` el primero. Ambos se omiten si no hay CVE (por lo tanto, EPSS = null). |
| `risk`, `cvss_score`, `cvss_version` | Para el score se usa CVSS v4.0, si no hay v3.0 y si no hay v2.0. Si la columna Risk viene vacía, el riesgo se deriva del CVSS. |
| `evidence` | "Plugin Output" de Nessus (versión detectada, certificado, etc.), truncado a 4000 caracteres. |
| `host_name` | FQDN, solo cuando el export trae las columnas `IP Address`/`FQDN`. |
| `asset.resolution` | Se resuelve por **IP + puerto** contra `asset_ips`. `MATCHED`: hay un activo registrado en ese IP:puerto o, si no, uno que abarca todo el host (`port = NULL`). `NOT_FOUND`: la IP no está registrada o solo lo está con otros puertos (el servicio no está inventariado). `AMBIGUOUS`: el inventario es contradictorio (dos activos distintos para todo el host). `NOT_CHECKED`: BD no disponible o enriquecimiento desactivado. |

Filtro: solo se publican hallazgos con riesgo ≥ `argus.nessus.min-risk` (por defecto `MEDIUM`).

## Garantías del productor

`acks=all` + `enable.idempotence=true`: el endpoint responde `202` solo cuando el broker confirmó todos los registros, y los reintentos no generan duplicados. La entrega hacia el consumidor es **at-least-once**, así que el agente debe ser idempotente usando `event_id` o la key.

## Versionado

Los cambios compatibles (agregar campos) mantienen `1.0`. Los cambios incompatibles suben `argus-schema-version`. El agente debe ignorar los campos que no conozca y mandar a la DLQ las versiones mayores que no soporte.

## Consumidor de referencia (Python)

```python
# pip install confluent-kafka stix2
import json
from confluent_kafka import Consumer, Producer
import stix2

consumer = Consumer({
    "bootstrap.servers": "localhost:9092",
    "group.id": "argus-ai-agent",
    "auto.offset.reset": "earliest",
    "enable.auto.commit": False,
})
dlq = Producer({"bootstrap.servers": "localhost:9092"})
consumer.subscribe(["vulnerabilities-ingest"])

while True:
    msg = consumer.poll(1.0)
    if msg is None or msg.error():
        continue
    headers = {k: v.decode() for k, v in (msg.headers() or [])}
    try:
        if not headers.get("argus-schema-version", "").startswith("1."):
            raise ValueError("unsupported schema version")
        event = json.loads(msg.value())
        bundle = stix2.parse(event["stix"], allow_custom=True)
        vuln = next(o for o in bundle.objects if o.type == "vulnerability")
        # -> agente de IA: vuln + event["finding"] (host, cvss, criticidad del activo)
    except Exception as exc:
        dlq.produce("vulnerabilities-ingest-dlq", msg.value(), key=msg.key(),
                    headers=list((msg.headers() or [])) + [("error", str(exc).encode())])
        dlq.flush()
    consumer.commit(msg)
```

## Probar localmente

```bash
docker compose -f docker-compose.messaging.yml up -d kafka kafka-init kafka-ui mysql
./mvnw quarkus:dev
curl -F "file=@src/test/java/org/acme/resources/nessus_sample.csv" http://localhost:8081/api/v1/ingest/nessus
# Ver mensajes: http://localhost:8090 (Kafka UI) o:
docker exec argus-kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic vulnerabilities-ingest --from-beginning --property print.key=true --property print.headers=true
```
