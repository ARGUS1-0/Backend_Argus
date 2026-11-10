# Argus Backend

Esqueleto de backend basado en Quarkus. Maven conserva las dependencias del stack: REST/JSON, Hibernate ORM Panache, MySQL, Kafka, RabbitMQ y Firebase Admin.

## Requisitos

- JDK 21
- Docker Compose (para MySQL y brokers locales)

## Desarrollo local

1. Copia `.env.example` a `.env` y ajusta credenciales si hace falta. Quarkus Dev Mode no carga automáticamente `.env`; exporta esas variables en tu terminal o usa los valores locales por defecto de `application.properties`.
2. Inicia los servicios: `docker compose -f docker-compose.messaging.yml up -d`.
3. Ejecuta la aplicación: `./mvnw quarkus:dev` (Windows: `mvnw.cmd quarkus:dev`).

MySQL queda disponible en `localhost:3306`, RabbitMQ y su panel en `localhost:5672` / `localhost:15672`, Kafka (modo KRaft, sin ZooKeeper) en `localhost:9092` y Kafka UI en `http://localhost:8090`. El servicio `kafka-init` crea los tópicos `vulnerabilities-ingest` y `vulnerabilities-ingest-dlq`.

### Pipeline Nessus → Kafka (STIX 2.1)

`POST /api/v1/ingest/nessus` (multipart, campo `file`) parsea el CSV y publica un evento por hallazgo Medium+ en `vulnerabilities-ingest`. El contrato del mensaje para el Agente de IA está en [docs/kafka-stix-contract.md](docs/kafka-stix-contract.md).

Las carpetas de paquetes Java se mantienen como espacios de trabajo para el nuevo proyecto. Firebase es opcional; guarda el JSON de servicio fuera del repositorio y configura `FIREBASE_SERVICE_ACCOUNT_LOCATION` cuando lo uses.
