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

### Prueba de concepto: alertas por Slack

La [guía de Slack](docs/slack-poc.md) explica cómo crear la app, obtener el bot
token, configurar un canal de pruebas y enviar una alerta ficticia mencionando
al custodio. El script funciona con PowerShell 5.1 o superior sin iniciar el backend.
Guarda `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID` y `SLACK_CUSTODIAN_USER_ID` en el
archivo `.env` de `Backend_Argus`; el script los carga automáticamente.
`.env.example` es la plantilla: los valores reales van en `.env`, ignorado por Git.
Las variables de entorno no vacías tienen prioridad sobre el archivo.

Desde la terminal del backend, envía la alerta con:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\send-slack-alert.ps1
```

Añade `-DryRun` al comando si solo quieres ver el mensaje sin enviarlo.
