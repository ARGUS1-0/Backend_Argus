# Prueba de concepto: alerta al custodio por Slack

Objetivo: configurar una app de Slack y enviar una alerta ficticia al canal
`#argus-alerta-pruebas`, mencionando al custodio del riesgo. Para la demo puedes
usar tu propio usuario como custodio.

El script [`scripts/send-slack-alert.ps1`](../scripts/send-slack-alert.ps1) usa
`POST https://slack.com/api/chat.postMessage` con un bot token. Se ejecuta desde
PowerShell 5.1 o superior y no requiere iniciar Quarkus, MySQL, Kafka ni Docker.
Esta POC valida el envío a Slack; la conexión con el pipeline de riesgos queda
para la integración posterior.

## 1. Crear la app y obtener el token

1. Inicia sesión en tu workspace y abre [Your Apps](https://api.slack.com/apps).
   Si aún no tienes workspace, crea uno de pruebas en Slack primero.
2. Pulsa **Create New App**, elige la creación manual (puede aparecer como
   **Pick features**, **Blank app** o **From scratch**), nómbrala
   **Argus Alertas POC** y selecciona tu workspace de pruebas. Completa la creación.
3. En **OAuth & Permissions → Scopes → Bot Token Scopes**, agrega `chat:write`.
   Es suficiente para publicar en un canal al que añadas el bot manualmente.
4. Pulsa **Install to Workspace → Allow**. Si tu workspace exige aprobación,
   el administrador debe autorizar la instalación.
5. En **OAuth & Permissions**, copia el **Bot User OAuth Token** que empieza
   con `xoxb-`. Ese es el secreto que necesita el script.

No necesitas Client Secret, Signing Secret, token `xapp-`, webhooks, una URL
pública ni Event Subscriptions para este envío. Si cambias los permisos,
reinstala la app para que el token tenga los nuevos permisos.

Referencia: [creación e instalación de apps de Slack](https://docs.slack.dev/app-management/quickstart-app-settings/).

## 2. Crear el canal y copiar los IDs

1. En Slack crea el canal **argus-alerta-pruebas** y añade a la persona que
   actuará como custodio.
2. Añade también la app **Argus Alertas POC** al canal: abre el nombre del canal
   y busca **Integrations / Integraciones → Add apps / Añadir aplicaciones**.
   También puedes usar `/invite` y seleccionar el bot.
3. Copia el **ID del canal** desde sus detalles. Otra opción es abrir el canal
   en Slack web: en una URL como `https://app.slack.com/client/T0123456789/C0123456789`,
   el ID del canal es `C0123456789`, no el valor que comienza por `T`.
4. Abre el perfil del custodio, pulsa **⋯ / Más → Copy member ID / Copiar ID del
   miembro**. Usa ese ID (`U...` o `W...`), no su nombre ni su correo.

El script construye la mención como `<@ID_DEL_MIEMBRO>`. La alerta se publica
en el canal de pruebas; no es un mensaje directo privado.

Referencias: [crear un canal](https://slack.com/help/articles/201402297-Create-a-channel),
[copiar el ID de un miembro](https://slack.com/help/articles/360003827751-Create-a-link-to-a-members-profile).

## 3. Ejecutar la prueba en Windows

Abre PowerShell en la carpeta `Backend/Backend_Argus`. Si ya estás ahí, no
necesitas cambiar de carpeta.

Guarda la configuración en el archivo **`.env`** de esa carpeta. Si aún no
existe, puedes crearlo copiando la plantilla sin sobrescribir un `.env` existente:

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
```

En tu editor, completa estas tres líneas de `.env` con tus valores reales:

```dotenv
SLACK_BOT_TOKEN=xoxb-TU_TOKEN_REAL
SLACK_CHANNEL_ID=C_ID_REAL_DEL_CANAL
SLACK_CUSTODIAN_USER_ID=U_ID_REAL_DEL_CUSTODIO
```

Usa el **Bot User OAuth Token**, el ID de `#argus-alerta-pruebas` y el ID de la
persona que recibirá la mención. `.env.example` es solo la plantilla compartida;
guarda los valores reales en **`.env`**, que está ignorado por Git. Guarda el
archivo antes de ejecutar el comando.

El script carga automáticamente esas tres variables de `.env`, localizado junto
al `pom.xml` del backend. Admite valores simples o entre comillas y no ejecuta
su contenido como código. Si ya exportaste alguna de esas variables en tu
terminal y tiene un valor no vacío, ese valor tiene prioridad sobre `.env`.

Para enviar **un mensaje real** al canal configurado, ejecuta:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\send-slack-alert.ps1
```

Opcionalmente, puedes ver el mensaje sin enviarlo añadiendo `-DryRun`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\send-slack-alert.ps1 -DryRun
```

La excepción de ejecución de scripts solo aplica al proceso de ese comando;
no cambia la política permanente del equipo. No necesitas iniciar Quarkus ni
exportar variables manualmente cuando ya están configuradas en `.env`.

El token se usa en el header `Authorization: Bearer ...`, nunca dentro del mensaje.
No lo subas al repositorio ni lo incluyas en capturas o en el reporte de la POC.

## 4. Resultado y evidencia de la entrega

La consola solo anuncia éxito si Slack devuelve `ok: true`:

```text
Mensaje de prueba enviado. Canal: C...; ts: ...
```

En el canal aparecerá **ARGUS | ALERTA DE PRUEBA** con estos cinco campos:

- **Vulnerabilidad:** Servicio expuesto sin autenticación (simulada).
- **Criticidad:** ALTA.
- **CVSS:** 7.5 / 10 (simulado).
- **Destinatario:** mención real del custodio configurado.
- **Recomendación de Mitigación:** Habilitar autenticación y restringir el
  acceso al servicio a usuarios y redes autorizados.

El mensaje también incluye la fecha y el aviso de que los datos son ficticios
y no corresponden a un incidente real.

Para documentar la POC guarda:

- Captura del permiso `chat:write`, sin mostrar el token.
- Captura del canal con el bot y el custodio agregados.
- Captura del mensaje recibido y su mención al custodio.
- Salida de consola con el ID del canal y el `ts` de Slack.

El modo `-DryRun` solo comprueba la preparación del mensaje. La POC se considera
validada de extremo a extremo cuando el envío real tiene éxito y ves la alerta
en Slack. La mención visible no garantiza una notificación push: depende de las
preferencias del custodio.

## Problemas habituales

| Error | Qué revisar |
| --- | --- |
| Variable faltante o ID inválido | Reemplaza los ejemplos por IDs reales; no uses `#nombre` ni `@nombre`. |
| `invalid_auth`, `token_revoked`, `token_expired` | Usa un bot token vigente de la app instalada en ese workspace. |
| `missing_scope` | Agrega `chat:write` a **Bot Token Scopes** y reinstala la app. |
| `not_in_channel`, `no_permission` | Añade el bot al canal, también si el canal es privado. |
| `channel_not_found` | Comprueba ID, workspace y acceso del bot al canal. |
| `is_archived` | Usa un canal activo. |
| HTTP 429 o `ratelimited` | Espera antes de repetir; Slack indica el plazo en `Retry-After`. |
| Error de red o timeout | Revisa primero el canal: el envío pudo completarse aunque se perdiera la respuesta. |

Slack puede devolver HTTP 200 con `ok: false`; el script trata ese caso como
fallo y termina con código 1. No reintenta automáticamente para evitar duplicados.
Referencia: [`chat.postMessage`](https://docs.slack.dev/reference/methods/chat.postMessage/).
