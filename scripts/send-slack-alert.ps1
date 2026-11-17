#requires -Version 5.1
<#
.SYNOPSIS
Envia una alerta ficticia de Argus a un canal de pruebas de Slack.
.DESCRIPTION
Requiere SLACK_BOT_TOKEN, SLACK_CHANNEL_ID y SLACK_CUSTODIAN_USER_ID.
Lee .env desde la raiz del backend. Las variables de entorno tienen prioridad.
Usa -DryRun para ver el JSON sin credenciales y sin enviar mensajes.
#>
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'

function Stop-SlackPoc {
    param([string]$Message)
    [Console]::Error.WriteLine("ERROR: $Message")
    exit 1
}

$config = @{
    SLACK_BOT_TOKEN = "$env:SLACK_BOT_TOKEN".Trim()
    SLACK_CHANNEL_ID = "$env:SLACK_CHANNEL_ID".Trim()
    SLACK_CUSTODIAN_USER_ID = "$env:SLACK_CUSTODIAN_USER_ID".Trim()
}
$envPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.env'
if (Test-Path -LiteralPath $envPath -PathType Leaf) {
    try {
        $envLines = [System.IO.File]::ReadAllLines($envPath)
    } catch {
        Stop-SlackPoc 'No se pudo leer .env. Revisa los permisos del archivo en la raiz del backend.'
    }
    foreach ($line in $envLines) {
        # Leer solo las tres claves de Slack; nunca ejecutar el contenido de .env.
        if ($line -cmatch '^\s*(?:export\s+)?(SLACK_BOT_TOKEN|SLACK_CHANNEL_ID|SLACK_CUSTODIAN_USER_ID)\s*=\s*(.*)$') {
            $key = $matches[1]
            $value = $matches[2].Trim()
            if ($config[$key]) { continue }
            if ($value.StartsWith('"') -or $value.StartsWith("'")) {
                if ($value -notmatch '^(["''])(.*?)\1\s*(?:#.*)?$') {
                    Stop-SlackPoc "Revisa las comillas de $key en .env."
                }
                $value = $matches[2]
            } else {
                $value = $value -replace '\s+#.*$', ''
            }
            $config[$key] = $value.Trim()
        }
    }
}

$channelId = $config['SLACK_CHANNEL_ID']
$custodianId = $config['SLACK_CUSTODIAN_USER_ID']

if ($DryRun) {
    if (-not $channelId) { $channelId = 'C0123456789' }
    if (-not $custodianId) { $custodianId = 'U0123456789' }
}

if ($channelId -cnotmatch '^[CG][A-Z0-9]+$') {
    Stop-SlackPoc 'Configura SLACK_CHANNEL_ID con el ID del canal de pruebas (C... o G...), no su nombre.'
}
if ($custodianId -cnotmatch '^[UW][A-Z0-9]+$') {
    Stop-SlackPoc 'Configura SLACK_CUSTODIAN_USER_ID con el ID del miembro custodio (U... o W...).'
}

$timestamp = [DateTime]::UtcNow.ToString('o')
$message = @"
:warning: *ARGUS | ALERTA DE PRUEBA*
*Vulnerabilidad:* Servicio expuesto sin autenticación (simulada).
*Criticidad:* ALTA
*CVSS:* 7.5 / 10 (simulado)
*Destinatario:* <@$custodianId>
*Recomendación de Mitigación:* Habilitar autenticación y restringir el acceso al servicio a usuarios y redes autorizados.
Fecha UTC: $timestamp
_Prueba de concepto con datos ficticios. No corresponde a un incidente real._
"@

$payload = [ordered]@{
    channel = $channelId
    text = $message
    mrkdwn = $true
    unfurl_links = $false
    unfurl_media = $false
} | ConvertTo-Json -Depth 5

if ($DryRun) {
    Write-Host 'Vista previa: no se envio ningun mensaje. Los IDs ausentes usan valores ficticios.'
    Write-Output $payload
    exit 0
}

$botToken = $config['SLACK_BOT_TOKEN']
if (-not $botToken.StartsWith('xoxb-')) {
    Stop-SlackPoc 'Configura SLACK_BOT_TOKEN con el Bot User OAuth Token (xoxb-...).'
}

try {
    $response = Invoke-RestMethod -Method Post `
        -Uri 'https://slack.com/api/chat.postMessage' `
        -Headers @{ Authorization = "Bearer $botToken" } `
        -ContentType 'application/json; charset=utf-8' `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) `
        -TimeoutSec 30
} catch {
    # No imprimir la excepcion completa, headers ni el token.
    $statusCode = $_.Exception.Response.StatusCode
    if ($statusCode) {
        if ([int]$statusCode -eq 429) {
            Stop-SlackPoc 'HTTP 429: limite de Slack alcanzado. Espera antes de repetir el envio.'
        }
        Stop-SlackPoc "Slack devolvio HTTP $([int]$statusCode). Revisa la conexion y la configuracion de la app."
    }
    Stop-SlackPoc 'No se pudo confirmar el envio (red o timeout). Revisa el canal antes de repetir para evitar duplicados.'
}

# Slack tambien devuelve errores con HTTP 200: siempre comprobar ok.
if ($response.ok -ne $true) {
    $reason = switch ($response.error) {
        'invalid_auth' { 'Token invalido: copia el Bot User OAuth Token de la app instalada.' }
        'token_revoked' { 'Token revocado: instala o autoriza nuevamente la app.' }
        'token_expired' { 'Token expirado: obten un nuevo token de la instalacion.' }
        'missing_scope' { 'Falta chat:write en Bot Token Scopes. Agregalo y reinstala la app.' }
        'not_in_channel' { 'Invita el bot al canal de pruebas antes de enviar.' }
        'no_permission' { 'El bot no tiene acceso. Agrega la app al canal de pruebas.' }
        'channel_not_found' { 'Revisa el ID del canal, el workspace del token y la membresia del bot.' }
        'is_archived' { 'El canal esta archivado. Usa un canal de pruebas activo.' }
        'ratelimited' { 'Limite de Slack alcanzado. Espera antes de repetir el envio.' }
        default { 'Slack rechazo el envio o devolvio una respuesta inesperada. Revisa la configuracion de la app.' }
    }
    Stop-SlackPoc $reason
}

Write-Output "Mensaje de prueba enviado. Canal: $($response.channel); ts: $($response.ts)"
