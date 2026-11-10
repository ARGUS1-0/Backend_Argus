-- Migración: relación hallazgo <-> activo por IP + puerto.
--
-- En argus1 todos los contenedores comparten IP, así que asset_ips necesita el puerto para saber
-- qué activo es dueño de cada hallazgo (10.128.0.10:6379 = Redis, 10.128.0.10:27017 = MongoDB...).
--
-- Cuándo correrla: en bases creadas antes de este cambio, con el backend detenido.
-- Hibernate (schema-management=update) agrega columnas pero NO elimina la unique vieja
-- uq_asset_ip (asset_id, ip_address), que impediría registrar dos puertos de un mismo activo.
-- En bases nuevas no hace falta: Hibernate crea el esquema correcto.
--
--   docker exec -i argus-mysql mysql -uargus -pargus_local argus_db < docs/migrations/2026-11-09_asset_ips_port.sql

-- 1) Columna port. NULL = el activo abarca todo el host (semántica de las filas existentes).
--    Índice propio para la FK de asset_id: hoy MySQL usa uq_asset_ip para respaldarla
--    y sin este índice no deja borrarla.
ALTER TABLE asset_ips
    ADD COLUMN port INT NULL AFTER ip_address,
    ADD INDEX ix_asset_ips_asset (asset_id),
    ADD CONSTRAINT ck_asset_ips_port CHECK (port IS NULL OR port BETWEEN 1 AND 65535);

-- 2) Unicidad: un mismo IP:puerto solo puede pertenecer a un activo.
ALTER TABLE asset_ips
    DROP INDEX uq_asset_ip,
    ADD CONSTRAINT uq_asset_ip_port UNIQUE (ip_address, port);

-- 3) Después de migrar, registrar los puertos de los activos de argus1. Ejemplo:
-- UPDATE asset_ips ai JOIN lyft_assets a ON a.id = ai.asset_id
--    SET ai.port = 6379 WHERE a.name = 'Redis Sesiones – Transporte';
