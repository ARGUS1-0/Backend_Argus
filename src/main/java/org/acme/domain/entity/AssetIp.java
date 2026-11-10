package org.acme.domain.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

/**
 * Punto de red de un activo. En argus1 todos los contenedores comparten IP, así que la llave para relacionar
 * un hallazgo con su activo es IP + puerto (p. ej. 10.128.0.10:6379 = "Redis Sesiones – Transporte").
 *
 * <p>{@code port = null} significa "todo el host": el activo es dueño de la IP completa y recibe los hallazgos
 * de cualquier puerto que no esté registrado explícitamente por otro activo.
 */
@Entity
@Table(name = "asset_ips",
    uniqueConstraints = @UniqueConstraint(name = "uq_asset_ip_port", columnNames = {"ip_address", "port"}),
    indexes = {
        @Index(name = "ix_asset_ip_address", columnList = "ip_address"),
        @Index(name = "ix_asset_ips_asset", columnList = "asset_id")})
public class AssetIp {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    public Asset asset;

    @Column(name = "ip_address", nullable = false, length = 45)
    public String ipAddress;

    /** Puerto del servicio (1-65535) o null si el activo abarca todo el host. */
    @Min(1)
    @Max(65535)
    @Column(name = "port")
    public Integer port;
}
