package org.acme.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.acme.domain.entity.Asset;
import org.acme.domain.entity.Vulnerability;
import org.acme.domain.stix.StixObject;
import org.acme.domain.stix.StixVulnerability;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Hallazgo Nessus agregado por (plugin, host, puerto, protocolo): Nessus exporta una fila por CVE,
 * aquí se consolidan en un único hallazgo con todos sus CVEs.
 */
public class NessusFinding {
    /**
     * MATCHED: la IP pertenece a un único activo. NOT_FOUND: a ninguno. AMBIGUOUS: a varios (p. ej. contenedores
     * que comparten IP en argus1, falta desambiguar por puerto). NOT_CHECKED: no se consultó o la BD falló.
     */
    public enum AssetResolution { NOT_CHECKED, MATCHED, NOT_FOUND, AMBIGUOUS }

    /** Escala de riesgo de Nessus, en orden ascendente. */
    public enum Risk {
        NONE, LOW, MEDIUM, HIGH, CRITICAL;

        public static Risk parse(String value) {
            if (value == null || value.isBlank()) return null;
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }

        /** Rangos cualitativos de CVSS v3/v4 (los mismos que usa Nessus). */
        public static Risk fromCvss(BigDecimal score) {
            if (score == null) return null;
            double s = score.doubleValue();
            if (s >= 9.0) return CRITICAL;
            if (s >= 7.0) return HIGH;
            if (s >= 4.0) return MEDIUM;
            if (s > 0.0) return LOW;
            return NONE;
        }
    }

    public String pluginId;
    /** Primer CVE, se conserva por compatibilidad con la entidad (columna cve_id). */
    public String cveId;
    public Set<String> cveIds = new LinkedHashSet<>();
    /** Texto original de Nessus (Critical, High, ...). */
    public String risk;
    public Risk riskLevel;
    public String hostIp;
    /** FQDN o nombre de host cuando el export lo incluye. */
    public String hostName;
    public Integer port;
    public String protocol;
    public BigDecimal cvssScore;
    /** "4.0", "3.0" o "2.0": versión de la que proviene {@link #cvssScore}. */
    public String cvssVersion;
    public String name;
    public String synopsis;
    public String description;
    public String solution;
    public Set<String> seeAlso = new LinkedHashSet<>();
    /** Evidencia del plugin (versión detectada, detalles del certificado...), truncada. */
    public String pluginOutput;

    /** SDO principal; también se persiste como stix_payload. */
    public StixVulnerability stix;
    /** Grafo STIX completo del hallazgo: vulnerability, infrastructure, ip, relationships. */
    public List<StixObject> stixObjects = new ArrayList<>();

    public Asset asset;
    public AssetResolution assetResolution = AssetResolution.NOT_CHECKED;

    public Vulnerability toEntity(ObjectMapper objectMapper) {
        Vulnerability entity = new Vulnerability();
        entity.cveId = cveId;
        entity.title = truncate(stix.name, 255);
        entity.cvssScore = cvssScore;
        entity.iaSeverityLabel = toSeverity(riskLevel);
        entity.stixPayload = objectMapper.valueToTree(stix);
        if (asset != null) entity.assets.add(asset);
        return entity;
    }

    private static Vulnerability.Severity toSeverity(Risk risk) {
        if (risk == null || risk == Risk.NONE) return Vulnerability.Severity.PENDING;
        return Vulnerability.Severity.valueOf(risk.name());
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
