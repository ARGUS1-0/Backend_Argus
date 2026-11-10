package org.acme.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import org.acme.domain.entity.AssetIp;
import org.acme.domain.stix.StixTimestamps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PushbackReader;
import java.io.Reader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parsea exportaciones CSV de Nessus a hallazgos con su grafo STIX 2.1
 * (vulnerability + infrastructure + ip + relationships).
 *
 * <ul>
 *   <li>Nessus exporta una fila por CVE: las filas se agregan por (plugin, host, puerto, protocolo).</li>
 *   <li>Se descartan hallazgos por debajo de {@code argus.nessus.min-risk} (por defecto MEDIUM) para reducir ruido.</li>
 *   <li>Hallazgos sin CVE (Redis sin contraseña, certificados SSL autofirmados...) se modelan igual,
 *       identificados por el plugin de Nessus.</li>
 * </ul>
 */
@ApplicationScoped
public class NessusParserService {
    static final int MAX_PLUGIN_OUTPUT = 4000;

    private static final String[] CVSS_COLUMNS = {
            "CVSS v4.0 Base Score", "CVSS v3.0 Base Score", "CVSS v2.0 Base Score"};
    private static final String[] CVSS_VERSIONS = {"4.0", "3.0", "2.0"};
    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL = Pattern.compile("https?://\\S+");

    @Inject
    EntityManager entityManager;

    @ConfigProperty(name = "argus.nessus.min-risk", defaultValue = "MEDIUM")
    NessusFinding.Risk minRisk;

    /** Lee un CSV UTF-8 de Nessus (con o sin BOM). Consume y cierra el stream. */
    public List<NessusFinding> parse(InputStream input) throws IOException {
        CSVFormat format = CSVFormat.RFC4180.builder()
                .setHeader()
                .setSkipHeaderRecord(true)
                .setIgnoreEmptyLines(true)
                .setIgnoreHeaderCase(true)
                .setTrim(true)
                .build();

        NessusFinding.Risk threshold = minRisk == null ? NessusFinding.Risk.MEDIUM : minRisk;
        Map<String, NessusFinding> findings = new LinkedHashMap<>();
        try (CSVParser parser = CSVParser.parse(skipBom(input), format)) {
            requireHeaders(parser);
            for (CSVRecord row : parser) {
                NessusFinding parsed = parseRow(row);
                if (parsed.riskLevel == null || parsed.riskLevel.compareTo(threshold) < 0) continue;
                findings.merge(aggregationKey(parsed), parsed, NessusParserService::mergeRows);
            }
        }

        String timestamp = StixTimestamps.now();
        List<NessusFinding> result = new ArrayList<>(findings.values());
        for (NessusFinding finding : result) {
            finding.cveId = finding.cveIds.isEmpty() ? null : finding.cveIds.iterator().next();
            NessusStixMapper.map(finding, timestamp);
        }
        return result;
    }

    public List<NessusFinding> parse(Path csvPath) throws IOException {
        try (InputStream input = Files.newInputStream(csvPath)) {
            return parse(input);
        }
    }

    /** Parsea un archivo y asocia cada hallazgo con su activo usando asset_ips (IP + puerto). */
    @Transactional
    public List<NessusFinding> parseAndResolveAssets(Path csvPath) throws IOException {
        return resolveAssets(parse(csvPath));
    }

    /**
     * Resuelve el activo de cada hallazgo por IP + puerto (ver {@link AssetMatcher}). Hace una sola consulta
     * para todas las IPs del archivo.
     */
    @Transactional
    public List<NessusFinding> resolveAssets(List<NessusFinding> findings) {
        Set<String> ips = findings.stream()
                .map(f -> f.hostIp).filter(Objects::nonNull).collect(Collectors.toSet());
        Map<String, List<AssetIp>> rowsByIp = ips.isEmpty() ? Map.of() : entityManager.createQuery(
                        "select ai from AssetIp ai join fetch ai.asset where ai.ipAddress in :ips", AssetIp.class)
                .setParameter("ips", ips)
                .getResultList().stream()
                .collect(Collectors.groupingBy(ai -> ai.ipAddress));

        for (NessusFinding finding : findings) {
            AssetMatcher.Match match = AssetMatcher.match(rowsByIp.get(finding.hostIp), finding.port);
            finding.asset = match.asset();
            finding.assetResolution = match.resolution();
        }
        return findings;
    }

    private static Reader skipBom(InputStream input) throws IOException {
        PushbackReader reader = new PushbackReader(new InputStreamReader(input, StandardCharsets.UTF_8), 1);
        int first = reader.read();
        if (first != -1 && first != '﻿') reader.unread(first);
        return reader;
    }

    private static void requireHeaders(CSVParser parser) throws IOException {
        Map<String, Integer> headers = parser.getHeaderMap();
        if (headers == null) throw new IOException("Nessus CSV is empty");
        for (String header : List.of("Plugin ID", "Host", "Port", "Name")) {
            if (!headers.containsKey(header)) {
                throw new IOException("Nessus CSV is missing required column: " + header);
            }
        }
        if (!headers.containsKey("Risk") && !headers.containsKey("Risk Factor")) {
            throw new IOException("Nessus CSV must contain Risk or Risk Factor");
        }
    }

    private static NessusFinding parseRow(CSVRecord row) throws IOException {
        long line = row.getRecordNumber();
        NessusFinding finding = new NessusFinding();
        finding.pluginId = value(row, "Plugin ID");
        finding.name = value(row, "Name");
        if (finding.pluginId == null || finding.name == null) {
            throw new IOException("Missing Plugin ID or Name at CSV record " + line);
        }

        // Exports recientes traen "IP Address" y "Host" como FQDN; los clásicos solo "Host" (IP).
        String ipColumn = value(row, "IP Address");
        String host = value(row, "Host");
        finding.hostIp = ipColumn != null ? ipColumn : host;
        finding.hostName = firstNonBlank(value(row, "FQDN"), ipColumn != null && host != null && !host.equals(ipColumn) ? host : null);
        if (finding.hostIp == null) throw new IOException("Missing Host at CSV record " + line);

        finding.port = parsePort(value(row, "Port"), line);
        String protocol = value(row, "Protocol");
        finding.protocol = protocol == null ? null : protocol.toLowerCase(Locale.ROOT);
        finding.synopsis = value(row, "Synopsis");
        finding.description = value(row, "Description");
        finding.solution = value(row, "Solution");
        finding.pluginOutput = truncate(value(row, "Plugin Output"));
        finding.cveIds.addAll(cves(value(row, "CVE")));
        finding.seeAlso.addAll(urls(value(row, "See Also")));

        for (int i = 0; i < CVSS_COLUMNS.length && finding.cvssScore == null; i++) {
            finding.cvssScore = parseScore(value(row, CVSS_COLUMNS[i]), line);
            if (finding.cvssScore != null) finding.cvssVersion = CVSS_VERSIONS[i];
        }

        finding.risk = firstNonBlank(value(row, "Risk"), value(row, "Risk Factor"));
        finding.riskLevel = NessusFinding.Risk.parse(finding.risk);
        if (finding.riskLevel == null) {
            finding.riskLevel = NessusFinding.Risk.fromCvss(finding.cvssScore);
            if (finding.riskLevel != null) finding.risk = capitalize(finding.riskLevel.name());
        }
        return finding;
    }

    private static NessusFinding mergeRows(NessusFinding existing, NessusFinding next) {
        existing.cveIds.addAll(next.cveIds);
        existing.seeAlso.addAll(next.seeAlso);
        if (existing.cvssScore == null && next.cvssScore != null) {
            existing.cvssScore = next.cvssScore;
            existing.cvssVersion = next.cvssVersion;
        }
        if (next.riskLevel != null && next.riskLevel.compareTo(existing.riskLevel) > 0) {
            existing.riskLevel = next.riskLevel;
            existing.risk = next.risk;
        }
        if (existing.pluginOutput == null) existing.pluginOutput = next.pluginOutput;
        return existing;
    }

    private static String aggregationKey(NessusFinding finding) {
        return finding.pluginId + "|" + finding.hostIp + "|" + finding.port + "|" + finding.protocol;
    }

    private static List<String> cves(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) return result;
        Matcher matcher = CVE.matcher(value);
        while (matcher.find()) result.add(matcher.group().toUpperCase(Locale.ROOT));
        return result;
    }

    private static List<String> urls(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) return result;
        Matcher matcher = URL.matcher(value);
        while (matcher.find()) result.add(matcher.group());
        return result;
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_PLUGIN_OUTPUT) return value;
        return value.substring(0, MAX_PLUGIN_OUTPUT) + "...[truncated]";
    }

    private static String capitalize(String value) {
        return value.charAt(0) + value.substring(1).toLowerCase(Locale.ROOT);
    }

    private static String firstNonBlank(String first, String fallback) {
        return first == null || first.isBlank() ? fallback : first;
    }

    private static String value(CSVRecord row, String column) {
        if (!row.isMapped(column) || !row.isSet(column)) return null;
        String value = row.get(column);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static Integer parsePort(String value, long rowNumber) throws IOException {
        if (value == null) return null;
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException ex) {
            throw new IOException("Invalid Port at CSV record " + rowNumber + ": " + value, ex);
        }
    }

    private static BigDecimal parseScore(String value, long rowNumber) throws IOException {
        if (value == null) return null;
        try {
            return new BigDecimal(value);
        } catch (NumberFormatException ex) {
            throw new IOException("Invalid CVSS score at CSV record " + rowNumber + ": " + value, ex);
        }
    }
}
