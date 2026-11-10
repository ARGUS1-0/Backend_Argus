package org.acme.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.acme.domain.stix.StixInfrastructure;
import org.acme.domain.stix.StixIpAddress;
import org.acme.domain.stix.StixObject;
import org.acme.domain.stix.StixRelationship;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class NessusParserServiceTest {
    private static final Path SAMPLE = Path.of("src/test/java/org/acme/resources/nessus_sample.csv");
    private static final Path ARGUS1 = Path.of("src/test/resources/nessus/argus1_scan.csv");

    private final NessusParserService parser = new NessusParserService();

    @Test
    void parsesSampleCsvAndMapsFindingsToStix() throws Exception {
        var findings = parser.parse(SAMPLE);

        assertEquals(2, findings.size(), "Low and None rows should be filtered out");
        var nginx = findings.get(0);
        assertEquals("112134", nginx.pluginId);
        assertEquals("CVE-2018-16843", nginx.cveId);
        assertEquals("10.128.0.5", nginx.hostIp);
        assertEquals(8080, nginx.port);
        assertEquals("Nginx 1.14.x < 1.15.6 HTTP/2 DoS", nginx.stix.name);
        assertEquals("vulnerability", nginx.stix.type);
        assertTrue(nginx.stix.id.startsWith("vulnerability--"));
        assertTrue(nginx.stix.external_references.stream()
                .anyMatch(ref -> "CVE-2018-16843".equals(ref.external_id)));

        var jenkins = findings.get(1);
        assertEquals("104743", jenkins.pluginId);
        assertEquals(new BigDecimal("9.8"), jenkins.cvssScore);
        assertEquals("3.0", jenkins.cvssVersion);
        assertEquals("Jenkins CLI RCE", jenkins.stix.name);
    }

    @Test
    void handlesEmptyCveAndFallsBackToCvssV2() throws Exception {
        String csv = "Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Port,Name,Description,CVSS v3.0 Base Score,Risk Factor\n"
                + "12345,,7.5,High,10.0.0.1,443,Test finding,Long description,,High\n";

        var findings = parse(csv);

        assertEquals(1, findings.size());
        var finding = findings.get(0);
        assertNull(finding.cveId);
        assertEquals(new BigDecimal("7.5"), finding.cvssScore);
        assertEquals("2.0", finding.cvssVersion);
        assertEquals("10.0.0.1", finding.hostIp);
        assertEquals("Test finding", finding.stix.name);
        assertFalse(finding.stix.external_references.stream()
                .anyMatch(ref -> "cve".equals(ref.source_name)));

        var entity = finding.toEntity(new ObjectMapper());
        assertEquals("Test finding", entity.title);
        assertEquals("HIGH", entity.iaSeverityLabel.name());
        assertEquals("Test finding", entity.stixPayload.get("name").asText());
    }

    @Test
    void parsesArgus1ScanWithBomAndAggregatesCveRows() throws Exception {
        Map<String, NessusFinding> byPlugin = parser.parse(ARGUS1).stream()
                .collect(Collectors.toMap(f -> f.pluginId, Function.identity()));

        // 11 filas: Redis x4 (1 sin auth + 3 CVE), Mongo x2, MySQL x2, None x1, Low x1 -> 5 hallazgos
        assertEquals(List.of("100634", "150105", "57582", "51192", "84729").stream().sorted().toList(),
                byPlugin.keySet().stream().sorted().toList());

        var redisCves = byPlugin.get("150105");
        assertEquals(List.of("CVE-2021-32626", "CVE-2021-32627", "CVE-2021-32628"), List.copyOf(redisCves.cveIds));
        assertEquals("CVE-2021-32626", redisCves.cveId);
        assertEquals(2, redisCves.seeAlso.size(), "Duplicate advisory URLs are collapsed");
        assertEquals(3, redisCves.stix.external_references.stream()
                .filter(ref -> "cve".equals(ref.source_name)).count());

        var mysql = byPlugin.get("84729");
        assertEquals(List.of("CVE-2015-2573", "CVE-2015-2582", "CVE-2015-4757"), List.copyOf(mysql.cveIds),
                "Comma-separated CVEs in a cell and CVEs across rows are merged");
    }

    @Test
    void redisWithoutAuthenticationHasNoCveButFullContext() throws Exception {
        NessusFinding redis = find(parser.parse(ARGUS1), "100634");

        assertTrue(redis.cveIds.isEmpty());
        assertNull(redis.cveId);
        assertEquals(NessusFinding.Risk.CRITICAL, redis.riskLevel);
        assertEquals(new BigDecimal("9.8"), redis.cvssScore);
        assertEquals("3.0", redis.cvssVersion);
        assertEquals(6379, redis.port);
        assertEquals("tcp", redis.protocol);
        assertTrue(redis.solution.contains("requirepass"));
        assertTrue(redis.pluginOutput.contains("redis_version:4.0.14"), "Multi-line plugin output is preserved");

        assertEquals("Redis Server Unprotected by Password Authentication", redis.stix.name);
        assertEquals("nessus-plugin", redis.stix.external_references.get(0).source_name);
        assertEquals("100634", redis.stix.external_references.get(0).external_id);
        assertEquals("CRITICAL", redis.toEntity(new ObjectMapper()).iaSeverityLabel.name());
    }

    @Test
    void sslCertificateFindingsKeepServiceEndpoint() throws Exception {
        NessusFinding selfSigned = find(parser.parse(ARGUS1), "57582");

        assertEquals(NessusFinding.Risk.MEDIUM, selfSigned.riskLevel);
        assertEquals(27017, selfSigned.port);
        assertTrue(selfSigned.pluginOutput.contains("CN=mongodb.argus.local"));
        StixInfrastructure infrastructure = only(selfSigned.stixObjects, StixInfrastructure.class);
        assertEquals("10.128.0.10:27017/tcp", infrastructure.name);
    }

    @Test
    void buildsInfrastructureIpAndRelationshipGraph() throws Exception {
        NessusFinding redis = find(parser.parse(ARGUS1), "100634");

        assertEquals(5, redis.stixObjects.size());
        StixInfrastructure infrastructure = only(redis.stixObjects, StixInfrastructure.class);
        StixIpAddress ip = only(redis.stixObjects, StixIpAddress.class);
        List<StixRelationship> relationships = redis.stixObjects.stream()
                .filter(StixRelationship.class::isInstance).map(StixRelationship.class::cast).toList();

        assertEquals("10.128.0.10:6379/tcp", infrastructure.name);
        assertEquals("ipv4-addr", ip.type);
        assertEquals("10.128.0.10", ip.value);
        assertTrue(relationships.stream().anyMatch(r -> "has".equals(r.relationship_type)
                && r.source_ref.equals(infrastructure.id) && r.target_ref.equals(redis.stix.id)));
        assertTrue(relationships.stream().anyMatch(r -> "consists-of".equals(r.relationship_type)
                && r.source_ref.equals(infrastructure.id) && r.target_ref.equals(ip.id)));
    }

    @Test
    void ipAddressIdIsDeterministicAcrossScans() throws Exception {
        String first = only(find(parser.parse(ARGUS1), "100634").stixObjects, StixIpAddress.class).id;
        String second = only(find(parser.parse(ARGUS1), "57582").stixObjects, StixIpAddress.class).id;
        assertEquals(first, second);
    }

    @Test
    void minRiskIsConfigurable() throws Exception {
        parser.minRisk = NessusFinding.Risk.LOW;
        assertNotNull(find(parser.parse(ARGUS1), "70658"), "Low findings are kept when min-risk=LOW");

        parser.minRisk = NessusFinding.Risk.CRITICAL;
        assertEquals(List.of("100634"), parser.parse(ARGUS1).stream().map(f -> f.pluginId).toList());
    }

    @Test
    void derivesRiskFromCvssWhenRiskColumnIsEmpty() throws Exception {
        var findings = parse("Plugin ID,CVE,Risk,Host,Port,Name,CVSS v3.0 Base Score\n"
                + "1,,,10.0.0.1,80,No risk label,9.1\n"
                + "2,,,10.0.0.1,81,Low score,2.0\n");

        assertEquals(1, findings.size());
        assertEquals(NessusFinding.Risk.CRITICAL, findings.get(0).riskLevel);
        assertEquals("Critical", findings.get(0).risk);
    }

    @Test
    void hostLevelFindingOnPortZeroUsesHostAsInfrastructureName() throws Exception {
        var finding = parse("Plugin ID,Risk,Host,Protocol,Port,Name\n"
                + "3,High,10.0.0.9,tcp,0,Host-level issue\n").get(0);
        assertEquals("10.0.0.9", only(finding.stixObjects, StixInfrastructure.class).name);
    }

    @Test
    void usesIpAddressColumnAndKeepsFqdnAsAlias() throws Exception {
        var finding = parse("Plugin ID,Risk,Host,IP Address,Port,Name\n"
                + "4,High,redis.argus.local,10.0.0.7,6379,Named host\n").get(0);

        assertEquals("10.0.0.7", finding.hostIp);
        assertEquals("redis.argus.local", finding.hostName);
        StixInfrastructure infrastructure = only(finding.stixObjects, StixInfrastructure.class);
        assertEquals(List.of("redis.argus.local"), infrastructure.aliases);
    }

    @Test
    void hostnameWithoutIpProducesNoIpObservable() throws Exception {
        var finding = parse("Plugin ID,Risk,Host,Port,Name\n5,High,web.argus.local,443,Hostname only\n").get(0);
        assertTrue(finding.stixObjects.stream().noneMatch(StixIpAddress.class::isInstance));
        assertEquals(3, finding.stixObjects.size(), "vulnerability + infrastructure + has");
    }

    @Test
    void rejectsCsvWithoutRequiredColumns() {
        IOException error = assertThrows(IOException.class, () -> parse("Plugin ID,Name\n1,x\n"));
        assertTrue(error.getMessage().contains("Host"));
    }

    @Test
    void rejectsInvalidPortWithRecordNumber() {
        IOException error = assertThrows(IOException.class,
                () -> parse("Plugin ID,Risk,Host,Port,Name\n1,High,10.0.0.1,abc,x\n"));
        assertTrue(error.getMessage().contains("record 1"));
    }

    private List<NessusFinding> parse(String csv) throws IOException {
        return parser.parse(new ByteArrayInputStream(csv.getBytes(StandardCharsets.UTF_8)));
    }

    private static NessusFinding find(List<NessusFinding> findings, String pluginId) {
        return findings.stream().filter(f -> pluginId.equals(f.pluginId)).findFirst()
                .orElseThrow(() -> new AssertionError("Plugin " + pluginId + " not found"));
    }

    private static <T extends StixObject> T only(List<StixObject> objects, Class<T> type) {
        List<T> matches = objects.stream().filter(type::isInstance).map(type::cast).toList();
        assertEquals(1, matches.size(), "Expected exactly one " + type.getSimpleName());
        return matches.get(0);
    }
}
