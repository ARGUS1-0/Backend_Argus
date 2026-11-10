package org.acme.service;

import org.acme.domain.stix.StixExternalReference;
import org.acme.domain.stix.StixIds;
import org.acme.domain.stix.StixInfrastructure;
import org.acme.domain.stix.StixIpAddress;
import org.acme.domain.stix.StixObject;
import org.acme.domain.stix.StixRelationship;
import org.acme.domain.stix.StixVulnerability;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Traduce un hallazgo Nessus al grafo STIX 2.1:
 * <pre>
 *   infrastructure (host:puerto/proto) --has--------> vulnerability (plugin + CVEs)
 *   infrastructure                     --consists-of-> ipv4-addr / ipv6-addr
 * </pre>
 */
final class NessusStixMapper {
    /** Identity del productor; determinista para que todos los bundles la referencien igual. */
    static final String PRODUCER_IDENTITY_ID =
            "identity--" + UUID.nameUUIDFromBytes("argus:nessus-ingestor".getBytes(StandardCharsets.UTF_8));

    private static final Pattern IPV4 =
            Pattern.compile("^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");

    private NessusStixMapper() {
    }

    /** Llena {@code finding.stix} y {@code finding.stixObjects}. Todos los objetos comparten {@code timestamp}. */
    static void map(NessusFinding finding, String timestamp) {
        StixVulnerability vulnerability = vulnerability(finding, timestamp);
        StixInfrastructure infrastructure = infrastructure(finding, timestamp);

        List<StixObject> objects = new ArrayList<>();
        objects.add(vulnerability);
        objects.add(infrastructure);
        objects.add(relationship("has", infrastructure.id, vulnerability.id, timestamp));

        if (isIpAddress(finding.hostIp)) {
            StixIpAddress ip = StixIpAddress.of(finding.hostIp);
            objects.add(ip);
            objects.add(relationship("consists-of", infrastructure.id, ip.id, timestamp));
        }

        finding.stix = vulnerability;
        finding.stixObjects = objects;
    }

    private static StixVulnerability vulnerability(NessusFinding finding, String timestamp) {
        StixVulnerability vulnerability = new StixVulnerability();
        vulnerability.id = StixIds.random("vulnerability");
        vulnerability.created = timestamp;
        vulnerability.modified = timestamp;
        vulnerability.created_by_ref = PRODUCER_IDENTITY_ID;
        vulnerability.name = finding.name;
        vulnerability.description = firstNonBlank(finding.description, finding.synopsis);

        List<StixExternalReference> references = new ArrayList<>();
        for (String cve : finding.cveIds) {
            references.add(reference("cve", cve, "https://www.cve.org/CVERecord?id=" + cve));
        }
        if (finding.pluginId != null) {
            references.add(reference("nessus-plugin", finding.pluginId,
                    "https://www.tenable.com/plugins/nessus/" + finding.pluginId));
        }
        for (String url : finding.seeAlso) {
            references.add(reference("advisory", null, url));
        }
        vulnerability.external_references = references;
        return vulnerability;
    }

    private static StixInfrastructure infrastructure(NessusFinding finding, String timestamp) {
        String host = firstNonBlank(finding.hostIp, finding.hostName);
        boolean hasPort = finding.port != null && finding.port > 0;
        String endpoint = hasPort
                ? host + ":" + finding.port + (finding.protocol == null ? "" : "/" + finding.protocol)
                : host;

        StixInfrastructure infrastructure = new StixInfrastructure();
        infrastructure.id = StixIds.random("infrastructure");
        infrastructure.created = timestamp;
        infrastructure.modified = timestamp;
        infrastructure.created_by_ref = PRODUCER_IDENTITY_ID;
        infrastructure.name = endpoint;
        infrastructure.description = hasPort
                ? "Servicio expuesto detectado por Nessus en " + endpoint
                : "Host analizado por Nessus (hallazgo a nivel de host)";
        infrastructure.last_seen = timestamp;
        if (finding.hostName != null && !finding.hostName.equals(host)) {
            infrastructure.aliases = List.of(finding.hostName);
        }
        return infrastructure;
    }

    private static StixRelationship relationship(String type, String source, String target, String timestamp) {
        StixRelationship relationship = new StixRelationship();
        relationship.id = StixIds.random("relationship");
        relationship.created = timestamp;
        relationship.modified = timestamp;
        relationship.created_by_ref = PRODUCER_IDENTITY_ID;
        relationship.relationship_type = type;
        relationship.source_ref = source;
        relationship.target_ref = target;
        return relationship;
    }

    private static StixExternalReference reference(String source, String externalId, String url) {
        StixExternalReference reference = new StixExternalReference();
        reference.source_name = source;
        reference.external_id = externalId;
        reference.url = url;
        return reference;
    }

    static boolean isIpAddress(String value) {
        if (value == null) return false;
        return IPV4.matcher(value).matches() || (value.contains(":") && IPV6.matcher(value).matches());
    }

    private static String firstNonBlank(String first, String fallback) {
        return first == null || first.isBlank() ? fallback : first;
    }
}
