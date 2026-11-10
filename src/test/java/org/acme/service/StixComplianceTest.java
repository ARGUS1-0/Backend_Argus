package org.acme.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.acme.domain.stix.StixBundle;
import org.acme.domain.stix.StixIds;
import org.acme.domain.stix.StixIpAddress;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifica las reglas de STIX 2.1 que más fallan al serializar a mano, sobre los bundles reales que se publican
 * en Kafka. Incluye un roundtrip JSON -> objetos para asegurar que el agente puede deserializarlos.
 */
class StixComplianceTest {
    private static final String TIMESTAMP_MS = "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z";
    private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
    private static final Set<String> SCO_TYPES = Set.of("ipv4-addr", "ipv6-addr");
    private static final Map<String, Set<String>> ALLOWED_RELATIONSHIPS = Map.of(
            "has", Set.of("infrastructure->vulnerability"),
            "consists-of", Set.of("infrastructure->ipv4-addr", "infrastructure->ipv6-addr"));

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void everyPublishedBundleIsStix21Compliant() throws Exception {
        VulnerabilityEventFactory factory = new VulnerabilityEventFactory();
        int checked = 0;
        for (NessusFinding finding : new NessusParserService().parse(Path.of("src/test/resources/nessus/argus1_scan.csv"))) {
            JsonNode bundle = mapper.valueToTree(factory.create(finding, "scan", "argus1_scan.csv").stix);
            assertBundle(bundle);
            checked++;
        }
        assertEquals(5, checked);
    }

    @Test
    void bundleRoundTripsThroughPolymorphicDeserialization() throws Exception {
        NessusFinding finding = new NessusParserService()
                .parse(Path.of("src/test/resources/nessus/argus1_scan.csv")).get(0);
        StixBundle original = new VulnerabilityEventFactory().create(finding, "scan", "f.csv").stix;

        StixBundle copy = mapper.readValue(mapper.writeValueAsString(original), StixBundle.class);

        assertEquals(original.objects.size(), copy.objects.size());
        for (int i = 0; i < original.objects.size(); i++) {
            assertEquals(original.objects.get(i).getClass(), copy.objects.get(i).getClass());
            assertEquals(original.objects.get(i).id, copy.objects.get(i).id);
        }
    }

    /**
     * Vector calculado en Python igual que la librería stix2:
     * uuid5(UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), '{"value":"10.128.0.10"}')
     */
    @Test
    void ipv4IdMatchesStixReferenceAlgorithm() {
        assertEquals("ipv4-addr--2088db49-fed0-5905-8b3f-5a009a59b4c3", StixIpAddress.of("10.128.0.10").id);
    }

    @Test
    void uuid5MatchesRfc4122Example() {
        // RFC 4122 / Python uuid.uuid5(NAMESPACE_DNS, "python.org")
        assertEquals("886313e1-3b8a-5372-9b90-0c9aee199e5d",
                StixIds.uuid5(java.util.UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), "python.org").toString());
    }

    private static void assertBundle(JsonNode bundle) {
        assertEquals("bundle", bundle.get("type").asText());
        assertTrue(bundle.get("id").asText().matches("bundle--" + UUID));
        assertFalse(bundle.has("spec_version"), "STIX 2.1 bundles must not carry spec_version");

        Set<String> ids = new HashSet<>();
        Map<String, String> typeById = new java.util.HashMap<>();
        for (JsonNode object : bundle.get("objects")) {
            String type = object.get("type").asText();
            String id = object.get("id").asText();
            assertTrue(id.matches(type + "--" + UUID), "Invalid id " + id);
            assertTrue(ids.add(id), "Duplicate id " + id);
            typeById.put(id, type);
            assertEquals("2.1", object.get("spec_version").asText());
            assertNoNullsOrEmptyLists(object, id);

            if (SCO_TYPES.contains(type)) {
                for (String forbidden : new String[]{"created", "modified", "created_by_ref"}) {
                    assertFalse(object.has(forbidden), type + " is an SCO and must not have " + forbidden);
                }
                continue;
            }
            assertTrue(object.get("created").asText().matches(TIMESTAMP_MS), id + " created");
            assertTrue(object.get("modified").asText().matches(TIMESTAMP_MS), id + " modified");
            assertTrue(object.get("modified").asText().compareTo(object.get("created").asText()) >= 0);
            if (!"identity".equals(type)) {
                assertTrue(object.has("created_by_ref"), id + " should reference the producer identity");
            }
            switch (type) {
                case "vulnerability", "infrastructure", "identity" -> assertTrue(object.hasNonNull("name"), id + " name");
                case "relationship" -> {
                    assertTrue(object.hasNonNull("relationship_type"));
                    assertTrue(object.hasNonNull("source_ref"));
                    assertTrue(object.hasNonNull("target_ref"));
                }
                default -> fail("Unexpected STIX type " + type);
            }
            if (object.has("external_references")) {
                for (JsonNode ref : object.get("external_references")) {
                    assertTrue(ref.hasNonNull("source_name"));
                    assertTrue(ref.has("url") || ref.has("external_id") || ref.has("description"),
                            "external_reference needs url, external_id or description");
                }
            }
        }

        for (JsonNode object : bundle.get("objects")) {
            if (object.has("created_by_ref")) {
                assertTrue(ids.contains(object.get("created_by_ref").asText()), "Dangling created_by_ref");
            }
            if (!"relationship".equals(object.get("type").asText())) continue;
            String source = typeById.get(object.get("source_ref").asText());
            String target = typeById.get(object.get("target_ref").asText());
            assertNotNull(source, "Dangling source_ref");
            assertNotNull(target, "Dangling target_ref");
            String relationship = object.get("relationship_type").asText();
            assertTrue(ALLOWED_RELATIONSHIPS.getOrDefault(relationship, Set.of()).contains(source + "->" + target),
                    "Relationship not defined by STIX 2.1: " + source + " " + relationship + " " + target);
        }
    }

    private static void assertNoNullsOrEmptyLists(JsonNode node, String path) {
        assertFalse(node.isNull(), "STIX forbids null at " + path);
        if (node.isArray()) {
            assertFalse(node.isEmpty(), "STIX forbids empty lists at " + path);
            node.forEach(child -> assertNoNullsOrEmptyLists(child, path + "[]"));
        } else if (node.isObject()) {
            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> field = it.next();
                assertNoNullsOrEmptyLists(field.getValue(), path + "." + field.getKey());
            }
        }
    }
}
