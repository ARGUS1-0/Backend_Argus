package org.acme.domain.stix;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

/** Base for STIX 2.1 Domain Objects used by the vulnerability feed. */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "type", visible = true)
@JsonSubTypes({
    @JsonSubTypes.Type(value = StixVulnerability.class, name = "vulnerability"),
    @JsonSubTypes.Type(value = StixIdentity.class, name = "identity"),
    @JsonSubTypes.Type(value = StixRelationship.class, name = "relationship"),
    @JsonSubTypes.Type(value = StixInfrastructure.class, name = "infrastructure"),
    @JsonSubTypes.Type(value = StixIpAddress.class, names = {"ipv4-addr", "ipv6-addr"})
})
// STIX 2.1 forbids null properties and empty lists.
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public abstract class StixObject {
    public String type;
    public String spec_version = "2.1";
    public String id;
    public String created;
    public String modified;
    public String created_by_ref;
    public Boolean revoked;
    public List<String> labels;
    public Integer confidence;
    public String lang;
    public List<StixExternalReference> external_references;
    public List<String> object_marking_refs;
    public List<StixGranularMarking> granular_markings;
    public Map<String, JsonNode> extensions;
}
