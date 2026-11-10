package org.acme.domain.stix;

/** STIX 2.1 Relationship SRO. */
public class StixRelationship extends StixObject {
    public String relationship_type;
    public String description;
    public String source_ref;
    public String target_ref;
    public String start_time;
    public String stop_time;

    public StixRelationship() {
        this.type = "relationship";
    }
}
