package org.acme.domain.stix;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** STIX 2.1 Bundle container. A Bundle is not itself a STIX Domain Object. */
// STIX 2.1 forbids null properties and empty lists.
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class StixBundle {
    public String type = "bundle";
    public String id;
    @JsonProperty("objects")
    public List<StixObject> objects;
}
