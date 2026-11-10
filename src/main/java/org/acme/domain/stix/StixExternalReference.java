package org.acme.domain.stix;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Reference to a CVE, advisory, or other external source. */
// STIX 2.1 forbids null properties and empty lists.
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class StixExternalReference {
    public String source_name;
    public String description;
    public String url;
    public String external_id;
    public String hash;
}
