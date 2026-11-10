package org.acme.domain.stix;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/** STIX granular marking selector and marking-definition reference. */
// STIX 2.1 forbids null properties and empty lists.
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class StixGranularMarking {
    public String lang;
    public String marking_ref;
    public List<String> selectors;
}
