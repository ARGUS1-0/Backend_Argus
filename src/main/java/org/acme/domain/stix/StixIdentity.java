package org.acme.domain.stix;

import java.util.List;

/** STIX 2.1 Identity SDO, useful as created_by_ref in feed bundles. */
public class StixIdentity extends StixObject {
    public String name;
    public String description;
    public List<String> roles;
    public String identity_class;
    public List<String> sectors;
    public String contact_information;

    public StixIdentity() {
        this.type = "identity";
    }
}
