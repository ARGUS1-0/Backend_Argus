package org.acme.domain.stix;

import java.util.List;

/**
 * STIX 2.1 Infrastructure SDO. En Argus representa el servicio expuesto donde Nessus encontró el hallazgo
 * (host + puerto + protocolo), que es la llave para relacionarlo con el activo de la CMDB.
 */
public class StixInfrastructure extends StixObject {
    public String name;
    public String description;
    public List<String> infrastructure_types;
    public List<String> aliases;
    public String first_seen;
    public String last_seen;

    public StixInfrastructure() {
        this.type = "infrastructure";
    }
}
