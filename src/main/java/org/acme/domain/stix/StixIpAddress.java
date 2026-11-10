package org.acme.domain.stix;

/**
 * STIX 2.1 Cyber-observable {@code ipv4-addr} / {@code ipv6-addr}. Los SCO no llevan created/modified ni
 * created_by_ref; su id es determinista (UUIDv5 sobre la propiedad {@code value}), ver {@link StixIds}.
 */
public class StixIpAddress extends StixObject {
    public String value;

    public StixIpAddress() {
    }

    public static StixIpAddress of(String ip) {
        StixIpAddress address = new StixIpAddress();
        address.type = ip.contains(":") ? "ipv6-addr" : "ipv4-addr";
        address.value = ip;
        address.id = StixIds.sco(address.type, "{\"value\":\"" + ip + "\"}");
        return address;
    }
}
