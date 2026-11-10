package org.acme.domain.stix;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/** Generación de identificadores STIX 2.1 ({@code <type>--<UUID>}). */
public final class StixIds {
    /** Namespace oficial de STIX 2.1 para ids deterministas de SCO (sección 2.9 de la especificación). */
    static final UUID STIX_SCO_NAMESPACE = UUID.fromString("00abedb4-aa42-466c-9c01-fed23315a9b7");

    private StixIds() {
    }

    /** SDO/SRO: la especificación recomienda UUIDv4. */
    public static String random(String type) {
        return type + "--" + UUID.randomUUID();
    }

    /**
     * SCO: UUIDv5 sobre el JSON canónico (RFC 8785) de sus propiedades contribuyentes, para que la misma IP
     * produzca siempre el mismo id y el agente pueda correlacionar entre escaneos.
     */
    public static String sco(String type, String canonicalJson) {
        return type + "--" + uuid5(STIX_SCO_NAMESPACE, canonicalJson);
    }

    /** UUID versión 5 (RFC 4122, SHA-1). */
    public static UUID uuid5(UUID namespace, String name) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(ByteBuffer.allocate(16)
                    .putLong(namespace.getMostSignificantBits())
                    .putLong(namespace.getLeastSignificantBits())
                    .array());
            byte[] hash = sha1.digest(name.getBytes(StandardCharsets.UTF_8));
            hash[6] = (byte) ((hash[6] & 0x0f) | 0x50);
            hash[8] = (byte) ((hash[8] & 0x3f) | 0x80);
            ByteBuffer buffer = ByteBuffer.wrap(hash, 0, 16);
            return new UUID(buffer.getLong(), buffer.getLong());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-1 not available", ex);
        }
    }
}
