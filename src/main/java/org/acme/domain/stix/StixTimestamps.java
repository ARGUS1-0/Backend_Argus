package org.acme.domain.stix;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** STIX 2.1 timestamps: RFC 3339, UTC "Z", exactly millisecond precision for created/modified. */
public final class StixTimestamps {
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private StixTimestamps() {
    }

    public static String format(Instant instant) {
        return FORMAT.format(instant);
    }

    public static String now() {
        return format(Instant.now());
    }
}
