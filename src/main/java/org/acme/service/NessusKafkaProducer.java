package org.acme.service;

import io.smallrye.reactive.messaging.MutinyEmitter;
import io.smallrye.reactive.messaging.annotations.OnOverflow;
import io.smallrye.reactive.messaging.kafka.api.OutgoingKafkaRecordMetadata;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.acme.domain.event.VulnerabilityIngestEvent;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.eclipse.microprofile.reactive.messaging.Channel;
import org.eclipse.microprofile.reactive.messaging.Message;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletionStage;

/**
 * Publishes vulnerability events (STIX 2.1 bundle + scan context) to the {@code vulnerabilities-ingest} topic.
 *
 * <p>Routing metadata is duplicated in Kafka headers so consumers can filter or reject by schema version
 * without deserializing the payload.
 */
@ApplicationScoped
public class NessusKafkaProducer {
    public static final String CHANNEL = "vulnerability-ingest";

    static final String HEADER_CONTENT_TYPE = "content-type";
    static final String HEADER_SCHEMA_VERSION = "argus-schema-version";
    static final String HEADER_EVENT_TYPE = "argus-event-type";
    static final String HEADER_STIX_VERSION = "stix-spec-version";
    static final String HEADER_SOURCE = "argus-source";
    static final String HEADER_SCAN_ID = "argus-scan-id";

    @Inject
    @Channel(CHANNEL)
    @OnOverflow(value = OnOverflow.Strategy.BUFFER, bufferSize = 256)
    MutinyEmitter<VulnerabilityIngestEvent> emitter;

    /** Completes when the broker acknowledges the record (acks=all), fails if the send is nacked. */
    public CompletionStage<Void> publish(String key, VulnerabilityIngestEvent event) {
        if (event == null || event.stix == null) {
            throw new IllegalArgumentException("Event with a STIX bundle must not be null");
        }
        String messageKey = (key == null || key.isBlank()) ? event.event_id : key;

        RecordHeaders headers = new RecordHeaders();
        header(headers, HEADER_CONTENT_TYPE, "application/json");
        header(headers, HEADER_SCHEMA_VERSION, event.schema_version);
        header(headers, HEADER_EVENT_TYPE, event.event_type);
        header(headers, HEADER_STIX_VERSION, "2.1");
        header(headers, HEADER_SOURCE, event.source == null ? null : event.source.scanner);
        header(headers, HEADER_SCAN_ID, event.scan_id);

        OutgoingKafkaRecordMetadata<String> metadata = OutgoingKafkaRecordMetadata.<String>builder()
                .withKey(messageKey)
                .withHeaders(headers)
                .build();

        return emitter.sendMessage(Message.of(event).addMetadata(metadata)).subscribeAsCompletionStage();
    }

    private static void header(RecordHeaders headers, String name, String value) {
        if (value != null) headers.add(name, value.getBytes(StandardCharsets.UTF_8));
    }
}
