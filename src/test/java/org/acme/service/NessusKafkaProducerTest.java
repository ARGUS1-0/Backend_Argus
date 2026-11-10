package org.acme.service;

import io.smallrye.mutiny.Uni;
import io.smallrye.reactive.messaging.MutinyEmitter;
import io.smallrye.reactive.messaging.kafka.api.OutgoingKafkaRecordMetadata;
import org.acme.domain.event.VulnerabilityIngestEvent;
import org.apache.kafka.common.header.Headers;
import org.eclipse.microprofile.reactive.messaging.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class NessusKafkaProducerTest {
    private NessusKafkaProducer producer;
    private MutinyEmitter<VulnerabilityIngestEvent> emitter;
    private VulnerabilityIngestEvent event;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        emitter = mock(MutinyEmitter.class);
        when(emitter.sendMessage(any())).thenReturn(Uni.createFrom().voidItem());
        producer = new NessusKafkaProducer();
        producer.emitter = emitter;

        NessusFinding finding = new NessusParserService()
                .parse(Path.of("src/test/java/org/acme/resources/nessus_sample.csv")).get(0);
        event = new VulnerabilityEventFactory().create(finding, "scan-42", "nessus_sample.csv");
    }

    @Test
    @SuppressWarnings("unchecked")
    void publishesWithKeyAndRoutingHeaders() throws Exception {
        producer.publish("nessus:112134:10.128.0.5:8080", event).toCompletableFuture().get(1, TimeUnit.SECONDS);

        ArgumentCaptor<Message<VulnerabilityIngestEvent>> captor = ArgumentCaptor.forClass(Message.class);
        verify(emitter).sendMessage(captor.capture());
        Message<VulnerabilityIngestEvent> message = captor.getValue();
        assertSame(event, message.getPayload());

        OutgoingKafkaRecordMetadata<String> metadata =
                message.getMetadata(OutgoingKafkaRecordMetadata.class).orElseThrow();
        assertEquals("nessus:112134:10.128.0.5:8080", metadata.getKey());
        Headers headers = metadata.getHeaders();
        assertEquals("application/json", header(headers, "content-type"));
        assertEquals("1.0", header(headers, "argus-schema-version"));
        assertEquals("argus.vulnerability.ingested", header(headers, "argus-event-type"));
        assertEquals("2.1", header(headers, "stix-spec-version"));
        assertEquals("nessus", header(headers, "argus-source"));
        assertEquals("scan-42", header(headers, "argus-scan-id"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void fallsBackToEventIdWhenKeyMissing() {
        producer.publish(" ", event);

        ArgumentCaptor<Message<VulnerabilityIngestEvent>> captor = ArgumentCaptor.forClass(Message.class);
        verify(emitter).sendMessage(captor.capture());
        assertEquals(event.event_id,
                captor.getValue().getMetadata(OutgoingKafkaRecordMetadata.class).orElseThrow().getKey());
    }

    @Test
    void propagatesBrokerFailure() {
        when(emitter.sendMessage(any())).thenReturn(Uni.createFrom().failure(new IllegalStateException("nack")));
        var future = producer.publish("k", event).toCompletableFuture();
        assertTrue(future.isCompletedExceptionally());
    }

    @Test
    void rejectsEventWithoutStix() {
        event.stix = null;
        assertThrows(IllegalArgumentException.class, () -> producer.publish("k", event));
    }

    private static String header(Headers headers, String name) {
        return new String(headers.lastHeader(name).value(), StandardCharsets.UTF_8);
    }
}
