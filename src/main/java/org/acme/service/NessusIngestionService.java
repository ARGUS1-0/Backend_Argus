package org.acme.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.acme.domain.event.VulnerabilityIngestEvent;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Coordinates CSV parsing, asset resolution and bounded asynchronous publication of STIX events. */
@ApplicationScoped
public class NessusIngestionService {
    private static final Logger LOG = Logger.getLogger(NessusIngestionService.class);
    private static final int MAX_IN_FLIGHT = 32;

    public record IngestResult(String scanId, String topic, int published) {
    }

    @Inject
    NessusParserService parser;

    @Inject
    VulnerabilityEventFactory eventFactory;

    @Inject
    NessusKafkaProducer producer;

    @ConfigProperty(name = "mp.messaging.outgoing.vulnerability-ingest.topic", defaultValue = "vulnerabilities-ingest")
    String topic;

    @ConfigProperty(name = "argus.ingest.resolve-assets", defaultValue = "true")
    boolean resolveAssets;

    public CompletionStage<IngestResult> ingest(Path csvPath) throws IOException {
        try (InputStream input = Files.newInputStream(csvPath)) {
            return ingest(input, csvPath.getFileName().toString());
        }
    }

    /**
     * Parses a Nessus export and publishes one event per accepted finding. Must run on a worker thread:
     * parsing and asset lookup are blocking. The returned stage completes once every record is acked.
     */
    public CompletionStage<IngestResult> ingest(InputStream csv, String fileName) throws IOException {
        List<NessusFinding> findings = parser.parse(csv);
        if (resolveAssets) resolveAssetsBestEffort(findings);

        String scanId = UUID.randomUUID().toString();
        List<VulnerabilityIngestEvent> events = findings.stream()
                .map(finding -> eventFactory.create(finding, scanId, fileName))
                .toList();

        CompletableFuture<Void> chain = CompletableFuture.completedFuture(null);
        for (int start = 0; start < findings.size(); start += MAX_IN_FLIGHT) {
            int from = start;
            int to = Math.min(start + MAX_IN_FLIGHT, findings.size());
            chain = chain.thenCompose(ignored -> {
                CompletableFuture<?>[] sends = new CompletableFuture<?>[to - from];
                for (int i = from; i < to; i++) {
                    sends[i - from] = producer.publish(eventFactory.kafkaKey(findings.get(i)), events.get(i))
                            .toCompletableFuture();
                }
                return CompletableFuture.allOf(sends);
            });
        }

        return chain.thenApply(ignored -> {
            LOG.infof("Published %d STIX events from '%s' to topic %s (scan_id=%s)",
                    findings.size(), fileName, topic, scanId);
            return new IngestResult(scanId, topic, findings.size());
        });
    }

    /** Inventory enrichment must not block the pipeline: on DB failure events go out as NOT_CHECKED. */
    private void resolveAssetsBestEffort(List<NessusFinding> findings) {
        try {
            parser.resolveAssets(findings);
        } catch (RuntimeException ex) {
            LOG.warnf("Asset resolution skipped, publishing without inventory context: %s", ex.getMessage());
            for (NessusFinding finding : findings) {
                finding.asset = null;
                finding.assetResolution = NessusFinding.AssetResolution.NOT_CHECKED;
            }
        }
    }
}
