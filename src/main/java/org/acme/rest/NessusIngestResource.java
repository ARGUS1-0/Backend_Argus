package org.acme.rest;

import io.smallrye.common.annotation.Blocking;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.acme.service.NessusIngestionService;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

@Path("/api/v1/ingest")
public class NessusIngestResource {
    private static final Logger LOG = Logger.getLogger(NessusIngestResource.class);
    private static final long PUBLISH_TIMEOUT_SECONDS = 60;

    @Inject
    NessusIngestionService ingestionService;

    @POST
    @Path("/nessus")
    @Blocking
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Parse a Nessus CSV export and publish each Medium+ finding as a STIX 2.1 event to Kafka")
    public Response ingestNessus(@RestForm("file") FileUpload file) {
        if (file == null || file.uploadedFile() == null) {
            return error(Response.Status.BAD_REQUEST, "Multipart field 'file' with the Nessus CSV is required");
        }
        try (InputStream input = Files.newInputStream(file.uploadedFile())) {
            NessusIngestionService.IngestResult result = ingestionService.ingest(input, file.fileName())
                    .toCompletableFuture()
                    .get(PUBLISH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return Response.accepted(Map.of(
                    "scan_id", result.scanId(),
                    "topic", result.topic(),
                    "published", result.published())).build();
        } catch (IOException ex) {
            return error(Response.Status.BAD_REQUEST, ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return error(Response.Status.SERVICE_UNAVAILABLE, "Interrupted while publishing to Kafka");
        } catch (Exception ex) {
            Throwable cause = ex instanceof CompletionException || ex instanceof java.util.concurrent.ExecutionException
                    ? ex.getCause() : ex;
            LOG.error("Failed to publish Nessus findings to Kafka", cause);
            return error(Response.Status.SERVICE_UNAVAILABLE, "Kafka publication failed: " + cause);
        }
    }

    private static Response error(Response.Status status, String message) {
        return Response.status(status).entity(Map.of("error", String.valueOf(message))).build();
    }
}
