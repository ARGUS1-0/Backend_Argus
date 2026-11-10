####
# Runtime-only Dockerfile para sanitek_backend (Quarkus JVM, Java 21).
# Requiere que ./mvnw package (o Cloud Build) haya generado target/quarkus-app/ antes.
####

FROM eclipse-temurin:21-jre

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

# Variables requeridas en runtime — inyectadas por Cloud Run (no hardcodear valores aqui)
ENV DB_USERNAME="" \
    DB_PASSWORD="" \
    DB_JDBC_URL="" \
    DB_SCHEMA_STRATEGY="" \
    FIREBASE_SERVICE_ACCOUNT_LOCATION=""

WORKDIR /deployments

COPY target/quarkus-app/lib/      lib/
COPY target/quarkus-app/*.jar     ./
COPY target/quarkus-app/app/      app/
COPY target/quarkus-app/quarkus/  quarkus/

EXPOSE 8080

ENTRYPOINT ["java", \
  "-Dquarkus.http.host=0.0.0.0", \
  "-Djava.util.logging.manager=org.jboss.logmanager.LogManager", \
  "-jar", "quarkus-run.jar"]
