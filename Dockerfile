FROM eclipse-temurin:21-jdk-alpine

RUN apk add --no-cache bash

WORKDIR /app

COPY target/oauth2server-0.0.1-SNAPSHOT.jar /app/app.jar
COPY scripts/run-dev.sh /app/run-dev.sh
COPY scripts/run-prod.sh /app/run-prod.sh

# ✅ Copiar recursos estáticos y templates
COPY src/main/resources/static /app/static/
COPY src/main/resources/templates /app/templates/
COPY src/main/resources/application-dev.properties /app/
COPY src/main/resources/application-prod.properties /app/

# ✅ Copiar migraciones de Flyway
COPY src/main/resources/db/migration /app/db/migration/

RUN chmod +x /app/run-dev.sh /app/run-prod.sh
RUN mkdir -p /data

EXPOSE 8080 8443
ENTRYPOINT ["java", "-jar", "/app/app.jar"]