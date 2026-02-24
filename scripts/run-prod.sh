#!/bin/sh

echo "=== Arrancando OAuth2Server en modo PRODUCCIÓN ==="
echo "JWT_SIGNING_KEY está definida: $(if [ -n \"$JWT_SIGNING_KEY\" ]; then echo \"SÍ\"; else echo \"NO\"; fi)"

export SPRING_PROFILES_ACTIVE=prod

exec java -jar /app/app.jar