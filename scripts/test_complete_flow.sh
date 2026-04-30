#!/bin/bash
# test_complete_flow.sh

# Configuración
CLIENT_ID="cine-platform"
CLIENT_SECRET="${CINE_PLATFORM_SECRET}"  # Asegúrate que esta variable está exportada
REDIRECT_URI="http://localhost:5000/oauth/callback"

echo "🔐 FLUJO OAuth2 COMPLETO"
echo "========================"

# 1. Generar code_verifier y code_challenge
echo "1️⃣ Generando PKCE..."
code_verifier=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-' | cut -c1-43)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
echo "   Code Verifier: $code_verifier"
echo "   Code Challenge: $code_challenge"

# 2. Construir URL de autorización
AUTH_URL="http://localhost:8080/oauth2/authorize"
PARAMS="response_type=code"
PARAMS="$PARAMS&client_id=$CLIENT_ID"
PARAMS="$PARAMS&redirect_uri=$REDIRECT_URI"
PARAMS="$PARAMS&scope=openid"
PARAMS="$PARAMS&code_challenge=$code_challenge"
PARAMS="$PARAMS&code_challenge_method=S256"
PARAMS="$PARAMS&state=$(openssl rand -hex 8)"

FULL_URL="$AUTH_URL?$PARAMS"
echo "2️⃣ URL de autorización (ábrela en el navegador):"
echo "   $FULL_URL"
echo
read -p "3️⃣ Pega el código de autorización de la URL: " auth_code

# 3. Canjear code por tokens
echo "4️⃣ Canjeando code por tokens..."
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$auth_code" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "code_verifier=$code_verifier" \
  -v
