# OAuth2Server

OAuth2Server es un servicio de autenticación y autorización basado en **Spring Boot**, diseñado para actuar como proveedor OAuth2 y emitir **tokens JWT** firmados. Su objetivo es centralizar la gestión de usuarios, roles y permisos dentro de un entorno de microservicios, ofreciendo un punto de entrada seguro y estandarizado para aplicaciones internas o externas.

El proyecto está preparado para ejecutarse tanto en **entornos locales** (H2, Docker) como en **producción** (PostgreSQL, Kubernetes), con migraciones gestionadas mediante **Flyway** y un despliegue completamente automatizado.

---

## ✨ Características principales

- **Servidor OAuth2 completo**  
  Implementación de los flujos:
  - **Authorization Code + PKCE** (para aplicaciones web/móviles)
  - **Client Credentials** (para M2M)

- **JWT firmado**  
  Tokens firmados con clave RSA, listos para validación en microservicios.

- **Gestión de usuarios**  
  - Entidad `UserEntity`  
  - Roles (`UserRole`)  
  - Contraseñas con **BCrypt**  
  - Endpoints REST para consulta y creación de usuarios

- **Migraciones Flyway**  
  - `V4__add_field_aplicacion.sql`  
  - `V5__add_user_field_app.sql`  
  Garantizan un esquema consistente en todos los entornos.

- **Base de datos flexible**  
  - **H2** en desarrollo (archivo persistente en `/data/oauth2db.mv.db`)  
  - **PostgreSQL** en producción

- **Despliegue en Kubernetes**  
  Incluye manifests completos:
  - Deployment
  - Service
  - PVC
  - Secrets
  - Ingress
  - Script de despliegue automatizado (`deploy.sh`)

- **Documentación automática**  
  Swagger UI habilitado mediante `SwaggerConfig` y `SwaggerUiConfig`.

---

## 📁 Estructura del proyecto

```
OAuth2Server/
├── Dockerfile
├── docker-compose.yml
├── generate-jwt-key.sh
├── COMMANDS.md
├── k8s/
│   ├── deployment.yaml
│   ├── deploy.sh
│   ├── ingress.yaml
│   ├── namespace.yaml
│   ├── pvc.yaml
│   ├── secrets.yaml
│   └── service.yaml
├── scripts/
│   ├── run-dev.sh
│   └── run-prod.sh
├── src/main/java/com/oauth/rest/
│   ├── Application.java
│   ├── config/
│   ├── controller/
│   ├── dto/
│   ├── exception/
│   ├── mapper/
│   ├── model/
│   ├── repository/
│   ├── security/
│   └── service/
└── src/main/resources/
    ├── application.properties
    ├── application-dev.properties
    ├── application-prod.properties
    ├── data.sql
    └── db/migration/
```

---

## 🚀 Ejecución local

### Con Maven

```bash
mvn clean package
java -jar target/OAuth2Server-0.0.1-SNAPSHOT.jar
```

### Con Spring Boot plugin

```bash
mvn spring-boot:run
```

---

## 🐳 Ejecución con Docker

### Construir imagen

```bash
docker build -t oauth2server .
```

### Ejecutar contenedor

```bash
docker run -p 8080:8080 oauth2server
```

---

## 🔐 Flujos OAuth2 soportados

### 1. Authorization Code + PKCE (Recomendado para usuarios)

Este es el flujo estándar para aplicaciones web y móviles. Requiere:

1. **Redireccionar al usuario al endpoint de autorización:**
```
http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=proveedor-oauth&
  redirect_uri=http://localhost:3000/callback&
  scope=openid%20profile%20read%20write&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

2. **El usuario se autentica en la página de login** (`/login`)

3. **Después del login, el servidor redirige al callback con el código:**
```
http://localhost:3000/callback?code=xxx
```

4. **Canjea el código por tokens:**
```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "proveedor-oauth:123456" \
  -d "grant_type=authorization_code" \
  -d "code=CODIGO_RECIBIDO" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  http://localhost:8080/oauth2/token
```

**Respuesta:**
```json
{
  "access_token": "eyJraWQiOi...",
  "id_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "xxx",
  "scope": "openid profile read write"
}
```

### 2. Client Credentials (M2M)

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "proveedor-oauth:123456" \
  -d "grant_type=client_credentials" \
  -d "scope=read write" \
  http://localhost:8080/oauth2/token
```

---

## 📝 Credenciales por defecto

Las credenciales del cliente OAuth2 y usuario se configuran en el archivo `.env`:

```properties
# Cliente OAuth2
OAUTH_CLIENT_ID=proveedor-oauth
OAUTH_CLIENT_SECRET=123456

# Usuario por defecto
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=Admin1
```

---

## ☸️ Despliegue en Kubernetes

El directorio `k8s/` contiene todo lo necesario para desplegar el servicio:

- `namespace.yaml`
- `secrets.yaml`
- `pvc.yaml`
- `deployment.yaml`
- `service.yaml`
- `ingress.yaml`
- `deploy.sh` (automatiza build → push → apply → restart)

### Despliegue completo

```bash
./k8s/deploy.sh
```

### Reiniciar el deployment

```bash
kubectl rollout restart deployment/oauth2-server -n auth
```

### Port-forward para pruebas locales

```bash
kubectl port-forward -n auth svc/oauth2-server 8080:8080
```

---

## 🗄️ Base de datos (H2 persistente)

El archivo de base de datos se guarda en:

```
/app/data/oauth2db.mv.db
```

### Copiar la BD desde el pod al host

```bash
kubectl cp auth/<POD>:/app/data/oauth2db.mv.db ./oauth2db.mv.db
```

### Copiar la BD desde el host al pod

```bash
kubectl cp ./oauth2db.mv.db auth/<POD>:/app/data/oauth2db.mv.db
```

---

## 🔑 Generar claves y contraseñas

### Generar clave JWT

```bash
./generate-jwt-key.sh
```

### Generar hash BCrypt

```bash
python3 - <<'PY'
import bcrypt
print(bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=10)).decode())
PY
```

---

## 📦 Variables de entorno en producción

Se definen en `k8s/secrets.yaml` (codificadas en base64):

- `jwt-signing-key` - Clave secreta para firmar tokens JWT
- `oauth-client-id` - ID del cliente OAuth2
- `oauth-client-secret` - Secreto del cliente OAuth2
- `oauth-redirect-uri` - URI de redirección OAuth2
- `oauth-audience` - Audience para JWT

Ejemplo:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-secrets
  namespace: auth
type: Opaque
data:
  jwt-signing-key: <base64>
  oauth-client-id: <base64>
  oauth-client-secret: <base64>
  oauth-redirect-uri: <base64>
  oauth-audience: <base64>
```

---

## 📄 Licencia

MIT

---
