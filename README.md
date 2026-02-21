# OAuth2Server

OAuth2Server es un servicio de autenticación y autorización basado en **Spring Boot**, diseñado para actuar como proveedor OAuth2 y emitir **tokens JWT** firmados. Su objetivo es centralizar la gestión de usuarios, roles y permisos dentro de un entorno de microservicios, ofreciendo un punto de entrada seguro y estandarizado para aplicaciones internas o externas.

El proyecto está preparado para ejecutarse tanto en **entornos locales** (H2, Docker) como en **producción** (PostgreSQL, Kubernetes), con migraciones gestionadas mediante **Flyway** y un despliegue completamente automatizado.

---

## ✨ Características principales

- **Servidor OAuth2 completo**  
  Implementación de los flujos:
  - *Password Grant*
  - *Client Credentials*

- **JWT firmado**  
  Tokens firmados con clave configurable (HMAC), listos para validación en microservicios.

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

## 🔐 Obtener un token OAuth2

### 📋 Requisitos previos

Antes de obtener un token, asegúrate de que:
1. La aplicación esté corriendo en el puerto 8080 (o el puerto configurado)
2. La base de datos tenga usuarios inicializados (el usuario `admin` se crea automáticamente)

### 🚀 Iniciar la aplicación

```bash
# En desarrollo
mvn spring-boot:run
```

O si hay conflictos de puerto:
```bash
export SPRING_PROFILES_ACTIVE=dev
mvn spring-boot:run
```

### 🔑 Password Grant (Recomendado para usuarios finales)

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "proveedor-oauth:123456" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=Admin1" \
  -d "scope=read write" \
  http://localhost:8080/oauth/token
```

**Parámetros:**
- `grant_type`: Debe ser `"password"`
- `username`: Nombre de usuario (por defecto: `admin`)
- `password`: Contraseña del usuario (por defecto: `Admin1`)
- `scope`: scopes separados por espacio (por defecto: `read write`)

**Ejemplo de respuesta:**
```json
{
  "access_token": "eyJraWQiOiJmMGI3NTZmOS04ZTZjLTRhYWUtODBjMC04NjUzNzQ3NWZiOTMiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "read write"
}
```

### 🔐 Client Credentials (Para servicios/máquinas)

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "proveedor-oauth:123456" \
  -d "grant_type=client_credentials" \
  -d "scope=read write" \
  http://localhost:8080/oauth/token
```

**Ejemplo de respuesta:**
```json
{
  "access_token": "eyJraWQiOiJmMGI3NTZmOS04ZTZjLTRhYWUtODBjMC04NjUzNzQ3NWZiOTMiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "read write"
}
```

### ✅ Verificar el token

```bash
curl -X GET \
  -H "Authorization: Bearer <TOKEN_OBTENIDO>" \
  http://localhost:8080/user/me
```

### 📝 Credenciales por defecto

Las credenciales se configuran en el archivo `application-dev.properties`:

```properties
oauth2.client-id=proveedor-oauth
oauth2.client-secret=123456
oauth2.default-user.username=admin
oauth2.default-user.password=Admin1
```

> **Nota:** Estas credenciales corresponden al perfil de desarrollo (`application-dev.properties`). En producción, estas variables se configuran mediante las variables de entorno o el archivo `application-prod.properties`.

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


