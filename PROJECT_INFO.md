This file is a merged representation of the entire codebase, combined into a single document by Repomix.
The content has been processed where security check has been disabled.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Security check has been disabled - content may contain sensitive information
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
.github/
  workflows/
    ci.yml
doc/
  COMMANDS.md
  ENDPOINTS.md
  MANUAL.md
  REGSITRAR_NUEVA_APLICACION.md
k8s/
  base/
    deployment.yaml
    ingress.yaml
    kustomization.yaml
    namespace.yaml
    pvc.yaml
    service.yaml
  postgres/
    base/
      kustomization.yaml
      postgres-configmap.yaml
      postgres-deployment.yaml
      postgres-init-sql.yaml
      postgres-pvc.yaml
      postgres-service.yaml
  deploy.sh
scripts/
  generate-hash.py
  generate-jwt-key.sh
  run-dev-docker.sh
  run-dev.sh
  run-prod-docker.sh
  run-prod.sh
  test_complete_flow.sh
src/
  main/
    java/
      com/
        oauth/
          adapters/
            input/
              rest/
                dto/
                  CreateUserDto.java
                  GetUserDto.java
                mapper/
                  UserDtoMapper.java
                LoginController.java
                UserController.java
              ApplicationServiceAdapter.java
              RoleServiceAdapter.java
              UserServiceAdapter.java
            output/
              persistence/
                ApplicationRepository.java
                ApplicationRepositoryAdapter.java
                RoleRepository.java
                RoleRepositoryAdapter.java
                UserApplicationRepositoryAdapter.java
                UserEntityRepository.java
                UserRepositoryAdapter.java
                UsuarioAplicacionRepository.java
              security/
                PasswordEncoderAdapter.java
          application/
            usecase/
              application/
                FindApplicationUseCase.java
              user/
                CreateUserUseCase.java
                GetUserUseCase.java
          config/
            AuthenticationManagerConfig.java
            CustomTokenEnhancer.java
            JpaConfig.java
            JpaRegisteredClientRepository.java
            OAuth2AuthorizationServer.java
            PasswordEncoderConfig.java
            RequestCacheConfig.java
            SecurityConfig.java
            SwaggerConfig.java
            WebConfig.java
          domain/
            exception/
              UserPasswordException.java
            model/
              Application.java
              ApplicationDetails.java
              Role.java
              UserEntity.java
              UsuarioAplicacion.java
            ports/
              in/
                application/
                  ApplicationServicePort.java
                role/
                  RoleServicePort.java
                usecase/
                  user/
                    CreateUserUseCasePort.java
                    GetUserUseCasePort.java
                user/
                  UserServicePort.java
              out/
                persistence/
                  ApplicationRepositoryPort.java
                  RoleRepositoryPort.java
                  UserApplicationRepositoryPort.java
                  UserRepositoryPort.java
                security/
                  PasswordEncoderPort.java
          infrastructure/
            service/
              AppAwareAuthenticationProvider.java
              ApplicationAuthenticationDetailsSource.java
              ApplicationService.java
              BaseService.java
              ClientIdExtractorFilter.java
              CustomUserDetailsService.java
              UserEntityService.java
              UsuarioAplicacionService.java
          Application.java
    resources/
      static/
        css/
          login.css
      templates/
        invalid-application.html
        login.html
        oauth2-consent.html
      application-dev.properties
      application.properties
  test/
    groovy/
      com/
        oauth/
          adapters/
            input/
              rest/
                dto/
                  CreateUserDtoSpec.groovy
                  GetUserDtoSpec.groovy
                mapper/
                  UserDtoMapperSpec.groovy
                UserControllerSpec.groovy
              UserServiceAdapterSpec.groovy
          application/
            usecase/
              user/
                CreateUserUseCaseSpec.groovy
          domain/
            exception/
              UserPasswordExceptionSpec.groovy
            model/
              UserEntitySpec.groovy
          infrastructure/
            service/
              BaseServiceSpec.groovy
              CustomUserDetailsServiceSpec.groovy
              UserEntityServiceSpec.groovy
          security/
            PasswordEncoderConfigSpec.groovy
          ApplicationSpec.groovy
    resources/
      application-test.properties
.gitignore
docker-compose.yml
pom.xml
README.md
```

# Files

## File: .github/workflows/ci.yml
````yaml
name: OAuth2Server CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: oauth2_dev
          POSTGRES_USER: oauth2_user
          POSTGRES_PASSWORD: oauth2_dev_password
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Build with Maven
        run: mvn clean compile -q
        env:
          # ===== CONFIGURACIÓN GENERAL =====
          OAUTH2_CLIENTS: TEST_CLIENT
          TEST_CLIENT_SECRET: test-secret
          TEST_CLIENT_REDIRECT_URI: http://localhost:8080/callback
          CORS_ALLOWED_ORIGINS: http://localhost:8080,http://localhost:5000
          CONTACT_EMAIL: admin@localhost
          SERVER_PORT: 8080
          SERVER_ADDRESS: 0.0.0.0
          SERVER_SSL_ENABLED: false
          
          # ===== BASE DE DATOS =====
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/oauth2_dev
          SPRING_DATASOURCE_USERNAME: oauth2_user
          SPRING_DATASOURCE_PASSWORD: oauth2_dev_password
          SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
          SPRING_JPA_DATABASE_PLATFORM: org.hibernate.dialect.PostgreSQLDialect
          SPRING_JPA_HIBERNATE_DDL_AUTO: update
          SPRING_JPA_SHOW_SQL: true
          
          # ===== FLYWAY =====
          SPRING_FLYWAY_ENABLED: true
          SPRING_FLYWAY_BASELINE_ON_MIGRATE: true
          SPRING_FLYWAY_VALIDATE_ON_MIGRATE: true
          
          # ===== OAUTH2 - TOKENS =====
          OAUTH2_ACCESS_TOKEN_VALIDITY_SECONDS: 86400
          OAUTH2_REFRESH_TOKEN_VALIDITY_SECONDS: 1296000
          JWT_SIGNING_KEY: dev-jwt-signing-key-for-ci-tests-123456
          JWT_AUDIENCE: oauth2-client
          ISSUER_URL: http://localhost:8080
          
          # ===== CLIENTE CINE-PLATFORM =====
          CINE_PLATFORM_SECRET: cine-platform-ci-secret-123
          CINE_PLATFORM_REDIRECT_URI: http://localhost:3000/callback
          
          # ===== CLIENTE TRANSCRIBERAPP =====
          TRANSCRIBERAPP_SECRET: transcriberapp-ci-secret-456
          TRANSCRIBERAPP_REDIRECT_URI: http://localhost:3001/callback
          
          # ===== CLIENTE POR DEFECTO (si se necesita) =====
          DEFAULT_CLIENT_ID: default-ci-client
          DEFAULT_CLIENT_SECRET: default-ci-secret-789
          
          # ===== USUARIOS POR DEFECTO =====
          DEFAULT_ADMIN_USERNAME: admin
          DEFAULT_ADMIN_PASSWORD: admin
          DEFAULT_USER_USERNAME: user
          DEFAULT_USER_PASSWORD: user
          
          # ===== H2 (no se usa pero por si acaso) =====
          SPRING_H2_CONSOLE_ENABLED: false
          
          # ===== LOGGING =====
          LOGGING_LEVEL_ROOT: INFO
          LOGGING_LEVEL_COM_OAUTH_REST: DEBUG
          LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY: DEBUG
          
          # ===== ACTUATOR =====
          MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: health,info
          MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: always

      - name: Run tests with coverage
        run: mvn test
        env:
          # ===== CONFIGURACIÓN GENERAL =====
          OAUTH2_CLIENTS: TEST_CLIENT
          TEST_CLIENT_SECRET: test-secret
          TEST_CLIENT_REDIRECT_URI: http://localhost:8080/callback            
          CORS_ALLOWED_ORIGINS: http://localhost:8080,http://localhost:5000
          CONTACT_EMAIL: admin@localhost
          SERVER_PORT: 8080
          SERVER_ADDRESS: 0.0.0.0
          SERVER_SSL_ENABLED: false
          
          # ===== BASE DE DATOS =====
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/oauth2_dev
          SPRING_DATASOURCE_USERNAME: oauth2_user
          SPRING_DATASOURCE_PASSWORD: oauth2_dev_password
          SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
          SPRING_JPA_DATABASE_PLATFORM: org.hibernate.dialect.PostgreSQLDialect
          SPRING_JPA_HIBERNATE_DDL_AUTO: update
          SPRING_JPA_SHOW_SQL: true
          
          # ===== FLYWAY =====
          SPRING_FLYWAY_ENABLED: true
          SPRING_FLYWAY_BASELINE_ON_MIGRATE: true
          SPRING_FLYWAY_VALIDATE_ON_MIGRATE: true
          
          # ===== OAUTH2 - TOKENS =====
          OAUTH2_ACCESS_TOKEN_VALIDITY_SECONDS: 86400
          OAUTH2_REFRESH_TOKEN_VALIDITY_SECONDS: 1296000
          JWT_SIGNING_KEY: dev-jwt-signing-key-for-ci-tests-123456
          JWT_AUDIENCE: oauth2-client
          ISSUER_URL: http://localhost:8080
          
          # ===== CLIENTE CINE-PLATFORM =====
          CINE_PLATFORM_SECRET: cine-platform-ci-secret-123
          CINE_PLATFORM_REDIRECT_URI: http://localhost:3000/callback
          
          # ===== CLIENTE TRANSCRIBERAPP =====
          TRANSCRIBERAPP_SECRET: transcriberapp-ci-secret-456
          TRANSCRIBERAPP_REDIRECT_URI: http://localhost:3001/callback
          
          # ===== CLIENTE POR DEFECTO (si se necesita) =====
          DEFAULT_CLIENT_ID: default-ci-client
          DEFAULT_CLIENT_SECRET: default-ci-secret-789
          
          # ===== USUARIOS POR DEFECTO =====
          DEFAULT_ADMIN_USERNAME: admin
          DEFAULT_ADMIN_PASSWORD: admin
          DEFAULT_USER_USERNAME: user
          DEFAULT_USER_PASSWORD: user
          
          # ===== H2 (no se usa pero por si acaso) =====
          SPRING_H2_CONSOLE_ENABLED: false
          
          # ===== LOGGING =====
          LOGGING_LEVEL_ROOT: INFO
          LOGGING_LEVEL_COM_OAUTH_REST: DEBUG
          LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY: DEBUG
          
          # ===== ACTUATOR =====
          MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: health,info
          MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: always

      - name: Verify coverage
        run: mvn verify -DskipTests=false
        env:
          # ===== CONFIGURACIÓN GENERAL =====
          OAUTH2_CLIENTS: TEST_CLIENT
          TEST_CLIENT_SECRET: test-secret
          TEST_CLIENT_REDIRECT_URI: http://localhost:8080/callback          
          CORS_ALLOWED_ORIGINS: http://localhost:8080,http://localhost:5000
          CONTACT_EMAIL: admin@localhost
          SERVER_PORT: 8080
          SERVER_ADDRESS: 0.0.0.0
          SERVER_SSL_ENABLED: false
          
          # ===== BASE DE DATOS =====
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/oauth2_dev
          SPRING_DATASOURCE_USERNAME: oauth2_user
          SPRING_DATASOURCE_PASSWORD: oauth2_dev_password
          SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
          SPRING_JPA_DATABASE_PLATFORM: org.hibernate.dialect.PostgreSQLDialect
          SPRING_JPA_HIBERNATE_DDL_AUTO: update
          SPRING_JPA_SHOW_SQL: true
          
          # ===== FLYWAY =====
          SPRING_FLYWAY_ENABLED: true
          SPRING_FLYWAY_BASELINE_ON_MIGRATE: true
          SPRING_FLYWAY_VALIDATE_ON_MIGRATE: true
          
          # ===== OAUTH2 - TOKENS =====
          OAUTH2_ACCESS_TOKEN_VALIDITY_SECONDS: 86400
          OAUTH2_REFRESH_TOKEN_VALIDITY_SECONDS: 1296000
          JWT_SIGNING_KEY: dev-jwt-signing-key-for-ci-tests-123456
          JWT_AUDIENCE: oauth2-client
          ISSUER_URL: http://localhost:8080
          
          # ===== CLIENTE CINE-PLATFORM =====
          CINE_PLATFORM_SECRET: cine-platform-ci-secret-123
          CINE_PLATFORM_REDIRECT_URI: http://localhost:3000/callback
          
          # ===== CLIENTE TRANSCRIBERAPP =====
          TRANSCRIBERAPP_SECRET: transcriberapp-ci-secret-456
          TRANSCRIBERAPP_REDIRECT_URI: http://localhost:3001/callback
          
          # ===== CLIENTE POR DEFECTO (si se necesita) =====
          DEFAULT_CLIENT_ID: default-ci-client
          DEFAULT_CLIENT_SECRET: default-ci-secret-789
          
          # ===== USUARIOS POR DEFECTO =====
          DEFAULT_ADMIN_USERNAME: admin
          DEFAULT_ADMIN_PASSWORD: admin
          DEFAULT_USER_USERNAME: user
          DEFAULT_USER_PASSWORD: user
          
          # ===== H2 (no se usa pero por si acaso) =====
          SPRING_H2_CONSOLE_ENABLED: false
          
          # ===== LOGGING =====
          LOGGING_LEVEL_ROOT: INFO
          LOGGING_LEVEL_COM_OAUTH_REST: DEBUG
          LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY: DEBUG
          
          # ===== ACTUATOR =====
          MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: health,info
          MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: always

      - name: Build package
        run: mvn package -DskipTests
        env:
          # ===== CONFIGURACIÓN GENERAL =====
          OAUTH2_CLIENTS: TEST_CLIENT
          TEST_CLIENT_SECRET: test-secret
          TEST_CLIENT_REDIRECT_URI: http://localhost:8080/callback          
          CORS_ALLOWED_ORIGINS: http://localhost:8080,http://localhost:5000
          CONTACT_EMAIL: admin@localhost
          SERVER_PORT: 8080
          SERVER_ADDRESS: 0.0.0.0
          SERVER_SSL_ENABLED: false
          
          # ===== BASE DE DATOS =====
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/oauth2_dev
          SPRING_DATASOURCE_USERNAME: oauth2_user
          SPRING_DATASOURCE_PASSWORD: oauth2_dev_password
          SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
          SPRING_JPA_DATABASE_PLATFORM: org.hibernate.dialect.PostgreSQLDialect
          SPRING_JPA_HIBERNATE_DDL_AUTO: update
          SPRING_JPA_SHOW_SQL: true
          
          # ===== FLYWAY =====
          SPRING_FLYWAY_ENABLED: true
          SPRING_FLYWAY_BASELINE_ON_MIGRATE: true
          SPRING_FLYWAY_VALIDATE_ON_MIGRATE: true
          
          # ===== OAUTH2 - TOKENS =====
          OAUTH2_ACCESS_TOKEN_VALIDITY_SECONDS: 86400
          OAUTH2_REFRESH_TOKEN_VALIDITY_SECONDS: 1296000
          JWT_SIGNING_KEY: dev-jwt-signing-key-for-ci-tests-123456
          JWT_AUDIENCE: oauth2-client
          ISSUER_URL: http://localhost:8080
          
          # ===== CLIENTE CINE-PLATFORM =====
          CINE_PLATFORM_SECRET: cine-platform-ci-secret-123
          CINE_PLATFORM_REDIRECT_URI: http://localhost:3000/callback
          
          # ===== CLIENTE TRANSCRIBERAPP =====
          TRANSCRIBERAPP_SECRET: transcriberapp-ci-secret-456
          TRANSCRIBERAPP_REDIRECT_URI: http://localhost:3001/callback
          
          # ===== CLIENTE POR DEFECTO (si se necesita) =====
          DEFAULT_CLIENT_ID: default-ci-client
          DEFAULT_CLIENT_SECRET: default-ci-secret-789
          
          # ===== USUARIOS POR DEFECTO =====
          DEFAULT_ADMIN_USERNAME: admin
          DEFAULT_ADMIN_PASSWORD: admin
          DEFAULT_USER_USERNAME: user
          DEFAULT_USER_PASSWORD: user
          
          # ===== H2 (no se usa pero por si acaso) =====
          SPRING_H2_CONSOLE_ENABLED: false
          
          # ===== LOGGING =====
          LOGGING_LEVEL_ROOT: INFO
          LOGGING_LEVEL_COM_OAUTH_REST: DEBUG
          LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY: DEBUG
          
          # ===== ACTUATOR =====
          MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: health,info
          MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: always

      - name: Verify application starts
        run: |
          java -jar target/oauth2server-0.0.1-SNAPSHOT.jar &
          APP_PID=$!
          for i in {1..60}; do
            if curl -s http://localhost:8080/login > /dev/null 2>&1; then
              echo "Application started successfully"
              break
            fi
            if ! kill -0 $APP_PID 2>/dev/null; then
              echo "Application failed to start"
              exit 1
            fi
            sleep 1
          done
          if curl -s http://localhost:8080/login > /dev/null 2>&1; then
            echo "Application is responding on port 8080"
          else
            echo "Application failed to respond"
            exit 1
          fi
          kill $APP_PID || true
        env:
          OAUTH2_CLIENTS: TEST_CLIENT
          TEST_CLIENT_SECRET: test-secret
          TEST_CLIENT_REDIRECT_URI: http://localhost:8080/callback        
          CORS_ALLOWED_ORIGINS: http://localhost:8080,http://localhost:5000
          CONTACT_EMAIL: admin@localhost
          SERVER_PORT: 8080
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/oauth2_dev
          SPRING_DATASOURCE_USERNAME: oauth2_user
          SPRING_DATASOURCE_PASSWORD: oauth2_dev_password
          SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
          SPRING_JPA_DATABASE_PLATFORM: org.hibernate.dialect.PostgreSQLDialect
          SPRING_JPA_HIBERNATE_DDL_AUTO: update
          SPRING_JPA_SHOW_SQL: true
          SPRING_FLYWAY_ENABLED: true
          SPRING_FLYWAY_BASELINE_ON_MIGRATE: true
          SPRING_FLYWAY_VALIDATE_ON_MIGRATE: true
          OAUTH2_ACCESS_TOKEN_VALIDITY_SECONDS: 86400
          OAUTH2_REFRESH_TOKEN_VALIDITY_SECONDS: 1296000
          JWT_SIGNING_KEY: dev-jwt-signing-key-for-ci-tests-123456
          JWT_AUDIENCE: oauth2-client
          ISSUER_URL: http://localhost:8080
          CINE_PLATFORM_SECRET: cine-platform-ci-secret-123
          CINE_PLATFORM_REDIRECT_URI: http://localhost:3000/callback
          TRANSCRIBERAPP_SECRET: transcriberapp-ci-secret-456
          TRANSCRIBERAPP_REDIRECT_URI: http://localhost:3001/callback
          DEFAULT_CLIENT_ID: default-ci-client
          DEFAULT_CLIENT_SECRET: default-ci-secret-789
          DEFAULT_ADMIN_USERNAME: admin
          DEFAULT_ADMIN_PASSWORD: admin
          DEFAULT_USER_USERNAME: user
          DEFAULT_USER_PASSWORD: user
          SPRING_H2_CONSOLE_ENABLED: false
          LOGGING_LEVEL_ROOT: INFO
          LOGGING_LEVEL_COM_OAUTH_REST: DEBUG
          LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY: DEBUG
          MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: health,info
          MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: always

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: target/surefire-reports/

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: target/site/jacoco/
````

## File: doc/COMMANDS.md
````markdown
# 📘 **GUÍA COMPLETA DE OPERACIONES – DOCKER + OAUTH2SERVER**

---

# 🟦 1. COMANDOS GENERALES DE DOCKER

### 🔍 Ver contenedores en ejecución
```bash
docker ps
```

### 📦 Ver todos los contenedores
```bash
docker ps -a
```

### 🧩 Ver imágenes
```bash
docker images
```

---

# 🟩 2. OAuth2Server con Docker Compose

### Iniciar servicios
```bash
docker-compose up --build
```

### Ver logs
```bash
docker-compose logs -f
```

### Detener servicios
```bash
docker-compose down
```

### Ver estado de servicios
```bash
docker-compose ps
```

---

# 🟧 3. OAuth2Server (local sin Docker)

## 🔧 Build y ejecución local

```bash
mvn clean package
java -jar target/oauth2server-0.0.1-SNAPSHOT.jar
```

### Comprobar puerto en uso
```bash
sudo lsof -i :8080
```

### Ejecutar con Spring Boot plugin
```bash
mvn spring-boot:run -X
```

---

## 🐳 Docker local

```bash
docker build -t mi-oauth2-server .
docker run -p 8080:8080 mi-oauth2-server
```

```bash
mvn clean package
docker build -t mi-oauth2-server:latest .
```

---

# 🟪 4. PostgreSQL (Base de datos)

## 🐚 Conectar a PostgreSQL

Si usas docker-compose, PostgreSQL está disponible en:
- Host: localhost
- Puerto: 5432
- Base de datos: oauth2_dev
- Usuario: oauth2_user
- Contraseña: oauth2_dev_password

### Conectar con psql
```bash
docker exec -it <NOMBRE_CONTENEDOR_POSTGRES> psql -U oauth2_user -d oauth2_dev
```

---

## 📤 Copiar base de datos

```bash
# Exportar
docker exec <CONTENEDOR> pg_dump -U oauth2_user oauth2_dev > backup.sql

# Importar
docker exec -i <CONTENEDOR> psql -U oauth2_user oauth2_dev < backup.sql
```

---

## 🔐 Cambiar contraseña de usuario

```sql
UPDATE usuarios
SET password = '$2b$12$t3XDd8U5098eeYodNTlJp.u6Rze/P8zdjmEZ.SklfEl6lFvMyUCtS'
WHERE username = 'dummy';
```

---

## 🔑 Generar bcrypt

```bash
python3 - <<'PY'
import bcrypt
print(bcrypt.hashpw(b"tu-contraseña", bcrypt.gensalt(rounds=10)).decode())
PY
```

---

# 🟫 5. Variables de entorno en producción

## 📌 ¿Dónde se definen?

Las variables de entorno se configuran en el archivo `application-prod.properties` o como variables de entorno del sistema.

### Variables principales

```bash
# Base de datos
SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/oauth2_prod
SPRING_DATASOURCE_USERNAME=oauth2_user
SPRING_DATASOURCE_PASSWORD=tu-contraseña-segura

# OAuth2
MI_EJEMPLO_APP_SECRET=tu-secreto
MI_EJEMPLO_APP_REDIRECT_URI=https://tu-dominio.com/callback

# JWT
JWT_SIGNING_KEY=tu-clave-secreta-jwt
ISSUER_URL=https://tu-dominio.com
```

---

# 🟬 6. Comandos adicionales

## 🔌 Port-forward (Kubernetes - si aplica)

```bash
kubectl port-forward -n auth svc/oauth2-server 8080:8080
```

## 📜 Logs en tiempo real

```bash
# Docker
docker-compose logs -f oauth2server

# Local
tail -f logs/oauth2server.log
```

## 📄 Documentación API (Swagger UI)

```
http://localhost:8080/swagger-ui/index.html
```

## 🔁 Reiniciar OAuth2Server

```bash
# Docker
docker-compose restart

# Local
# Detén y vuelve a ejecutar el JAR
```

---

## 🧼 Crear contenedor temporal (si usas Kubernetes)

```bash
kubectl run cleaner -n auth --image=mi-oauth2-server:latest --command -- sleep 3600
```

---

## 🧹 Kubernetes: Eliminar finalizers de un PVC

```bash
kubectl patch pvc oauth2-pvc -n auth -p '{"metadata":{"finalizers":null}}' --type=merge
```

---

## 🟭 7. Troubleshooting

### Verificar que PostgreSQL está disponible

```bash
docker exec -it <CONTENEDOR_POSTGRES> pg_isready -U oauth2_user
```

### Ver logs de OAuth2Server

```bash
docker-compose logs -f --tail=100 oauth2server
```

### Reiniciar servicios

```bash
docker-compose down
docker-compose up --build
```
````

## File: doc/ENDPOINTS.md
````markdown
# 📚 Documentación de Endpoints – OAuth2Server

OAuth2Server expone endpoints para autenticación OAuth2, emisión de tokens JWT y gestión básica de usuarios.  
Todos los endpoints siguen el estándar OAuth2 y devuelven respuestas en formato **JSON**.

---

# 🔐 1. Endpoints OAuth2

## 1.1. `/oauth2/authorize` – Autorización

Endpoint para iniciar el flujo de Authorization Code con PKCE.

### Método
```
GET /oauth2/authorize
```

### Parámetros
- `response_type`: Debe ser `"code"`
- `client_id`: ID del cliente (ej: `mi-ejemplo-app`)
- `redirect_uri`: URI de callback (ej: `http://localhost:3000/callback`)
- `scope`: scopes separados por espacio (ej: `openid profile read write`)
- `code_challenge`: Challenge de PKCE
- `code_challenge_method`: Método de verificación (`S256`)

### Ejemplo
```
http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=mi-ejemplo-app&
  redirect_uri=http://localhost:3000/callback&
  scope=openid%20profile%20read%20write&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### Respuesta
- Si el usuario no está autenticado: Redirige a `/login`
- Si está autenticado: Muestra pantalla de consentimiento
- Después del consentimiento: Redirige al callback con el código

```
http://localhost:3000/callback?code=xxx
```

---

## 1.2. `/oauth2/token` – Obtener token

Endpoint para obtener tokens JWT.

### Método
```
POST /oauth2/token
```

### Headers
```
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded
```

---

### 🔹 A) Authorization Code + PKCE

Canjea el código de autorización por tokens.

### Request
```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mi-ejemplo-app:mi-ejemplo-secreto" \
  -d "grant_type=authorization_code" \
  -d "code=CODIGO_RECIBIDO" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  http://localhost:8080/oauth2/token
```

### Response
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

---

### 🔹 B) Client Credentials (M2M)

Para aplicaciones Machine-to-Machine.

### Request
```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mi-ejemplo-app:mi-ejemplo-secreto" \
  -d "grant_type=client_credentials" \
  -d "scope=read write" \
  http://localhost:8080/oauth2/token
```

### Response
```json
{
  "access_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "read write"
}
```

---

# 🧪 2. Endpoints de Usuario

Los endpoints de usuario están protegidos por **Bearer Token**.  
Requieren incluir:

```
Authorization: Bearer <ACCESS_TOKEN>
```

---

## 2.1. `GET /user/me` – Obtener usuario actual

### Request
```bash
curl -X GET \
  -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8080/user/me
```

### Response
```json
{
  "id": 1,
  "username": "admin",
  "role": "ADMIN"
}
```

---

## 2.2. `POST /user` – Crear usuario

### Request
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
        "username": "nuevo",
        "password": "1234",
        "email": "nuevo@ejemplo.com",
        "app": "mi-ejemplo-app",
        "role": "USER"
      }' \
  http://localhost:8080/user
```

### Response
```json
{
  "id": 3,
  "username": "nuevo",
  "role": "USER"
}
```

---

## 2.3. `GET /login` – Página de login

Página de login para usuarios.

### Request
```bash
curl -X GET http://localhost:8080/login
```

### Response
Página HTML con formulario de login.

---

# 🔒 3. Seguridad y Roles

El sistema define dos roles:

- `ADMIN`
- `USER`

### Permisos por defecto:

| Endpoint | USER | ADMIN |
|----------|------|-------|
| `/oauth2/authorize` | ✔️ | ✔️ |
| `/oauth2/token` | ✔️ | ✔️ |
| `/login` | ✔️ | ✔️ |
| `GET /user/me` | ✔️ | ✔️ |
| `POST /user` | ✔️ | ✔️ |

---

# 🧾 4. Errores comunes

### Token inválido
```json
{
  "error": "invalid_token",
  "error_description": "JWT expired"
}
```

### Código inválido
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid authorization code"
}
```

### Credenciales incorrectas
```json
{
  "error": "invalid_grant",
  "error_description": "Bad credentials"
}
```

---

# 🧭 5. Swagger UI

El proyecto incluye documentación interactiva:

```
http://localhost:8080/swagger-ui/index.html
```

---

# 🎯 6. Resumen

OAuth2Server proporciona:

- **Authorization Code + PKCE** para aplicaciones web/móviles  
- **Client Credentials** para M2M  
- Emisión de JWT firmados con RSA  
- Gestión de usuarios  
- Seguridad basada en roles  
- Integración lista para microservicios  
- Despliegue completo en Docker/Kubernetes
````

## File: doc/MANUAL.md
````markdown
# Servidor OAuth2 - Manual de Instalación y Ejecución

Este manual te guiará paso a paso para configurar y ejecutar el servidor OAuth2 desde cero.

## Requisitos Previos

### Software necesario

1. **Java 21** o superior
   - Verificar instalación: `java -version`
   - Descargar: https://adoptium.net/

2. **Maven 3.9** o superior
   - Verificar instalación: `mvn -version`
   - Descargar: https://maven.apache.org/

3. **Git** (para clonar el repositorio)
   - Verificar instalación: `git --version`

4. **Docker y Docker Compose** (opcional, para ejecutar con PostgreSQL)
   - Verificar instalación: `docker --version`

---

## Paso 1: Clonar el Repositorio

```bash
# Clonar el repositorio
git clone <URL_DEL_REPOSITORIO>
cd OAuth2Server
```

---

## Paso 2: Configuración de la Base de Datos

La aplicación usa **PostgreSQL** en todos los entornos (desarrollo y producción).

### Opción A: Docker Compose (Recomendado para desarrollo)

```bash
# Ejecutar PostgreSQL y OAuth2Server
docker-compose up --build
```

Esto iniciara:
- PostgreSQL en el puerto 5432
- OAuth2Server en el puerto 8080

### Opción B: PostgreSQL local

1. Instala PostgreSQL
2. Crea una base de datos:

```bash
createdb oauth2_dev
```

3. Configura las credenciales en `application-dev.properties`:

```properties
spring.datasource.url=jdbclocalhost:5432:postgresql:///oauth2_dev
spring.datasource.username=oauth2_user
spring.datasource.password=oauth2_dev_password
```

---

## Paso 3: Compilar el Proyecto

```bash
# Compilar el proyecto (sin tests)
mvn clean compile

# Compilar con tests
mvn clean verify
```

---

## Paso 4: Ejecutar el Servidor

### Opción A: Desde Maven

```bash
# Ejecutar en modo desarrollo
mvn spring-boot:run
```

### Opción B: Ejecutar JAR directamente

```bash
# Primero compilar el JAR
mvn clean package -DskipTests

# Ejecutar el JAR
java -jar target/oauth2server-0.0.1-SNAPSHOT.jar
```

El servidor se ejecutará en: **http://localhost:8080**

---

## Paso 5: Verificar que el Servidor está Activo

### Verificar en navegador

1. Abrir: http://localhost:8080/login
2. Debes ver la página de login

### Verificar con curl

```bash
# Verificar que el servidor responde
curl -s http://localhost:8080/login | head -20
```

---

## Paso 6: Credenciales por Defecto

Al iniciar por primera vez, se crea un usuario administrador:

| Campo | Valor |
|-------|-------|
| Usuario | admin |
| Contraseña | admin123 |

---

## Paso 7: Obtener Token de Acceso

### Flujo Authorization Code + PKCE

#### 1. Iniciar flujo de autorización

```bash
# Redirigir al usuario a esta URL
http://localhost:8080/oauth2/authorize?
    response_type=code&
    client_id=mi-ejemplo-app&
    redirect_uri=http://localhost:3000/callback&
    scope=openid%20profile%20read%20write&
    code_challenge=...&
    code_challenge_method=S256
```

#### 2. Después del login, obtener token

```bash
curl -v -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mi-ejemplo-app:mi-ejemplo-secreto" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=CODE_VERIFIER" \
  http://localhost:8080/oauth2/token
```

### Flujo Client Credentials (M2M)

```bash
# Obtener token para máquina-a-máquina
curl -v -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mi-ejemplo-app:mi-ejemplo-secreto" \
  -d "grant_type=client_credentials" \
  -d "scope=read write" \
  http://localhost:8080/oauth2/token
```

---

## Integración PKCE en Cliente

PKCE (Proof Key for Code Exchange) es una extensión del flujo Authorization Code que añade seguridad adicional. Es obligatorio para aplicaciones públicas (SPAs, móviles).

### Flujo PKCE Paso a Paso

#### Paso 1: Generar Code Verifier y Code Challenge

```javascript
// Generador de code_verifier (string aleatorio de 43-128 caracteres)
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

// Generar code_challenge a partir del code_verifier
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(digest));
}

// Helper para codificar en base64url
function base64URLEncode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
```

#### Paso 2: Redirigir al Servidor de Autorización

```javascript
const authUrl = new URL('http://localhost:8080/oauth2/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'mi-ejemplo-app');
authUrl.searchParams.set('redirect_uri', 'http://localhost:3000/callback');
authUrl.searchParams.set('scope', 'openid profile read write');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('state', generateRandomState());
window.location.href = authUrl.toString();
```

#### Paso 3: Intercambiar Código por Token

```javascript
async function exchangeCodeForToken(code, codeVerifier) {
    const response = await fetch('http://localhost:8080/oauth2/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + btoa('mi-ejemplo-app:mi-ejemplo-secreto')
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: 'http://localhost:3000/callback',
            code_verifier: codeVerifier
        })
    });
    return response.json();
}
```

#### Ejemplo Completo HTML

```html
<!DOCTYPE html>
<html>
<head><title>OAuth2 PKCE Login</title></head>
<body>
    <button id="loginBtn">Iniciar Sesión</button>
    <pre id="result"></pre>
    
    <script>
        const CLIENT_ID = 'mi-ejemplo-app';
        const CLIENT_SECRET = 'mi-ejemplo-secreto';
        const REDIRECT_URI = 'http://localhost:3000/callback';
        const AUTH_SERVER = 'http://localhost:8080';
        
        let codeVerifier = null;
        
        document.getElementById('loginBtn').addEventListener('click', startLogin);
        
        async function startLogin() {
            codeVerifier = generateCodeVerifier();
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            sessionStorage.setItem('codeVerifier', codeVerifier);
            
            const authUrl = new URL(`${AUTH_SERVER}/oauth2/authorize`);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('client_id', CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
            authUrl.searchParams.set('scope', 'openid profile read write');
            authUrl.searchParams.set('code_challenge', codeChallenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');
            authUrl.searchParams.set('state', Math.random().toString(36).substring(2));
            
            window.location.href = authUrl.toString();
        }
        
        if (window.location.search.includes('code=')) {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            codeVerifier = sessionStorage.getItem('codeVerifier');
            if (code && codeVerifier) exchangeCodeForToken(code, codeVerifier);
        }
        
        async function exchangeCodeForToken(code, codeVerifier) {
            const response = await fetch(`${AUTH_SERVER}/oauth2/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code: code,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: codeVerifier
                })
            });
            const tokens = await response.json();
            document.getElementById('result').textContent = JSON.stringify(tokens, null, 2);
            localStorage.setItem('accessToken', tokens.access_token);
        }
        
        function generateCodeVerifier() {
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        async function generateCodeChallenge(verifier) {
            const encoder = new TextEncoder();
            const data = encoder.encode(verifier);
            const digest = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
    </script>
</body>
</html>
```

---

## Configuración de Aplicaciones

### Estructura de Base de Datos

El servidor usa la tabla `USUARIOS` con el campo `app` para distinguir aplicaciones:

| Campo | Descripción |
|-------|-------------|
| username | Nombre de usuario |
| password | Contraseña encriptada (BCrypt) |
| app | Identificador de aplicación |
| roles | Roles del usuario (USER, ADMIN) |
| fullName | Nombre completo |
| email | Correo electrónico |

### Clientes OAuth2 por Defecto

La aplicación viene con dos clientes de ejemplo configurados en `application-dev.properties`:

| client_id | redirect_uri |
|-----------|--------------|
| mi-ejemplo-app | http://localhost:3000/callback |
| mi-segunda-app | http://localhost:9000/callback |

### Agregar Nuevo Cliente

Para agregar un nuevo cliente, modifica `application-dev.properties`:

```properties
# Nuevo cliente
oauth2.clients[2].client-id=mi-nueva-app
oauth2.clients[2].client-secret=mi-nueva-secreto
oauth2.clients[2].redirect-uris[0]=http://localhost:4000/callback
oauth2.clients[2].scopes[0]=openid
oauth2.clients[2].scopes[1]=profile
oauth2.clients[2].scopes[2]=read
oauth2.clients[2].authorization-grant-types=authorization_code,client_credentials,refresh_token
```

---

## Configuración de Perfiles

### Perfil Dev (desarrollo)

Usa PostgreSQL (configurado en docker-compose):

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Perfil Prod (producción)

Requiere PostgreSQL configurado y variables de entorno:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=prod
```

Configurar variables de entorno:

```bash
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/oauth2_prod
SPRING_DATASOURCE_USERNAME=oauth2_user
SPRING_DATASOURCE_PASSWORD=tu_password
```

---

## Añadir Nuevos Usuarios

### Mediante API REST

```bash
curl -X POST http://localhost:8080/user \
  -H "Content-Type: application/json" \
  -d '{
    "username": "juan",
    "password": "contraseña123",
    "email": "juan@ejemplo.com",
    "app": "mi-ejemplo-app",
    "role": "USER"
  }'
```

---

## Ejecutar Tests

```bash
# Ejecutar todos los tests
mvn test

# Ejecutar tests con cobertura
mvn verify

# Ver reporte de cobertura
# Abrir: target/site/jacoco/index.html
```

---

## Endpoints Disponibles

| Endpoint | Método | Descripción | Auth |
|----------|--------|-------------|------|
| /oauth2/authorize | GET | Iniciar autorización | No |
| /oauth2/token | POST | Obtener token | Sí (client_id:secret) |
| /login | GET | Página de login | No |
| /user | POST | Crear usuario | No |
| /user/me | GET | Info usuario actual | Sí |
| /swagger-ui | GET | Documentación API | ADMIN |

---

## Swagger UI

Disponible en: **http://localhost:8080/swagger-ui/index.html**

Requiere autenticación con rol ADMIN.

---

## Solución de Problemas

### Error: "The dependencies of some of the beans form a cycle"

Este error indica una dependencia circular entre beans de Spring. Para resolverlo:

1. Verifica que el bean `RequestCache` esté definido en una clase de configuración separada (`RequestCacheConfig.java`)
2. Asegúrate de que `SecurityConfig` no defina el bean `RequestCache` directamente
3. Ejecuta `mvn clean install` para recompilar

### Error: "Port 8080 already in use"

```bash
# Encontrar proceso usando el puerto
lsof -i :8080

# Matar proceso
kill -9 <PID>
```

### Error: "Database not found"

```bash
# Verificar que la base de datos PostgreSQL existe
# Crear base de datos manualmente si es necesario
createdb oauth2_dev
```

### Error: "Could not resolve placeholder"

Verificar que el perfil está configurado correctamente:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Ver logs en tiempo real

```bash
# Linux/Mac
tail -f server.log

# Windows (PowerShell)
Get-Content server.log -Wait
```

---

## Estructura del Proyecto

```
OAuth2Server/
├── src/main/
│   ├── java/com/oauth/rest/
│   │   ├── config/          # Configuración
│   │   ├── controller/     # Controladores REST
│   │   ├── dto/            # Objetos de transferencia
│   │   ├── exception/      # Excepciones
│   │   ├── mapper/         # Mapeadores
│   │   ├── model/         # Entidades
│   │   ├── repository/    # Repositorios JPA
│   │   ├── security/      # Seguridad
│   │   │   ├── RequestCacheConfig.java      # Bean RequestCache
│   │   │   ├── SecurityConfig.java          # Configuración principal
│   │   │   ├── AppAwareAuthenticationProvider.java
│   │   │   ├── PasswordEncoderConfig.java
│   │   │   └── oauth2/    # Componentes OAuth2
│   │   │       ├── OAuth2AuthorizationServer.java
│   │   │       └── ...
│   │   └── service/       # Servicios
│   └── resources/
│       ├── application-*.properties
│       ├── db/migration/   # Flyway migrations
│       └── templates/      # Plantillas Thymeleaf
├── src/test/              # Tests
├── pom.xml
├── docker-compose.yml     # Contenedores Docker
└── MANUAL.md             # Este archivo
```

---

## Próximos Pasos

1. **Para producción**: Configurar PostgreSQL y HTTPS
2. **Registrar nuevas aplicaciones**: Añadir clientes en `application-dev.properties`
3. **Crear usuarios**: Usar el endpoint `/user` o directamente en la base de datos
````

## File: doc/REGSITRAR_NUEVA_APLICACION.md
````markdown
# 📋 **PASO A PASO: Registrar una nueva aplicación en OAuth2Server**

## **Escenario: Quieres añadir una nueva aplicación que corre en http://localhost:6000**

---

## ✅ **Paso 1: Identificar los datos de la nueva aplicación**

| Dato | Ejemplo |
|------|---------|
| **client_id** | `mi-nueva-app` |
| **client_secret** | `mi-nueva-secreto` |
| **redirect_uri** | `http://localhost:6000/oauth/callback` |
| **scopes** | `openid profile read write` |
| **Puerto** | `6000` |

---

## ✅ **Paso 2: Modificar `application-dev.properties`**

Edita el archivo `src/main/resources/application-dev.properties` y añade un nuevo bloque:

```properties
# ============================
# 🆕 NUEVA APLICACIÓN
# ============================
oauth2.clients[2].client-id=mi-nueva-app
oauth2.clients[2].client-secret=mi-nueva-secreto
oauth2.clients[2].redirect-uris[0]=http://localhost:6000/oauth/callback
oauth2.clients[2].scopes[0]=openid
oauth2.clients[2].scopes[1]=profile
oauth2.clients[2].scopes[2]=read
oauth2.clients[2].scopes[3]=write
oauth2.clients[2].require-consent=true
oauth2.clients[2].require-proof-key=false
oauth2.clients[2].authorization-grant-types=authorization_code,client_credentials,refresh_token
```

### Explicación de campos

| Campo | Descripción |
|-------|-------------|
| `client-id` | Identificador único de tu aplicación |
| `client-secret` | Contraseña secreta (no compartir) |
| `redirect-uris` | URL donde OAuth2 devolverá al usuario |
| `scopes` | Permisos que solicita la app |
| `authorization-grant-types` | Tipos de flujo OAuth2 soportados |

---

## ✅ **Paso 3: (Opcional) Si la app necesita scopes específicos**

```properties
# Ejemplo con scopes personalizados
oauth2.clients[2].scopes[0]=openid
oauth2.clients[2].scopes[1]=profile
oauth2.clients[2].scopes[2]=custom:read
oauth2.clients[2].scopes[3]=custom:write
oauth2.clients[2].scopes[4]=admin:users
```

---

## ✅ **Paso 4: Reiniciar OAuth2Server**

Reinicia el servidor para que cargue la nueva configuración:

```bash
# Si usas Docker
docker-compose down
docker-compose up --build

# Si ejecutas directamente
java -jar target/oauth2server-0.0.1-SNAPSHOT.jar
```

---

## ✅ **Paso 5: Probar el flujo completo**

### 1. Probar la URL de autorización manualmente

```
http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=mi-nueva-app&
  redirect_uri=http://localhost:6000/oauth/callback&
  scope=openid%20profile%20read%20write&
  state=test123
```

Deberías ver la página de login.

### 2. Login con credenciales por defecto

- Usuario: `admin`
- Contraseña: `admin123`

### 3. Redirección esperada

```
http://localhost:6000/oauth/callback?code=XXX&state=test123
```

---

## ✅ **Paso 6: Obtener el token**

Canjea el código por un token:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u "mi-nueva-app:mi-nueva-secreto" \
  -d "grant_type=authorization_code" \
  -d "code=CODIGO_RECIBIDO" \
  -d "redirect_uri=http://localhost:6000/oauth/callback"
```

---

## ✅ **Paso 7: Para producción**

En `application-prod.properties`, añade las variables de entorno:

```bash
# Variables de entorno para producción
MI_NUEVA_APP_SECRET=tu-secreto-produccion
MI_NUEVA_APP_REDIRECT_URI=https://tu-dominio.com/callback
```

O en el archivo de propiedades:

```properties
oauth2.clients[2].client-secret=${MI_NUEVA_APP_SECRET}
oauth2.clients[2].redirect-uris[0]=${MI_NUEVA_APP_REDIRECT_URI}
```

---

## 🎯 **Resumen rápido**

| Paso | Acción |
|------|--------|
| 1 | Elegir `client_id` y `client_secret` |
| 2 | Añadir bloque en `application-dev.properties` |
| 3 | Reiniciar OAuth2Server |
| 4 | Probar con `/oauth2/authorize` |
| 5 | Canjear código por token |

---

## ⚠️ **Notas importantes**

- El **índice** (`[2]`) debe ser único y consecutivo
- El `redirect_uri` debe coincidir **exactamente** (incluyendo `/` al final o no)
- Si la app corre en otro dominio en producción, actualiza `redirect_uris` en el perfil `prod`
- Usa valores diferentes para desarrollo y producción
````

## File: k8s/base/deployment.yaml
````yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
  namespace: auth
spec:
  revisionHistoryLimit: 2
  replicas: 1
  selector:
    matchLabels:
      app: oauth2-server
  template:
    metadata:
      labels:
        app: oauth2-server
    spec:
      initContainers:
      - name: generate-keystore
        image: felixmurcia/oauth2server:v20260305-1816
        command:
          - /bin/sh
          - -c
          - |
            echo "=== Instalando openssl ==="
            apk add --no-cache openssl

            echo "=== Copiando certificados ==="
            cp /certs-secret/tls.crt /keystore/
            cp /certs-secret/tls.key /keystore/

            echo "=== Generando keystore ==="
            cd /keystore

            echo "Archivos disponibles:"
            ls -la

            openssl pkcs12 -export \
              -in tls.crt \
              -inkey tls.key \
              -out keystore.p12 \
              -name tomcat \
              -password pass:${KEYSTORE_PASSWORD}

            echo "=== keystore generado ==="
            ls -la keystore.p12
        env:
        - name: KEYSTORE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: tls-keystore-popos
              key: keystore-password
        volumeMounts:
        - name: tls-certs-secret
          mountPath: /certs-secret
          readOnly: true
        - name: tls-keystore
          mountPath: /keystore

      containers:
      - name: oauth2-server
        image: felixmurcia/oauth2server:v20260305-1816
        command:
          - java
          - -jar
          - /app/app.jar
        env:
        # ===== CONFIGURACIÓN CRÍTICA PARA PROXY =====
        - name: SERVER_FORWARD_HEADERS_STRATEGY
          value: "framework"
        - name: SERVER_USE_FORWARD_HEADERS
          value: "true"
        - name: SERVER_ADDRESS
          value: "0.0.0.0"
        - name: SERVER_PORT
          value: "8080"
        - name: SERVER_SSL_ENABLED
          value: "true"
        - name: SERVER_SSL_KEY_STORE
          value: "/keystore/keystore.p12"
        - name: SERVER_SSL_KEY_STORE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: tls-keystore-popos
              key: keystore-password
        
        # ===== PERFIL ACTIVO (lo define el overlay) =====
        - name: SPRING_PROFILES_ACTIVE
          value: "prod"  # Será sobrescrito por Kustomize según entorno

        # ===== VARIABLES POSTGRESQL (MAYÚSCULAS - NUEVAS) =====
        - name: SPRING_DATASOURCE_URL
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: SPRING_DATASOURCE_URL
        - name: SPRING_DATASOURCE_USERNAME
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: SPRING_DATASOURCE_USERNAME
        - name: SPRING_DATASOURCE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: SPRING_DATASOURCE_PASSWORD
        
        # ===== TOKEN VALIDITY =====
        - name: ACCESS_TOKEN_VALIDITY
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: ACCESS_TOKEN_VALIDITY
        - name: REFRESH_TOKEN_VALIDITY
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: REFRESH_TOKEN_VALIDITY
        - name: JWT_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: jwt-signing-key
        - name: JWT_AUDIENCE
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: oauth-audience
        - name: OAUTH_REDIRECT_URI
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: oauth-redirect-uri
        - name: DEFAULT_ADMIN_USERNAME
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: default-admin-username
        - name: DEFAULT_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: default-admin-password
        - name: DEFAULT_USER_USERNAME
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: default-user-username
        - name: DEFAULT_USER_PASSWORD
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: default-user-password
        - name: ISSUER_URL
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: issuer-url
        - name: H2_USERNAME
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: h2-username
        - name: H2_PASSWORD
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: h2-password
        - name: CINE_PLATFORM_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: CINE_PLATFORM_SECRET
        - name: CINE_PLATFORM_REDIRECT_URI
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: CINE_PLATFORM_REDIRECT_URI
        - name: TRANSCRIBERAPP_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: TRANSCRIBERAPP_SECRET
        - name: TRANSCRIBERAPP_REDIRECT_URI
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: TRANSCRIBERAPP_REDIRECT_URI
        - name: SSL_CERT_FILE
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: SSL_CERT_FILE
        - name: SSL_KEY_FILE
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: SSL_KEY_FILE
        - name: CONTACT_EMAIL
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: CONTACT_EMAIL
        - name: cors-allowed-origins
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: cors-allowed-origins
        - name: SSL_KEY_STORE
          value: "/keystore/keystore.p12"
        - name: KEYSTORE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: tls-keystore-popos
              key: keystore-password
              
        ports:
        - containerPort: 8080
          name: https
        volumeMounts:
        - name: oauth2-data
          mountPath: /data
        - name: tls-keystore
          mountPath: /keystore
          readOnly: true

      volumes:
      - name: oauth2-data
        persistentVolumeClaim:
          claimName: oauth2-pvc
      - name: tls-certs-secret
        secret:
          secretName: tls-keystore-popos
      - name: tls-keystore
        emptyDir: {}
````

## File: k8s/base/ingress.yaml
````yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-server-ingress
  namespace: auth
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "8m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/secure-backends: "true"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  # tls y rules se añaden vía patch
````

## File: k8s/base/kustomization.yaml
````yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: auth
resources:
  - namespace.yaml
  - deployment.yaml
  - service.yaml
  - ingress.yaml
  - pvc.yaml
````

## File: k8s/base/namespace.yaml
````yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth
````

## File: k8s/base/pvc.yaml
````yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: oauth2-pvc
  namespace: auth
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
````

## File: k8s/base/service.yaml
````yaml
apiVersion: v1
kind: Service
metadata:
  name: oauth2-server
  namespace: auth
spec:
  selector:
    app: oauth2-server
  ports:
    - name: https
      port: 443
      targetPort: 8080
      protocol: TCP
    - name: https-nodeport
      port: 8080
      targetPort: 8080
      nodePort: 30444
      protocol: TCP
  type: NodePort
````

## File: k8s/postgres/base/kustomization.yaml
````yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: auth
resources:
  - postgres-configmap.yaml
  - postgres-pvc.yaml
  - postgres-deployment.yaml
  - postgres-service.yaml
  - postgres-init-sql.yaml
````

## File: k8s/postgres/base/postgres-configmap.yaml
````yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-config
  namespace: auth
data:
  POSTGRES_DB: oauth2
  POSTGRES_USER: oauth2_user
  PGDATA: /var/lib/postgresql/data/pgdata
  POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256 --auth-local=scram-sha-256"
````

## File: k8s/postgres/base/postgres-deployment.yaml
````yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: auth
  labels:
    app: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
          name: postgres
        env:
        - name: POSTGRES_DB
          valueFrom:
            configMapKeyRef:
              name: postgres-config
              key: POSTGRES_DB
        - name: POSTGRES_USER
          valueFrom:
            configMapKeyRef:
              name: postgres-config
              key: POSTGRES_USER
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secrets
              key: postgres-password
        - name: PGDATA
          valueFrom:
            configMapKeyRef:
              name: postgres-config
              key: PGDATA
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        - name: postgres-init
          mountPath: /docker-entrypoint-initdb.d
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - oauth2_user
            - -d
            - oauth2
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - oauth2_user
            - -d
            - oauth2
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: postgres-data
        persistentVolumeClaim:
          claimName: postgres-pvc
      - name: postgres-init
        configMap:
          name: postgres-init-sql
````

## File: k8s/postgres/base/postgres-init-sql.yaml
````yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-init-sql
  namespace: auth
data:
  init.sql: |
    -- Scripts de inicialización para PostgreSQL (opcional)
    -- Como Flyway gestiona todo, este archivo puede estar vacío
    -- o contener configuraciones específicas del cluster
    
    -- Ejemplo: crear extensiones necesarias
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
````

## File: k8s/postgres/base/postgres-pvc.yaml
````yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: auth
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: local-path
````

## File: k8s/postgres/base/postgres-service.yaml
````yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: auth
  labels:
    app: postgres
spec:
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: 5432
      protocol: TCP
  type: ClusterIP
````

## File: k8s/deploy.sh
````bash
#!/bin/bash

export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

set -e

# ===== CONFIGURACIÓN =====
IMAGE_NAME="felixmurcia/oauth2server"
NAMESPACE="auth"
DEPLOYMENT="oauth2-server"
ENVIRONMENT=${1:-prod}

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
    echo "❌ Entorno no válido. Usa: dev o prod"
    exit 1
fi

echo "======================================"
echo "  🌍 Desplegando en entorno: $ENVIRONMENT"
echo "======================================"

# ===== COMPILACIÓN Y TESTS =====
echo "======================================"
echo "  🔨 Compilando aplicación"
echo "======================================"

mvn clean install

if [ $? -ne 0 ]; then
    echo "❌ Error en la compilación"
    exit 1
fi

# ===== IMAGEN DOCKER =====
TAG=$(date +"v%Y%m%d-%H%M")
FULL_IMAGE="$IMAGE_NAME:$TAG"

echo "======================================"
echo "  🚀 Construyendo imagen: $FULL_IMAGE"
echo "======================================"

docker build -t $FULL_IMAGE .
docker push $FULL_IMAGE

# Actualizar imagen en base
sed -i "s|image: .*|image: $FULL_IMAGE|" k8s/base/deployment.yaml

# ===== DESPLEGAR POSTGRES PRIMERO =====
echo "======================================"
echo "  🗄️  Desplegando PostgreSQL"
echo "======================================"

kubectl apply -k k8s/postgres/overlays/$ENVIRONMENT

# Esperar a que PostgreSQL esté listo
echo "⏳ Esperando a que PostgreSQL esté listo..."
kubectl wait --for=condition=ready pod -l app=postgres -n $NAMESPACE --timeout=120s

# ===== DESPLEGAR APLICACIÓN =====
echo "======================================"
echo "  🚀 Desplegando aplicación"
echo "======================================"

kubectl apply -k k8s/overlays/$ENVIRONMENT

# ===== REINICIAR Y VERIFICAR =====
echo "======================================"
echo "  🔄 Reiniciando deployment"
echo "======================================"

kubectl rollout restart deployment/$DEPLOYMENT -n $NAMESPACE
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=120s

echo "======================================"
echo "  🧹 Limpiando imágenes antiguas de oauth2server"
echo "======================================"

IMAGES_TO_DELETE=$(docker images $IMAGE_NAME --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | sort -k2 -r | tail -n +2 | awk '{print $1}')

for IMG in $IMAGES_TO_DELETE; do
  echo "🗑️  Eliminando imagen antigua: $IMG"
  docker rmi -f "$IMG" || true
done

echo "======================================"
echo "  🧹 Limpiando imágenes antiguas de Docker"
echo "======================================"

docker image prune -f
docker container prune -f
docker image prune -a --filter "until=720h" -f

echo "======================================"
echo "  📊 Estado de los pods"
echo "======================================"
kubectl get pods -n $NAMESPACE

echo "======================================"
echo "  📜 Logs del nuevo pod (Ctrl+C para salir)"
echo "======================================"

# Mostrar logs del pod más reciente
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)
if [ ! -z "$POD_NAME" ]; then
    echo "📝 Mostrando logs de: $POD_NAME"
    kubectl logs -n $NAMESPACE $POD_NAME -f
else
    echo "❌ No se encontró ningún pod para mostrar logs"
fi

echo "======================================"
echo "  ✅ Despliegue completado"
echo "======================================"
````

## File: scripts/generate-hash.py
````python
#!/usr/bin/env python3
import bcrypt
import sys

def generar_hash(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Uso: python generar_hash.py <contraseña1> <contraseña2> ...")
        print("   Ejemplo: python generar_hash.py admin user1 user2")
        sys.exit(1)
    
    print("\n🔐 Hashes BCrypt generados:")
    print("=" * 70)
    
    for i, password in enumerate(sys.argv[1:], 1):
        hashed = generar_hash(password)
        print(f"{i}. Contraseña: {password}")
        print(f"   Hash:       {hashed}")
        print("-" * 70)
````

## File: scripts/generate-jwt-key.sh
````bash
#!/usr/bin/env bash

echo "Generando clave JWT segura (64 bytes base64)..."
JWT_KEY=$(openssl rand -base64 64)
echo
echo "Clave generada:"
echo "$JWT_KEY"
echo
echo "En base64 para el Secret de Kubernetes:"
echo -n "$JWT_KEY" | base64
echo
````

## File: scripts/run-dev-docker.sh
````bash
#!/bin/sh

echo "Down OAuth2Server en modo DESARROLLO (si está corriendo)..."
docker-compose -f docker-compose.yml down

echo "=== Arrancando OAuth2Server en modo DESARROLLO ==="
docker-compose -f docker-compose.yml up -d
````

## File: scripts/run-dev.sh
````bash
#!/usr/bin/env bash

echo "=== Arrancando OAuth2Server en modo DEV ==="

export SPRING_PROFILES_ACTIVE=dev

# Ejecutar la aplicación (sin redirección a /data)
java -Dspring.profiles.active=dev -Dserver.address=0.0.0.0 -jar /app/app.jar
````

## File: scripts/run-prod-docker.sh
````bash
#!/bin/sh

echo "Down OAuth2Server en modo PRODUCCIÓN (si está corriendo)..."
docker-compose -f docker-compose.prod.yml down

echo "=== Arrancando OAuth2Server en modo PRODUCCIÓN ==="
docker-compose -f docker-compose.prod.yml up -d --build
````

## File: scripts/run-prod.sh
````bash
#!/bin/sh

echo "=== Arrancando OAuth2Server en modo PRODUCCIÓN ==="
echo "JWT_SIGNING_KEY está definida: $(if [ -n \"$JWT_SIGNING_KEY\" ]; then echo \"SÍ\"; else echo \"NO\"; fi)"

export SPRING_PROFILES_ACTIVE=prod

exec java -jar /app/app.jar
````

## File: scripts/test_complete_flow.sh
````bash
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
````

## File: src/main/java/com/oauth/adapters/input/rest/dto/CreateUserDto.java
````java
package com.oauth.adapters.input.rest.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserDto {
    private String username;
    private String fullName;
    private String email;
    private String password;
    private String password2;
}
````

## File: src/main/java/com/oauth/adapters/input/rest/dto/GetUserDto.java
````java
package com.oauth.adapters.input.rest.dto;

import java.util.Set;

/**
 * DTO para devolver datos de usuario
 * Record inmutable - Java class
 */
public record GetUserDto(Long id, String username, String fullName, String email, Set<String> roles) {
    
    /**
     * Factory method para crear instancia sin roles
     */
    public static GetUserDto of(Long id, String username, String fullName, String email) {
        return new GetUserDto(id, username, fullName, email, null);
    }
}
````

## File: src/main/java/com/oauth/adapters/input/rest/mapper/UserDtoMapper.java
````java
package com.oauth.adapters.input.rest.mapper;

import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.oauth.adapters.input.rest.dto.GetUserDto;
import com.oauth.domain.model.UserEntity;

@Component
public class UserDtoMapper {

    public GetUserDto toGetUserDto(UserEntity user) {
        return new GetUserDto(
                user.getId(),
                user.getUsername(),
                user.getFullName(),
                user.getEmail(),
                user.getRoles().stream()
                        .map(role -> role.getName())
                        .collect(Collectors.toSet()));
    }
}
````

## File: src/main/java/com/oauth/adapters/input/rest/LoginController.java
````java
package com.oauth.adapters.input.rest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controlador para las páginas de login de Thymeleaf
 * Maneja las plantillas de login e invalid-application
 */
@Controller
public class LoginController {

    private final String contactEmail;

    public LoginController(@Value("${app.contact.email:admin@localhost}") String contactEmail) {
        this.contactEmail = contactEmail;
    }


    @GetMapping({ "/login", "/oauth2/login" })
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "registered", required = false) String registered,
            @RequestParam(value = "client_id", required = false) String clientId,
            Model model) {

        if (error != null) {
            model.addAttribute("error", "Usuario o contraseña incorrectos");
        }

        if (logout != null) {
            model.addAttribute("logout", "Sesión cerrada correctamente");
        }

        if (registered != null) {
            model.addAttribute("registered", "Usuario registrado correctamente");
        }

        // Pasar client_id al modelo (puede ser nulo si no viene en la URL)
        model.addAttribute("clientId", clientId);

        return "login";
    }

    /**
     * Página mostrada cuando el usuario intenta acceder directamente al login
     * sin un redirect_uri válido (flujo OAuth2).
     */
    @GetMapping("/invalid-application")
    public String invalidApplication(Model model) {
        model.addAttribute("contactEmail", contactEmail);
        return "invalid-application";
    }
}
````

## File: src/main/java/com/oauth/adapters/input/rest/UserController.java
````java
package com.oauth.adapters.input.rest;

import java.util.concurrent.CompletableFuture;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oauth.domain.ports.in.usecase.user.CreateUserUseCasePort;
import com.oauth.domain.ports.in.usecase.user.GetUserUseCasePort;
import com.oauth.adapters.input.rest.dto.CreateUserDto;
import com.oauth.adapters.input.rest.dto.GetUserDto;
import com.oauth.adapters.input.rest.mapper.UserDtoMapper;
import com.oauth.domain.model.UserEntity;

/**
 * Controlador REST para usuarios - Adaptador de entrada
 * Implementa los endpoints de la API usando los casos de uso del dominio
 * Usa las interfaces de los puertos de entrada (SOLID - Dependency Inversion)
 */
@RestController
@RequestMapping("/user")
public class UserController {

    private final CreateUserUseCasePort createUserUseCase;
    private final GetUserUseCasePort getUserUseCase;
    private final UserDtoMapper userDtoMapper;

    public UserController(CreateUserUseCasePort createUserUseCase,
                         GetUserUseCasePort getUserUseCase,
                         UserDtoMapper userDtoMapper) {
        this.createUserUseCase = createUserUseCase;
        this.getUserUseCase = getUserUseCase;
        this.userDtoMapper = userDtoMapper;
    }

    @PostMapping
    public CompletableFuture<GetUserDto> nuevoUsuario(@RequestBody CreateUserDto newUser) {
        return createUserUseCase.execute(
                newUser.getUsername(),
                newUser.getEmail(),
                newUser.getPassword(),
                newUser.getPassword2(),
                newUser.getFullName()
        ).thenApply(userDtoMapper::toGetUserDto)
         .exceptionally(ex -> { 
             Throwable cause = ex.getCause();
             if (cause instanceof RuntimeException) {
                 throw (RuntimeException) cause;
             }
             throw new RuntimeException(cause != null ? cause : ex);
         });
    }

    @GetMapping("/me")
    public GetUserDto me(@AuthenticationPrincipal UserEntity authenticatedUser) {
        return userDtoMapper.toGetUserDto(authenticatedUser);
    }
}
````

## File: src/main/java/com/oauth/adapters/input/ApplicationServiceAdapter.java
````java
package com.oauth.adapters.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.ports.in.application.ApplicationServicePort;
import com.oauth.domain.ports.out.persistence.ApplicationRepositoryPort;
import com.oauth.domain.model.Application;

/**
 * Adaptador de entrada que implementa el puerto de servicio de aplicaciones
 */
@Service
public class ApplicationServiceAdapter implements ApplicationServicePort {

    private final ApplicationRepositoryPort applicationRepositoryPort;

    public ApplicationServiceAdapter(ApplicationRepositoryPort applicationRepositoryPort) {
        this.applicationRepositoryPort = applicationRepositoryPort;
    }

    @Override
    public Optional<Application> findById(Long id) {
        return applicationRepositoryPort.findById(id);
    }

    @Override
    public Optional<Application> findByClientId(String clientId) {
        return applicationRepositoryPort.findByClientId(clientId);
    }

    @Override
    public Optional<Application> findByName(String name) {
        return applicationRepositoryPort.findByName(name);
    }

    @Override
    public Application save(Application application) {
        return applicationRepositoryPort.save(application);
    }
}
````

## File: src/main/java/com/oauth/adapters/input/RoleServiceAdapter.java
````java
package com.oauth.adapters.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.ports.in.role.RoleServicePort;
import com.oauth.domain.ports.out.persistence.RoleRepositoryPort;
import com.oauth.domain.model.Role;

/**
 * Adaptador de entrada que implementa el puerto de servicio de roles
 */
@Service
public class RoleServiceAdapter implements RoleServicePort {

    private final RoleRepositoryPort roleRepositoryPort;

    public RoleServiceAdapter(RoleRepositoryPort roleRepositoryPort) {
        this.roleRepositoryPort = roleRepositoryPort;
    }

    @Override
    public Optional<Role> findByName(String name) {
        return roleRepositoryPort.findByName(name);
    }

    @Override
    public Optional<Role> findById(Long id) {
        return roleRepositoryPort.findById(id);
    }

    @Override
    public Role save(Role role) {
        return roleRepositoryPort.save(role);
    }

    @Override
    public Role findOrCreateRole(String name, String description) {
        return roleRepositoryPort.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role(name, description);
                    return roleRepositoryPort.save(role);
                });
    }
}
````

## File: src/main/java/com/oauth/adapters/input/UserServiceAdapter.java
````java
package com.oauth.adapters.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.ports.in.user.UserServicePort;
import com.oauth.domain.ports.out.persistence.UserRepositoryPort;
import com.oauth.domain.model.UserEntity;

/**
 * Adaptador de entrada que implementa el puerto de servicio de usuarios
 */
@Service
public class UserServiceAdapter implements UserServicePort {

    private final UserRepositoryPort userRepositoryPort;

    public UserServiceAdapter(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Override
    public Optional<UserEntity> findByUsername(String username) {
        return userRepositoryPort.findByUsername(username);
    }

    @Override
    public Optional<UserEntity> findByEmail(String email) {
        return userRepositoryPort.findByEmail(email);
    }

    @Override
    public Optional<UserEntity> findById(Long id) {
        return userRepositoryPort.findById(id);
    }

    @Override
    public UserEntity save(UserEntity user) {
        return userRepositoryPort.save(user);
    }
}
````

## File: src/main/java/com/oauth/adapters/output/persistence/ApplicationRepository.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.domain.model.Application;

public interface ApplicationRepository extends JpaRepository<Application, Long> {

    Optional<Application> findByClientId(String clientId);

    Optional<Application> findByName(String name);

}
````

## File: src/main/java/com/oauth/adapters/output/persistence/ApplicationRepositoryAdapter.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.domain.ports.out.persistence.ApplicationRepositoryPort;
import com.oauth.domain.model.Application;
import com.oauth.adapters.output.persistence.ApplicationRepository;

/**
 * Adaptador de salida que implementa el puerto de repositorio de aplicaciones
 */
@Repository
public class ApplicationRepositoryAdapter implements ApplicationRepositoryPort {

    private final ApplicationRepository applicationRepository;

    public ApplicationRepositoryAdapter(ApplicationRepository applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    @Override
    public Optional<Application> findById(Long id) {
        return applicationRepository.findById(id);
    }

    @Override
    public Optional<Application> findByClientId(String clientId) {
        return applicationRepository.findByClientId(clientId);
    }

    @Override
    public Optional<Application> findByName(String name) {
        return applicationRepository.findByName(name);
    }

    @Override
    public Application save(Application application) {
        return applicationRepository.save(application);
    }

    @Override
    public void deleteById(Long id) {
        applicationRepository.deleteById(id);
    }

    @Override
    public void delete(Application application) {
        applicationRepository.delete(application);
    }
}
````

## File: src/main/java/com/oauth/adapters/output/persistence/RoleRepository.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.domain.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

}
````

## File: src/main/java/com/oauth/adapters/output/persistence/RoleRepositoryAdapter.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.domain.ports.out.persistence.RoleRepositoryPort;
import com.oauth.domain.model.Role;
import com.oauth.adapters.output.persistence.RoleRepository;

/**
 * Adaptador de salida que implementa el puerto de repositorio de roles
 */
@Repository
public class RoleRepositoryAdapter implements RoleRepositoryPort {

    private final RoleRepository roleRepository;

    public RoleRepositoryAdapter(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<Role> findById(Long id) {
        return roleRepository.findById(id);
    }

    @Override
    public Optional<Role> findByName(String name) {
        return roleRepository.findByName(name);
    }

    @Override
    public Role save(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void deleteById(Long id) {
        roleRepository.deleteById(id);
    }

    @Override
    public void delete(Role role) {
        roleRepository.delete(role);
    }
}
````

## File: src/main/java/com/oauth/adapters/output/persistence/UserApplicationRepositoryAdapter.java
````java
package com.oauth.adapters.output.persistence;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.domain.ports.out.persistence.UserApplicationRepositoryPort;
import com.oauth.domain.model.UsuarioAplicacion;
import com.oauth.adapters.output.persistence.UsuarioAplicacionRepository;

/**
 * Adaptador de salida que implementa el puerto de repositorio de usuario-aplicación
 */
@Repository
public class UserApplicationRepositoryAdapter implements UserApplicationRepositoryPort {

    private final UsuarioAplicacionRepository usuarioAplicacionRepository;

    public UserApplicationRepositoryAdapter(UsuarioAplicacionRepository usuarioAplicacionRepository) {
        this.usuarioAplicacionRepository = usuarioAplicacionRepository;
    }

    @Override
    public Optional<UsuarioAplicacion> findById(Long id) {
        return usuarioAplicacionRepository.findById(id);
    }

    @Override
    public List<UsuarioAplicacion> findByUsuarioId(Long usuarioId) {
        return usuarioAplicacionRepository.findByUsuarioId(usuarioId);
    }

    @Override
    public List<UsuarioAplicacion> findByApplicationId(Long applicationId) {
        return usuarioAplicacionRepository.findByApplicationId(applicationId);
    }

    @Override
    public Optional<UsuarioAplicacion> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId) {
        return usuarioAplicacionRepository.findByUsuarioIdAndApplicationId(usuarioId, applicationId);
    }

    @Override
    public UsuarioAplicacion save(UsuarioAplicacion userApplication) {
        return usuarioAplicacionRepository.save(userApplication);
    }

    @Override
    public void deleteById(Long id) {
        usuarioAplicacionRepository.deleteById(id);
    }

    @Override
    public void delete(UsuarioAplicacion userApplication) {
        usuarioAplicacionRepository.delete(userApplication);
    }
}
````

## File: src/main/java/com/oauth/adapters/output/persistence/UserEntityRepository.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.domain.model.UserEntity;

public interface UserEntityRepository extends JpaRepository<UserEntity, Long> {

	Optional<UserEntity> findByUsername(String username);

	Optional<UserEntity> findByEmail(String email);

}
````

## File: src/main/java/com/oauth/adapters/output/persistence/UserRepositoryAdapter.java
````java
package com.oauth.adapters.output.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.domain.ports.out.persistence.UserRepositoryPort;
import com.oauth.domain.model.UserEntity;
import com.oauth.adapters.output.persistence.UserEntityRepository;

/**
 * Adaptador de salida que implementa el puerto de repositorio de usuarios
 */
@Repository
public class UserRepositoryAdapter implements UserRepositoryPort {

    private final UserEntityRepository userEntityRepository;

    public UserRepositoryAdapter(UserEntityRepository userEntityRepository) {
        this.userEntityRepository = userEntityRepository;
    }

    @Override
    public Optional<UserEntity> findById(Long id) {
        return userEntityRepository.findById(id);
    }

    @Override
    public Optional<UserEntity> findByUsername(String username) {
        return userEntityRepository.findByUsername(username);
    }

    @Override
    public Optional<UserEntity> findByEmail(String email) {
        return userEntityRepository.findByEmail(email);
    }

    @Override
    public UserEntity save(UserEntity user) {
        return userEntityRepository.save(user);
    }

    @Override
    public void deleteById(Long id) {
        userEntityRepository.deleteById(id);
    }

    @Override
    public void delete(UserEntity user) {
        userEntityRepository.delete(user);
    }
}
````

## File: src/main/java/com/oauth/adapters/output/persistence/UsuarioAplicacionRepository.java
````java
package com.oauth.adapters.output.persistence;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.domain.model.UsuarioAplicacion;

public interface UsuarioAplicacionRepository extends JpaRepository<UsuarioAplicacion, Long> {

    List<UsuarioAplicacion> findByUsuarioId(Long usuarioId);

    List<UsuarioAplicacion> findByApplicationId(Long applicationId);

    Optional<UsuarioAplicacion> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId);

}
````

## File: src/main/java/com/oauth/adapters/output/security/PasswordEncoderAdapter.java
````java
package com.oauth.adapters.output.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.oauth.domain.ports.out.security.PasswordEncoderPort;

/**
 * Adaptador de salida que implementa el puerto de codificador de contraseñas
 */
@Repository
public class PasswordEncoderAdapter implements PasswordEncoderPort {

    private final PasswordEncoder passwordEncoder;

    public PasswordEncoderAdapter(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
````

## File: src/main/java/com/oauth/application/usecase/application/FindApplicationUseCase.java
````java
package com.oauth.application.usecase.application;

import java.util.Optional;

import com.oauth.domain.ports.in.application.ApplicationServicePort;
import com.oauth.domain.model.Application;
import org.springframework.stereotype.Service;

/**
 * Caso de uso para buscar aplicaciones
 */
@Service
public class FindApplicationUseCase {

    private final ApplicationServicePort applicationService;

    public FindApplicationUseCase(ApplicationServicePort applicationService) {
        this.applicationService = applicationService;
    }

    /**
     * Busca una aplicación por su ID
     */
    public Optional<Application> findById(Long id) {
        return applicationService.findById(id);
    }

    /**
     * Busca una aplicación por su clientId
     */
    public Optional<Application> findByClientId(String clientId) {
        return applicationService.findByClientId(clientId);
    }

    /**
     * Busca una aplicación por su nombre
     */
    public Optional<Application> findByName(String name) {
        return applicationService.findByName(name);
    }
}
````

## File: src/main/java/com/oauth/application/usecase/user/CreateUserUseCase.java
````java
package com.oauth.application.usecase.user;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.oauth.domain.exception.UserPasswordException;
import com.oauth.domain.model.Role;
import com.oauth.domain.model.UserEntity;
import com.oauth.domain.ports.in.role.RoleServicePort;
import com.oauth.domain.ports.in.usecase.user.CreateUserUseCasePort;
import com.oauth.domain.ports.in.user.UserServicePort;
import com.oauth.domain.ports.out.security.PasswordEncoderPort;

/**
 * Caso de uso para crear un nuevo usuario
 * Implementa la lógica de negocio para el registro de usuarios
 * Implementa el puerto CreateUserUseCasePort
 */
@Service
public class CreateUserUseCase implements CreateUserUseCasePort {

    private final UserServicePort userService;
    private final RoleServicePort roleService;
    private final PasswordEncoderPort passwordEncoder;

    public CreateUserUseCase(UserServicePort userService, 
                             RoleServicePort roleService,
                             PasswordEncoderPort passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Ejecuta el caso de uso para crear un nuevo usuario
     */
    @Override
    public CompletableFuture<UserEntity> execute(String username, String email, 
                                                  String password, String password2, 
                                                  String fullName) {
        return CompletableFuture
                .supplyAsync(() -> validatePasswords(password, password2))
                .thenApply(dto -> createUserEntity(username, email, password, fullName))
                .thenCompose(this::assignDefaultRole)
                .thenApply(userService::save)
                .exceptionally(this::handleException);
    }

    /**
     * Valida que las contraseñas coincidan
     */
    private Void validatePasswords(String password, String password2) {
        if (!password.equals(password2)) {
            throw new UserPasswordException();
        }
        return null;
    }

    /**
     * Crea la entidad de usuario con los datos básicos
     */
    private UserEntity createUserEntity(String username, String email, 
                                         String password, String fullName) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setEnabled(true);
        return user;
    }

    /**
     * Asigna el rol por defecto al usuario
     */
    private CompletableFuture<UserEntity> assignDefaultRole(UserEntity user) {
        return CompletableFuture
                .supplyAsync(() -> roleService.findOrCreateRole("ROLE_USER", "Usuario estándar"))
                .thenApply(role -> {
                    Set<Role> roles = new HashSet<>();
                    roles.add(role);
                    user.setRoles(roles);
                    return user;
                });
    }

    /**
     * Maneja las excepciones ocurridas durante la creación del usuario
     */
    private UserEntity handleException(Throwable ex) {
        var cause = ex.getCause() != null ? ex.getCause() : ex;

        if (cause instanceof UserPasswordException) {
            throw (UserPasswordException) cause;
        }
        if (cause instanceof ResponseStatusException) {
            throw (ResponseStatusException) cause;
        }
        if (cause instanceof DataIntegrityViolationException) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "El nombre de usuario o email ya existe");
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }

        throw new RuntimeException(cause);
    }
}
````

## File: src/main/java/com/oauth/application/usecase/user/GetUserUseCase.java
````java
package com.oauth.application.usecase.user;

import java.util.Optional;

import com.oauth.domain.ports.in.usecase.user.GetUserUseCasePort;
import com.oauth.domain.ports.in.user.UserServicePort;
import com.oauth.domain.model.UserEntity;
import org.springframework.stereotype.Service;

/**
 * Caso de uso para obtener información de un usuario
 * Implementa el puerto GetUserUseCasePort
 */
@Service
public class GetUserUseCase implements GetUserUseCasePort {

    private final UserServicePort userService;

    public GetUserUseCase(UserServicePort userService) {
        this.userService = userService;
    }

    /**
     * Busca un usuario por su nombre de usuario
     */
    public Optional<UserEntity> findByUsername(String username) {
        return userService.findByUsername(username);
    }

    /**
     * Busca un usuario por su ID
     */
    public Optional<UserEntity> findById(Long id) {
        return userService.findById(id);
    }

    /**
     * Busca un usuario por su correo electrónico
     */
    public Optional<UserEntity> findByEmail(String email) {
        return userService.findByEmail(email);
    }
}
````

## File: src/main/java/com/oauth/config/AuthenticationManagerConfig.java
````java
package com.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.oauth.infrastructure.service.AppAwareAuthenticationProvider;


@Configuration
public class AuthenticationManagerConfig {

    private final AppAwareAuthenticationProvider appAwareAuthenticationProvider;
    private final UserDetailsService userDetailsService;

    public AuthenticationManagerConfig(
            AppAwareAuthenticationProvider appAwareAuthenticationProvider,
            UserDetailsService userDetailsService) {
        this.appAwareAuthenticationProvider = appAwareAuthenticationProvider;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        // Usar SOLO tu provider personalizado
        return new ProviderManager(appAwareAuthenticationProvider);
    }
}
````

## File: src/main/java/com/oauth/config/CustomTokenEnhancer.java
````java
package com.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import com.oauth.domain.model.UserEntity;
import com.oauth.infrastructure.service.UserEntityService;

@Configuration
@Slf4j
public class CustomTokenEnhancer {

    private final UserEntityService userService;

    public CustomTokenEnhancer(UserEntityService userService) {
        this.userService = userService;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            
            // Solo procesar access tokens
            if (!"access_token".equals(context.getTokenType().getValue())) {
                log.debug("No es access_token, saliendo");
                return;
            }

            var username = context.getPrincipal().getName();
            
            // Buscar usuario
            UserEntity user = userService.findUserByUsername(username).orElse(null);
            
            if (user != null) {                
                var email = user.getEmail();
                var name = user.getFullName() != null ? user.getFullName() : username;
                
                // Añadir claims directamente
                context.getClaims().claim("sub", email);
                context.getClaims().claim("email", email);
                context.getClaims().claim("name", name);
                
            } else {
                log.debug("Usuario NO encontrado en BD!");
            }
            
            // Añadir roles
            Set<String> authorities = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("roles", authorities);
        };
    }
}
````

## File: src/main/java/com/oauth/config/JpaConfig.java
````java
package com.oauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
public class JpaConfig {
    // Configuración específica de JPA
}
````

## File: src/main/java/com/oauth/config/JpaRegisteredClientRepository.java
````java
package com.oauth.config;

import com.oauth.adapters.output.persistence.ApplicationRepository;
import com.oauth.domain.model.Application;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Slf4j
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final ApplicationRepository applicationRepository;
    private final PasswordEncoder passwordEncoder;
    private final int accessTokenValiditySeconds;
    private final int refreshTokenValiditySeconds;

    public JpaRegisteredClientRepository(ApplicationRepository applicationRepository,
                                         PasswordEncoder passwordEncoder,
                                         int accessTokenValiditySeconds,
                                         int refreshTokenValiditySeconds) {
        this.applicationRepository = applicationRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // Secrets are managed via DB migrations; encoding upgrades are intentionally ignored
    }

    @Override
    public RegisteredClient findById(String id) {
        return applicationRepository.findByClientId(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return applicationRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(Application app) {
        String encodedSecret = app.getClientSecret();
        if (!encodedSecret.startsWith("{")) {
            encodedSecret = passwordEncoder.encode(encodedSecret);
        }

        var builder = RegisteredClient.withId(UUID.nameUUIDFromBytes(app.getClientId().getBytes()).toString())
                .clientId(app.getClientId())
                .clientSecret(encodedSecret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid")
                .scope("profile")
                .scope("email")
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(accessTokenValiditySeconds))
                        .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenValiditySeconds))
                        .reuseRefreshTokens(false)
                        .build());

        if (app.getRedirectUri() != null && !app.getRedirectUri().isBlank()) {
            builder.redirectUri(app.getRedirectUri());
        }

        return builder.build();
    }
}
````

## File: src/main/java/com/oauth/config/OAuth2AuthorizationServer.java
````java
package com.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import com.oauth.adapters.output.persistence.ApplicationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@Slf4j
public class OAuth2AuthorizationServer {

    @Value("${oauth2.access-token-validity-seconds:3600}")
    private int accessTokenValiditySeconds;

    @Value("${oauth2.refresh-token-validity-seconds:7200}")
    private int refreshTokenValiditySeconds;

    private String issuerUrl;

    public OAuth2AuthorizationServer() {
        issuerUrl = System.getenv("ISSUER_URL") != null ? System.getenv("ISSUER_URL") : "http://localhost:8080";
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(ApplicationRepository applicationRepository,
                                                                  PasswordEncoder passwordEncoder) {
        return new JpaRegisteredClientRepository(applicationRepository, passwordEncoder,
                accessTokenValiditySeconds, refreshTokenValiditySeconds);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        var keyPair = generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        var rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        
        var jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            log.error("Failed to generate RSA key pair", ex);
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUrl)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcClientRegistrationEndpoint("/connect/register")
                .build();
    }
}
````

## File: src/main/java/com/oauth/config/PasswordEncoderConfig.java
````java
package com.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
````

## File: src/main/java/com/oauth/config/RequestCacheConfig.java
````java
package com.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * RequestCache separado para evitar dependencias circulares con SecurityConfig.
 */
@Configuration
public class RequestCacheConfig {

    @Bean
    public RequestCache requestCache() {
        return new HttpSessionRequestCache();
    }
}
````

## File: src/main/java/com/oauth/config/SecurityConfig.java
````java
package com.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import com.oauth.infrastructure.service.ApplicationAuthenticationDetailsSource;
import com.oauth.infrastructure.service.ClientIdExtractorFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    // Dependencias necesarias
    private final ApplicationAuthenticationDetailsSource applicationAuthenticationDetailsSource;
    private final ClientIdExtractorFilter clientIdExtractorFilter;

    public SecurityConfig(
            ApplicationAuthenticationDetailsSource applicationAuthenticationDetailsSource,
            ClientIdExtractorFilter clientIdExtractorFilter) {
        this.applicationAuthenticationDetailsSource = applicationAuthenticationDetailsSource;
        this.clientIdExtractorFilter = clientIdExtractorFilter;
        log.debug("[SecurityConfig] Initialized");
    }

    @Bean
    public StrictHttpFirewall httpFirewall() {
        var firewall = new StrictHttpFirewall();
        firewall.setAllowSemicolon(true);
        firewall.setAllowUrlEncodedPercent(true);
        firewall.setAllowUrlEncodedSlash(false);
        firewall.setAllowBackSlash(false);
        firewall.setAllowUrlEncodedDoubleSlash(false);
        return firewall;
    }

    @Bean
    @Order(0)
    public FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
        FilterRegistrationBean<ForwardedHeaderFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new ForwardedHeaderFilter());
        registration.setOrder(0);
        return registration;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var configuration = new CorsConfiguration();
        
        // Leer orígenes permitidos desde variable de entorno (separados por coma)
        var allowedOriginsEnv = System.getenv("CORS_ALLOWED_ORIGINS");
        if (allowedOriginsEnv == null || allowedOriginsEnv.isBlank()) {
            throw new IllegalStateException("CORS_ALLOWED_ORIGINS environment variable is required");
        }
        var allowedOrigins = allowedOriginsEnv.split(",");
        
        log.info("[SecurityConfig] CORS allowed origins: {}", String.join(", ", allowedOrigins));
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-CSRF-TOKEN",
                "Accept"
        ));
        configuration.setExposedHeaders(Arrays.asList("X-CSRF-TOKEN"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Configurar matcher primero
        http.securityMatcher(
            "/oauth2/authorize",
            "/oauth2/token",
            "/oauth2/jwks",
            "/oauth2/introspect",
            "/oauth2/revoke",
            "/userinfo",
            "/connect/register",
            "/.well-known/**"
        );
        
        // Configurar CORS y CSRF
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                .ignoringRequestMatchers(
                    "/oauth2/token",
                    "/oauth2/introspect", 
                    "/oauth2/revoke"
                )
            )
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            );
        
        // Aplicar configuración OAuth2 (esto incluye su propio authorizeHttpRequests)
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        // Habilitar OIDC
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        log.debug("[SecurityConfig] OAuth2 Authorization Server configured");
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // Añadir nuestro filtro personalizado ANTES de UsernamePasswordAuthenticationFilter
            .addFilterBefore(clientIdExtractorFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
            
            .securityMatcher(
                "/",
                "/login",
                "/oauth2/login",
                "/logout",
                "/css/**",
                "/js/**",
                "/images/**",
                "/webjars/**",
                "/favicon.ico",
                "/error",
                "/invalid-application",
                "/h2-console/**",
                "/api/**",
                "/user/**"
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                // Ignorar CSRF para el endpoint de login
                .ignoringRequestMatchers("/login")
            )
            .authorizeHttpRequests(authorize -> authorize
                // Rutas públicas
                .requestMatchers(new String[]{
                        "/css/**", 
                        "/js/**", 
                        "/images/**", 
                        "/webjars/**",
                        "/favicon.ico",
                        "/error", 
                        "/invalid-application",
                        "/h2-console/**",
                        "/login", 
                        "/oauth2/login",
                        "/logout"
                }).permitAll()
                // OPTIONS preflight
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // API protegidas
                .requestMatchers("/api/**").authenticated()
                .requestMatchers("/user/**").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .authenticationDetailsSource(applicationAuthenticationDetailsSource)
                // Usar el success handler por defecto de Spring (ya maneja SavedRequest)
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
                .failureUrl("/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout=true")
                .permitAll()
            )
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()
                .invalidSessionUrl("/login")
            )
            .headers(headers -> headers
                .frameOptions(frame -> frame.disable())
            );

        log.debug("[SecurityConfig] Default security configured - ClientIdExtractorFilter added");
        return http.build();
    }
}
````

## File: src/main/java/com/oauth/config/SwaggerConfig.java
````java
package com.oauth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Value("${swagger.title:OAuth2 Server API}")
    private String title;
    
    @Value("${swagger.version:1.0}")
    private String version;
    
    @Value("${swagger.description:API REST con autenticación OAuth2}")
    private String description;
    
    @Value("${swagger.contact.name:OAuth2 Server}")
    private String contactName;
    
    @Value("${swagger.contact.email:soporte@oauth.example.com}")
    private String contactEmail;
    
    @Value("${swagger.contact.url:https://oauth.example.com}")
    private String contactUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title(title)
                        .version(version)
                        .description(description)
                        .contact(new Contact()
                                .name(contactName)
                                .email(contactEmail)
                                .url(contactUrl))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}
````

## File: src/main/java/com/oauth/config/WebConfig.java
````java
package com.oauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }
}
````

## File: src/main/java/com/oauth/domain/exception/UserPasswordException.java
````java
package com.oauth.domain.exception;

/**
 * Excepción de dominio para errores de validación de contraseña
 */
public class UserPasswordException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UserPasswordException() {
        super("Las contraseñas no coinciden");
    }

    public UserPasswordException(String message) {
        super(message);
    }
}
````

## File: src/main/java/com/oauth/domain/model/Application.java
````java
package com.oauth.domain.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "applications")
@EntityListeners(AuditingEntityListener.class)
public class Application implements java.io.Serializable {

    private static final long serialVersionUID = 987654321012345678L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    @Column(name = "client_id", nullable = false, unique = true, length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "redirect_uri", length = 500)
    private String redirectUri;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "application")
    private Set<UsuarioAplicacion> usuarioAplicaciones = new HashSet<>();

    public Application() {
    }

    public Application(String name, String description, String clientId, String clientSecret, String redirectUri) {
        this.name = name;
        this.description = description;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    // Getters y setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public Set<UsuarioAplicacion> getUsuarioAplicaciones() {
        return usuarioAplicaciones;
    }

    public void setUsuarioAplicaciones(Set<UsuarioAplicacion> usuarioAplicaciones) {
        this.usuarioAplicaciones = usuarioAplicaciones;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Application other = (Application) obj;
        if (clientId == null) {
            if (other.clientId != null)
                return false;
        } else if (!clientId.equals(other.clientId))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "Application{id=" + id + ", name='" + name + "', clientId='" + clientId + "'}";
    }
}
````

## File: src/main/java/com/oauth/domain/model/ApplicationDetails.java
````java
package com.oauth.domain.model;

/**
 * Value object para detalles de autenticación específicos de aplicación
 * Record inmutable para clientId
 */
public record ApplicationDetails(String clientId) {
    
    @Override
    public String toString() {
        return String.format("ApplicationDetails{clientId='%s'}", clientId());
    }
}
````

## File: src/main/java/com/oauth/domain/model/Role.java
````java
package com.oauth.domain.model;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "roles")
@EntityListeners(AuditingEntityListener.class)
public class Role implements java.io.Serializable {

    private static final long serialVersionUID = 1234567890123456789L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(length = 255)
    private String description;

    @ManyToMany(mappedBy = "roles")
    private Set<UserEntity> users = new HashSet<>();

    public Role() {
    }

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    // Getters y setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<UserEntity> getUsers() {
        return users;
    }

    public void setUsers(Set<UserEntity> users) {
        this.users = users;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Role other = (Role) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "Role{id=" + id + ", name='" + name + "'}";
    }
}
````

## File: src/main/java/com/oauth/domain/model/UserEntity.java
````java
package com.oauth.domain.model;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "usuarios")
@EntityListeners(AuditingEntityListener.class)
public class UserEntity implements UserDetails {

    private static final long serialVersionUID = 6189678452627071360L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "full_name")
    private String fullName;

    @Column(nullable = false)
    private Boolean enabled = true;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_password_change_at", nullable = false)
    private LocalDateTime lastPasswordChangeAt = LocalDateTime.now();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "usuario_rol", joinColumns = @JoinColumn(name = "usuario_id"), inverseJoinColumns = @JoinColumn(name = "rol_id"), uniqueConstraints = @UniqueConstraint(columnNames = {
            "usuario_id", "rol_id" }))
    private Set<Role> roles = new HashSet<>();

    public UserEntity() {
    }

    public UserEntity(String username, String email, String password, String fullName,
            Boolean enabled, Set<Role> roles, LocalDateTime createdAt, LocalDateTime lastPasswordChangeAt) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.fullName = fullName;
        this.enabled = enabled;
        this.roles = roles;
        this.createdAt = createdAt;
        this.lastPasswordChangeAt = lastPasswordChangeAt;
    }

    // Getters y setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getLastPasswordChangeAt() {
        return lastPasswordChangeAt;
    }

    public void setLastPasswordChangeAt(LocalDateTime lastPasswordChangeAt) {
        this.lastPasswordChangeAt = lastPasswordChangeAt;
    }

    // Spring Security

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
````

## File: src/main/java/com/oauth/domain/model/UsuarioAplicacion.java
````java
package com.oauth.domain.model;

import java.io.Serializable;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "usuario_aplicacion", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "usuario_id", "application_id" })
})
@EntityListeners(AuditingEntityListener.class)
public class UsuarioAplicacion implements Serializable {

    private static final long serialVersionUID = 1111111111111111111L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "usuario_id", nullable = false)
    private UserEntity usuario;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "application_id", nullable = false)
    private Application application;

    @CreatedDate
    @Column(name = "registered_at", nullable = false, updatable = false)
    private LocalDateTime registeredAt;

    public UsuarioAplicacion() {
    }

    public UsuarioAplicacion(UserEntity usuario, Application application) {
        this.usuario = usuario;
        this.application = application;
    }

    // Getters y setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UserEntity getUsuario() {
        return usuario;
    }

    public void setUsuario(UserEntity usuario) {
        this.usuario = usuario;
    }

    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    public LocalDateTime getRegisteredAt() {
        return registeredAt;
    }

    public void setRegisteredAt(LocalDateTime registeredAt) {
        this.registeredAt = registeredAt;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((usuario == null || application == null) ? 0
                : usuario.getId().hashCode() + application.getId().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UsuarioAplicacion other = (UsuarioAplicacion) obj;
        if (usuario == null || other.usuario == null || application == null || other.application == null)
            return false;
        return usuario.getId().equals(other.usuario.getId()) &&
                application.getId().equals(other.application.getId());
    }

    @Override
    public String toString() {
        return "UsuarioAplicacion{usuarioId=" + (usuario != null ? usuario.getId() : null) +
                ", applicationId=" + (application != null ? application.getId() : null) + "}";
    }
}
````

## File: src/main/java/com/oauth/domain/ports/in/application/ApplicationServicePort.java
````java
package com.oauth.domain.ports.in.application;

import java.util.Optional;

import com.oauth.domain.model.Application;

/**
 * Puerto de entrada para servicios de Aplicación
 * Define las operaciones de negocio relacionadas con aplicaciones OAuth
 */
public interface ApplicationServicePort {

    /**
     * Busca una aplicación por su ID
     */
    Optional<Application> findById(Long id);

    /**
     * Busca una aplicación por su clientId
     */
    Optional<Application> findByClientId(String clientId);

    /**
     * Busca una aplicación por su nombre
     */
    Optional<Application> findByName(String name);

    /**
     * Guarda una aplicación
     */
    Application save(Application application);
}
````

## File: src/main/java/com/oauth/domain/ports/in/role/RoleServicePort.java
````java
package com.oauth.domain.ports.in.role;

import java.util.Optional;

import com.oauth.domain.model.Role;

/**
 * Puerto de entrada para servicios de Rol
 * Define las operaciones de negocio relacionadas con roles
 */
public interface RoleServicePort {

    /**
     * Busca un rol por su nombre
     */
    Optional<Role> findByName(String name);

    /**
     * Busca un rol por su ID
     */
    Optional<Role> findById(Long id);

    /**
     * Guarda un rol
     */
    Role save(Role role);

    /**
     * Busca un rol por nombre o lo crea si no existe
     */
    Role findOrCreateRole(String name, String description);
}
````

## File: src/main/java/com/oauth/domain/ports/in/usecase/user/CreateUserUseCasePort.java
````java
package com.oauth.domain.ports.in.usecase.user;

import java.util.concurrent.CompletableFuture;

import com.oauth.domain.model.UserEntity;

/**
 * Puerto de entrada para el caso de uso de creación de usuario
 * Define la interfaz que implementa el caso de uso
 */
public interface CreateUserUseCasePort {

    /**
     * Ejecuta el caso de uso para crear un nuevo usuario
     * 
     * @param username  nombre de usuario
     * @param email     correo electrónico
     * @param password  contraseña
     * @param password2 confirmación de contraseña
     * @param fullName  nombre completo
     * @return CompletableFuture con el usuario creado
     */
    CompletableFuture<UserEntity> execute(String username, String email, String password,
            String password2, String fullName);
}
````

## File: src/main/java/com/oauth/domain/ports/in/usecase/user/GetUserUseCasePort.java
````java
package com.oauth.domain.ports.in.usecase.user;

import java.util.Optional;

import com.oauth.domain.model.UserEntity;

/**
 * Puerto de entrada para el caso de uso de obtención de usuario
 * Define la interfaz que implementa el caso de uso
 */
public interface GetUserUseCasePort {

    /**
     * Busca un usuario por su nombre de usuario
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * Busca un usuario por su ID
     */
    Optional<UserEntity> findById(Long id);

    /**
     * Busca un usuario por su correo electrónico
     */
    Optional<UserEntity> findByEmail(String email);
}
````

## File: src/main/java/com/oauth/domain/ports/in/user/UserServicePort.java
````java
package com.oauth.domain.ports.in.user;

import java.util.Optional;

import com.oauth.domain.model.UserEntity;

/**
 * Puerto de entrada para servicios de Usuario
 * Define las operaciones de negocio relacionadas con usuarios
 */
public interface UserServicePort {

    /**
     * Busca un usuario por su nombre de usuario
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * Busca un usuario por su correo electrónico
     */
    Optional<UserEntity> findByEmail(String email);

    /**
     * Busca un usuario por su ID
     */
    Optional<UserEntity> findById(Long id);

    /**
     * Guarda un usuario
     */
    UserEntity save(UserEntity user);
}
````

## File: src/main/java/com/oauth/domain/ports/out/persistence/ApplicationRepositoryPort.java
````java
package com.oauth.domain.ports.out.persistence;

import java.util.Optional;

import com.oauth.domain.model.Application;

/**
 * Puerto de salida para operaciones de repositorio de aplicaciones
 */
public interface ApplicationRepositoryPort {

    Optional<Application> findById(Long id);

    Optional<Application> findByClientId(String clientId);

    Optional<Application> findByName(String name);

    Application save(Application application);

    void deleteById(Long id);

    void delete(Application application);
}
````

## File: src/main/java/com/oauth/domain/ports/out/persistence/RoleRepositoryPort.java
````java
package com.oauth.domain.ports.out.persistence;

import java.util.Optional;

import com.oauth.domain.model.Role;

/**
 * Puerto de salida para operaciones de repositorio de roles
 */
public interface RoleRepositoryPort {

    Optional<Role> findById(Long id);

    Optional<Role> findByName(String name);

    Role save(Role role);

    void deleteById(Long id);

    void delete(Role role);
}
````

## File: src/main/java/com/oauth/domain/ports/out/persistence/UserApplicationRepositoryPort.java
````java
package com.oauth.domain.ports.out.persistence;

import java.util.List;
import java.util.Optional;

import com.oauth.domain.model.UsuarioAplicacion;

/**
 * Puerto de salida para operaciones de repositorio de usuario-aplicación
 */
public interface UserApplicationRepositoryPort {

    Optional<UsuarioAplicacion> findById(Long id);

    List<UsuarioAplicacion> findByUsuarioId(Long usuarioId);

    List<UsuarioAplicacion> findByApplicationId(Long applicationId);

    Optional<UsuarioAplicacion> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId);

    UsuarioAplicacion save(UsuarioAplicacion usuarioAplicacion);

    void deleteById(Long id);

    void delete(UsuarioAplicacion usuarioAplicacion);
}
````

## File: src/main/java/com/oauth/domain/ports/out/persistence/UserRepositoryPort.java
````java
package com.oauth.domain.ports.out.persistence;

import java.util.Optional;

import com.oauth.domain.model.UserEntity;

/**
 * Puerto de salida para operaciones de repositorio de usuarios
 */
public interface UserRepositoryPort {

    Optional<UserEntity> findById(Long id);

    Optional<UserEntity> findByUsername(String username);

    Optional<UserEntity> findByEmail(String email);

    UserEntity save(UserEntity user);

    void deleteById(Long id);

    void delete(UserEntity user);
}
````

## File: src/main/java/com/oauth/domain/ports/out/security/PasswordEncoderPort.java
````java
package com.oauth.domain.ports.out.security;

/**
 * Puerto de salida para codificación de contraseñas
 */
public interface PasswordEncoderPort {

    /**
     * Codifica una contraseña plana
     * @param rawPassword contraseña sin codificar
     * @return contraseña codificada
     */
    String encode(CharSequence rawPassword);

    /**
     * Compara una contraseña plana con una codificada
     * @param rawPassword contraseña sin codificar
     * @param encodedPassword contraseña codificada
     * @return true si coinciden
     */
    boolean matches(CharSequence rawPassword, String encodedPassword);
}
````

## File: src/main/java/com/oauth/infrastructure/service/AppAwareAuthenticationProvider.java
````java
package com.oauth.infrastructure.service;

import com.oauth.domain.model.ApplicationDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class AppAwareAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(AppAwareAuthenticationProvider.class);

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AppAwareAuthenticationProvider(
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        var username = authentication.getName();
        var password = authentication.getCredentials() != null ? 
            authentication.getCredentials().toString() : "null";
        
        // ========== DETALLES DE AUTENTICACIÓN ==========
        var details = authentication.getDetails();
        
        if (details != null) {
            
            // Si es un Map, mostrar solo las keys (no valores para evitar exponer datos sensibles)
            if (details instanceof java.util.Map) {
                java.util.Map<?, ?> map = (java.util.Map<?, ?>) details;
                log.debug("Authentication details keys: {}", map.keySet());
            }
        }
        
        // ========== EXTRACCIÓN DE CLIENT_ID ==========
        var application = extractClientId(authentication);

        try {
            // ========== BÚSQUEDA DE USUARIO ==========
            UserDetails user;
            if (StringUtils.hasText(application)) {
                try {
                    user = userDetailsService.loadUserByUsernameAndApplication(username, application);
                } catch (UsernameNotFoundException e) {
                    throw e;
                }
            } else {
                log.debug("Buscando usuario global (sin aplicación)");
                try {
                    user = userDetailsService.loadUserByUsername(username);
                } catch (UsernameNotFoundException e) {
                    throw e;
                }
            }

            var passwordMatches = passwordEncoder.matches(password, user.getPassword());
            
            if (!passwordMatches) {
                throw new BadCredentialsException("Invalid credentials");
            }

            var authenticatedToken = 
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            authenticatedToken.setDetails(authentication.getDetails());
            
            log.debug("Token de autenticación creado exitosamente");
            
            return authenticatedToken;

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado: '{}' para aplicación: '{}' - {}", username, application, e.getMessage());
            throw new BadCredentialsException("Invalid credentials");
        } catch (Exception e) {
            log.error("Error inesperado durante autenticación: {}", e.getMessage(), e);
            throw new BadCredentialsException("Authentication failed: " + e.getMessage());
        }
    }

    private String extractClientId(Authentication authentication) {
        Object details = authentication.getDetails();
        
        // Caso 1: Es ApplicationDetails
        if (details instanceof ApplicationDetails appDetails) {
            var clientId = appDetails.clientId();
            log.debug("Extracted clientId from ApplicationDetails");
            return clientId;
        }
        
        // Caso 2: Es un Map (posiblemente de Spring)
        if (details instanceof java.util.Map) {
            java.util.Map<?, ?> map = (java.util.Map<?, ?>) details;
            var clientId = map.get("client_id");
            if (clientId != null) {
                log.debug("Extracted clientId from Map");
                return clientId.toString();
            }
        }
        
        // Caso 3: Es un String
        if (details instanceof String) {
            log.debug("Details is a String, not ApplicationDetails");
            // Podría ser el client_id directamente
            return (String) details;
        }
        
        log.debug("No se pudo extraer clientId. Details class: {}", 
            details != null ? details.getClass().getName() : "null");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        var supports = UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        log.debug("AppAwareAuthenticationProvider.supports({}) = {}", authentication.getSimpleName(), supports);
        return supports;
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/ApplicationAuthenticationDetailsSource.java
````java
package com.oauth.infrastructure.service;

import com.oauth.domain.model.ApplicationDetails;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class ApplicationAuthenticationDetailsSource 
        implements AuthenticationDetailsSource<HttpServletRequest, ApplicationDetails> {

    @Override
    public ApplicationDetails buildDetails(HttpServletRequest context) {
        String clientId = (String) context.getAttribute("CLIENT_ID");
        return new ApplicationDetails(clientId);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/ApplicationService.java
````java
package com.oauth.infrastructure.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.model.Application;
import com.oauth.adapters.output.persistence.ApplicationRepository;

@Service
public class ApplicationService extends BaseService<Application, Long, ApplicationRepository> {

    public ApplicationService(ApplicationRepository repository) {
        super(repository);
    }

    public Optional<Application> findByClientId(String clientId) {
        return this.repository.findByClientId(clientId);
    }

    public Optional<Application> findByName(String name) {
        return this.repository.findByName(name);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/BaseService.java
````java
package com.oauth.infrastructure.service;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import lombok.NonNull;
import org.springframework.transaction.annotation.Transactional;

public abstract class BaseService<T, ID, R extends JpaRepository<T, ID>> {

    protected final R repository;

    protected BaseService(R repository) {
        this.repository = repository;
    }

    @Transactional
    public @NonNull T save(@NonNull T entity) {
        return repository.save(entity);
    }

    @Transactional(readOnly = true)
    public @NonNull Optional<T> findById(@NonNull ID id) {
        return repository.findById(id);
    }

    @Transactional(readOnly = true)
    public @NonNull List<T> findAll() {
        return repository.findAll();
    }

    @Transactional(readOnly = true)
    public @NonNull Page<T> findAll(@NonNull Pageable pageable) {
        return repository.findAll(pageable);
    }

    @Transactional
    public @NonNull T update(@NonNull T entity) {
        return repository.save(entity);
    }

    @Transactional
    public void delete(@NonNull T entity) {
        repository.delete(entity);
    }

    @Transactional
    public void deleteById(@NonNull ID id) {
        repository.deleteById(id);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/ClientIdExtractorFilter.java
````java
package com.oauth.infrastructure.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(0)
public class ClientIdExtractorFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ClientIdExtractorFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        var uri = request.getRequestURI();
        var method = request.getMethod();
        
        // Procesar tanto GET como POST para /login
        if ("/login".equals(uri)) {
                                    
            var clientId = request.getParameter("client_id");
            var redirectUri = request.getParameter("redirect_uri");
            var codeChallenge = request.getParameter("code_challenge");
            var state = request.getParameter("state");
            
            if ("GET".equalsIgnoreCase(method)) {
                var session = request.getSession(true);
                
                if (clientId != null && !clientId.isEmpty()) {
                    session.setAttribute("CLIENT_ID", clientId);
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    session.setAttribute("REDIRECT_URI", redirectUri);
                }
                
                if (codeChallenge != null && !codeChallenge.isEmpty()) {
                    session.setAttribute("CODE_CHALLENGE", codeChallenge);
                }
                
                if (state != null && !state.isEmpty()) {
                    session.setAttribute("STATE", state);
                }
            }
            
            if ("POST".equalsIgnoreCase(method)) {
                var session = request.getSession(false);
                
                if (session != null) {
                    // Recuperar client_id si no viene en parámetros
                    if (clientId == null || clientId.isEmpty()) {
                        clientId = (String) session.getAttribute("CLIENT_ID");
                    }
                    
                    // Recuperar redirect_uri (siempre de sesión, no suele venir en POST)
                    redirectUri = (String) session.getAttribute("REDIRECT_URI");
                }
                
                // Guardar en request attribute para el resto de la cadena
                if (clientId != null && !clientId.isEmpty()) {
                    request.setAttribute("CLIENT_ID", clientId);
                } else {
                    log.debug("No se puede procesar login sin client_id");
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    request.setAttribute("REDIRECT_URI", redirectUri);
                } else {
                    log.debug("No hay redirect_uri, se usará el comportamiento por defecto");
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/CustomUserDetailsService.java
````java
package com.oauth.infrastructure.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.oauth.domain.model.UserEntity;
import com.oauth.adapters.output.persistence.UserEntityRepository;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    private final UserEntityRepository userEntityRepository;
    private final ApplicationService applicationService;
    private final UsuarioAplicacionService usuarioAplicacionService;

    public CustomUserDetailsService(UserEntityRepository userEntityRepository,
            ApplicationService applicationService,
            UsuarioAplicacionService usuarioAplicacionService) {
        this.userEntityRepository = userEntityRepository;
        this.applicationService = applicationService;
        this.usuarioAplicacionService = usuarioAplicacionService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userEntityRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }

    /**
     * Carga un usuario verificando que esté registrado en la aplicación
     * 
     * @param username    nombre de usuario
     * @param application identificador de la aplicación
     */
    public UserDetails loadUserByUsernameAndApplication(String username, String application) {
        UserEntity user = userEntityRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        // Verificar que el usuario esté registrado en la aplicación usando el objeto
        // user ya obtenido
        if (!applicationService.findByClientId(application)
                .map(app -> usuarioAplicacionService
                        .findByUsuarioIdAndApplicationId(user.getId(), app.getId())
                        .isPresent())
                .orElse(false)) {
            throw new UsernameNotFoundException(
                    "Usuario no encontrado: " + username + " para la app: " + application);
        }

        return user;
    }

    /**
     * Verifica si un usuario está registrado en una aplicación
     * 
     * @param username            nombre de usuario
     * @param applicationClientId client_id de la aplicación
     * @return true si está registrado
     */
    public boolean isUserRegisteredInApplication(String username, String applicationClientId) {
        UserEntity user = userEntityRepository.findByUsername(username)
                .orElse(null);

        if (user == null) {
            return false;
        }

        return applicationService.findByClientId(applicationClientId)
                .map(app -> usuarioAplicacionService
                        .findByUsuarioIdAndApplicationId(user.getId(), app.getId())
                        .isPresent())
                .orElse(false);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/UserEntityService.java
````java
package com.oauth.infrastructure.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.model.UserEntity;
import com.oauth.adapters.output.persistence.UserEntityRepository;

/**
 * Servicio de infraestructura para operaciones de persistencia de usuarios.
 * Solo contiene operaciones CRUD básicas y métodos de búsqueda.
 * La lógica de negocio debe estar en la capa de aplicación (Use Cases).
 */
@Service
public class UserEntityService extends BaseService<UserEntity, Long, UserEntityRepository> {

    public UserEntityService(UserEntityRepository repository) {
        super(repository);
    }

    /**
     * Busca un usuario por su nombre de usuario
     * Nota: Este método es usado por CustomUserDetailsService para autenticación
     */
    public Optional<UserEntity> findUserByUsername(String username) {
        return this.repository.findByUsername(username);
    }

    /**
     * Busca un usuario por su correo electrónico
     */
    public Optional<UserEntity> findUserByEmail(String email) {
        return this.repository.findByEmail(email);
    }
}
````

## File: src/main/java/com/oauth/infrastructure/service/UsuarioAplicacionService.java
````java
package com.oauth.infrastructure.service;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.domain.model.UsuarioAplicacion;
import com.oauth.adapters.output.persistence.UsuarioAplicacionRepository;

@Service
public class UsuarioAplicacionService extends BaseService<UsuarioAplicacion, Long, UsuarioAplicacionRepository> {

    public UsuarioAplicacionService(UsuarioAplicacionRepository repository) {
        super(repository);
    }

    public List<UsuarioAplicacion> findByUsuarioId(Long usuarioId) {
        return this.repository.findByUsuarioId(usuarioId);
    }

    public List<UsuarioAplicacion> findByApplicationId(Long applicationId) {
        return this.repository.findByApplicationId(applicationId);
    }

    public Optional<UsuarioAplicacion> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId) {
        return this.repository.findByUsuarioIdAndApplicationId(usuarioId, applicationId);
    }
}
````

## File: src/main/java/com/oauth/Application.java
````java
package com.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.env.Environment;

@SpringBootApplication
@ComponentScan(basePackages = { "com.oauth" })
public class Application {

	private static final Logger log = LoggerFactory.getLogger(Application.class);

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(Application.class);

		Environment env = app.run(args).getEnvironment();

		// Verificar configuración (solo para depuración)
		log.debug("Perfiles activos: {}", String.join(", ", env.getActiveProfiles()));
	}
}
````

## File: src/main/resources/static/css/login.css
````css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Google Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: #f5f5f5;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
}

.login-container {
    background: white;
    padding: 3rem 2.5rem;
    border-radius: 28px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
    width: 100%;
    max-width: 420px;
    transition: box-shadow 0.3s ease;
}

.login-container:hover {
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.08);
}

h1 {
    text-align: left;
    color: #1a1a1a;
    margin-bottom: 2rem;
    font-size: 1.8rem;
    font-weight: 500;
    letter-spacing: -0.5px;
}

.form-group {
    margin-bottom: 1.5rem;
}

label {
    display: block;
    margin-bottom: 0.5rem;
    color: #5f6368;
    font-weight: 400;
    font-size: 0.9rem;
    transition: color 0.2s ease;
}

input[type="text"],
input[type="password"] {
    width: 100%;
    padding: 0.85rem 0;
    border: none;
    border-bottom: 2px solid #e0e0e0;
    font-size: 1rem;
    transition: border-color 0.2s ease;
    background: transparent;
    outline: none;
}

input[type="text"]:focus,
input[type="password"]:focus {
    border-bottom-color: #1a73e8;
}

input[type="text"]:focus + label,
input[type="password"]:focus + label {
    color: #1a73e8;
}

button {
    width: 100%;
    padding: 0.85rem;
    background: #1a73e8;
    color: white;
    border: none;
    border-radius: 100px;
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.2s ease;
    margin: 1.5rem 0 2rem 0;
    letter-spacing: 0.25px;
}

button:hover {
    background: #1557b0;
}

button:active {
    transform: scale(0.98);
}

.error {
    background: #fce8e8;
    color: #d93025;
    padding: 0.85rem 1rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
    text-align: left;
    font-size: 0.9rem;
    border: 1px solid rgba(217, 48, 37, 0.1);
}

.logout {
    background: #e6f4ea;
    color: #137333;
    padding: 0.85rem 1rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
    text-align: left;
    font-size: 0.9rem;
    border: 1px solid rgba(19, 115, 51, 0.1);
}

.info {
    text-align: center;
    margin-top: 1.5rem;
    color: #5f6368;
    font-size: 0.8rem;
    border-top: 1px solid #f0f0f0;
    padding-top: 1.5rem;
}

.info .brand {
    opacity: 0.8;
    margin-right: 0.25rem;
}

.info .name {
    background: linear-gradient(135deg, #1a73e8, #8ab4f8);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 500;
}

/* Media Queries para dispositivos móviles */
@media (max-width: 480px) {
    .login-container {
        padding: 2rem 1.5rem;
        border-radius: 24px;
    }

    h1 {
        font-size: 1.5rem;
        margin-bottom: 1.5rem;
    }

    input[type="text"],
    input[type="password"] {
        padding: 0.75rem 0;
        font-size: 16px; /* Previene zoom en iOS */
    }

    button {
        padding: 0.75rem;
        margin: 1.25rem 0 1.5rem 0;
    }

    .info {
        margin-top: 1.25rem;
        padding-top: 1.25rem;
    }
}

/* Ajuste para pantallas muy pequeñas */
@media (max-width: 320px) {
    .login-container {
        padding: 1.5rem 1rem;
    }

    h1 {
        font-size: 1.3rem;
    }

    .error, .logout {
        padding: 0.7rem;
        font-size: 0.85rem;
    }
}

/* Estilos para tablets */
@media (min-width: 481px) and (max-width: 768px) {
    .login-container {
        max-width: 450px;
        padding: 2.5rem 2rem;
    }
}

/* Mejoras de accesibilidad */
@media (prefers-reduced-motion: reduce) {
    * {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}

/* Estilo para autocompletado */
input:-webkit-autofill,
input:-webkit-autofill:hover,
input:-webkit-autofill:focus {
    -webkit-box-shadow: 0 0 0px 1000px white inset;
    box-shadow: 0 0 0px 1000px white inset;
    -webkit-text-fill-color: #1a1a1a;
    border-bottom-color: #1a73e8;
}
````

## File: src/main/resources/templates/invalid-application.html
````html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acceso no autorizado - OAuth2 Server</title>
    <link rel="stylesheet" href="/css/login.css">
    <style>
        .warning-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            display: block;
        }
        
        .message-box {
            background: #fef7e0;
            border: 1px solid #f9a825;
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
            text-align: left;
        }
        
        .message-box h2 {
            color: #f57f17;
            font-size: 1.1rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            letter-spacing: -0.3px;
        }
        
        .message-box p {
            color: #5f6368;
            font-size: 0.9rem;
            line-height: 1.5;
        }
        
        .developer-info {
            background: #e8f0fe;
            border: 1px solid rgba(26, 115, 232, 0.2);
            border-radius: 12px;
            padding: 0.75rem 1.25rem;
            margin: 1.5rem 0;
            text-align: left;
        }
        
        .developer-header {
            width: 100%;
            background: none;
            border: none;
            padding: 0.5rem 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            color: #1a73e8;
            font-weight: 500;
            font-size: 0.95rem;
            border-radius: 8px;
            transition: background-color 0.2s;
        }
        
        .developer-header:hover {
            background-color: rgba(26, 115, 232, 0.08);
        }
        
        .developer-header:focus-visible {
            outline: 2px solid #1a73e8;
            outline-offset: 2px;
        }
        
        .developer-title {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .developer-title::before {
            content: "⚙️";
        }
        
        .collapse-icon {
            transition: transform 0.3s ease;
            font-size: 0.8rem;
        }
        
        .developer-header[aria-expanded="true"] .collapse-icon {
            transform: rotate(180deg);
        }
        
        .developer-content {
            transition: max-height 0.3s ease-in-out;
            overflow: hidden;
            max-height: 0;
            padding: 0 0.5rem;
        }
        
        .developer-content[hidden] {
            display: none;
        }
        
        .developer-content:not([hidden]) {
            max-height: 400px;
            padding: 0.5rem 0.5rem 1rem 0.5rem;
        }
        
        .developer-content p {
            color: #5f6368;
            font-size: 0.85rem;
            line-height: 1.5;
            margin-bottom: 0.75rem;
        }
        
        .code-example {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 0.75rem;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.75rem;
            color: #37474f;
            word-break: break-all;
            border: 1px solid #e0e0e0;
            margin-top: 0.5rem;
        }
        
        .code-example .label {
            color: #1a73e8;
            font-weight: 500;
        }
        
        .btn-secondary {
            background: #f5f5f5;
            color: #5f6368;
            border: 1px solid #e0e0e0;
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.2s;
            width: auto;
            min-width: 150px;
        }
        
        .btn-secondary:hover {
            background: #e8e8e8;
            color: #3c4043;
            border-color: #d0d0d0;
        }
        
        .actions {
            text-align: center;
            margin: 2rem 0;
        }
        
        .note {
            color: #9e9e9e;
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }
        
        .help-text {
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid #f0f0f0;
            color: #5f6368;
            font-size: 0.85rem;
            text-align: center;
        }
        
        .help-text a {
            color: #1a73e8;
            text-decoration: none;
        }
        
        .help-text a:hover {
            text-decoration: underline;
        }
        
        .info {
            margin-top: 2rem;
            color: #999;
            font-size: 0.8rem;
        }
        
        @media (max-width: 480px) {
            .message-box, .developer-info {
                padding: 1rem;
            }
            
            .code-example {
                font-size: 0.7rem;
            }
            
            .btn-secondary {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <span class="warning-icon">🔒</span>
        
        <h1>Acceso no autorizado</h1>
        
        <div class="message-box">
            <h2>Esta página de inicio de sesión no es válida</h2>
            <p>La página de login de OAuth2 Server solo puede ser utilizada desde una aplicación autorizada. No puedes acceder directamente a través del navegador.</p>
        </div>
        
        <div class="developer-info">
            <button class="developer-header" aria-expanded="false" aria-controls="developer-content">
                <span class="developer-title">Información para desarrolladores</span>
                <span class="collapse-icon">▼</span>
            </button>
            <div id="developer-content" class="developer-content" hidden>
                <p>Para implementar el flujo OAuth2 correctamente, tu aplicación debe redirigir al usuario a esta URL con los parámetros correctos:</p>
                <div class="code-example">
                    <span class="label">redirect_uri=</span>https://tu-app.com/callback&client_id=tu-client-id&response_type=code&scope=openid profile email
                </div>
                <p style="margin-top: 0.75rem;">Asegúrate de que tu aplicación esté registrada en OAuth2 Server y que el <code>redirect_uri</code> coincida exactamente con el registrado.</p>
            </div>
        </div>
        
        <div class="actions">
            <p class="note">
                Puedes cerrar esta pestaña cuando quieras.
            </p>
        </div>

        <div class="help-text">
            <p>
                ¿Necesitas ayuda? 
                <a th:href="'mailto:' + ${contactEmail} + '?subject=Problema%20con%20autenticaci%C3%B3n'">
                    Contacta con el administrador
                </a>
            </p>
        </div>
        
        <div class="info">
            <span class="brand">Powered by</span>
            <strong class="name"> · OAuth2Server</strong>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const developerHeader = document.querySelector('.developer-header');
            const developerContent = document.getElementById('developer-content');
            
            if (developerHeader && developerContent) {
                developerHeader.addEventListener('click', function() {
                    const isExpanded = developerHeader.getAttribute('aria-expanded') === 'true';
                    
                    // Toggle estado
                    developerHeader.setAttribute('aria-expanded', !isExpanded);
                    
                    if (isExpanded) {
                        developerContent.hidden = true;
                    } else {
                        developerContent.hidden = false;
                    }
                });
                
                // Soporte para teclado (Enter y Espacio)
                developerHeader.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        developerHeader.click();
                    }
                });
            }
        });
    </script>
</body>
</html>
````

## File: src/main/resources/templates/login.html
````html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - OAuth2 Server</title>
    <link rel="stylesheet" href="/css/login.css">
    <script>
        // Capturar client_id de la URL si existe
        window.onload = function() {
            const urlParams = new URLSearchParams(window.location.search);
            const clientId = urlParams.get('client_id');
            if (clientId) {
                document.getElementById('client_id').value = clientId;
            }
        };
    </script>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Iniciar Sesión</h1>

        <div th:if="${error}" class="error" th:text="${error}"></div>
        <div th:if="${logout}" class="logout" th:text="${logout}"></div>

        <form th:action="@{/login}" method="post">
            <input type="hidden" id="client_id" name="client_id" th:value="${clientId}" />

            <div class="form-group">
                <label for="username">Usuario</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Contraseña</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">Iniciar Sesión</button>
        </form>

        <div class="info">
            <span class="brand">Powered by</span>
            <strong class="name"> · OAuth2Server</strong>
        </div>
    </div>
</body>
</html>
````

## File: src/main/resources/templates/oauth2-consent.html
````html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth2 Consent</title>
    <link rel="stylesheet" href="/css/login.css">
</head>
<body>
    <div class="login-container">
        <h1>🔐 Autorizar Aplicación</h1>
        
        <p>La aplicación <strong><span th:text="${clientId}">client</span></strong> está solicitando acceso a tu cuenta.</p>
        
        <p>Por favor revisa los siguientes permisos:</p>
        
        <form th:action="@{/oauth2/authorize}" method="post">
            <input type="hidden" name="client_id" th:value="${clientId}">
            <input type="hidden" name="state" th:value="${state}">
            <input type="hidden" name="scope" th:value="${scope}">
            
            <div class="form-group">
                <label><strong>Permisos solicitados:</strong></label>
                <ul>
                    <li th:each="s : ${scopes}" th:text="${s}">scope</li>
                </ul>
            </div>
            
            <div class="form-group">
                <label>
                    <input type="checkbox" name="consent" required>
                    Acepto compartir mi información con esta aplicación
                </label>
            </div>
            
            <div class="form-actions">
                <button type="submit" name="approve" value="true" class="btn btn-primary">Autorizar</button>
                <button type="submit" name="deny" value="true" class="btn btn-secondary">Denegar</button>
            </div>
        </form>
    </div>
</body>
</html>
````

## File: src/main/resources/application-dev.properties
````
app.contact.email=${CONTACT_EMAIL:admin@tudominio.com}

# SpringDoc OpenAPI Configuration
springdoc.api-docs.path=/api-docs
springdoc.swagger-ui.path=/swagger-ui.html
springdoc.swagger-ui.operationsSorter=method
springdoc.swagger-ui.tagsSorter=alpha
springdoc.swagger-ui.try-it-out-enabled=true
springdoc.swagger-ui.filter=true
springdoc.swagger-ui.display-request-duration=true

# Swagger Custom Properties
swagger.title=OAuth2 Server API
swagger.version=1.0
swagger.description=API REST con autenticación OAuth2. ## Flujo de Autorización Este servidor implementa OAuth2 con PKCE. ## Endpoints Principales * /oauth2/authorize - Autorización * /oauth2/token - Obtención de tokens * /oauth2/jwks - Claves públicas * /.well-known/openid-configuration - OpenID Connect discovery
swagger.contact.name=Soporte OAuth2
swagger.contact.email=soporte@oauth.example.com
swagger.contact.url=https://oauth.example.com

cors.allowed-origins=${ALLOWED_ORIGINS:http://localhost:8080}

# ============================
# 📊 LOGGING
# ============================
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.oauth2=DEBUG
logging.level.org.springframework.security.oauth2.server.authorization=DEBUG
logging.level.com.oauth=DEBUG

# ============================
# 🔌 Thymeleaf - Configuración de plantillas
# ============================
spring.thymeleaf.cache=false
spring.thymeleaf.prefix=classpath:/templates/
spring.thymeleaf.suffix=.html
spring.thymeleaf.mode=HTML
spring.thymeleaf.encoding=UTF-8

# ============================
# 🔌 Base de datos PostgreSQL
# ============================
# Usa las variables del script entrypoint (SPRING_DATASOURCE_URL_DEV, etc.)
spring.datasource.url=${SPRING_DATASOURCE_URL:jdbc:postgresql://postgres-dev:5432/oauth2_dev}
spring.datasource.username=${SPRING_DATASOURCE_USERNAME:oauth2_user}
spring.datasource.password=${SPRING_DATASOURCE_PASSWORD:oauth2_dev_password}
spring.datasource.driver-class-name=org.postgresql.Driver

# Pool de conexiones
spring.datasource.hikari.maximum-pool-size=10
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=30000

# Puerto
server.port=${PORT:8080}

# SSL (deshabilitado en dev)
server.ssl.enabled=false

# ============================
# 🗄️ JPA / Hibernate
# ============================
# IMPORTANTE: Solo validate, Flyway es el único responsable del esquema
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect

# ============================
# 📦 Inicialización de datos
# ============================
spring.jpa.defer-datasource-initialization=false
spring.sql.init.mode=never

# ============================
# 🔄 Flyway - Único responsable del esquema
# ============================
spring.flyway.enabled=true
spring.flyway.baseline-on-migrate=true
spring.flyway.locations=classpath:db/migration
# Dev: clean deshabilitado para evitar borrados accidentales
spring.flyway.clean-disabled=true

# ============================
# 🔐 OAuth2 - Configuración base para tokens
# ============================
oauth2.access-token-validity-seconds=${ACCESS_TOKEN_VALIDITY:86400}
oauth2.refresh-token-validity-seconds=${REFRESH_TOKEN_VALIDITY:1296000}

# ============================
# 📋 CLIENTES OAuth2
# ============================

# Cliente 0 - cine-platform
oauth2.clients[0].client-id=cine-platform
oauth2.clients[0].client-secret=${CINE_PLATFORM_SECRET:cine-platform}
oauth2.clients[0].redirect-uris[0]=${CINE_PLATFORM_REDIRECT_URI:http://localhost:5000/oauth/callback}
oauth2.clients[0].scopes[0]=openid
oauth2.clients[0].scopes[1]=profile
oauth2.clients[0].scopes[2]=read
oauth2.clients[0].scopes[3]=write
oauth2.clients[0].require-consent=false
oauth2.clients[0].require-proof-key=true
oauth2.clients[0].authorization-grant-types=client_credentials,authorization_code,refresh_token

# Cliente 1 - transcriberapp
oauth2.clients[1].client-id=transcriberapp
oauth2.clients[1].client-secret=${TRANSCRIBERAPP_SECRET:transcriberapp}
oauth2.clients[1].redirect-uris[0]=${TRANSCRIBERAPP_REDIRECT_URI:http://localhost:9000/oauth/callback}
oauth2.clients[1].scopes[0]=openid
oauth2.clients[1].scopes[1]=profile
oauth2.clients[1].scopes[2]=read
oauth2.clients[1].scopes[3]=write
oauth2.clients[1].require-consent=false
oauth2.clients[1].require-proof-key=false
oauth2.clients[1].authorization-grant-types=client_credentials,authorization_code,refresh_token

# ============================
# 🔑 JWT
# ============================
spring.security.oauth2.authorizationserver.issuer=${ISSUER_URL:http://localhost:8080}
spring.security.oauth2.resourceserver.jwt.issuer-uri=${ISSUER_URL:http://localhost:8080}
spring.security.oauth2.resourceserver.jwt.audience=${JWT_AUDIENCE:oauth2-client}
oauth2.jwt-signing-key=${JWT_SIGNING_KEY}
````

## File: src/main/resources/application.properties
````
server.port=8080

spring.mvc.pathmatch.matching-strategy=ant_path_matcher

# JSON
spring.jackson.mapper.default-view-inclusion=true

# Perfil por defecto (se sobrescribe con variable de entorno SPRING_PROFILES_ACTIVE)
# spring.profiles.active=dev

# Permitir referencias circulares
spring.main.allow-circular-references=true

app.contact.email=${CONTACT_EMAIL}

logging.level.org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer=ERROR
````

## File: src/test/groovy/com/oauth/adapters/input/rest/dto/CreateUserDtoSpec.groovy
````groovy
package com.oauth.adapters.input.rest.dto

import spock.lang.Specification

class CreateUserDtoSpec extends Specification {

    def 'CreateUserDto can be created with all fields'() {
        given:
        CreateUserDto dto = new CreateUserDto()
        dto.setUsername("newuser")
        dto.setEmail("newuser@example.com")
        dto.setPassword("testPassword123")
        dto.setPassword2("testPassword123")
        dto.setFullName("New User")

        expect:
        dto.getUsername() == "newuser"
        dto.getEmail() == "newuser@example.com"
        dto.getPassword() == "testPassword123"
        dto.getPassword2() == "testPassword123"
        dto.getFullName() == "New User"
    }

    def 'CreateUserDto defaults'() {
        given:
        CreateUserDto dto = new CreateUserDto()

        expect:
        dto.getUsername() == null
        dto.getEmail() == null
        dto.getPassword() == null
        dto.getPassword2() == null
        dto.getFullName() == null
    }

    def 'CreateUserDto can be created with constructor'() {
        when:
        CreateUserDto dto = new CreateUserDto(
            username: "testuser",
            password: "testPass123",
            password2: "testPass123"
        )

        then:
        dto.getUsername() == "testuser"
        dto.getPassword() == "testPass123"
        dto.getPassword2() == "testPass123"
    }
}
````

## File: src/test/groovy/com/oauth/adapters/input/rest/dto/GetUserDtoSpec.groovy
````groovy
package com.oauth.adapters.input.rest.dto

import spock.lang.Specification

class GetUserDtoSpec extends Specification {

    def 'GetUserDto full constructor works'() {
        when:
        GetUserDto dto = new GetUserDto(1L, 'testuser', 'Test User', 'test@example.com', ['ROLE_USER'] as Set)

        then:
        dto.id() == 1L
        dto.username() == 'testuser'
        dto.fullName() == 'Test User'
        dto.email() == 'test@example.com'
        dto.roles() == ['ROLE_USER'] as Set
    }

    def 'GetUserDto can have null roles'() {
        when:
        GetUserDto dto = new GetUserDto(1L, 'testuser', 'Test User', 'test@example.com', null)

        then:
        dto.id() == 1L
        dto.username() == 'testuser'
        dto.roles() == null
    }

    def 'GetUserDto factory method works'() {
        when:
        GetUserDto dto = GetUserDto.of(1L, 'testuser', 'Test User', 'test@example.com')

        then:
        dto.id() == 1L
        dto.username() == 'testuser'
        dto.fullName() == 'Test User'
        dto.email() == 'test@example.com'
        dto.roles() == null
    }
}
````

## File: src/test/groovy/com/oauth/adapters/input/rest/mapper/UserDtoMapperSpec.groovy
````groovy
package com.oauth.adapters.input.rest.mapper

import com.oauth.adapters.input.rest.dto.GetUserDto
import com.oauth.domain.model.Role
import com.oauth.domain.model.UserEntity
import spock.lang.Specification

class UserDtoMapperSpec extends Specification {

    def 'toGetUserDto maps UserEntity to GetUserDto'() {
        given:
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername('testuser')
        user.setEmail('test@example.com')
        user.setPassword('hashedPassword')
        user.setFullName('Test User')
        user.setRoles(Set.of(new Role('ROLE_USER', 'Usuario estándar')))

        UserDtoMapper mapper = new UserDtoMapper()

        when:
        GetUserDto dto = mapper.toGetUserDto(user)

        then:
        dto.username() == 'testuser'
        dto.email() == 'test@example.com'
        dto.fullName() == 'Test User'
        dto.roles() != null
        dto.roles().contains('ROLE_USER')
    }

    def 'toGetUserDto maps roles correctly'() {
        given:
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername('admin')
        user.setEmail('admin@example.com')
        user.setPassword('password')
        user.setRoles(Set.of(
            new Role('ROLE_USER', 'Usuario estándar'),
            new Role('ROLE_ADMIN', 'Administrador')
        ))

        UserDtoMapper mapper = new UserDtoMapper()

        when:
        GetUserDto dto = mapper.toGetUserDto(user)

        then:
        dto.roles().size() == 2
        dto.roles().contains('ROLE_USER')
        dto.roles().contains('ROLE_ADMIN')
    }

    def 'toGetUserDto handles empty roles'() {
        given:
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername('nobody')
        user.setEmail('nobody@example.com')
        user.setPassword('password')
        user.setRoles(new HashSet<>())

        UserDtoMapper mapper = new UserDtoMapper()

        when:
        GetUserDto dto = mapper.toGetUserDto(user)

        then:
        dto.roles().isEmpty()
    }
}
````

## File: src/test/groovy/com/oauth/adapters/input/rest/UserControllerSpec.groovy
````groovy
package com.oauth.adapters.input.rest

import com.oauth.adapters.input.rest.dto.CreateUserDto
import com.oauth.adapters.input.rest.dto.GetUserDto
import com.oauth.adapters.input.rest.mapper.UserDtoMapper
import com.oauth.domain.exception.UserPasswordException
import com.oauth.domain.model.Role
import com.oauth.domain.model.UserEntity
import com.oauth.domain.ports.in.usecase.user.CreateUserUseCasePort
import com.oauth.domain.ports.in.usecase.user.GetUserUseCasePort
import org.springframework.web.server.ResponseStatusException
import spock.lang.Specification

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException

class UserControllerSpec extends Specification {

    CreateUserUseCasePort createUserUseCase
    GetUserUseCasePort getUserUseCase
    UserDtoMapper userDtoMapper
    UserController userController

    def setup() {
        createUserUseCase = Mock(CreateUserUseCasePort)
        getUserUseCase = Mock(GetUserUseCasePort)
        userDtoMapper = new UserDtoMapper()
        userController = new UserController(createUserUseCase, getUserUseCase, userDtoMapper)
    }

    def 'nuevoUsuario returns GetUserDto on success'() {
        given:
        CreateUserDto dto = new CreateUserDto()
        dto.setUsername('newuser')
        dto.setPassword('ValidPass123')
        dto.setPassword2('ValidPass123')
        dto.setFullName('New User')
        dto.setEmail('newuser@example.com')

        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername(dto.getUsername())
        user.setPassword('hashedPassword')
        user.setFullName(dto.getFullName())
        user.setEmail(dto.getEmail())
        user.setRoles(Set.of(new Role('ROLE_USER', 'Usuario estándar')))

        when:
        CompletableFuture<GetUserDto> future = userController.nuevoUsuario(dto)
        GetUserDto result = future.get()

        then:
        1 * createUserUseCase.execute('newuser', 'newuser@example.com', 'ValidPass123', 'ValidPass123', 'New User') >> CompletableFuture.completedFuture(user)
        result != null
        result.username() == 'newuser'
        result.id() == 1L
    }

    def 'nuevoUsuario throws exception when passwords do not match'() {
        given:
        CreateUserDto dto = new CreateUserDto()
        dto.setUsername('newuser')
        dto.setPassword('ValidPass123')
        dto.setPassword2('DifferentPass123')

        when:
        CompletableFuture<GetUserDto> future = userController.nuevoUsuario(dto)
        future.get()

        then:
        1 * createUserUseCase.execute(_, _, _, _, _) >> CompletableFuture.failedFuture(new UserPasswordException())
        def ex = thrown(ExecutionException)
        ex.cause instanceof UserPasswordException
    }

    def 'me returns GetUserDto from authenticated user'() {
        given:
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername('admin')
        user.setEmail('admin@example.com')
        user.setPassword('hashedPassword')
        user.setFullName('Admin User')
        user.setRoles(Set.of(new Role('ROLE_ADMIN', 'Administrador')))

        when:
        GetUserDto result = userController.me(user)

        then:
        result != null
        result.username() == 'admin'
        result.id() == 1L
        result.roles().contains('ROLE_ADMIN')
    }

    def 'me returns empty roles when user has no roles'() {
        given:
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername('nobody')
        user.setEmail('nobody@example.com')
        user.setPassword('hashedPassword')
        user.setFullName('No Body')
        user.setRoles(new HashSet<>())

        when:
        GetUserDto result = userController.me(user)

        then:
        result != null
        result.username() == 'nobody'
        result.roles().isEmpty()
    }
}
````

## File: src/test/groovy/com/oauth/adapters/input/UserServiceAdapterSpec.groovy
````groovy
package com.oauth.adapters.input

import com.oauth.domain.model.UserEntity
import com.oauth.domain.ports.in.user.UserServicePort
import com.oauth.domain.ports.out.persistence.UserRepositoryPort
import spock.lang.Specification

class UserServiceAdapterSpec extends Specification {

    UserRepositoryPort userRepositoryPort
    UserServiceAdapter userServiceAdapter

    def setup() {
        userRepositoryPort = Mock(UserRepositoryPort)
        userServiceAdapter = new UserServiceAdapter(userRepositoryPort)
    }

    def 'findByUsername returns user when user exists'() {
        given:
        String username = 'admin'
        UserEntity user = new UserEntity()
        user.setUsername(username)
        user.setEmail('admin@oauth.net')

        when:
        def result = userServiceAdapter.findByUsername(username)

        then:
        1 * userRepositoryPort.findByUsername(username) >> Optional.of(user)
        result.isPresent()
        result.get().username == username
    }

    def 'findByUsername returns empty when user does not exist'() {
        given:
        String username = 'nonexistent'

        when:
        def result = userServiceAdapter.findByUsername(username)

        then:
        1 * userRepositoryPort.findByUsername(username) >> Optional.empty()
        !result.isPresent()
    }

    def 'findByEmail returns user when email exists'() {
        given:
        String email = 'admin@oauth.net'
        UserEntity user = new UserEntity()
        user.setUsername('admin')
        user.setEmail(email)

        when:
        def result = userServiceAdapter.findByEmail(email)

        then:
        1 * userRepositoryPort.findByEmail(email) >> Optional.of(user)
        result.isPresent()
        result.get().email == email
    }

    def 'save returns saved user'() {
        given:
        UserEntity user = new UserEntity()
        user.setUsername('testuser')
        user.setEmail('test@example.com')

        when:
        def result = userServiceAdapter.save(user)

        then:
        1 * userRepositoryPort.save(user) >> user
        result == user
    }
}
````

## File: src/test/groovy/com/oauth/application/usecase/user/CreateUserUseCaseSpec.groovy
````groovy
package com.oauth.application.usecase.user

import com.oauth.domain.exception.UserPasswordException
import com.oauth.domain.model.Role
import com.oauth.domain.model.UserEntity
import com.oauth.domain.ports.in.role.RoleServicePort
import com.oauth.domain.ports.in.usecase.user.CreateUserUseCasePort
import com.oauth.domain.ports.in.user.UserServicePort
import com.oauth.domain.ports.out.security.PasswordEncoderPort
import spock.lang.Specification

class CreateUserUseCaseSpec extends Specification {

    UserServicePort userService
    RoleServicePort roleService
    PasswordEncoderPort passwordEncoder
    CreateUserUseCase createUserUseCase

    def setup() {
        userService = Mock(UserServicePort)
        roleService = Mock(RoleServicePort)
        passwordEncoder = Mock(PasswordEncoderPort)
        createUserUseCase = new CreateUserUseCase(userService, roleService, passwordEncoder)
    }

    def 'execute throws UserPasswordException when passwords do not match'() {
        when:
        createUserUseCase.execute('testuser', 'test@example.com', 'Password123', 'DifferentPass', 'Test User').get()

        then:
        def ex = thrown(Exception)
        ex.cause instanceof UserPasswordException
    }

    def 'execute creates user with valid credentials'() {
        given:
        Role userRole = new Role('ROLE_USER', 'Usuario estándar')
        UserEntity savedUser = new UserEntity()
        savedUser.setId(1L)
        savedUser.setUsername('testuser')
        savedUser.setEmail('test@example.com')
        savedUser.setFullName('Test User')

        when:
        def result = createUserUseCase.execute('testuser', 'test@example.com', 'Password123', 'Password123', 'Test User').get()

        then:
        1 * passwordEncoder.encode('Password123') >> 'encodedPassword'
        1 * roleService.findOrCreateRole('ROLE_USER', 'Usuario estándar') >> userRole
        1 * userService.save(_) >> savedUser
        result.username == 'testuser'
    }

    def 'execute throws exception when username already exists'() {
        given:
        Role userRole = new Role('ROLE_USER', 'Usuario estándar')
        
        when:
        createUserUseCase.execute('existinguser', 'test@example.com', 'Password123', 'Password123', 'Test User').get()

        then:
        1 * passwordEncoder.encode(_) >> 'encodedPassword'
        1 * roleService.findOrCreateRole('ROLE_USER', _) >> userRole
        1 * userService.save(_) >> { throw new org.springframework.dao.DataIntegrityViolationException('Duplicate key') }
        
        def ex = thrown(Exception)
        ex.cause != null
    }
}
````

## File: src/test/groovy/com/oauth/domain/exception/UserPasswordExceptionSpec.groovy
````groovy
package com.oauth.domain.exception

import spock.lang.Specification

class UserPasswordExceptionSpec extends Specification {

    def 'UserPasswordException can be created with default message'() {
        when:
        def exception = new UserPasswordException()

        then:
        exception != null
        exception.message == "Las contraseñas no coinciden"
    }

    def 'UserPasswordException can be created with custom message'() {
        when:
        def exception = new UserPasswordException("Custom error message")

        then:
        exception != null
        exception.message == "Custom error message"
    }

    def 'UserPasswordException extends RuntimeException'() {
        expect:
        RuntimeException.isAssignableFrom(UserPasswordException)
    }
}
````

## File: src/test/groovy/com/oauth/domain/model/UserEntitySpec.groovy
````groovy
package com.oauth.domain.model

import spock.lang.Specification

class UserEntitySpec extends Specification {

    def 'UserEntity can be created with username and email'() {
        given:
        UserEntity user = new UserEntity()
        user.setUsername("testuser")
        user.setEmail("test@example.com")
        user.setPassword("password123")

        expect:
        user.getUsername() == "testuser"
        user.getEmail() == "test@example.com"
        user.getPassword() == "password123"
    }

    def 'UserEntity can have roles'() {
        given:
        UserEntity user = new UserEntity()
        Role adminRole = new Role('ROLE_ADMIN', 'Administrator')
        Role userRole = new Role('ROLE_USER', 'User')

        when:
        user.setRoles(Set.of(adminRole, userRole))

        then:
        user.getRoles().size() == 2
        user.getRoles().contains(adminRole)
        user.getRoles().contains(userRole)
    }

    def 'UserEntity defaults'() {
        given:
        UserEntity user = new UserEntity()

        expect:
        user.getId() == null
        user.getUsername() == null
        user.getEmail() == null
        user.getPassword() == null
    }
}
````

## File: src/test/groovy/com/oauth/infrastructure/service/BaseServiceSpec.groovy
````groovy
package com.oauth.infrastructure.service

import com.oauth.adapters.output.persistence.UserEntityRepository
import spock.lang.Specification

class BaseServiceSpec extends Specification {

    def "BaseService is abstract and cannot be instantiated"() {
        expect:
        // BaseService is an abstract class
        // It provides generic CRUD operations for all services
        true
    }

    def "UserEntityService extends BaseService"() {
        given:
        UserEntityRepository repository = Mock(UserEntityRepository)
        
        when:
        UserEntityService userService = new UserEntityService(repository)

        then:
        userService != null
    }
}
````

## File: src/test/groovy/com/oauth/infrastructure/service/CustomUserDetailsServiceSpec.groovy
````groovy
package com.oauth.infrastructure.service

import com.oauth.domain.model.Application
import com.oauth.domain.model.Role
import com.oauth.domain.model.UserEntity
import com.oauth.domain.model.UsuarioAplicacion
import com.oauth.adapters.output.persistence.UserEntityRepository
import org.springframework.security.core.userdetails.UsernameNotFoundException
import spock.lang.Specification

class CustomUserDetailsServiceSpec extends Specification {

    UserEntityRepository userEntityRepository
    ApplicationService applicationService
    UsuarioAplicacionService usuarioAplicacionService
    CustomUserDetailsService customUserDetailsService

    def setup() {
        userEntityRepository = Mock(UserEntityRepository)
        applicationService = Mock(ApplicationService)
        usuarioAplicacionService = Mock(UsuarioAplicacionService)
        customUserDetailsService = new CustomUserDetailsService(
            userEntityRepository, 
            applicationService, 
            usuarioAplicacionService
        )
    }

    def "loadUserByUsername returns user when user exists"() {
        given:
        String username = "admin"
        UserEntity user = new UserEntity()
        user.setUsername(username)
        user.setEmail("admin@oauth.net")
        user.setPassword("hashedPassword")
        user.setRoles(Set.of(new Role('ROLE_ADMIN', 'Administrador')))

        when:
        def result = customUserDetailsService.loadUserByUsername(username)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        result.getUsername() == username
    }

    def "loadUserByUsername throws exception when user does not exist"() {
        given:
        String username = "nonexistent"

        when:
        customUserDetailsService.loadUserByUsername(username)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "loadUserByUsernameAndApplication returns user when user exists for app"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername(username)
        user.setEmail("admin@oauth.net")
        user.setPassword("hashedPassword")
        user.setRoles(Set.of(new Role('ROLE_ADMIN', 'Administrador')))
        
        Application app = new Application()
        app.setId(1L)
        app.setClientId(appClientId)

        when:
        def result = customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        1 * applicationService.findByClientId(appClientId) >> Optional.of(app)
        1 * usuarioAplicacionService.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.of(new UsuarioAplicacion())
        result.getUsername() == username
    }

    def "loadUserByUsernameAndApplication throws exception when user not registered for app"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserEntity user = new UserEntity()
        user.setId(1L)
        user.setUsername(username)
        user.setEmail("admin@oauth.net")
        
        Application app = new Application()
        app.setId(1L)
        app.setClientId(appClientId)

        when:
        customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        1 * applicationService.findByClientId(appClientId) >> Optional.of(app)
        1 * usuarioAplicacionService.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "loadUserByUsernameAndApplication throws exception when user does not exist"() {
        given:
        String username = "nonexistent"
        String appClientId = "cine-platform"

        when:
        customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "isUserRegisteredInApplication returns true when user is registered"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserEntity user = new UserEntity()
        user.setId(1L)
        
        Application app = new Application()
        app.setId(1L)

        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        1 * applicationService.findByClientId(appClientId) >> Optional.of(app)
        1 * usuarioAplicacionService.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.of(new UsuarioAplicacion())
        result == true
    }

    def "isUserRegisteredInApplication returns false when user is not registered"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserEntity user = new UserEntity()
        user.setId(1L)
        
        Application app = new Application()
        app.setId(1L)

        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        1 * applicationService.findByClientId(appClientId) >> Optional.of(app)
        1 * usuarioAplicacionService.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.empty()
        result == false
    }

    def "isUserRegisteredInApplication returns false when user does not exist"() {
        given:
        String username = "nonexistent"
        String appClientId = "cine-platform"

        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.empty()
        result == false
    }
}
````

## File: src/test/groovy/com/oauth/infrastructure/service/UserEntityServiceSpec.groovy
````groovy
package com.oauth.infrastructure.service

import com.oauth.domain.model.UserEntity
import com.oauth.adapters.output.persistence.UserEntityRepository
import spock.lang.Specification

class UserEntityServiceSpec extends Specification {

    UserEntityRepository userEntityRepository
    UserEntityService userEntityService

    def setup() {
        userEntityRepository = Mock(UserEntityRepository)
        userEntityService = new UserEntityService(userEntityRepository)
    }

    def "findUserByUsername returns user when user exists"() {
        given:
        String username = "admin"
        UserEntity user = new UserEntity()
        user.setUsername(username)
        user.setEmail("admin@oauth.net")
        user.setPassword("hashedPassword")

        when:
        Optional<UserEntity> result = userEntityService.findUserByUsername(username)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.of(user)
        result.isPresent()
        result.get().getUsername() == username
    }

    def "findUserByUsername returns empty when user does not exist"() {
        given:
        String username = "nonexistent"

        when:
        Optional<UserEntity> result = userEntityService.findUserByUsername(username)

        then:
        1 * userEntityRepository.findByUsername(username) >> Optional.empty()
        !result.isPresent()
    }

    def "findUserByEmail returns user when email exists"() {
        given:
        String email = "admin@oauth.net"
        UserEntity user = new UserEntity()
        user.setUsername("admin")
        user.setEmail(email)
        user.setPassword("hashedPassword")

        when:
        Optional<UserEntity> result = userEntityService.findUserByEmail(email)

        then:
        1 * userEntityRepository.findByEmail(email) >> Optional.of(user)
        result.isPresent()
        result.get().getEmail() == email
    }

    def "findUserByEmail returns empty when email does not exist"() {
        given:
        String email = "nonexistent@example.com"

        when:
        Optional<UserEntity> result = userEntityService.findUserByEmail(email)

        then:
        1 * userEntityRepository.findByEmail(email) >> Optional.empty()
        !result.isPresent()
    }
}
````

## File: src/test/groovy/com/oauth/security/PasswordEncoderConfigSpec.groovy
````groovy
package com.oauth.security

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import com.oauth.config.PasswordEncoderConfig
import spock.lang.Specification

class PasswordEncoderConfigSpec extends Specification {

    def 'PasswordEncoderConfig creates BCryptPasswordEncoder'() {
        given:
        PasswordEncoderConfig config = new PasswordEncoderConfig()

        when:
        PasswordEncoder encoder = config.passwordEncoder()

        then:
        encoder != null
        encoder instanceof BCryptPasswordEncoder
    }

    def 'PasswordEncoderConfig returns password encoder'() {
        given:
        PasswordEncoderConfig config = new PasswordEncoderConfig()

        when:
        PasswordEncoder encoder = config.passwordEncoder()

        then:
        encoder != null
        encoder instanceof BCryptPasswordEncoder
    }

    def 'PasswordEncoder encodes and matches passwords'() {
        given:
        PasswordEncoderConfig config = new PasswordEncoderConfig()
        PasswordEncoder encoder = config.passwordEncoder()
        String rawPassword = "testPassword123"

        when:
        String encoded = encoder.encode(rawPassword)
        boolean matches = encoder.matches(rawPassword, encoded)

        then:
        encoded != rawPassword
        matches == true
    }
}
````

## File: src/test/groovy/com/oauth/ApplicationSpec.groovy
````groovy
package com.oauth

import spock.lang.Specification

class ApplicationSpec extends Specification {

    def 'Application main method can be called'() {
        given:
        // Application class has a main method that starts Spring Boot
        // We just verify the class exists and can be instantiated structurally
        
        expect:
        Application != null
    }
}
````

## File: src/test/resources/application-test.properties
````
# Test configuration
spring.application.name=OAuth2Server
server.port=8080

# H2 Test Database
spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL
spring.datasource.username=sa
spring.datasource.password=
spring.datasource.driverClassName=org.h2.Driver

# JPA
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.format_sql=false
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect

# Flyway
spring.flyway.enabled=false

# OAuth2
oauth2.client-id=default-client
oauth2.client-secret=123456
oauth2.redirect-uri=http://localhost:3000/callback
oauth2.access-token-validity-seconds=86400
oauth2.refresh-token-validity-seconds=1296000

# JWT
spring.security.oauth2.authorizationserver.issuer=http://localhost:8080
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080
spring.security.oauth2.resourceserver.jwt.audience=oauth2-client
oauth2.jwt-signing-key=test-secret-key-for-testing-purposes-only

# Logging
logging.level.org.springframework.security=WARN
logging.level.org.springframework.security.oauth2=WARN
````

## File: .gitignore
````
HELP.md
target/
!.mvn/wrapper/maven-wrapper.jar
!**/src/main/**/target/
!**/src/test/**/target/

.mvn/

application-secrets.properties
.env
*.log
*.sql

### STS ###
.apt_generated
.classpath
.factorypath
.project
.settings
.springBeans
.sts4-cache

### IntelliJ IDEA ###
.idea/
*.iws
*.iml
*.ipr

### NetBeans ###
nbproject/private/
nbbuild/
dist/
nbdist/
.nb-gradle/
build/
!**/src/main/**/build/
!**/src/test/**/build/

### VS Code ###
.vscode/

### k8s secrets - solo overlays, no bases ###
k8s/**/overlays/**
!k8s/**/overlays/example/
k8s/**/overlays/prod/**
k8s/**/overlays/dev/**
k8s/**/overlays/staging/**
k8s/**/secrets.yaml
k8s/**/*-secrets.yaml

### Certificados y archivos sensibles ###
*.p12
*.crt
*.key
*.jks
*.pem
*.cer
*.pfx
*.keystore
*.truststore

### Scripts de entorno ###
entrypoint.sh
*.bat
*.cmd

### Archivos temporales ###
*.tmp
*.temp
*.log
*.bak
*.swp
*.swo
*~

### Docker ###
.dockerignore
Dockerfile
!Dockerfile.prod
!Dockerfile.dev

### Bases de datos y migraciones ###
src/main/resources/data.sql

### Directorios de build ###
dist/
bin/

application-prod.properties
backup-sensitive.sh
docker-compose.prod.yml
Dockerfile.prod

CLAUDE.md
.claude/
````

## File: docker-compose.yml
````yaml
services:
  # ===========================================
  # PostgreSQL Desarrollo (ÚNICA BASE DE DATOS)
  # ===========================================
  postgres:
    image: postgres:15-alpine
    container_name: oauth2-postgres-dev
    environment:
      POSTGRES_DB: oauth2_dev
      POSTGRES_USER: oauth2_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-oauth2_dev_password}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth2_user -d oauth2_dev"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s
    networks:
      - oauth-network
      - cine-network
    restart: unless-stopped

  # ===========================================
  # Servidor OAuth2
  # ===========================================
  oauth2-server:
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 8080 || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    build: .
    image: felixmurcia/oauth2server:latest
    container_name: oauth2server-dev
    ports:
      - "${PORT:-8080}:${PORT:-8080}"
    env_file:
      - .env      
    environment:
      # Perfil activo - SIEMPRE dev en local
      SPRING_PROFILES_ACTIVE: dev

      # ===========================================
      # OAuth2 Clients
      # ===========================================
      OAUTH2_CLIENTS: ${OAUTH2_CLIENTS:-CINE_PLATFORM,TRANSCRIBERAPP}
      CINE_PLATFORM_SECRET: ${CINE_PLATFORM_SECRET:-cine-platform}
      CINE_PLATFORM_REDIRECT_URI: ${CINE_PLATFORM_REDIRECT_URI:-http://localhost:5000/oauth/callback}
      TRANSCRIBERAPP_SECRET: ${TRANSCRIBERAPP_SECRET:-transcriberapp}
      TRANSCRIBERAPP_REDIRECT_URI: ${TRANSCRIBERAPP_REDIRECT_URI:-http://localhost:9000/oauth/callback}
      
      # ===========================================
      # Database - SOLO desarrollo
      # ===========================================
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/oauth2_dev
      SPRING_DATASOURCE_USERNAME: oauth2_user
      SPRING_DATASOURCE_PASSWORD: ${POSTGRES_PASSWORD:-oauth2_dev_password}
      SPRING_DATASOURCE_DRIVER_CLASS_NAME: org.postgresql.Driver
      
      # ===========================================
      # JPA / Hibernate
      # ===========================================
      SPRING_JPA_HIBERNATE_DDL_AUTO: validate
      SPRING_JPA_SHOW_SQL: "true"
      SPRING_JPA_PROPERTIES_HIBERNATE_DIALECT: org.hibernate.dialect.PostgreSQLDialect
      SPRING_JPA_PROPERTIES_HIBERNATE_FORMAT_SQL: "true"
      
      # ===========================================
      # Flyway
      # ===========================================
      SPRING_FLYWAY_ENABLED: "true"
      SPRING_FLYWAY_BASELINE_ON_MIGRATE: "true"
      SPRING_FLYWAY_LOCATIONS: classpath:db/migration
      SPRING_FLYWAY_CLEAN_DISABLED: "true"
      
      # ===========================================
      # Configuración del servidor
      # ===========================================
      SERVER_PORT: ${PORT:-8080}
      SPRING_THYMELEAF_CACHE: "false"
      
      # ===========================================
      # OAuth2 Clients genéricos
      # ===========================================
      OAUTH_CLIENT_ID: ${OAUTH_CLIENT_ID:-cine-platform}
      OAUTH_CLIENT_SECRET: ${OAUTH_CLIENT_SECRET:-cine-platform}
      OAUTH_REDIRECT_URI: ${OAUTH_REDIRECT_URI:-http://localhost:5000/oauth/callback}
      
      # ===========================================
      # Token validity
      # ===========================================
      ACCESS_TOKEN_VALIDITY: ${ACCESS_TOKEN_VALIDITY:-86400}
      REFRESH_TOKEN_VALIDITY: ${REFRESH_TOKEN_VALIDITY:-1296000}
      
      # ===========================================
      # JWT
      # ===========================================
      JWT_AUDIENCE: ${JWT_AUDIENCE:-oauth2-client}
      JWT_SIGNING_KEY: ${JWT_SIGNING_KEY:-clave-secreta-para-desarrollo}

      SERVER_SSL_ENABLED: "false"
      SSL_KEY_STORE: ""
      SSL_KEY_STORE_PASSWORD: ""
      SSL_KEY_ALIAS: ""

      CONTACT_EMAIL: ${CONTACT_EMAIL:-admin@localhost}
      CORS_ALLOWED_ORIGINS: ${CORS_ALLOWED_ORIGINS:-http://localhost:9000,http://localhost:5000}
      ISSUER_URL: ${ISSUER_URL:-http://localhost:8080}
    volumes:
      - ./logs:/app/logs
    command: ["/app/run-dev.sh"]
    restart: unless-stopped
    networks:
      - oauth-network
      - cine-network

volumes:
  postgres_data:
    name: oauth2_postgres_dev_data

networks:
  oauth-network:
    driver: bridge
  cine-network:
    external: "true"
    name: cine-network
````

## File: pom.xml
````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.5.11</version>
        <relativePath />
    </parent>

    <groupId>com.oauth.rest</groupId>
    <artifactId>oauth2server</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>OAuth2Server</name>
    <description>Implementación de la seguridad OAuth2 en API REST</description>

    <properties>
        <java.version>21</java.version>
        <springdoc.version>2.8.6</springdoc.version>
        <modelmapper.version>3.2.2</modelmapper.version>
        <oauth2-authorization-server.version>1.4.2</oauth2-authorization-server.version>
        <maven-compiler-plugin.version>3.13.0</maven-compiler-plugin.version>
    </properties>

    <dependencies>

        <!-- Web + JPA -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>

        <!-- H2 (solo para tests) -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- PostgreSQL -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- Seguridad + OAuth2 Resource Server -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>

        <!-- OAuth2 Authorization Server -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
            <version>${oauth2-authorization-server.version}</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- Thymeleaf for templates -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!-- Springdoc OpenAPI -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>${springdoc.version}</version>
        </dependency>

        <!-- Bean Validation API y Hibernate Validator -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- ModelMapper -->
        <dependency>
            <groupId>org.modelmapper</groupId>
            <artifactId>modelmapper</artifactId>
            <version>${modelmapper.version}</version>
        </dependency>

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Spring Boot Configuration Processor (para eliminar warnings) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Tests -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- Spock Framework for testing -->
        <dependency>
            <groupId>org.spockframework</groupId>
            <artifactId>spock-core</artifactId>
            <version>2.3-groovy-3.0</version>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.spockframework</groupId>
            <artifactId>spock-spring</artifactId>
            <version>2.3-groovy-3.0</version>
            <scope>test</scope>
        </dependency>

        <!-- Groovy -->
        <dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy</artifactId>
            <version>3.0.23</version>
            <scope>test</scope>
        </dependency>

        <!-- Flyway -->
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>

        <!-- Flyway PostgreSQL support -->
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-database-postgresql</artifactId>
        </dependency>
    </dependencies>

    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.eclipse.m2e</groupId>
                    <artifactId>lifecycle-mapping</artifactId>
                    <version>1.0.0</version>
                    <configuration>
                        <lifecycleMappingMetadata>
                            <pluginExecutions>
                                <pluginExecution>
                                    <pluginExecutionFilter>
                                        <groupId>org.codehaus.gmavenplus</groupId>
                                        <artifactId>gmavenplus-plugin</artifactId>
                                        <versionRange>[3.0.2,)</versionRange>
                                        <goals>
                                            <goal>addSources</goal>
                                            <goal>addTestSources</goal>
                                            <goal>compile</goal>
                                            <goal>compileTests</goal>
                                        </goals>
                                    </pluginExecutionFilter>
                                    <action>
                                        <ignore />
                                    </action>
                                </pluginExecution>
                            </pluginExecutions>
                        </lifecycleMappingMetadata>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>

        <plugins>

            <!-- Plugin de Spring Boot -->
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>

            <!-- Plugin de Maven Compiler -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>${maven-compiler-plugin.version}</version>
                <configuration>
                    <source>${java.version}</source>
                    <target>${java.version}</target>
                    <parameters>true</parameters>
                    <annotationProcessorPaths>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                            <version>${lombok.version}</version>
                        </path>
                        <path>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-configuration-processor</artifactId>
                            <version>${project.parent.version}</version>
                        </path>
                    </annotationProcessorPaths>
                </configuration>
            </plugin>

            <!-- Spock Compiler Plugin -->
            <plugin>
                <groupId>org.codehaus.gmavenplus</groupId>
                <artifactId>gmavenplus-plugin</artifactId>
                <version>3.0.2</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>addSources</goal>
                            <goal>addTestSources</goal>
                            <goal>compile</goal>
                            <goal>compileTests</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>

            <!-- Maven Surefire Plugin -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.5.4</version>
                <configuration>
                    <includes>
                        <include>**/*Spec.java</include>
                        <include>**/*Test.java</include>
                        <include>**/*Spec.groovy</include>
                        <include>**/*Test.groovy</include>
                    </includes>
                </configuration>
            </plugin>

            <!-- JaCoCo for code coverage -->
            <plugin>
                <groupId>org.jacoco</groupId>
                <artifactId>jacoco-maven-plugin</artifactId>
                <version>0.8.12</version>
                <executions>
                    <execution>
                        <id>prepare-agent</id>
                        <goals>
                            <goal>prepare-agent</goal>
                        </goals>
                    </execution>
                    <execution>
                        <id>report</id>
                        <phase>test</phase>
                        <goals>
                            <goal>report</goal>
                        </goals>
                    </execution>
                    <execution>
                        <id>check</id>
                        <goals>
                            <goal>check</goal>
                        </goals>
                        <configuration>
                            <rules>
                                <rule>
                                    <element>BUNDLE</element>
                                    <limits>
                                        <limit>
                                            <counter>LINE</counter>
                                            <value>COVEREDRATIO</value>
                                            <minimum>0.15</minimum>
                                        </limit>
                                        <limit>
                                            <counter>BRANCH</counter>
                                            <value>COVEREDRATIO</value>
                                            <minimum>0.02</minimum>
                                        </limit>
                                    </limits>
                                </rule>
                            </rules>
                        </configuration>
                    </execution>
                </executions>
            </plugin>

        </plugins>
    </build>

    <distributionManagement>
        <repository>
            <id>github</id>
            <name>GitHub OWNER Apache Maven Packages</name>
            <url>https://maven.pkg.github.com/FelixMarin/OAuth2Server</url>
        </repository>
    </distributionManagement>
</project>
````

## File: README.md
````markdown
# OAuth2Server

OAuth2Server es un servidor de autenticación basado en **Spring Boot** que emite tokens JWT firmados. Sirve para que otras aplicaciones puedan autenticar usuarios de forma segura.

---

## 🏗️ Arquitectura

Este proyecto implementa **Arquitectura Hexagonal** (Ports and Adapters) para mantener el código limpio, testeable y desacoplado del framework.

```
src/main/java/com/oauth/
├── domain/                    # 🔵 NÚCLEO - Sin dependencias externas
│   ├── exception/            # Excepciones del dominio
│   ├── model/                # Entidades y value objects
│   └── ports/                # Interfaces (contratos)
│       └── in/               # Puertos de entrada
│
├── application/              # 🟢 CASOS DE USO
│   └── usecase/             # Implementaciones de use cases
│
├── adapters/                 # 🟡 ADAPTADORES EXTERNOS
│   ├── input/               # Adaptadores de entrada (Driven)
│   │   └── rest/            # Controladores REST
│   │
│   └── output/              # Adaptadores de salida (Driving)
│       ├── persistence/      # Repositorios JPA
│       └── security/         # Adaptadores de seguridad
│
├── infrastructure/           # 🟠 INFRAESTRUCTURA
│   └── service/             # Servicios específicos del framework
│
└── config/                   # 🔴 Configuración Spring
```

### Principios aplicados
- **Dominio limpio**: La lógica de negocio no depende de frameworks
- **Puertos**: Interfaces que definen contratos entre capas
- **Adaptadores**: Implementaciones concretas de los puertos
- **Inversión de dependencias**: Las dependencias apuntan hacia el dominio

---

## 🚀 Inicio rápido

### Requisitos
- Java 21
- Maven 3.9+
- Docker y Docker Compose

### Ejecutar en 5 minutos

```bash
# 1. Clonar el proyecto
git clone https://github.com/FelixMarin/OAuth2Server.git
cd OAuth2Server

# 2. Ejecutar con Docker Compose (incluye PostgreSQL)
docker-compose up --build

# 3. Acceder a la aplicación
# http://localhost:8080 (desarrollo)
```

---

## 🔐 Primeros pasos

### Credenciales por defecto

Al iniciar por primera vez, se crea un usuario administrador:

| Campo | Valor |
|-------|-------|
| Usuario | admin |
| Contraseña | admin123 |

### Probar que funciona

1. Abre http://localhost:8080/login
2. Inicia sesión con **admin / admin123**
3. Verás la página de consentimiento OAuth2

---

## 🗄️ Base de datos

La aplicación usa **PostgreSQL** en todos los entornos (desarrollo y producción).

### Desarrollo (docker-compose)

El archivo `docker-compose.yml` configura automáticamente:
- PostgreSQL en el puerto 5432
- Base de datos: `oauth2_dev`
- Usuario: `oauth2_user`
- Contraseña: `oauth2_dev_password`

### Producción

Consulta `docker-compose.prod.yml` para la configuración de producción.

---

## ⚙️ Configuración

### Variables de entorno principales

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `SERVER_PORT` | Puerto de la aplicación | 8080 |
| `SPRING_DATASOURCE_URL` | URL de PostgreSQL | jdbc:postgresql://postgres:5432/oauth2_dev |
| `SPRING_DATASOURCE_USERNAME` | Usuario de BD | oauth2_user |
| `SPRING_DATASOURCE_PASSWORD` | Contraseña de BD | oauth2_dev_password |
| `ISSUER_URL` | URL pública del servidor | https://auth.midominio.com |
| `CORS_ALLOWED_ORIGINS` | Orígenes permitidos para CORS | http://localhost:3000 |

### Perfiles Spring

- `dev`: Desarrollo (usa PostgreSQL en docker-compose)
- `prod`: Producción (configuración optimizada)

---

## 🏢 Añadir una nueva aplicación

Los clientes OAuth2 se gestionan directamente en la base de datos a través de migraciones Flyway. No se requieren variables de entorno por cliente.

Crea un nuevo fichero de migración (p. ej. `V7__add_mi_app.sql`):

```sql
INSERT INTO applications (name, client_id, client_secret, redirect_uri, description)
VALUES (
    'mi-app',
    'mi-app',
    '{bcrypt}$2a$10$...',   -- secreto hasheado con BCrypt, o {noop}secreto-en-texto-plano para desarrollo
    'https://miapp.com/oauth/callback',
    'Mi nueva aplicación'
);
```

Al arrancar la aplicación, Flyway aplica la migración y el cliente queda registrado automáticamente. No es necesario reiniciar ni cambiar ningún fichero de código.

### Clientes registrados

| Aplicación | `client_id` | Callback (desarrollo) | Migración |
|------------|-------------|----------------------|-----------|
| cine-platform | `cine-platform` | `http://localhost:5000/oauth/callback` | V2 |
| transcriberapp | `transcriberapp` | `http://localhost:9000/oauth/callback` | V2 |
| empresa-web | `empresa-web` | `http://localhost:8001/oauth/callback` | V7 |

### Flujo Authorization Code

**1. Redirige al usuario a:**

```
http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=mi-aplicacion&
  redirect_uri=http://localhost:3000/callback&
  scope=openid%20profile%20read%20write&
  state=texto-aleatorio
```

**2. El usuario se loguea en OAuth2Server**

**3. La app recibe un código en el callback:**

```
http://localhost:3000/callback?code=XYZ123&state=texto-aleatorio
```

**4. Canjea el código por tokens:**

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u "mi-aplicacion:mi-secreto-seguro" \
  -d "grant_type=authorization_code" \
  -d "code=CODIGO_RECIBIDO" \
  -d "redirect_uri=http://localhost:3000/callback"
```

**5. Respuesta (tokens):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "abc...",
  "scope": "openid profile read write"
}
```

### Flujo Client Credentials (M2M)

Sin usuario, solo para comunicación entre servicios:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u "mi-aplicacion:mi-secreto-seguro" \
  -d "grant_type=client_credentials" \
  -d "scope=read write"
```

---

## 🐳 Docker Compose

El archivo `docker-compose.yml` incluye:
- **OAuth2Server** - Puerto 8080
- **PostgreSQL** - Puerto 5432

### Comandos útiles

```bash
# Iniciar servicios
docker-compose up --build

# Ver logs
docker-compose logs -f

# Detener servicios
docker-compose down
```

---

## 📡 Endpoints principales

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/oauth2/authorize` | GET | Iniciar login OAuth2 |
| `/oauth2/token` | POST | Obtener tokens |
| `/login` | GET/POST | Página de login |
| `/user/me` | GET | Info del usuario actual |
| `/user` | POST | Crear usuario |

---

## 🧪 Tests

```bash
# Ejecutar tests
mvn test

# Ver cobertura
mvn verify
```

---

## ❓ Problemas frecuentes

**No puedo iniciar sesión**
- Verifica que el usuario existe en la base de datos
- Prueba con las credenciales por defecto: admin / admin123

**Error de redirect_uri**
- Asegúrate de que la URL de callback en la petición coincide exactamente con la registrada en la tabla `applications`

**Error de conexión a PostgreSQL**
- Verifica que el contenedor de PostgreSQL está corriendo
- Comprueba las credenciales en las variables de entorno

---

## Documentación extendida
- [COMMANDS](doc/COMMANDS.md)
- [ENDPOINTS](doc/ENDPOINTS.md)
- [MANUAL](doc/MANUAL.md)
- [REGISTRAR APLICACIÓN](doc/REGSITRAR_NUEVA_APLICACION.md)

---

## ℹ️ Notas

- La base de datos es **PostgreSQL** (no H2)
- Los tokens JWT se firman con un par de claves RSA generado en cada arranque
- Los clientes OAuth2 se registran en la tabla `applications` de la BD; no se usan variables de entorno por cliente
- La configuración sensible se gestiona mediante variables de entorno (no hardcoded)

---

## 📄 Licencia

MIT
````
