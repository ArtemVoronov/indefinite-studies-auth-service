# How to build and run
1. Create appropriate `.env` file at the root of project, e.g.:
```
#common settings
APP_HTTP_API_PORT=3005
APP_GRPC_API_PORT=50051
APP_MODE=debug # release or debug
APP_SHUTDOWN_TIMEOUT_IN_SECONDS=5
APP_TLS_CERT_PATH=configs/tls/server-cert.pem
APP_TLS_KEY_PATH=configs/tls/server-key.pem

CORS='*'

#required for db service inside app
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_NAME=indefinite_studies_auth_service_db
DATABASE_USER=indefinite_studies_auth_service_user
DATABASE_PASSWORD=password
DATABASE_SSL_MODE=disable
DATABASE_QUERY_TIMEOUT_IN_SECONDS=30

#required for liquibase
DATABASE_URL=jdbc:postgresql://postgres:5432/indefinite_studies_auth_service_db

#jwt auth:
JWT_SIGN=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2
JWT_ACCESS_DURATION_IN_SECONDS=1800 # 30 min
JWT_REFRESH_DURATION_IN_SECONDS=2592000 # 30 days
JWT_ISSUER=crazyprincipal

#required for nginx
HOST_API=192.168.0.18

#external services
PROFILES_SERVICE_GRPC_HOST=192.168.0.18
PROFILES_SERVICE_GRPC_PORT=10003
PROFILES_SERVICE_HTTP_PORT=10002
PROFILES_SERVICE_CLIENT_TLS_CERT_PATH=configs/tls/ca-cert.pem

#http client
HTTP_CLIENT_REQUEST_TIMEOUT_IN_SECONDS=30 # connection time, any redirects, and reading the response body
```
2. `docker-compose build && docker-compose up`