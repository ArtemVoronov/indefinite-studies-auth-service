package services

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	profilesREST "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db"
	profilesGRPC "github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
)

type Services struct {
	profilesREST *profilesREST.ProfilesService
	profilesGRPC *profilesGRPC.ProfilesGRPCService
	jwt          *jwt.JWTService
	db           *db.PostgreSQLService
}

var once sync.Once
var instance *Services

func Instance() *Services {
	once.Do(func() {
		if instance == nil {
			instance = createServices()
		}
	})
	return instance
}

func createServices() *Services {
	client := &http.Client{
		Timeout: utils.EnvVarDurationDefault("HTTP_CLIENT_REQUEST_TIMEOUT_IN_SECONDS", time.Second, 30*time.Second),
	}
	// TODO: add env var with paths to certs
	creds, err := app.LoadTLSCredentialsForClient("configs/tls/ca-cert.pem")
	if err != nil {
		log.Fatalf("unable to load TLS credentials")
	}
	jwtService := jwt.CreateJWTService()
	return &Services{
		profilesREST: profilesREST.CreateProfilesService(client, utils.EnvVar("PROFILES_SERVICE_URL"), jwtService),
		profilesGRPC: profilesGRPC.CreateProfilesGRPCService(utils.EnvVar("PROFILES_SERVICE_GRPC_HOST")+":"+utils.EnvVar("PROFILES_SERVICE_GRPC_PORT"), &creds),
		jwt:          jwtService,
		db:           db.CreatePostgreSQLService(),
	}
}

func (s *Services) Shutdown() {
	s.profilesREST.Shutdown()
	s.profilesGRPC.Shutdown()
	s.jwt.Shutdown()
	s.db.Shutdown()
}

func (s *Services) DB() *db.PostgreSQLService {
	return s.db
}

func (s *Services) JWT() *jwt.JWTService {
	return s.jwt
}

func (s *Services) ProfilesREST() *profilesREST.ProfilesService {
	return s.profilesREST
}

func (s *Services) ProfilesGRPC() *profilesGRPC.ProfilesGRPCService {
	return s.profilesGRPC
}
