package services

import (
	"sync"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/log"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
)

type Services struct {
	profiles *profiles.ProfilesGRPCService
	jwt      *jwt.JWTService
	db       *db.PostgreSQLService
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
	creds, err := app.LoadTLSCredentialsForClient(utils.EnvVar("PROFILES_SERVICE_CLIENT_TLS_CERT_PATH"))
	if err != nil {
		log.Fatalf("unable to load TLS credentials: %s", err)
	}

	jwtService := jwt.CreateJWTService()

	return &Services{
		profiles: profiles.CreateProfilesGRPCService(utils.EnvVar("PROFILES_SERVICE_GRPC_HOST")+":"+utils.EnvVar("PROFILES_SERVICE_GRPC_PORT"), &creds),
		jwt:      jwtService,
		db:       db.CreatePostgreSQLService(),
	}
}

func (s *Services) Shutdown() {
	s.profiles.Shutdown()
	s.jwt.Shutdown()
	s.db.Shutdown()
}

func (s *Services) DB() *db.PostgreSQLService {
	return s.db
}

func (s *Services) JWT() *jwt.JWTService {
	return s.jwt
}

func (s *Services) Profiles() *profiles.ProfilesGRPCService {
	return s.profiles
}
