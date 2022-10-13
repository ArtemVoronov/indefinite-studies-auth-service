package services

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/tokens"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/log"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/shard"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
)

type Services struct {
	profiles *profiles.ProfilesGRPCService
	jwt      *jwt.JWTService
	tokens   *tokens.TokensService
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

	dbClients := []*db.PostgreSQLService{}
	for i := 1; i <= shard.DEFAULT_BUCKET_FACTOR; i++ {
		dbConfig := &db.DBParams{
			Host:         utils.EnvVar("DATABASE_HOST"),
			Port:         utils.EnvVar("DATABASE_PORT"),
			Username:     utils.EnvVar("DATABASE_USER"),
			Password:     utils.EnvVar("DATABASE_PASSWORD"),
			DatabaseName: utils.EnvVar("DATABASE_NAME_PREFIX") + "_" + strconv.Itoa(i),
			SslMode:      utils.EnvVar("DATABASE_SSL_MODE"),
		}
		dbClients = append(dbClients, db.CreatePostgreSQLService(dbConfig))
	}

	return &Services{
		profiles: profiles.CreateProfilesGRPCService(utils.EnvVar("PROFILES_SERVICE_GRPC_HOST")+":"+utils.EnvVar("PROFILES_SERVICE_GRPC_PORT"), &creds),
		jwt:      jwtService,
		tokens:   tokens.CreateTokensService(dbClients),
	}
}

func (s *Services) Shutdown() error {
	result := []error{}
	err := s.profiles.Shutdown()
	if err != nil {
		result = append(result, err)
	}
	err = s.jwt.Shutdown()
	if err != nil {
		result = append(result, err)
	}
	err = s.tokens.Shutdown()
	if err != nil {
		result = append(result, err)
	}
	if len(result) > 0 {
		return fmt.Errorf("errors during shutdown: %v", result)
	}
	return nil
}

func (s *Services) JWT() *jwt.JWTService {
	return s.jwt
}

func (s *Services) Profiles() *profiles.ProfilesGRPCService {
	return s.profiles
}

func (s *Services) Tokens() *tokens.TokensService {
	return s.tokens
}
