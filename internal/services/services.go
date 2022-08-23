package services

import (
	"net/http"
	"sync"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
)

type Services struct {
	profiles *profiles.ProfilesService
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
	client := &http.Client{
		Timeout: utils.EnvVarDurationDefault("HTTP_CLIENT_REQUEST_TIMEOUT_IN_SECONDS", time.Second, 30*time.Second),
	}
	jwtService := jwt.CreateJWTService()
	return &Services{
		profiles: profiles.CreateProfilesService(client, utils.EnvVar("PROFILES_SERVICE_BASE_URL"), jwtService),
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

func (s *Services) Profiles() *profiles.ProfilesService {
	return s.profiles
}
