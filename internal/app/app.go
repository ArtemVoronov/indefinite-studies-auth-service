package app

import (
	"context"
	"fmt"
	"log"
	"net/http"

	authRestApi "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/auth"
	authGRPC "github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/auth"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

// TODO: unify gRPC implementation
type server struct {
	authGRPC.UnimplementedAuthServiceServer
}

func (s *server) VerifyToken(ctx context.Context, in *authGRPC.VerifyTokenRequest) (*authGRPC.VerifyTokenReply, error) {
	log.Printf("Token: %v", in.GetToken()) // todo clean

	result, err := services.Instance().JWT().Validate(in.GetToken())
	if err != nil {
		return nil, err
	}

	return &authGRPC.VerifyTokenReply{IsValid: result.IsValid, IsExpired: result.IsExpired}, nil
}

func Start() {
	app.LoadEnv()
	serviceServer := &server{}

	registerServices := func(s *grpc.Server) {
		auth.RegisterAuthServiceServer(s, serviceServer)
	}

	// TODO: add env var with paths to certs
	creds, err := app.LoadTLSCredentialsForServer("configs/tls/server-cert.pem", "configs/tls/server-key.pem")
	if err != nil {
		log.Fatalf("unable to load TLS credentials")
	}

	go func() {
		app.StartGRPC(setup, shutdown, app.HostGRPC(), registerServices, &creds)
	}()
	app.StartHTTP(setup, shutdown, app.HostHTTP(), router())
}

func setup() {
	services.Instance()
}

func shutdown() {
	services.Instance().Shutdown()
}

func router() *gin.Engine {
	router := gin.Default()
	gin.SetMode(app.Mode())
	router.Use(app.Cors())
	router.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.String(http.StatusInternalServerError, fmt.Sprintf("error: %s", err))
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))

	// TODO: add permission controller by user role and user state
	v1 := router.Group("/api/v1")

	v1.GET("/ping", ping.Ping)
	v1.POST("/auth/login", authRestApi.Authenicate)
	v1.POST("/auth/refresh-token", authRestApi.RefreshToken)
	v1.POST("/auth/verify-token", authRestApi.VerifyToken)

	return router
}
