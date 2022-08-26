package app

import (
	"fmt"
	"net/http"

	authREST "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
	authGRPC "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/auth"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/auth"
	"github.com/gin-contrib/expvar"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

func Start() {
	app.LoadEnv()
	creds := app.TLSCredentials()
	go func() {
		app.StartGRPC(setup, shutdown, app.HostGRPC(), createGrpcApi, &creds)
	}()
	app.StartHTTP(setup, shutdown, app.HostHTTP(), createRestApi())
}

func setup() {
	services.Instance()
}

func shutdown() {
	services.Instance().Shutdown()
}

func createRestApi() *gin.Engine {
	router := gin.Default()
	gin.SetMode(app.Mode())
	router.Use(app.Cors())
	router.Use(gin.Logger())
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.String(http.StatusInternalServerError, fmt.Sprintf("error: %s", err))
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))

	// TODO: add permission controller by user role and user state
	v1 := router.Group("/api/v1")

	v1.GET("/auth/ping", ping.Ping)
	v1.POST("/auth/login", authREST.Authenicate)
	v1.POST("/auth/refresh-token", authREST.RefreshToken)

	authorized := router.Group("/api/v1")
	authorized.Use(app.AuthReqired(authenicate))
	{
		authorized.GET("/auth/debug/vars", expvar.Handler())
		authorized.GET("/auth/safe-ping", ping.SafePing)
	}
	return router
}

func createGrpcApi(s *grpc.Server) {
	authGRPC.RegisterServiceServer(s)
}

func authenicate(token string) (*auth.VerificationResult, error) {
	result, err := services.Instance().JWT().VerifyToken(token)
	if err != nil {
		return nil, err
	}
	return &auth.VerificationResult{IsValid: result.IsValid, IsExpired: result.IsExpired}, nil
}
