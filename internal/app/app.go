package app

import (
	"fmt"
	"log"
	"net/http"
	"os"

	authGRPC "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/grpc/v1/auth"
	authREST "github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/auth"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/gin-contrib/expvar"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func Start() {
	app.LoadEnv()
	logger := app.NewLogrusLogger()
	logpath := utils.EnvVarDefault("APP_LOGS_PATH", "stdout")
	if logpath != "stdout" {
		file, err := os.OpenFile(logpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("unable init logging: %v", err)
		}
		logger.SetOutput(file)
		defer file.Close()
	}
	creds := app.TLSCredentials()
	go func() {
		app.StartGRPC(setup, shutdown, app.HostGRPC(), createGrpcApi, &creds, logger)
	}()
	app.StartHTTP(setup, shutdown, app.HostHTTP(), createRestApi(logger))
}

func setup() {
	services.Instance()
}

func shutdown() {
	services.Instance().Shutdown()
}

func createRestApi(logger *logrus.Logger) *gin.Engine {
	router := gin.Default()
	gin.SetMode(app.Mode())
	router.Use(app.Cors())
	router.Use(app.NewLoggerMiddleware(logger))
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.String(http.StatusInternalServerError, fmt.Sprintf("error: %s", err))
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))

	v1 := router.Group("/api/v1")

	v1.GET("/auth/ping", ping.Ping)
	v1.POST("/auth/login", authREST.Authenicate)
	v1.POST("/auth/refresh-token", authREST.RefreshToken)

	authorized := router.Group("/api/v1")
	authorized.Use(app.AuthReqired(authenicate))
	{
		authorized.GET("/auth/debug/vars", app.RequiredOwnerRole(), expvar.Handler())
		authorized.GET("/auth/safe-ping", app.RequiredOwnerRole(), ping.SafePing)
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
