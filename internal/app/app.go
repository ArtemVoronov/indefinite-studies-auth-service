package app

import (
	"fmt"
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

type server struct {
	authGRPC.UnimplementedAuthServiceServer
}

func Start() {
	app.LoadEnv()
	serviceServer := &server{}

	registerServices := func(s *grpc.Server) {
		auth.RegisterAuthServiceServer(s, serviceServer)
	}
	go func() {
		app.StartGRPC(setup, shutdown, app.HostGRPC(), registerServices)
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
