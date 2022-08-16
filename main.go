package main

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/expvar"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/app"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/gin-gonic/gin"
)

func main() {

	app.InitEnv()
	auth.Setup()
	host := app.GetHost()

	router := gin.Default()

	router.Use(app.Cors(utils.EnvVar("CORS")))

	// Global middleware
	// Logger middleware will write the logs to gin.DefaultWriter even if you set with GIN_MODE=release.
	// By default gin.DefaultWriter = os.Stdout
	router.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.String(http.StatusInternalServerError, fmt.Sprintf("error: %s", err))
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))

	db.GetInstance()

	// TODO: add permission controller by user role and user state
	// v1 := router.Group("/api/v1", gin.BasicAuth(apiUsers)) // TODO: add auth via jwt, update model accordingly
	v1 := router.Group("/api/v1") // TODO: add auth via jwt, update model accordingly

	v1.GET("/ping", ping.Ping)
	v1.POST("/auth/login", auth.Authenicate)
	v1.POST("/auth/refresh-token", auth.RefreshToken)
	authorized := router.Group("/api/v1")
	authorized.Use(app.AuthReqired())
	{
		authorized.GET("/debug/vars", expvar.Handler())
		authorized.GET("/safe-ping", ping.SafePing)
	}

	app.StartServer(host, router)
}
