package app

import (
	"fmt"
	"net/http"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/app"
	"github.com/gin-gonic/gin"
)

func Start() {
	app.Start(setup, shutdown, app.Host(), router())
}

func setup() {
	db.Instance()
	jwt.Instance()
	profiles.Instance()
}

func shutdown() {
	db.Instance().Shutdown()
	jwt.Instance().Shutdown()
	profiles.Instance().Shutdown()
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
	v1.POST("/auth/login", auth.Authenicate)
	v1.POST("/auth/refresh-token", auth.RefreshToken)
	v1.POST("/auth/verify-token", auth.VerifyToken)

	return router
}
