package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/ping"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func Start() {
	setup()
	defer shutdown()
	srv := &http.Server{
		Addr:    host(),
		Handler: router(),
	}

	go func() {
		log.Printf("App starting at localhost%s ...\n", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Println("Server was closed")
		} else if err != nil {
			log.Fatalf("Unable to start app: %v\n", err)
		}
	}()

	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server has been shutdown")
}

func setup() {
	loadEnv()
	db.Instance()
	jwt.Instance()
	profiles.Instance()
}

func shutdown() {
	db.Instance().Shutdown()
	jwt.Instance().Shutdown()
	profiles.Instance().Shutdown()
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Print("No .env file found")
	}
}

func host() string {
	port := utils.EnvVarDefault("APP_PORT", "3005")
	host := ":" + port
	return host
}

func mode() string {
	return utils.EnvVarDefault("APP_MODE", "debug")
}

func router() *gin.Engine {
	router := gin.Default()
	gin.SetMode(mode())
	router.Use(cors())
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

func cors() gin.HandlerFunc {
	cors := utils.EnvVarDefault("CORS", "*")
	return func(c *gin.Context) {
		c.Writer.Header().Add("Access-Control-Allow-Origin", cors)
		c.Next()
	}
}
