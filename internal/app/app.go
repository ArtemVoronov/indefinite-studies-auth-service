package app

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/api/rest/v1/auth"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func Cors(cors string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Add("Access-Control-Allow-Origin", cors)
		c.Next()
	}
}

// TODO: authorization based on http only cookies or on by auth header, should work both: 1st mainly for browsers, 2nd for other api, http clients or mobile devies
func AuthReqired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		// fmt.Println("---------------AuthReqired---------------")
		// fmt.Printf("header: %v\n", header)
		// fmt.Println("---------------AuthReqired---------------")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") {
			c.JSON(http.StatusUnauthorized, "Unauthorized")
			c.Abort()
			return
		}

		token := authHeader[len("Bearer "):]
		validationResult, err := auth.Verify(token)

		if err != nil {
			c.JSON(http.StatusInternalServerError, "Internal Server Error")
			log.Printf("error during verifying access token: %v\n", err)
			c.Abort()
			return
		}

		if (*validationResult).IsExpired {
			c.JSON(http.StatusUnauthorized, "Unauthorized")
			c.Abort()
			return
		}

		c.Next()
	}
}

func InitEnv() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func GetHost() string {
	port := utils.EnvVarDefault("APP_PORT", "3000")
	host := ":" + port
	return host
}

func StartServer(host string, router *gin.Engine) {
	srv := &http.Server{
		Addr:    host,
		Handler: router,
	}

	// Initializing the server in a goroutine so that it won't block the graceful shutdown handling below
	go func() {
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Printf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	defer db.GetInstance().GetDB().Close()
	log.Println("Server exiting")
}
