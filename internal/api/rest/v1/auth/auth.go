package auth

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db/queries"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/profiles"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api/validation"
	"github.com/gin-gonic/gin"
)

func Authenicate(c *gin.Context) {
	var authenicationDTO jwt.AuthenicationDTO

	if err := c.ShouldBindJSON(&authenicationDTO); err != nil {
		validation.SendError(c, err)
		return
	}

	// TODO: add counter of invalid athorizations, then use it for temporary blocking access
	validatoionResult, err := profiles.Instance().ValidateCredentials(authenicationDTO)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during authenication: %v\n", err)
		return
	}
	if !validatoionResult.IsValid || validatoionResult.UserId == -1 {
		c.JSON(http.StatusBadRequest, api.ERROR_WRONG_PASSWORD_OR_EMAIL)
		return
	}

	result, err := jwt.Instance().GenerateNewTokenPair(validatoionResult.UserId, jwt.TOKEN_TYPE_USER)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during authenication: %v\n", err)
		return
	}

	err = db.Instance().TxVoid(func(tx *sql.Tx, ctx context.Context, cancel context.CancelFunc) error {
		err := queries.UpdateRefreshToken(tx, ctx, validatoionResult.UserId, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)

		if err == sql.ErrNoRows {
			err = queries.CreateRefreshToken(tx, ctx, validatoionResult.UserId, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)
		}

		return err
	})()

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during authenication: %v\n", err)
		return
	}

	c.JSON(http.StatusOK, result)
}

func RefreshToken(c *gin.Context) {
	var refreshToken jwt.RefreshTokenDTO

	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		validation.SendError(c, err)
		return
	}

	validationResult, err := jwt.Instance().Validate(refreshToken.RefreshToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	if (*validationResult).IsExpired {
		c.JSON(http.StatusBadRequest, api.ERROR_TOKEN_IS_EXPIRED)
		return
	}

	claims, ok := (*validationResult).Token.Claims.(*jwt.UserClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, "Unable to authenicate")
		log.Printf("error during refreshing token: %v\n", api.ERROR_ASSERT_RESULT_TYPE)
		return
	}

	result, err := jwt.Instance().GenerateNewTokenPair(claims.Id, claims.Type)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	err = db.Instance().TxVoid(func(tx *sql.Tx, ctx context.Context, cancel context.CancelFunc) error {
		err := queries.UpdateRefreshToken(tx, ctx, claims.Id, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)
		if err == sql.ErrNoRows {
			err = queries.CreateRefreshToken(tx, ctx, claims.Id, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)
		}

		return err
	})()

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	c.JSON(http.StatusOK, result)
}

func VerifyToken(c *gin.Context) {
	var verification jwt.VerificationDTO

	if err := c.ShouldBindJSON(&verification); err != nil {
		validation.SendError(c, err)
		return
	}

	validationResult, err := jwt.Instance().Validate(verification.AccessToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	// TODO: make some complex analysis based on claims in future, e.g. check the token type (user or service), permission etc

	c.JSON(http.StatusOK, &jwt.VerificationResult{IsValid: validationResult.IsValid, IsExpired: validationResult.IsExpired})
}
