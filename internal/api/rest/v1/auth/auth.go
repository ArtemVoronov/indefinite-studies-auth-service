package auth

import (
	"net/http"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api/validation"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/log"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db/entities"
	"github.com/gin-gonic/gin"
)

func Authenicate(c *gin.Context) {
	var authenicationDTO jwt.AuthenicationDTO

	if err := c.ShouldBindJSON(&authenicationDTO); err != nil {
		validation.SendError(c, err)
		return
	}

	// TODO: add counter of invalid athorizations, then use it for temporary blocking access
	validationResult, err := services.Instance().Profiles().ValidateCredentials(authenicationDTO.Email, authenicationDTO.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Error("error during authenication", err.Error())
		return
	}
	if !validationResult.IsValid || validationResult.UserUuid == "" {
		c.JSON(http.StatusBadRequest, api.ERROR_WRONG_PASSWORD_OR_EMAIL)
		return
	}

	result, err := services.Instance().JWT().GenerateNewTokenPair(validationResult.UserUuid, entities.TOKEN_TYPE_USER, validationResult.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Error("error during authenication", err.Error())
		return
	}

	err = services.Instance().Tokens().UpsertRefreshToken(validationResult.UserUuid, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Error("error during authenication", err.Error())
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

	validationResult, err := services.Instance().JWT().VerifyToken(refreshToken.RefreshToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		log.Error("error during refreshing token", err.Error())
		return
	}

	if (*validationResult).IsExpired {
		c.JSON(http.StatusBadRequest, api.ERROR_TOKEN_IS_EXPIRED)
		return
	}

	claims, ok := (*validationResult).Token.Claims.(*jwt.UserClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, "Unable to authenicate")
		log.Error("error during refreshing token", api.ERROR_ASSERT_RESULT_TYPE)
		return
	}

	result, err := services.Instance().JWT().GenerateNewTokenPair(claims.Uuid, claims.Type, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Error("error during refreshing token", err.Error())
		return
	}

	err = services.Instance().Tokens().UpsertRefreshToken(claims.Uuid, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Error("error during refreshing token", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}
