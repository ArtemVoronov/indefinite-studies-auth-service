package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/db"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/db/queries"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/api/validation"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var hmacSecret []byte
var accessTokenDuration time.Duration
var refreshTokenDuration time.Duration
var tokenIssuer string
var once sync.Once

func Setup() {
	once.Do(func() {
		hmacSecret = utils.EnvVarBytes("JWT_SIGN")
		accessTokenDuration = utils.EnvVarDuration("JWT_ACCESS_DURATION_IN_SECONDS", time.Second)
		refreshTokenDuration = utils.EnvVarDuration("JWT_REFRESH_DURATION_IN_SECONDS", time.Second)
		tokenIssuer = utils.EnvVar("JWT_ISSUER")
	})
}

type CredentialsValidationResult struct {
	UserId  int  `json:"userId" binding:"required,email"`
	IsValid bool `json:"isValid" binding:"required"`
}

type TokenValidationResult struct {
	IsValid   bool
	IsExpired bool
	token     *jwt.Token
}

type AuthenicationDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type VerificationDTO struct {
	AccessToken string `json:"accessToken" binding:"required"`
}

type VerificationResult struct {
	IsValid   bool
	IsExpired bool
}

type AuthenicationResultDTO struct {
	AccessToken           string           `json:"accessToken" binding:"required"`
	RefreshToken          string           `json:"refreshToken" binding:"required"`
	AccessTokenExpiredAt  *jwt.NumericDate `json:"accessTokenExpiredAt" binding:"required"`
	RefreshTokenExpiredAt *jwt.NumericDate `json:"refreshTokenExpiredAt" binding:"required"`
}

type RefreshTokenDTO struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type UserClaims struct {
	UserId int
	jwt.RegisteredClaims
}

func Authenicate(c *gin.Context) {
	var authenicationDTO AuthenicationDTO

	if err := c.ShouldBindJSON(&authenicationDTO); err != nil {
		validation.ProcessAndSendValidationErrorMessage(c, err)
		return
	}

	// TODO: add counter of invalid athorizations, then use it for temporary blocking access
	validatoionResult, err := checkUserCredentials(authenicationDTO)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during authenication: %v\n", err)
		return
	}
	if !validatoionResult.IsValid || validatoionResult.UserId == -1 {
		c.JSON(http.StatusBadRequest, api.ERROR_WRONG_PASSWORD_OR_EMAIL)
		return
	}

	result, err := generateNewTokenPair(validatoionResult.UserId)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during authenication: %v\n", err)
		return
	}

	err = db.TxVoid(func(tx *sql.Tx, ctx context.Context, cancel context.CancelFunc) error {
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
	var refreshToken RefreshTokenDTO

	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		validation.ProcessAndSendValidationErrorMessage(c, err)
		return
	}

	validationResult, err := validate(refreshToken.RefreshToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	if (*validationResult).IsExpired {
		c.JSON(http.StatusBadRequest, api.ERROR_TOKEN_IS_EXPIRED)
		return
	}

	claims, ok := (*validationResult).token.Claims.(*UserClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, "Unable to authenicate")
		log.Printf("error during refreshing token: %v\n", api.ERROR_ASSERT_RESULT_TYPE)
		return
	}

	result, err := generateNewTokenPair(claims.UserId)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal server error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	err = db.TxVoid(func(tx *sql.Tx, ctx context.Context, cancel context.CancelFunc) error {
		err := queries.UpdateRefreshToken(tx, ctx, claims.UserId, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)
		if err == sql.ErrNoRows {
			err = queries.CreateRefreshToken(tx, ctx, claims.UserId, (*result).RefreshToken, (*result).RefreshTokenExpiredAt.Time)
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

func generateNewTokenPair(userId int) (*AuthenicationResultDTO, error) {
	var result *AuthenicationResultDTO
	expireAtForAccessToken := jwt.NewNumericDate(time.Now().Add(accessTokenDuration))
	expireAtForRefreshToken := jwt.NewNumericDate(time.Now().Add(refreshTokenDuration))

	accessToken, err := createToken(expireAtForAccessToken, userId, "access")
	if err != nil {
		return result, fmt.Errorf("error token pair generation: %v", err)
	}

	refreshToken, err := createToken(expireAtForRefreshToken, userId, "refresh")
	if err != nil {
		return result, fmt.Errorf("error token pair generation: %v", err)
	}

	result = &AuthenicationResultDTO{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiredAt:  expireAtForAccessToken,
		RefreshTokenExpiredAt: expireAtForRefreshToken,
	}

	return result, nil
}

func createToken(expireAt *jwt.NumericDate, userId int, subject string) (string, error) {
	claims := UserClaims{
		userId,
		jwt.RegisteredClaims{
			ExpiresAt: expireAt,
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   subject,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(hmacSecret)
	return signedToken, err
}

func validate(token string) (*TokenValidationResult, error) {
	t, err := jwt.ParseWithClaims(token, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return hmacSecret, nil
	})

	if err != nil {
		if strings.HasPrefix(err.Error(), "token is expired") {
			return &TokenValidationResult{IsValid: false, IsExpired: true}, nil
		}
		return nil, err
	}

	return &TokenValidationResult{IsValid: true, IsExpired: false, token: t}, nil
}

func VerifyToken(c *gin.Context) {
	var verification VerificationDTO

	if err := c.ShouldBindJSON(&verification); err != nil {
		validation.ProcessAndSendValidationErrorMessage(c, err)
		return
	}

	validationResult, err := validate(verification.AccessToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		log.Printf("error during refreshing token: %v\n", err)
		return
	}

	if (*validationResult).IsExpired {
		c.JSON(http.StatusBadRequest, api.ERROR_TOKEN_IS_EXPIRED)
		return
	}

	// TODO: make some complex analysis based on claims in future, e.g. check the role, permission etc

	c.JSON(http.StatusOK, &VerificationResult{IsValid: validationResult.IsValid, IsExpired: validationResult.IsExpired})
}

func checkUserCredentials(authenicationDTO AuthenicationDTO) (CredentialsValidationResult, error) {
	var result CredentialsValidationResult
	// TODO: unify http client calls to utils and reuse it
	client := &http.Client{}

	body, err := json.Marshal(authenicationDTO)
	if err != nil {
		return result, fmt.Errorf("unable to check credentials : %s", err)
	}

	// TODO: get profiles-service URL from discovery-service
	req, err := http.NewRequest(http.MethodPut, "http://192.168.0.18/api/v1/users/credentials:validate", bytes.NewBuffer(body))
	if err != nil {
		return result, fmt.Errorf("unable to check credentials : %s", err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("unable to check credentials : %s", err)
	}
	fmt.Printf("--------resp: %v\n", resp)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result, fmt.Errorf("unable to check credentials : not ok response")
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("unable to check credentials : %s", err)
	}
	err = json.Unmarshal(resBody, &result)
	if err != nil {
		return result, fmt.Errorf("unable to check credentials : %s", err)
	}
	// result, ok := data.(CredentialsValidationResult)
	// if !ok {
	// 	return result, fmt.Errorf("unable to check credentials : %s", api.ERROR_ASSERT_RESULT_TYPE)
	// }

	fmt.Printf("--------result: %v\n", result)

	return result, nil
}

func addAuthCookies(c *gin.Context, auth *AuthenicationResultDTO) {
	// TODO: read from config appropriate options for cookies
	c.SetCookie("AccessToken", (*auth).AccessToken, int(accessTokenDuration.Seconds()), "/", "localhost", false, true)
	// c.SetCookie("RefreshToken", (*auth).RefreshToken, int(refreshTokenDuration.Seconds()), "/", "localhost", false, true)
}
