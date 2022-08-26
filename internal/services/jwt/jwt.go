package jwt

import (
	"fmt"
	"strings"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
	"github.com/golang-jwt/jwt/v4"
)

type AuthenicationDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthenicationResultDTO struct {
	AccessToken           string           `json:"accessToken" binding:"required"`
	RefreshToken          string           `json:"refreshToken" binding:"required"`
	AccessTokenExpiredAt  *jwt.NumericDate `json:"accessTokenExpiredAt" binding:"required"`
	RefreshTokenExpiredAt *jwt.NumericDate `json:"refreshTokenExpiredAt" binding:"required"`
}

type UserClaims struct {
	Id   int
	Type string
	jwt.RegisteredClaims
}

type TokenVerificationResult struct {
	IsValid   bool
	IsExpired bool
	Token     *jwt.Token
}

type VerificationDTO struct {
	AccessToken string `json:"accessToken" binding:"required"`
}

type VerificationResult struct {
	IsValid   bool
	IsExpired bool
}

type RefreshTokenDTO struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

const (
	TOKEN_TYPE_USER     = "USER"
	TOKEN_TYPE_SERVICE  = "SERVICE"
	AUTH_SERVICE_ID     = -1
	PROFILES_SERVICE_ID = -2
)

type JWTService struct {
	hmacSecret           []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	tokenIssuer          string
}

func CreateJWTService() *JWTService {
	return &JWTService{
		hmacSecret:           utils.EnvVarBytes("JWT_SIGN"),
		accessTokenDuration:  utils.EnvVarDurationDefault("JWT_ACCESS_DURATION_IN_SECONDS", time.Second, 30*time.Second),
		refreshTokenDuration: utils.EnvVarDurationDefault("JWT_REFRESH_DURATION_IN_SECONDS", time.Second, 30*time.Second),
		tokenIssuer:          utils.EnvVar("JWT_ISSUER"),
	}
}

func (s *JWTService) Shutdown() error {
	return nil
}

func (s *JWTService) GenerateNewTokenPair(id int, tokenType string) (*AuthenicationResultDTO, error) {
	var result *AuthenicationResultDTO
	expireAtForAccessToken := jwt.NewNumericDate(time.Now().Add(s.accessTokenDuration))
	expireAtForRefreshToken := jwt.NewNumericDate(time.Now().Add(s.refreshTokenDuration))

	accessToken, err := s.createToken(expireAtForAccessToken, id, tokenType, "access")
	if err != nil {
		return result, fmt.Errorf("error token pair generation: %v", err)
	}

	refreshToken, err := s.createToken(expireAtForRefreshToken, id, tokenType, "refresh")
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

func (s *JWTService) createToken(expireAt *jwt.NumericDate, id int, tokenType string, subject string) (string, error) {
	claims := UserClaims{
		id,
		tokenType,
		jwt.RegisteredClaims{
			ExpiresAt: expireAt,
			Issuer:    s.tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   subject,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(s.hmacSecret)
	return signedToken, err
}

func (s *JWTService) VerifyToken(token string) (*TokenVerificationResult, error) {
	t, err := jwt.ParseWithClaims(token, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.hmacSecret, nil
	})

	if err != nil {
		if strings.HasPrefix(err.Error(), "token is expired") {
			return &TokenVerificationResult{IsValid: false, IsExpired: true}, nil
		}
		return nil, err
	}

	return &TokenVerificationResult{IsValid: true, IsExpired: false, Token: t}, nil
}
