package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
)

type CredentialsValidationResult struct {
	UserId  int  `json:"userId" binding:"required,email"`
	IsValid bool `json:"isValid" binding:"required"`
}

type ProfilesService struct {
	jwt                    *jwt.JWTService
	client                 *http.Client
	accessToken            string
	baseURL                string
	validateCredentialsURL string
}

func CreateProfilesService(client *http.Client, baseUrl string, jwtService *jwt.JWTService) *ProfilesService {
	pair, err := jwtService.GenerateNewTokenPair(jwt.AUTH_SERVICE_ID, jwt.TOKEN_TYPE_SERVICE)
	if err != nil {
		panic("unable to generate jwt for auth service")
	}
	return &ProfilesService{
		jwt:                    jwtService,
		client:                 client,
		accessToken:            pair.AccessToken,
		baseURL:                baseUrl,
		validateCredentialsURL: baseUrl + "/api/v1/users/credentials:validate",
	}
}

func (s *ProfilesService) Shutdown() error {
	return nil
}

func (s *ProfilesService) ValidateCredentials(authenicationDTO jwt.AuthenicationDTO) (CredentialsValidationResult, error) {
	var result CredentialsValidationResult

	body, err := json.Marshal(authenicationDTO)
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	req, err := http.NewRequest(http.MethodPut, s.validateCredentialsURL, bytes.NewBuffer(body))
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.accessToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		pair, err := s.jwt.GenerateNewTokenPair(jwt.AUTH_SERVICE_ID, jwt.TOKEN_TYPE_SERVICE)
		if err != nil {
			return result, fmt.Errorf("unable to validate credentials: %s", err)
		}
		s.accessToken = pair.AccessToken
	}

	if resp.StatusCode != 200 {
		return result, fmt.Errorf("unable to validate credentials, response status code: %v", resp.StatusCode)
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	err = json.Unmarshal(resBody, &result)
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	return result, nil
}
