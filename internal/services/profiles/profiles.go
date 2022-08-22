package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/utils"
)

type CredentialsValidationResult struct {
	UserId  int  `json:"userId" binding:"required,email"`
	IsValid bool `json:"isValid" binding:"required"`
}

// var profilesServiceBaseURL string
// var validateCredentialsURL string
// var accessTokenForAuthService string
// var once sync.Once

type ProfilesService struct {
	client                 *http.Client
	accessToken            string
	baseURL                string
	validateCredentialsURL string
}

var once sync.Once
var instance *ProfilesService

// TODO: move settings to .env
var client *http.Client = &http.Client{
	Timeout: time.Second * 30,
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

func Instance() *ProfilesService {
	once.Do(func() {
		if instance == nil {
			instance = createProfilesService(client, utils.EnvVar("PROFILES_SERVICE_BASE_URL"))
		}
	})
	return instance
}

// TODO: make public costructor, move to utils project
func createProfilesService(client *http.Client, baseUrl string) *ProfilesService {
	pair, err := jwt.Instance().GenerateNewTokenPair(jwt.AUTH_SERVICE_ID, jwt.TOKEN_TYPE_SERVICE)
	if err != nil {
		panic("unable to generate jwt for auth service")
	}
	return &ProfilesService{
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

	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("unable to validate credentials: %s", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		pair, err := jwt.Instance().GenerateNewTokenPair(jwt.AUTH_SERVICE_ID, jwt.TOKEN_TYPE_SERVICE)
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
