package auth

import (
	"context"
	"fmt"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/jwt"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/auth"
	"google.golang.org/grpc"
)

type AuthServiceServer struct {
	auth.UnimplementedAuthServiceServer
}

func RegisterServiceServer(s *grpc.Server) {
	auth.RegisterAuthServiceServer(s, &AuthServiceServer{})
}

func (s *AuthServiceServer) VerifyToken(ctx context.Context, in *auth.VerifyTokenRequest) (*auth.VerifyTokenReply, error) {
	result, err := services.Instance().JWT().VerifyToken(in.GetToken())
	if err != nil {
		return nil, err
	}

	claims, ok := result.Token.Claims.(*jwt.UserClaims)
	if !ok {
		return nil, fmt.Errorf("unable to parse token claims")
	}

	return &auth.VerifyTokenReply{
		IsValid:   result.IsValid,
		IsExpired: result.IsExpired,
		Id:        int32(claims.Id),
		Type:      claims.Type,
		Role:      claims.Role,
	}, nil
}

func (s *AuthServiceServer) GetTokenClaims(ctx context.Context, in *auth.GetTokenClaimsRequest) (*auth.GetTokenClaimsReply, error) {
	result, err := services.Instance().JWT().VerifyToken(in.GetToken())
	if err != nil {
		return nil, err
	}

	claims, ok := result.Token.Claims.(*jwt.UserClaims)
	if !ok {
		return nil, fmt.Errorf("unable to parse token claims")
	}

	return &auth.GetTokenClaimsReply{Id: int32(claims.Id), Type: claims.Type, Role: claims.Role}, nil
}
