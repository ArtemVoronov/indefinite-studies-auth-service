package auth

import (
	"context"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services"
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

	return &auth.VerifyTokenReply{IsValid: result.IsValid, IsExpired: result.IsExpired}, nil
}
