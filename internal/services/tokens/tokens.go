package tokens

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db/queries"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/log"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/db"
	"github.com/ArtemVoronov/indefinite-studies-utils/pkg/services/shard"
)

type TokensService struct {
	clientShards []*db.PostgreSQLService
	ShardsNum    int
	shardService *shard.ShardService
}

func CreateTokensService(clients []*db.PostgreSQLService) *TokensService {
	return &TokensService{
		clientShards: clients,
		ShardsNum:    len(clients),
		shardService: shard.CreateShardService(len(clients)),
	}
}

func (s *TokensService) Shutdown() error {
	result := []error{}
	l := len(s.clientShards)
	for i := 0; i < l; i++ {
		err := s.clientShards[i].Shutdown()
		if err != nil {
			result = append(result, err)
		}
	}
	if len(result) > 0 {
		return errors.Join(result...)
	}
	return nil
}

func (s *TokensService) client(userUuid string) *db.PostgreSQLService {
	bucketIndex := s.shardService.GetBucketIndex(userUuid)
	bucket := s.shardService.GetBucketByIndex(bucketIndex)
	log.Info(fmt.Sprintf("bucket: %v\tbucketIndex: %v", bucket, bucketIndex))
	return s.clientShards[bucket]
}

func (s *TokensService) UpsertRefreshToken(userUuid string, token string, expireAt time.Time) error {
	return s.client(userUuid).TxVoid(func(tx *sql.Tx, ctx context.Context, cancel context.CancelFunc) error {
		err := queries.UpdateRefreshToken(tx, ctx, userUuid, token, expireAt)

		if err == sql.ErrNoRows {
			err = queries.CreateRefreshToken(tx, ctx, userUuid, token, expireAt)
		}

		return err
	})()
}
