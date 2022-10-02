package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/services/db/entities"
)

var ErrorRefreshTokenDuplicateKey = errors.New("pq: duplicate key value violates unique constraint \"refresh_tokens_token_unique\"")

func GetRefreshTokenByToken(tx *sql.Tx, ctx context.Context, token string) (entities.RefreshToken, error) {
	var refreshToken entities.RefreshToken

	err := tx.QueryRowContext(ctx, "SELECT user_id, token, expire_at, create_date FROM refresh_tokens WHERE token = $1", token).
		Scan(&refreshToken.UserId, &refreshToken.Token, &refreshToken.ExpireAt, &refreshToken.CreateDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return refreshToken, err
		} else {
			return refreshToken, fmt.Errorf("error at loading refresh token '%s' from db, case after QueryRow.Scan: %s", token, err)
		}
	}

	return refreshToken, nil
}

func GetRefreshTokenByUserId(tx *sql.Tx, ctx context.Context, userId int) (entities.RefreshToken, error) {
	var refreshToken entities.RefreshToken

	err := tx.QueryRowContext(ctx, "SELECT user_id, token, expire_at, create_date FROM refresh_tokens WHERE user_id = $1", userId).
		Scan(&refreshToken.UserId, &refreshToken.Token, &refreshToken.ExpireAt, &refreshToken.CreateDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return refreshToken, err
		} else {
			return refreshToken, fmt.Errorf("error at loading refresh token by user id '%v' from db, case after QueryRow.Scan: %s", userId, err)
		}
	}

	return refreshToken, nil
}

func CreateRefreshToken(tx *sql.Tx, ctx context.Context, userId int, token string, expireAt time.Time) error {
	createDate := time.Now()

	stmt, err := tx.PrepareContext(ctx, "INSERT INTO refresh_tokens(user_id, token, expire_at, create_date) VALUES($1, $2, $3, $4)")
	if err != nil {
		return fmt.Errorf("error at creating refresh token, case after preparing statement: %s", err)
	}

	_, err = stmt.ExecContext(ctx, userId, token, expireAt, createDate)
	if err != nil {
		if err.Error() == ErrorRefreshTokenDuplicateKey.Error() {
			return ErrorRefreshTokenDuplicateKey
		}
		return fmt.Errorf("error at creating refresh token '%s' into db, case after ExecContext: %s", token, err)
	}

	return nil
}

func UpdateRefreshToken(tx *sql.Tx, ctx context.Context, userId int, token string, expireAt time.Time) error {
	createDate := time.Now()
	stmt, err := tx.PrepareContext(ctx, "UPDATE refresh_tokens SET token = $2, expire_at = $3, create_date = $4 WHERE user_id = $1")
	if err != nil {
		return fmt.Errorf("error at updating refresh token, case after preparing statement: %s", err)
	}
	res, err := stmt.ExecContext(ctx, userId, token, expireAt, createDate)
	if err != nil {
		return fmt.Errorf("error at updating refresh token '%s', case after executing statement: %s", token, err)
	}

	affectedRowsCount, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("error at updating refresh token '%s', case after counting affected rows: %s", token, err)
	}
	if affectedRowsCount == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func DeleteRefreshToken(tx *sql.Tx, ctx context.Context, userId int) error {
	stmt, err := tx.PrepareContext(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1")
	if err != nil {
		return fmt.Errorf("error at deleting refresh token, case after preparing statement: %s", err)
	}
	res, err := stmt.ExecContext(ctx, userId)
	if err != nil {
		return fmt.Errorf("error at deleting refresh token by user id '%d', case after executing statement: %s", userId, err)
	}
	affectedRowsCount, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("error at deleting refresh token by user id '%d', case after counting affected rows: %s", userId, err)
	}
	if affectedRowsCount == 0 {
		return sql.ErrNoRows
	}
	return nil
}
