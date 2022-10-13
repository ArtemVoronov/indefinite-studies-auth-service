package entities

import "time"

type RefreshToken struct {
	UserUuid   string
	Token      string
	CreateDate time.Time
	ExpireAt   time.Time
}
