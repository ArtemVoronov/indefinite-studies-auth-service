package entities

import "time"

type RefreshToken struct {
	UserId     int
	Token      string
	CreateDate time.Time
	ExpireAt   time.Time
}
