package password

import (
	"context"
	"time"
)

type VerificationCodeRepository interface {
	Save(ctx context.Context, id string, passcode string, expireAt time.Time) (int64, error)
	Load(ctx context.Context, id string) (string, time.Time, error)
	Delete(ctx context.Context, id string) (int64, error)
}
