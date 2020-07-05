package password

import (
	"context"
	"time"
)

type VerificationCodeSender interface {
	Send(ctx context.Context, to string, code string, expireAt time.Time, params interface{}) error
}
