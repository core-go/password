package password

import "context"

type PasswordService interface {
	ForgotPassword(ctx context.Context, email string) (bool, error)
	ResetPassword(ctx context.Context, pass PasswordReset) (int32, error)
	ChangePassword(ctx context.Context, pass PasswordChange) (int32, error)
}
