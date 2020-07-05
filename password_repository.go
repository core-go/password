package password

import "context"

type PasswordRepository interface {
	GetUserId(ctx context.Context, username string) (string, error)
	GetUser(ctx context.Context, usernameOrEmail string) (string, string, string, string, error)
	Update(ctx context.Context, userId string, newPassword string) (int64, error)
	UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error)
	GetHistory(ctx context.Context, userId string, max int) ([]string, error)
}
