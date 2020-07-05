package password

import "context"

type TwoFactorsRepository interface {
	Require(ctx context.Context, id string) (bool, error)
}
