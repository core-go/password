# Password
## Models
- PasswordChange
- PasswordReset

## Services
- PasswordService

## Installation

Please make sure to initialize a Go module before installing common-go/password:

```shell
go get -u github.com/common-go/password
```

Import:

```go
import "github.com/common-go/password"
```

## Implementations of PasswordRepository
- [sql](https://github.com/common-go/password-sql): requires [gorm](https://github.com/go-gorm/gorm)
- [mongo](https://github.com/common-go/password-mongo)
- [dynamodb](https://github.com/common-go/password-dynamodb)
- [firestore](https://github.com/common-go/password-firestore)
- [elasticsearch](https://github.com/common-go/password-elasticsearch)

## Details:
#### password_reset.go
```go
type PasswordReset struct {
	Username        string `json:"username,omitempty"`
	Passcode        string `json:"passcode,omitempty"`
	NewPassword     string `json:"newPassword,omitempty"`
}
```

#### password_change.go
```go
type PasswordChange struct {
	Step            int    `json:"step,omitempty"`
	Username        string `json:"username,omitempty"`
	Passcode        string `json:"passcode,omitempty"`
	CurrentPassword string `json:"currentPassword,omitempty"`
	NewPassword     string `json:"newPassword,omitempty"`
	SenderType      string `json:"senderType,omitempty"`
}
```

#### password_service.go
```go
type PasswordService interface {
	ForgotPassword(email string) (bool, error)
	ResetPassword(pass PasswordReset) (bool, error)
	ChangePassword(pass PasswordChange) (int32, error)
}
```
