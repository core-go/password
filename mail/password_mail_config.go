package mail

import (
	"github.com/common-go/mail"
	"github.com/common-go/password"
)

type PasswordMailConfig struct {
	ResetExpires  int                           `mapstructure:"reset_expires"`
	ChangeExpires int                           `mapstructure:"change_expires"`
	Exp1          string                        `mapstructure:"exp1"`
	Exp2          string                        `mapstructure:"exp2"`
	Exp3          string                        `mapstructure:"exp3"`
	Exp4          string                        `mapstructure:"exp4"`
	Exp5          string                        `mapstructure:"exp5"`
	Exp6          string                        `mapstructure:"exp6"`
	Schema        password.PasswordSchemaConfig `mapstructure:"schema"`
	Template      PasswordTemplateConfig        `mapstructure:"template"`
}

type PasswordTemplateConfig struct {
	ResetTemplate  mail.TemplateConfig `mapstructure:"reset"`
	ChangeTemplate mail.TemplateConfig `mapstructure:"change"`
}
