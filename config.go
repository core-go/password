package password

type PasswordConfig struct {
	ResetExpires  int                  `mapstructure:"reset_expires"`
	ChangeExpires int                  `mapstructure:"change_expires"`
	Exp1          string               `mapstructure:"exp1"`
	Exp2          string               `mapstructure:"exp2"`
	Exp3          string               `mapstructure:"exp3"`
	Exp4          string               `mapstructure:"exp4"`
	Exp5          string               `mapstructure:"exp5"`
	Exp6          string               `mapstructure:"exp6"`
	Schema        PasswordSchemaConfig `mapstructure:"schema"`
}
