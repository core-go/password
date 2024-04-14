package password

type PasswordSchemaConfig struct {
	UserId      string `mapstructure:"user_id"`
	Username    string `mapstructure:"username"`
	ToAddress   string `mapstructure:"to_address"`
	Password    string `mapstructure:"password"`
	FailCount   string `mapstructure:"fail_count"`
	ChangedTime string `mapstructure:"changed_time"`
	ChangedBy   string `mapstructure:"changed_by"`
	Timestamp   string `mapstructure:"timestamp"`
	History     string `mapstructure:"history"`
}
