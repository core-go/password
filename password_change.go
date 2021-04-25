package password

type PasswordChange struct {
	Step            int    `mapstructure:"step" json:"step,omitempty" gorm:"column:step" bson:"step,omitempty" dynamodbav:"step,omitempty" firestore:"step,omitempty"`
	Username        string `mapstructure:"username" json:"username,omitempty" gorm:"column:username" bson:"username,omitempty" dynamodbav:"username,omitempty" firestore:"username,omitempty"`
	Passcode        string `mapstructure:"passcode" json:"passcode,omitempty" gorm:"column:passcode" bson:"passcode,omitempty" dynamodbav:"passcode,omitempty" firestore:"passcode,omitempty"`
	CurrentPassword string `mapstructure:"current_password" json:"currentPassword,omitempty" gorm:"column:currentpassword" bson:"currentPassword,omitempty" dynamodbav:"currentPassword,omitempty" firestore:"currentPassword,omitempty"`
	Password        string `mapstructure:"password" json:"password,omitempty" gorm:"column:password" bson:"password,omitempty" dynamodbav:"password,omitempty" firestore:"password,omitempty"`
	Sender          string `mapstructure:"sender" json:"sender,omitempty" gorm:"column:sender" bson:"sender,omitempty" dynamodbav:"sender,omitempty" firestore:"sender,omitempty"`
}
