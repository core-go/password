package password

type PasswordChange struct {
	Step            int    `json:"step,omitempty" gorm:"column:step" bson:"step,omitempty" dynamodbav:"step,omitempty" firestore:"step,omitempty"`
	Username        string `json:"username,omitempty" gorm:"column:username" bson:"username,omitempty" dynamodbav:"username,omitempty" firestore:"username,omitempty"`
	Passcode        string `json:"passcode,omitempty" gorm:"column:passcode" bson:"passcode,omitempty" dynamodbav:"passcode,omitempty" firestore:"passcode,omitempty"`
	CurrentPassword string `json:"currentPassword,omitempty" gorm:"column:currentpassword" bson:"currentPassword,omitempty" dynamodbav:"currentPassword,omitempty" firestore:"currentPassword,omitempty"`
	Password        string `json:"password,omitempty" gorm:"column:password" bson:"password,omitempty" dynamodbav:"password,omitempty" firestore:"password,omitempty"`
	SenderType      string `json:"senderType,omitempty" gorm:"column:sendertype" bson:"senderType,omitempty" dynamodbav:"senderType,omitempty" firestore:"senderType,omitempty"`
}
