package password

type PasswordReset struct {
	Username string `json:"username,omitempty" gorm:"column:username" bson:"username,omitempty" dynamodbav:"username,omitempty" firestore:"username,omitempty"`
	Passcode string `json:"passcode,omitempty" gorm:"column:passcode" bson:"passcode,omitempty" dynamodbav:"passcode,omitempty" firestore:"passcode,omitempty"`
	Password string `json:"password,omitempty" gorm:"column:password" bson:"password,omitempty" dynamodbav:"password,omitempty" firestore:"password,omitempty"`
}
