package password

type PasswordConfig struct {
	ResetExpires  int                  `mapstructure:"reset_expires" json:"resetExpires,omitempty" gorm:"column:resetexpires" bson:"resetExpires,omitempty" dynamodbav:"resetExpires,omitempty" firestore:"resetExpires,omitempty"`
	ChangeExpires int                  `mapstructure:"change_expires" json:"changeExpires,omitempty" gorm:"column:changeexpires" bson:"changeExpires,omitempty" dynamodbav:"changeExpires,omitempty" firestore:"changeExpires,omitempty"`
	Exp1          string               `mapstructure:"exp1" json:"exp1,omitempty" gorm:"column:exp1" bson:"exp1,omitempty" dynamodbav:"exp1,omitempty" firestore:"exp1,omitempty"`
	Exp2          string               `mapstructure:"exp2" json:"exp2,omitempty" gorm:"column:exp2" bson:"exp2,omitempty" dynamodbav:"exp2,omitempty" firestore:"exp2,omitempty"`
	Exp3          string               `mapstructure:"exp3" json:"exp3,omitempty" gorm:"column:exp3" bson:"exp3,omitempty" dynamodbav:"exp3,omitempty" firestore:"exp3,omitempty"`
	Exp4          string               `mapstructure:"exp4" json:"exp4,omitempty" gorm:"column:exp4" bson:"exp4,omitempty" dynamodbav:"exp4,omitempty" firestore:"exp4,omitempty"`
	Exp5          string               `mapstructure:"exp5" json:"exp5,omitempty" gorm:"column:exp5" bson:"exp5,omitempty" dynamodbav:"exp5,omitempty" firestore:"exp5,omitempty"`
	Exp6          string               `mapstructure:"exp6" json:"exp6,omitempty" gorm:"column:exp6" bson:"exp6,omitempty" dynamodbav:"exp6,omitempty" firestore:"exp6,omitempty"`
	Schema        PasswordSchemaConfig `mapstructure:"schema" json:"schema,omitempty" gorm:"column:schema" bson:"schema,omitempty" dynamodbav:"schema,omitempty" firestore:"schema,omitempty"`
}
