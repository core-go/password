package password

type PasscodeGenerator interface {
	Generate() string
}
