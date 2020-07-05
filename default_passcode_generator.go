package password

type DefaultPasscodeGenerator struct {
	Length int
}

func (s DefaultPasscodeGenerator) Generate() string {
	if s.Length <= 0 {
		return generate(6)
	}
	return generate(s.Length)
}
