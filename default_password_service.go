package password

import (
	"context"
	"errors"
	"log"
	"regexp"
	"time"
)

type DefaultPasswordService struct {
	PasswordComparator       TextComparator
	PasswordRepository       PasswordRepository
	PasswordResetExpires     int
	ResetPasscodeRepository  PasscodeRepository
	SendResetCode            func(ctx context.Context, to string, code string, expireAt time.Time, params interface{}) error
	TokenBlacklistRepository TokenBlacklistRepository
	Regexps                  []regexp.Regexp
	DuplicateCount           int
	RequireTwoFactors        func(ctx context.Context, id string) (bool, error)
	PasswordChangeExpires    int
	ChangePasscodeRepository PasscodeRepository
	SendChangeCode           func(ctx context.Context, to string, code string, expireAt time.Time, params interface{}) error
	Generate                 func() string
}

func NewPasswordService(passwordComparator TextComparator, passwordRepossitory PasswordRepository, passwordResetExpires int, resetPasscodeService PasscodeRepository, sendResetCode func(context.Context, string, string, time.Time, interface{}) error, blacklistTokenService TokenBlacklistRepository, expressions []string, duplicateCount int, requireTwoFactors func(ctx context.Context, id string) (bool, error), passwordChangeExpires int, changePasscodeService PasscodeRepository, sendChangeCode func(context.Context, string, string, time.Time, interface{}) error, generate func() string) *DefaultPasswordService {
	if requireTwoFactors != nil && (changePasscodeService == nil || sendChangeCode == nil || passwordChangeExpires <= 0) {
		panic(errors.New("when requireTwoFactors is not nil, changePasscodeService and sendChangeCode must not be nil, and passwordChangeExpires must be greater than 0"))
	}
	regExps := make([]regexp.Regexp, 0)
	if len(expressions) > 0 {
		for _, expression := range expressions {
			if len(expression) > 0 {
				regExp := regexp.MustCompile(expression)
				regExps = append(regExps, *regExp)
			}
		}
	}
	return &DefaultPasswordService{passwordComparator, passwordRepossitory, passwordResetExpires, resetPasscodeService, sendResetCode, blacklistTokenService, regExps, duplicateCount, requireTwoFactors, passwordChangeExpires, changePasscodeService, sendChangeCode, generate}
}

func NewDefaultPasswordService(passwordComparator TextComparator, passwordRepossitory PasswordRepository, passwordResetExpires int, resetPasscodeService PasscodeRepository, sendCode func(context.Context, string, string, time.Time, interface{}) error, blacklistTokenService TokenBlacklistRepository, expressions []string, duplicateCount int, requireTwoFactors func(ctx context.Context, id string) (bool, error)) *DefaultPasswordService {
	return NewPasswordService(passwordComparator, passwordRepossitory, passwordResetExpires, resetPasscodeService, sendCode, blacklistTokenService, expressions, duplicateCount, requireTwoFactors, passwordResetExpires, resetPasscodeService, sendCode, nil)
}

func (s DefaultPasswordService) ChangePassword(ctx context.Context, passwordChange PasswordChange) (int32, error) {
	if len(s.Regexps) > 0 {
		for _, exp := range s.Regexps {
			if !exp.MatchString(passwordChange.Password) {
				return -2, nil
			}
		}
	}
	if passwordChange.Step > 0 && len(passwordChange.Passcode) == 0 {
		return 0, nil
	}

	userId, username, email, password, er0 := s.PasswordRepository.GetUser(ctx, passwordChange.Username)
	if er0 != nil || len(userId) == 0 {
		return 0, er0
	}
	validPassword, er2 := s.PasswordComparator.Compare(passwordChange.CurrentPassword, password)
	if !validPassword || er2 != nil {
		return 0, er2
	}

	if s.DuplicateCount > 0 {
		histories, er3 := s.PasswordRepository.GetHistory(ctx, userId, s.DuplicateCount-1)
		if er3 != nil {
			return 0, er3
		}
		duplicate, er4 := duplicate(ctx, s.PasswordComparator, passwordChange.Password, password, histories, s.DuplicateCount)
		if er4 != nil {
			return 0, er4
		}
		if duplicate {
			return -1, nil
		}
	}

	if s.RequireTwoFactors != nil {
		required, er4 := s.RequireTwoFactors(ctx, userId)
		if er4 != nil {
			return 0, er4
		}
		if required {
			if passwordChange.Step <= 0 {
				var codeSend string
				if s.Generate != nil {
					codeSend = s.Generate()
				} else {
					codeSend = Generate(6)
				}

				codeSave, er5 := s.PasswordComparator.Hash(codeSend)
				if er5 != nil {
					return 0, er5
				}
				expiredAt := addSeconds(time.Now(), s.PasswordChangeExpires)
				count, er6 := s.ChangePasscodeRepository.Save(ctx, userId, codeSave, expiredAt)
				if count > 0 && er6 == nil {
					er7 := s.SendChangeCode(ctx, username, codeSend, expiredAt, email)
					return 2, er7
				}
			}
			code, expiredAt, er8 := s.ChangePasscodeRepository.Load(ctx, userId)
			if er8 != nil || len(code) == 0 {
				return 0, er8
			}
			if compareDate(expiredAt, time.Now()) < 0 {
				deleteCode(ctx, s.ChangePasscodeRepository, userId)
				return 0, nil
			}
			valid, er9 := s.PasswordComparator.Compare(passwordChange.Passcode, code)
			if er9 == nil {
				deleteCode(ctx, s.ChangePasscodeRepository, userId)
			}
			if !valid || er9 != nil {
				return 0, er9
			}
		}
	}

	newPassword, er6 := s.PasswordComparator.Hash(passwordChange.Password)
	if er6 != nil {
		return 0, er6
	}
	count, er7 := s.PasswordRepository.UpdateWithCurrentPassword(ctx, userId, password, newPassword)
	if count > 0 && er7 == nil {
		if s.TokenBlacklistRepository != nil {
			er8 := s.TokenBlacklistRepository.RevokeAllTokens(userId, "The user has changed password.")
			return 1, er8
		}
		return 1, er7
	}
	return 0, er7
}

func duplicate(ctx context.Context, comparator TextComparator, newPassword, currentPassword string, histories []string, count int) (bool, error) {
	equal0, er0 := comparator.Compare(newPassword, currentPassword)
	if equal0 || er0 != nil {
		return equal0, er0
	}
	length := min(count-1, len(histories))
	for i := 0; i < length; i++ {
		equal1, er1 := comparator.Compare(newPassword, histories[i])
		if equal1 || er1 != nil {
			return equal1, er1
		}
	}
	return false, nil
}

func min(n1, n2 int) int {
	if n1 <= n2 {
		return n1
	}
	return n2
}

func (s DefaultPasswordService) ForgotPassword(ctx context.Context, emailTo string) (bool, error) {
	userId, username, email, _, er1 := s.PasswordRepository.GetUser(ctx, emailTo)
	if len(userId) == 0 || er1 != nil {
		return false, er1
	}

	var codeSend string
	if s.Generate != nil {
		codeSend = s.Generate()
	} else {
		codeSend = Generate(6)
	}

	codeSave, er0 := s.PasswordComparator.Hash(codeSend)
	if er0 != nil {
		return false, er0
	}
	expiredAt := addSeconds(time.Now(), s.PasswordResetExpires)
	count, er1 := s.ResetPasscodeRepository.Save(ctx, userId, codeSave, expiredAt)
	if count > 0 && er1 == nil {
		expiredAt := addSeconds(time.Now(), s.PasswordResetExpires)
		er2 := s.SendResetCode(ctx, username, codeSend, expiredAt, email)
		if er2 != nil {
			return false, er2
		}
		return true, nil
	}
	return false, er1
}

func (s DefaultPasswordService) ResetPassword(ctx context.Context, passwordReset PasswordReset) (int32, error) {
	if len(s.Regexps) > 0 {
		for _, exp := range s.Regexps {
			if !exp.MatchString(passwordReset.Password) {
				return -2, nil
			}
		}
	}
	var userId, password string
	var er0 error
	if s.DuplicateCount <= 0 {
		userId, er0 = s.PasswordRepository.GetUserId(ctx, passwordReset.Username)
	} else {
		userId, _, _, password, er0 = s.PasswordRepository.GetUser(ctx, passwordReset.Username)
	}
	if len(userId) == 0 || er0 != nil {
		return 0, er0
	}

	passcode, expiredAt, er2 := s.ResetPasscodeRepository.Load(ctx, userId)
	if er2 != nil {
		return 0, er2
	}
	if compareDate(expiredAt, time.Now()) < 0 {
		deleteCode(ctx, s.ResetPasscodeRepository, userId)
		return 0, nil
	}
	valid, er3 := s.PasswordComparator.Compare(passwordReset.Passcode, passcode)
	if s.DuplicateCount > 0 && valid && er3 == nil {
		histories, er3 := s.PasswordRepository.GetHistory(ctx, userId, s.DuplicateCount-1)
		if er3 != nil {
			return 0, er3
		}
		duplicate, er4 := duplicate(ctx, s.PasswordComparator, passwordReset.Password, password, histories, s.DuplicateCount)
		if er4 != nil {
			return 0, er4
		}
		if duplicate {
			return -1, nil
		}
	}

	if er3 == nil {
		deleteCode(ctx, s.ResetPasscodeRepository, userId)
	}
	if !valid || er3 != nil {
		return 0, er3
	}
	newPassword, er4 := s.PasswordComparator.Hash(passwordReset.Password)
	if er4 != nil {
		return 0, er4
	}
	var count int64
	if s.DuplicateCount <= 0 {
		count, er0 = s.PasswordRepository.Update(ctx, userId, newPassword)
	} else {
		count, er0 = s.PasswordRepository.UpdateWithCurrentPassword(ctx, userId, password, newPassword)
	}

	if count > 0 && er0 == nil {
		if s.TokenBlacklistRepository != nil {
			er6 := s.TokenBlacklistRepository.RevokeAllTokens(userId, "The user has reset password.")
			return 1, er6
		}
		return 1, er0
	}
	return 0, er0
}

func deleteCode(ctx context.Context, codeService PasscodeRepository, id string) {
	go func() {
		ctxDelete, _ := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := codeService.Delete(ctxDelete, id)
		if err != nil {
			log.Println(err)
		}
	}()
}
