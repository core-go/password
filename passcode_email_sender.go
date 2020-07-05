package password

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/common-go/mail"
)

type PasscodeEmailSender struct {
	MailService    mail.SimpleMailService
	From           mail.Email
	TemplateLoader mail.TemplateLoader
}

func NewPasscodeEmailSender(mailService mail.SimpleMailService, from mail.Email, templateLoader mail.TemplateLoader) *PasscodeEmailSender {
	return &PasscodeEmailSender{mailService, from, templateLoader}
}

func truncatingSprintf(str string, args ...interface{}) string {
	n := strings.Count(str, "%s")
	if n > len(args) {
		n = len(args)
	}
	return fmt.Sprintf(str, args[0:n]...)
}

func (s *PasscodeEmailSender) Send(ctx context.Context, to string, code string, expireAt time.Time, params interface{}) error {
	diff := expireAt.Sub(time.Now())
	strDiffMinutes := fmt.Sprint(diff.Minutes())
	subject, template, err := s.TemplateLoader.Load(ctx, to)
	if err != nil {
		return err
	}

	content := truncatingSprintf(template,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes,
		to, code, strDiffMinutes)

	toMail := params.(string)
	mailTo := []mail.Email{{Address: toMail}}
	mailData := mail.NewSimpleHtmlMail(s.From, subject, mailTo, nil, content)
	return s.MailService.Send(*mailData)
}
