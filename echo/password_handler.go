package echo

import (
	"context"
	"encoding/json"
	p "github.com/core-go/password"
	"github.com/labstack/echo/v4"
	"io/ioutil"
	"net/http"
	"strings"
)

type PasswordHandler struct {
	PasswordService p.PasswordService
	Error           func(context.Context, string, ...map[string]interface{})
	Decrypt         func(string) (string, error)
	Config          p.PasswordActionConfig
	Log             func(ctx context.Context, resource string, action string, success bool, desc string) error
}

func NewPasswordHandlerWithDecrypter(authenticationService p.PasswordService, logError func(context.Context, string, ...map[string]interface{}), decrypt func(string) (string, error), writeLog func(context.Context, string, string, bool, string) error, options...p.PasswordActionConfig) *PasswordHandler {
	var c p.PasswordActionConfig
	if len(options) >= 1 {
		conf := options[0]
		c.Resource = conf.Resource
		c.Change = conf.Change
		c.Reset = conf.Reset
		c.Forgot = conf.Forgot
	}
	if len(c.Resource) == 0 {
		c.Resource = "password"
	}
	if len(c.Change) == 0 {
		c.Change = "change"
	}
	if len(c.Reset) == 0 {
		c.Reset = "reset"
	}
	if len(c.Forgot) == 0 {
		c.Forgot = "forgot"
	}
	return &PasswordHandler{PasswordService: authenticationService, Config: c, Error: logError, Log: writeLog, Decrypt: decrypt}
}

func NewDefaultPasswordHandler(authenticationService p.PasswordService, logError func(context.Context, string, ...map[string]interface{}), options...func(context.Context, string, string, bool, string) error) *PasswordHandler {
	var writeLog func(context.Context, string, string, bool, string) error
	if len(options) >= 1 {
		writeLog = options[0]
	}
	return NewPasswordHandlerWithDecrypter(authenticationService, logError, nil, writeLog)
}

func NewPasswordHandler(authenticationService p.PasswordService, logError func(context.Context, string, ...map[string]interface{}), writeLog func(context.Context, string, string, bool, string) error, options...p.PasswordActionConfig) *PasswordHandler {
	return NewPasswordHandlerWithDecrypter(authenticationService, logError, nil, writeLog, options...)
}

func (h *PasswordHandler) ChangePassword(ctx echo.Context) error {
	r := ctx.Request()
	var passwordChange p.PasswordChange
	er1 := json.NewDecoder(r.Body).Decode(&passwordChange)
	if er1 != nil {
		if h.Error != nil {
			msg := "Cannot decode PasswordChange model: " + er1.Error()
			h.Error(r.Context(), msg)
		}
		return ctx.String(http.StatusBadRequest, "Cannot decode PasswordChange model")
	}
	if h.Decrypt != nil {
		decodedCurrentPassword, er2 := h.Decrypt(passwordChange.CurrentPassword)
		if er2 != nil {
			if h.Error != nil {
				msg := "cannot decode current password: " + er2.Error()
				h.Error(r.Context(), msg)
			}
			return ctx.String(http.StatusBadRequest, "cannot decode current password")
		}
		decodedNewPassword, er3 := h.Decrypt(passwordChange.Password)
		if er3 != nil {
			if h.Error != nil {
				msg := "cannot decode new password: " + er3.Error()
				h.Error(r.Context(), msg)
			}
			return ctx.String(http.StatusBadRequest, "cannot decode new password")
		}
		passwordChange.CurrentPassword = decodedCurrentPassword
		passwordChange.Password = decodedNewPassword
	}
	result, er4 := h.PasswordService.ChangePassword(r.Context(), passwordChange)
	if er4 != nil {
		msg := er4.Error()
		if h.Error != nil {
			h.Error(r.Context(), msg)
		}
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Change, false, msg)
	} else {
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Change, result > 0, "")
	}
}
func (h *PasswordHandler) ForgotPassword(ctx echo.Context) error {
	r := ctx.Request()
	email := ""
	if r.Method == "GET" {
		i := strings.LastIndex(r.RequestURI, "/")
		if i >= 0 {
			email = r.RequestURI[i+1:]
		}
	} else {
		b, er1 := ioutil.ReadAll(r.Body)
		if er1 != nil {
			if h.Error != nil {
				msg := "Cannot get the body of 'Forgot Password': " + er1.Error()
				h.Error(r.Context(), msg)
			}
			return ctx.String(http.StatusBadRequest, "Cannot get the body of 'Forgot Password'")
		}
		email = strings.Trim(string(b), " ")
	}
	result, er2 := h.PasswordService.ForgotPassword(r.Context(), email)
	if er2 != nil {
		msg := er2.Error()
		if h.Error != nil {
			h.Error(r.Context(), msg)
		}
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Forgot, false, msg)
	} else {
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Forgot, result, "")
	}
}
func (h *PasswordHandler) ResetPassword(ctx echo.Context) error {
	r := ctx.Request()
	var passwordReset p.PasswordReset
	er1 := json.NewDecoder(r.Body).Decode(&passwordReset)
	if er1 != nil {
		if h.Error != nil {
			msg := "Cannot decode PasswordReset model: " + er1.Error()
			h.Error(r.Context(), msg)
		}
		return ctx.String(http.StatusBadRequest, "Cannot decode PasswordReset model")
	}
	if h.Decrypt != nil {
		decodedNewPassword, er2 := h.Decrypt(passwordReset.Password)
		if er2 != nil {
			if h.Error != nil {
				msg := "cannot decode new password: " + er2.Error()
				h.Error(r.Context(), msg)
			}
			return ctx.String(http.StatusBadRequest, "cannot decode new password")
		}
		passwordReset.Password = decodedNewPassword
	}
	result, er3 := h.PasswordService.ResetPassword(r.Context(), passwordReset)
	if er3 != nil {
		msg := er3.Error()
		if h.Error != nil {
			h.Error(r.Context(), msg)
		}
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Reset, false, msg)
	} else {
		return respond(ctx, http.StatusOK, result, h.Log, h.Config.Resource, h.Config.Reset, result == 1, "")
	}
}
func respond(ctx echo.Context, code int, result interface{}, writeLog func(context.Context, string, string, bool, string) error, resource string, action string, success bool, desc string) error {
	err := ctx.JSON(code, result)
	if writeLog != nil {
		writeLog(ctx.Request().Context(), resource, action, success, desc)
	}
	return err
}
