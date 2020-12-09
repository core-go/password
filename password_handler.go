package password

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

type PasswordActivityLogWriter interface {
	Write(ctx context.Context, resource string, action string, success bool, desc string) error
}

type ValueDecrypter interface {
	Decrypt(cipherText string, secretKey string) (string, error)
}
type PasswordActionConfig struct {
	Resource string `mapstructure:"resource"`
	Change   string `mapstructure:"change"`
	Reset    string `mapstructure:"reset"`
	Forgot   string `mapstructure:"forgot"`
}
type PasswordHandler struct {
	PasswordService PasswordService
	Config          PasswordActionConfig
	LogError        func(context.Context, string)
	LogWriter       PasswordActivityLogWriter
	Decrypter       ValueDecrypter
	EncryptionKey   string
}

func NewPasswordHandlerWithDecrypter(authenticationService PasswordService, conf *PasswordActionConfig, logError func(context.Context, string), logWriter PasswordActivityLogWriter, decrypter ValueDecrypter, encryptionKey string) *PasswordHandler {
	var c PasswordActionConfig
	if conf != nil {
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
	return &PasswordHandler{PasswordService: authenticationService, Config: c, LogError: logError, LogWriter: logWriter, Decrypter: decrypter, EncryptionKey: encryptionKey}
}

func NewPasswordHandler(authenticationService PasswordService, conf *PasswordActionConfig, logError func(context.Context, string), logWriter PasswordActivityLogWriter) *PasswordHandler {
	return NewPasswordHandlerWithDecrypter(authenticationService, conf, logError, logWriter, nil, "")
}

func (h *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var passwordChange PasswordChange
	er1 := json.NewDecoder(r.Body).Decode(&passwordChange)
	if er1 != nil {
		if h.LogError != nil {
			msg := "Cannot decode PasswordChange model: "+er1.Error()
			h.LogError(r.Context(), msg)
		}
		http.Error(w, "Cannot decode PasswordChange model", http.StatusBadRequest)
		return
	}
	if h.Decrypter != nil && len(h.EncryptionKey) > 0 {
		decodedCurrentPassword, er2 := h.Decrypter.Decrypt(passwordChange.CurrentPassword, h.EncryptionKey)
		if er2 != nil {
			if h.LogError != nil {
				msg := "cannot decode current password: " + er2.Error()
				h.LogError(r.Context(), msg)
			}
			http.Error(w, "cannot decode current password", http.StatusBadRequest)
			return
		}
		decodedNewPassword, er3 := h.Decrypter.Decrypt(passwordChange.Password, h.EncryptionKey)
		if er3 != nil {
			if h.LogError != nil {
				msg := "cannot decode new password: " + er3.Error()
				h.LogError(r.Context(), msg)
			}
			http.Error(w, "cannot decode new password", http.StatusBadRequest)
			return
		}
		passwordChange.CurrentPassword = decodedCurrentPassword
		passwordChange.Password = decodedNewPassword
	}
	result, er4 := h.PasswordService.ChangePassword(r.Context(), passwordChange)
	if er4 != nil {
		msg := er4.Error()
		if h.LogError != nil {
			h.LogError(r.Context(), msg)
		}
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Change, false, msg)
	} else {
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Change, result > 0, "")
	}
}
func (h *PasswordHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := ""
	if r.Method == "GET" {
		i := strings.LastIndex(r.RequestURI, "/")
		if i >= 0 {
			email = r.RequestURI[i+1:]
		}
	} else {
		b, er1 := ioutil.ReadAll(r.Body)
		if er1 != nil {
			if h.LogError != nil {
				msg := "Cannot get the body of 'Forgot Password': " + er1.Error()
				h.LogError(r.Context(), msg)
			}
			http.Error(w, "Cannot get the body of 'Forgot Password'", http.StatusBadRequest)
			return
		}
		email = strings.Trim(string(b), " ")
	}
	result, er2 := h.PasswordService.ForgotPassword(r.Context(), email)
	if er2 != nil {
		msg := er2.Error()
		if h.LogError != nil {
			h.LogError(r.Context(), msg)
		}
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Forgot, false, msg)
	} else {
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Forgot, result, "")
	}
}
func (h *PasswordHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var passwordReset PasswordReset
	er1 := json.NewDecoder(r.Body).Decode(&passwordReset)
	if er1 != nil {
		if h.LogError != nil {
			msg := "Cannot decode PasswordReset model: "+er1.Error()
			h.LogError(r.Context(), msg)
		}
		http.Error(w, "Cannot decode PasswordReset model", http.StatusBadRequest)
		return
	}
	if h.Decrypter != nil && len(h.EncryptionKey) > 0 {
		decodedNewPassword, er2 := h.Decrypter.Decrypt(passwordReset.Password, h.EncryptionKey)
		if er2 != nil {
			if h.LogError != nil {
				msg := "cannot decode new password: "+er2.Error()
				h.LogError(r.Context(), msg)
			}
			http.Error(w, "cannot decode new password", http.StatusBadRequest)
			return
		}
		passwordReset.Password = decodedNewPassword
	}
	result, er3 := h.PasswordService.ResetPassword(r.Context(), passwordReset)
	if er3 != nil {
		msg := er3.Error()
		if h.LogError != nil {
			h.LogError(r.Context(), msg)
		}
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Reset, false, msg)
	} else {
		respond(w, r, http.StatusOK, result, h.LogWriter, h.Config.Resource, h.Config.Reset, result == 1, "")
	}
}
func respond(w http.ResponseWriter, r *http.Request, code int, result interface{}, logWriter PasswordActivityLogWriter, resource string, action string, success bool, desc string) {
	response, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	if logWriter != nil {
		newCtx := context.WithValue(r.Context(), "request", r)
		logWriter.Write(newCtx, resource, action, success, desc)
	}
}