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

type PasswordHandler struct {
	PasswordService PasswordService
	Decrypter       ValueDecrypter
	EncryptionKey   string
	LogWriter       PasswordActivityLogWriter
}

func NewPasswordHandler(authenticationService PasswordService, decrypter ValueDecrypter, encryptionKey string, logWriter PasswordActivityLogWriter) *PasswordHandler {
	return &PasswordHandler{authenticationService, decrypter, encryptionKey, logWriter}
}

func NewDefaultPasswordHandler(authenticationService PasswordService) *PasswordHandler {
	return NewPasswordHandler(authenticationService, nil, "", nil)
}


func (c *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var passwordChange PasswordChange
	er1 := json.NewDecoder(r.Body).Decode(&passwordChange)
	if er1 != nil {
		RespondString(w, r, http.StatusBadRequest, "Cannot decode PasswordChange model: "+er1.Error())
		return
	}
	if c.Decrypter != nil && len(c.EncryptionKey) > 0 {
		decodedCurrentPassword, er2 := c.Decrypter.Decrypt(passwordChange.CurrentPassword, c.EncryptionKey)
		if er2 != nil {
			RespondString(w, r, http.StatusBadRequest, "cannot decode current password")
			return
		}
		decodedNewPassword, er3 := c.Decrypter.Decrypt(passwordChange.Password, c.EncryptionKey)
		if er3 != nil {
			RespondString(w, r, http.StatusBadRequest, "cannot decode new password")
		}
		passwordChange.CurrentPassword = decodedCurrentPassword
		passwordChange.Password = decodedNewPassword
	}
	result, er4 := c.PasswordService.ChangePassword(r.Context(), passwordChange)
	if er4 != nil {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Change", false, er4.Error())
	} else {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Change", result > 0, "")
	}
}
func (c *PasswordHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := ""
	if r.Method == "GET" {
		i := strings.LastIndex(r.RequestURI, "/")
		if i >= 0 {
			email = r.RequestURI[i + 1:]
		}
	} else {
		b, er1 := ioutil.ReadAll(r.Body)
		if er1 != nil {
			RespondString(w, r, http.StatusBadRequest, "Cannot get the body of 'Forgot Password'")
			return
		}
		email = strings.Trim(string(b), " ")
	}
	result, er2 := c.PasswordService.ForgotPassword(r.Context(), email)
	if er2 != nil {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Forgot", false, er2.Error())
	} else {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Forgot", result, "")
	}
}
func (c *PasswordHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var passwordReset PasswordReset
	er1 := json.NewDecoder(r.Body).Decode(&passwordReset)
	if er1 != nil {
		RespondString(w, r, http.StatusBadRequest, "Cannot decode PasswordReset model")
		return
	}
	if c.Decrypter != nil && len(c.EncryptionKey) > 0 {
		decodedNewPassword, er2 := c.Decrypter.Decrypt(passwordReset.Password, c.EncryptionKey)
		if er2 != nil {
			RespondString(w, r, http.StatusBadRequest, "cannot decode new password")
			return
		}
		passwordReset.Password = decodedNewPassword
	}
	result, er3 := c.PasswordService.ResetPassword(r.Context(), passwordReset)
	if er3 != nil {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Reset", false, er3.Error())
	} else {
		Respond(w, r, http.StatusOK, result, c.LogWriter, "Password", "Reset", result == 1, "")
	}
}
func RespondString(w http.ResponseWriter, r *http.Request, code int, result string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write([]byte(result))
}
func Respond(w http.ResponseWriter, r *http.Request, code int, result interface{}, logWriter PasswordActivityLogWriter, resource string, action string, success bool, desc string) {
	response, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	if logWriter != nil {
		newCtx := context.WithValue(r.Context(), "request", r)
		logWriter.Write(newCtx, resource, action, success, desc)
	}
}
