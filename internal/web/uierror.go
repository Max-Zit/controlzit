package web

import (
	"errors"
	"fmt"
	"net/http"
)

// uiError is an error whose text is a sentence for the user: the English
// text stays apart from its values, so it can be translated before the
// values are filled in.
type uiError struct {
	key  string
	args []any
}

func uiErr(key string) error { return &uiError{key: key} }

func uiErrf(key string, args ...any) error { return &uiError{key: key, args: args} }

func (e *uiError) Error() string {
	if len(e.args) == 0 {
		return e.key
	}
	return fmt.Errorf(e.key, e.args...).Error()
}

// Unwrap gives errors.Is and errors.As the wrapped error, if any.
func (e *uiError) Unwrap() error {
	for _, a := range e.args {
		if err, ok := a.(error); ok {
			return err
		}
	}
	return nil
}

// errText is err in the user's language.
func (s *Server) errText(r *http.Request, err error) string {
	var ue *uiError
	if !errors.As(err, &ue) || ue != err { // only an outermost sentence is translated
		return translate(s.lang(r, userFrom(r)), err.Error())
	}
	key := translate(s.lang(r, userFrom(r)), ue.key)
	if len(ue.args) == 0 {
		return key
	}
	return fmt.Errorf(key, ue.args...).Error()
}

// redirectErr is redirect with an error message.
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, to string, err error) {
	s.flash(w, r, "!"+s.errText(r, err))
	http.Redirect(w, r, to, http.StatusSeeOther)
}
