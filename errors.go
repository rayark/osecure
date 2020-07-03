package osecure

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrorInvalidSession                 = errors.New("invalid session")                       // Authorize()
	ErrorInvalidAuthorizationSyntax     = errors.New("invalid authorization syntax")          // Authorize()
	ErrorUnsupportedAuthorizationScheme = errors.New("unsupported authorization scheme")      // Authorize()
	ErrorInvalidClientID                = errors.New("invalid client ID (audience of token)") // Authorize()
	ErrorInvalidUserID                  = errors.New("invalid user ID (subject of token)")    // not used

)

const (
	ErrorStringFailedToExchangeAuthorizationCode = "failed to exchange authorization code"
	ErrorStringUnableToSetCookie                 = "unable to set cookie"
	ErrorStringUnauthorized                      = "unauthorized"
	ErrorStringCannotIntrospectToken             = "cannot introspect token"
	ErrorStringCannotGetPermission               = "cannot get permission"
	ErrorStringInvalidState                      = "invalid state"
)

func WrapError(msg string, err error) error {
	return fmt.Errorf("%s: %w", msg, err)
}

func CompareErrorMessage(err error, msg string) bool {
	errMsg := strings.SplitN(err.Error(), ":", 2)[0]
	return errMsg == msg
}
