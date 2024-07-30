package state_handler

import "errors"

var (
	ErrorCannotGenerateCompleteState = errors.New("cannot generate complete state")
	ErrorCannotRetrieveCookie        = errors.New("cannot retrieve cookie")
	ErrorInvalidState                = errors.New("invalid state")
)
