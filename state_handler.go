// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"net/http"
)

type StateHandler struct {
	StateGenerator StateGenerator
	StateVerifier  StateVerifier
}

type StateGenerator func(r *http.Request) (state string)
type StateVerifier func(r *http.Request, state string) (ok bool, continueURI string)

func DefaultStateGenerator(r *http.Request) string {
	return r.RequestURI
}

func DefaultStateVerifier(r *http.Request, state string) (bool, string) {
	return true, state
}
