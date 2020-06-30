// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"net/http"

	"github.com/gorilla/sessions"
)

type StateHandler interface {
	Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (state string, err error)
	Verifier(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (continueURI string, err error)
}
