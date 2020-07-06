// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"net/http"

	"github.com/gorilla/sessions"
)

type StateHandler interface {
	Generate(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (state string, err error)
	Verify(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (continueURI string, err error)
}
