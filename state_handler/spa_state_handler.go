// Package osecure/state_handler provides state generator and verifier in OAuth flow.
package state_handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"net/http"

	"github.com/gorilla/sessions"
)

func NewOAuthSPAStateHandler(continueURI, cookieName string) SPAStateHandler {
	return SPAStateHandler{
		ContinueURI: continueURI,
		CookieName:  cookieName,
	}
}

func init() {
	gob.Register(&spaStateData{})
}

type SPAStateHandler struct {
	ContinueURI string
	CookieName  string
}

type spaStateData struct {
	ContinueURI string `json:"continue_uri"`
	Nonce       string `json:"nonce"`
}

func (sh SPAStateHandler) retrieveCookie(cookieStore *sessions.CookieStore, r *http.Request) *spaStateData {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return nil
	}

	v, found := session.Values["state"]
	if !found {
		return nil
	}

	stateData, ok := v.(*spaStateData)
	if !ok {
		return nil
	}

	return stateData
}

func (sh SPAStateHandler) setCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, stateData *spaStateData) error {
	session, err := cookieStore.New(r, sh.CookieName)
	if err != nil {
		return err
	}
	session.Values["state"] = stateData
	err = session.Save(r, w)
	return err
}

func (sh SPAStateHandler) deleteCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) error {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return err
	}
	delete(session.Values, "state")
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	return err
}

func (sh SPAStateHandler) Generate(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	// use specified uri as continue_uri, or backup current uri to continue_uri
	continueURI := sh.ContinueURI
	if continueURI == "" {
		continueURI = r.RequestURI
	}

	// retrieve redirect url from query
	q := r.URL.Query()
	redirectUrl := q.Get(redirectParam)
	var err error
	if redirectUrl != "" {
		continueURI = redirectUrl
	}

	// generate nonce
	nonce := make([]byte, nonceSize)
	n, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	if n != nonceSize {
		err = ErrorCannotGenerateCompleteState
		return "", err
	}

	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	// insert continue_uri and nonce to state
	stateData := &spaStateData{
		ContinueURI: continueURI,
		Nonce:       nonceB64,
	}

	// insert state data to cookie
	err = sh.setCookie(cookieStore, w, r, stateData)
	if err != nil {
		return "", err
	}

	return stateData.Nonce, nil
}

func (sh SPAStateHandler) Verify(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (string, error) {
	// retrieve state data from cookie
	stateData := sh.retrieveCookie(cookieStore, r)
	if stateData == nil {
		return "", ErrorCannotRetrieveCookie
	}

	// check if state is equal to stateData.Nonce
	if state != stateData.Nonce {
		return "", ErrorInvalidState
	}

	// delete cookie
	err := sh.deleteCookie(cookieStore, w, r)
	if err != nil {
		return "", err
	}

	return stateData.ContinueURI, nil
}
