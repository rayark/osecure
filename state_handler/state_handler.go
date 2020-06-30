// Package osecure/state_handler provides state generator and verifier in OAuth flow.
package state_handler

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	nonceSize = int(16)
)

var (
	ErrorCannotGenerateCompleteState = errors.New("cannot generate complete state")
	ErrorCannotRetrieveNonce         = errors.New("cannot retrieve nonce")
	ErrorInvalidNonce                = errors.New("invalid nonce")
)

type DefaultStateHandler struct {
	CookieName string
}

type defaultStateData struct {
	Nonce       []byte `json:"nonce"`
	ContinueURI string `json:"continue_uri"`
}

func (sh DefaultStateHandler) retrieveNonceCookie(cookieStore *sessions.CookieStore, r *http.Request) []byte {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return nil
	}

	v, found := session.Values["nonce"]
	if !found {
		return nil
	}

	nonce, ok := v.([]byte)
	if !ok {
		return nil
	}

	return nonce
}

func (sh DefaultStateHandler) setNonceCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, nonce []byte) error {
	session, err := cookieStore.New(r, sh.CookieName)
	if err != nil {
		return err
	}
	session.Values["nonce"] = nonce
	err = session.Save(r, w)
	return err
}

func (sh DefaultStateHandler) deleteNonceCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) error {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return err
	}
	delete(session.Values, "nonce")
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	return err
}

func (sh DefaultStateHandler) Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	// backup current uri to continue_uri
	continueURI := r.RequestURI

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

	// insert nonce and continue_uri to state
	stateData := defaultStateData{
		Nonce:       nonce,
		ContinueURI: continueURI,
	}

	var stateBuf bytes.Buffer
	enc := json.NewEncoder(&stateBuf)
	err = enc.Encode(stateData)
	if err != nil {
		return "", err
	}

	state := base64.RawURLEncoding.EncodeToString(stateBuf.Bytes())

	// insert nonce to cookie
	err = sh.setNonceCookie(cookieStore, w, r, nonce)
	if err != nil {
		return "", err
	}

	return state, nil
}

func (sh DefaultStateHandler) Verifier(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (string, error) {
	// retrieve nonce from cookie
	nonce := sh.retrieveNonceCookie(cookieStore, r)
	if len(nonce) <= 0 {
		return "", ErrorCannotRetrieveNonce
	}

	// retrieve nonce and continue_uri from state
	stateBytes, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}

	var stateData defaultStateData

	stateBuf := bytes.NewBuffer(stateBytes)
	dec := json.NewDecoder(stateBuf)
	err = dec.Decode(&stateData)
	if err != nil {
		return "", err
	}

	// compare nonce from state and nonce from cookie
	if bytes.Compare(stateData.Nonce, nonce) != 0 {
		return "", ErrorInvalidNonce
	}

	// delete nonce cookie
	err = sh.deleteNonceCookie(cookieStore, w, r)
	if err != nil {
		return "", err
	}

	return stateData.ContinueURI, nil
}

type SimpleStateHandler struct{}

func (_ SimpleStateHandler) Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) string {
	return r.RequestURI
}

func (_ SimpleStateHandler) Verifier(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (bool, string) {
	return true, state
}
