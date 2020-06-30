// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
)

type StateHandler interface {
	Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (state string, err error)
	Verifier(cookieStore *sessions.CookieStore, r *http.Request, state string) (ok bool, continueURI string)
}

const (
	nonceSize = int(16)
)

var (
	ErrorCannotGenerateCompleteState = errors.New("cannot generate complete state")
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

func (sh DefaultStateHandler) Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	continueURI := r.RequestURI

	nonce := make([]byte, nonceSize)
	n, err := rand.Read(nonce)
	if n != nonceSize {
		err = ErrorCannotGenerateCompleteState
		return "", err
	}
	if err != nil {
		return "", err
	}

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

	err = sh.setNonceCookie(cookieStore, w, r, nonce)
	if err != nil {
		return "", err
	}

	return state, nil
}

func (sh DefaultStateHandler) Verifier(cookieStore *sessions.CookieStore, r *http.Request, state string) (bool, string) {
	nonce := sh.retrieveNonceCookie(cookieStore, r)
	if len(nonce) <= 0 {
		return false, ""
	}

	stateBytes, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return false, ""
	}

	var stateData defaultStateData

	stateBuf := bytes.NewBuffer(stateBytes)
	dec := json.NewDecoder(stateBuf)
	err = dec.Decode(&stateData)
	if err != nil {
		return false, ""
	}

	if bytes.Compare(stateData.Nonce, nonce) != 0 {
		return false, ""
	}

	return true, stateData.ContinueURI
}

type SimpleStateHandler struct{}

func (_ SimpleStateHandler) Generator(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) string {
	return r.RequestURI
}

func (_ SimpleStateHandler) Verifier(cookieStore *sessions.CookieStore, r *http.Request, state string) (bool, string) {
	return true, state
}
