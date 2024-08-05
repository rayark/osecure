// Package osecure/state_handler provides state generator and verifier in OAuth flow.
package state_handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	nonceSize     = int(16)
	continueParam = "continue_url"
)

var (
	ErrorCannotGenerateCompleteState = errors.New("cannot generate complete state")
	ErrorCannotRetrieveCookie        = errors.New("cannot retrieve cookie")
	ErrorInvalidState                = errors.New("invalid state")
)

func init() {
	gob.Register(&defaultStateData{})
}

type DefaultStateHandler struct {
	ContinueURI string
	CookieName  string
}

type defaultStateData struct {
	ContinueURI string `json:"continue_uri"`
	Nonce       string `json:"nonce"`
}

func (sh DefaultStateHandler) retrieveCookie(cookieStore *sessions.CookieStore, r *http.Request) *defaultStateData {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return nil
	}

	v, found := session.Values["state"]
	if !found {
		return nil
	}

	stateData, ok := v.(*defaultStateData)
	if !ok {
		return nil
	}

	return stateData
}

func (sh DefaultStateHandler) setCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, stateData *defaultStateData) error {
	session, err := cookieStore.New(r, sh.CookieName)
	if err != nil {
		return err
	}
	session.Values["state"] = stateData
	err = session.Save(r, w)
	return err
}

func (sh DefaultStateHandler) deleteCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) error {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return err
	}
	delete(session.Values, "state")
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	return err
}

func (sh DefaultStateHandler) Generate(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	// use specified uri as continue_uri, or backup current uri to continue_uri
	continueURI := sh.ContinueURI
	if continueURI == "" {
		continueURI = r.RequestURI
	}

	// retrieve redirect url from query in order to let frontend decide where to redirect
	q := r.URL.Query()
	continueArg := q.Get(continueParam)
	var err error
	if continueArg != "" {
		continueURI = continueArg
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
	stateData := &defaultStateData{
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

func (sh DefaultStateHandler) Verify(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (string, error) {
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

type JSONStateHandler struct {
	ContinueURI string
	CookieName  string
}

type jsonStateData struct {
	ContinueURI string `json:"continue_uri"`
	Nonce       []byte `json:"nonce"`
}

func (sh JSONStateHandler) retrieveCookie(cookieStore *sessions.CookieStore, r *http.Request) []byte {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return nil
	}

	v, found := session.Values["hash"]
	if !found {
		return nil
	}

	sum, ok := v.([]byte)
	if !ok {
		return nil
	}

	return sum
}

func (sh JSONStateHandler) setCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, sum []byte) error {
	session, err := cookieStore.New(r, sh.CookieName)
	if err != nil {
		return err
	}
	session.Values["hash"] = sum
	err = session.Save(r, w)
	return err
}

func (sh JSONStateHandler) deleteCookie(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) error {
	session, err := cookieStore.Get(r, sh.CookieName)
	if err != nil {
		return err
	}
	delete(session.Values, "hash")
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	return err
}

func (sh JSONStateHandler) Generate(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	// use specified uri as continue_uri, or backup current uri to continue_uri
	continueURI := sh.ContinueURI
	if continueURI == "" {
		continueURI = r.RequestURI
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

	// insert continue_uri and nonce to state
	stateData := jsonStateData{
		ContinueURI: continueURI,
		Nonce:       nonce,
	}

	/*var stateBytes []byte
	stateBytes, err = json.Marshal(stateData)
	if err != nil {
		return "", err
	}*/

	var stateBuf bytes.Buffer
	enc := json.NewEncoder(&stateBuf)
	err = enc.Encode(stateData)
	if err != nil {
		return "", err
	}
	stateBytes := stateBuf.Bytes()

	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// calculate checksum
	h := sha256.New()
	h.Write(stateBytes)
	sum := h.Sum(nil)

	// insert checksum to cookie
	err = sh.setCookie(cookieStore, w, r, sum)
	if err != nil {
		return "", err
	}

	return state, nil
}

func (sh JSONStateHandler) Verify(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (string, error) {
	// retrieve expected checksum from cookie
	expectedSum := sh.retrieveCookie(cookieStore, r)
	if len(expectedSum) <= 0 {
		return "", ErrorCannotRetrieveCookie
	}

	// retrieve state
	stateBytes, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}

	// calculate checksum
	h := sha256.New()
	h.Write(stateBytes)
	sum := h.Sum(nil)

	// check if state checksum is expected
	if bytes.Compare(sum, expectedSum) != 0 {
		return "", ErrorInvalidState
	}

	// retrieve continue_uri and nonce from state
	var stateData jsonStateData

	/*err = json.Unmarshal(stateBytes, &stateData)
	if err != nil {
		return "", err
	}*/

	stateBuf := bytes.NewBuffer(stateBytes)
	dec := json.NewDecoder(stateBuf)
	err = dec.Decode(&stateData)
	if err != nil {
		return "", err
	}

	// delete checksum cookie
	err = sh.deleteCookie(cookieStore, w, r)
	if err != nil {
		return "", err
	}

	return stateData.ContinueURI, nil
}

type SimpleStateHandler struct {
	ContinueURI string
}

func (sh SimpleStateHandler) Generate(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) (string, error) {
	// use specified uri as continue_uri, or backup current uri to continue_uri
	continueURI := sh.ContinueURI
	if continueURI == "" {
		continueURI = r.RequestURI
	}

	return continueURI, nil
}

func (_ SimpleStateHandler) Verify(cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request, state string) (string, error) {
	return state, nil
}
