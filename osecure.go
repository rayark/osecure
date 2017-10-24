// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"sort"
	"time"

	"strings"
)

var (
	ErrorInvalidSession                   = errors.New("invalid session")
	ErrorInvalidAuthorizationHeaderFormat = errors.New("invalid authorization header format")
	ErrorUnsupportedAuthorizationType     = errors.New("unsupported authorization type")
	ErrorCannotFoundCurrentSubject        = errors.New("cannot found current subject (a.k.a. user ID)")
)

var (
	SessionExpireTime    = 86400
	PermissionExpireTime = 600
)

func init() {
	gob.Register(&time.Time{})
	gob.Register(&authSessionData{})
}

type authSessionData struct {
	Subject             string
	Audience            string
	Token               *oauth2.Token
	Permissions         []string
	PermissionsExpireAt time.Time
}

// CookieConfig is a config of github.com/gorilla/securecookie. Recommended
// configurations are base64 of 64 bytes key for SigningKey, and base64 of 32
// bytes key for EncryptionKey.
type CookieConfig struct {
	SigningKey    string `yaml:"signing_key" env:"skey"`
	EncryptionKey string `yaml:"encryption_key" env:"ekey"`
}

// OAuthConfig is a config of osecure.
type OAuthConfig struct {
	ClientID                 string   `yaml:"client_id" env:"client_id"`
	ClientSecret             string   `yaml:"client_secret" env:"client_secret"`
	Scopes                   []string `yaml:"scopes" env:"scopes"`
	AuthURL                  string   `yaml:"auth_url" env:"auth_url"`
	TokenURL                 string   `yaml:"token_url" env:"token_url"`
	ServerTokenURL           string   `yaml:"server_token_url" env:"server_token_url"`
	ServerTokenEncryptionKey string   `yaml:"server_token_encryption_key" env:"server_token_encryption_key"`
}

func newAuthSessionData(subject string, audience string, token *oauth2.Token) *authSessionData {
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().Add(time.Duration(SessionExpireTime) * time.Second)
	}
	return &authSessionData{
		Subject:             subject,
		Audience:            audience,
		Token:               token,
		Permissions:         []string{},
		PermissionsExpireAt: time.Time{}, // Zero time
	}
}

func (data *authSessionData) isTokenExpired() bool {
	return data.Token.Expiry.Before(time.Now())
}

func (data *authSessionData) isPermissionsExpired() bool {
	return data.PermissionsExpireAt.Before(time.Now())
}

type OAuthSession struct {
	name                     string
	cookieStore              *sessions.CookieStore
	client                   *oauth2.Config
	tokenVerifier            *TokenVerifier
	serverTokenURL           string
	serverTokenEncryptionKey []byte
}

// NewOAuthSession creates osecure session.
func NewOAuthSession(name string, cookieConf *CookieConfig, oauthConf *OAuthConfig, tokenVerifier *TokenVerifier, callbackURL string) *OAuthSession {
	client := &oauth2.Config{
		ClientID:     oauthConf.ClientID,
		ClientSecret: oauthConf.ClientSecret,
		Scopes:       oauthConf.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauthConf.AuthURL,
			TokenURL: oauthConf.TokenURL,
		},
		RedirectURL: callbackURL,
	}

	serverTokenEncryptionKey, err := hex.DecodeString(oauthConf.ServerTokenEncryptionKey)
	if err != nil {
		panic(err)
	}

	return &OAuthSession{
		name:                     name,
		cookieStore:              newCookieStore(cookieConf),
		client:                   client,
		tokenVerifier:            tokenVerifier,
		serverTokenURL:           oauthConf.ServerTokenURL,
		serverTokenEncryptionKey: serverTokenEncryptionKey,
	}
}

// Secured is a http middleware to check if the current user has logged in.
func (s *OAuthSession) Secured(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorized(w, r) {
			s.startOAuth(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// ExpireSession is a http function to log out the user.
func (s *OAuthSession) ExpireSession(redirect string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.expireAuthCookie(w, r)
		http.Redirect(w, r, redirect, 303)
	}
}

func (s *OAuthSession) isAuthorized(w http.ResponseWriter, r *http.Request) bool {
	data, err := s.getAuthSessionDataFromRequest(r)
	if err != nil {
		return false
	}
	if data == nil || data.isTokenExpired() {
		return false
	}

	err = s.issueAuthCookie(w, r, data)
	if err != nil {
		return false
	}

	return true
}

func (s *OAuthSession) ensurePermUpdated(w http.ResponseWriter, r *http.Request, data *authSessionData) error {
	if !data.isPermissionsExpired() {
		return nil
	}

	permissions, err := s.tokenVerifier.GetPermissionsFunc(data.Subject, data.Audience, data.Token)
	if err != nil {
		return err
	}

	data.Permissions = permissions
	data.PermissionsExpireAt = time.Now().Add(time.Duration(PermissionExpireTime) * time.Second)

	// Sort the string, as sort.SearchStrings needs sorted []string.
	sort.Strings(data.Permissions)

	err = s.issueAuthCookie(w, r, data)
	if err != nil {
		return err
	}

	return nil
}

// GetPermissions lists the permissions of the current user and client.
func (s *OAuthSession) GetPermissions(w http.ResponseWriter, r *http.Request) ([]string, error) {
	data, err := s.getAuthSessionDataFromRequest(r)
	if err != nil {
		return nil, err
	}
	if data == nil || data.isTokenExpired() {
		return nil, ErrorInvalidSession
	}

	err = s.ensurePermUpdated(w, r, data)
	if err != nil {
		return nil, err
	}

	return data.Permissions, nil
}

// HasPermission checks if the current user has such permission.
func (s *OAuthSession) HasPermission(w http.ResponseWriter, r *http.Request, permission string) bool {
	perms, err := s.GetPermissions(w, r)
	if err != nil {
		return false
	}

	id := sort.SearchStrings(perms, permission)
	result := id < len(perms) && perms[id] == permission

	return result
}

func (s *OAuthSession) getAuthSessionDataFromRequest(r *http.Request) (*authSessionData, error) {
	data := s.getAuthSessionDataFromCookie(r)
	if data == nil || data.isTokenExpired() {
		subject, audience, token, err := s.getAndIntrospectBearerToken(r)
		if err != nil {
			return nil, err
		}

		data = newAuthSessionData(subject, audience, token)
	}
	return data, nil
}

func (s *OAuthSession) getAndIntrospectBearerToken(r *http.Request) (subject string, audience string, token *oauth2.Token, err error) {
	bearerToken, err := s.getBearerToken(r)
	if err != nil {
		return
	}

	subject, audience, token, err = s.tokenVerifier.IntrospectTokenFunc(bearerToken)
	return
}

func (s *OAuthSession) startOAuth(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.client.AuthCodeURL(r.RequestURI), 303)
}

// CallbackView is a http handler for the authentication redirection of the
// auth server.
func (s *OAuthSession) CallbackView(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	cont := q.Get("state")

	token, err := s.client.Exchange(oauth2.NoContext, code)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// TODO: how to get subject (account ID) when using exchange code only?
	subject, audience, _, err := s.tokenVerifier.IntrospectTokenFunc(token.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = s.issueAuthCookie(w, r, newAuthSessionData(subject, audience, token))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	http.Redirect(w, r, cont, 303)
}

func (s *OAuthSession) getBearerToken(r *http.Request) (string, error) {
	authorizationHeaderValue := r.Header.Get("Authorization")

	authorizationData := strings.SplitN(authorizationHeaderValue, " ", 2)
	if len(authorizationData) != 2 {
		return "", ErrorInvalidAuthorizationHeaderFormat
	}

	tokenType := authorizationData[0]
	if tokenType != "Bearer" {
		return "", ErrorUnsupportedAuthorizationType
	}

	bearerToken := authorizationData[1]
	return bearerToken, nil
}

func (s *OAuthSession) getAuthSessionDataFromCookie(r *http.Request) *authSessionData {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		return nil
	}

	v, found := session.Values["data"]
	if !found {
		return nil
	}

	data, ok := v.(*authSessionData)
	if !ok {
		return nil
	}

	return data
}

func (s *OAuthSession) issueAuthCookie(w http.ResponseWriter, r *http.Request, data *authSessionData) error {
	session, err := s.cookieStore.New(r, s.name)
	if err != nil {
		return err
	}
	session.Values["data"] = data
	err = session.Save(r, w)
	return err
}

func (s *OAuthSession) expireAuthCookie(w http.ResponseWriter, r *http.Request) {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		panic(err)
	}
	delete(session.Values, "data")
	session.Options.MaxAge = -1
	session.Save(r, w)
}

func newCookieStore(conf *CookieConfig) *sessions.CookieStore {

	var signingKey, encryptionKey []byte
	var err error

	if conf != nil {
		signingKey, err = base64.StdEncoding.DecodeString(conf.SigningKey)
		if err != nil {
			panic(err)
		}

		encryptionKey, err = base64.StdEncoding.DecodeString(conf.EncryptionKey)
		if err != nil {
			panic(err)
		}
	} else {
		signingKey = securecookie.GenerateRandomKey(64)
		encryptionKey = securecookie.GenerateRandomKey(32)
	}

	return sessions.NewCookieStore(signingKey, encryptionKey)
}
