// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"sort"
	"time"
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
	Token        oauth2.Token
	ExpireAt     time.Time
	Permissions  []string
	PermExpireAt time.Time
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
	ClientID                 string `yaml:"client_id" env:"client_id"`
	Secret                   string `yaml:"secret" env:"secret"`
	AuthURL                  string `yaml:"auth_url" env:"auth_url"`
	TokenURL                 string `yaml:"token_url" env:"token_url"`
	PermissionsURL           string `yaml:"permissions_url" env:"permissions_url"`
	ServerTokenURL           string `yaml:"server_token_url" env:"server_token_url"`
	ServerTokenEncryptionKey string `yaml:"server_token_encryption_key" env:"server_token_encryption_key"`
}

func newAuthSessionData(token oauth2.Token) *authSessionData {
	return &authSessionData{
		Token:        token,
		ExpireAt:     time.Now().Add(time.Duration(SessionExpireTime) * time.Second),
		Permissions:  []string{},
		PermExpireAt: time.Time{}, // Zero time
	}
}

func (data *authSessionData) isExpired() bool {
	return data.ExpireAt.Before(time.Now())
}

func (data *authSessionData) isPermExpired() bool {
	return data.PermExpireAt.Before(time.Now())
}

type OAuthSession struct {
	name                     string
	cookieStore              *sessions.CookieStore
	client                   *oauth2.Config
	permissionsURL           string
	serverTokenURL           string
	serverTokenEncryptionKey []byte
}

// NewOAuthSession creates osecure session.
func NewOAuthSession(name string, oauthConf *OAuthConfig, cookieConf *CookieConfig, callbackURL string) *OAuthSession {

	client := &oauth2.Config{
		ClientID:     oauthConf.ClientID,
		ClientSecret: oauthConf.Secret,
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
		permissionsURL:           oauthConf.PermissionsURL,
		serverTokenURL:           oauthConf.ServerTokenURL,
		serverTokenEncryptionKey: serverTokenEncryptionKey,
	}
}

// Secured is a http middleware to check if the current user has logged in.
func (s *OAuthSession) Secured(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if !s.IsAuthorized(r) {
			s.StartOAuth(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// ExpireSession is a http function to log out the user.
func (s *OAuthSession) ExpireSession(redirect string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		s.expireAuthCookie(w, r)
		http.Redirect(w, r, redirect, 303)
	}
	return http.HandlerFunc(fn)
}

func (s *OAuthSession) IsAuthorized(r *http.Request) bool {
	data := s.getAuthSessionDataFromRequest(r)
	if data == nil || data.isExpired() {
		return false
	}

	return true
}

func (s *OAuthSession) ensurePermUpdated(w http.ResponseWriter, r *http.Request, data *authSessionData) {
	if !data.isPermExpired() {
		return
	}

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(&data.Token))

	resp, err := client.Get(s.permissionsURL)
	if err != nil {
		panic(err)
	}

	var result struct {
		Permissions []string `json:"permissions"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		panic(err)
	}

	data.Permissions = result.Permissions
	data.PermExpireAt = time.Now().Add(time.Duration(PermissionExpireTime) * time.Second)

	// Sort the string, as sort.SearchStrings needs sorted []string.
	sort.Strings(data.Permissions)

	s.issueAuthCookie(w, r, data)
	return
}

// GetPermissions lists the permissions of the current user and client.
func (s *OAuthSession) GetPermissions(w http.ResponseWriter, r *http.Request) ([]string, error) {
	data := s.getAuthSessionDataFromRequest(r)
	if data == nil || data.isExpired() {
		return nil, errors.New("invalid session")
	}

	s.ensurePermUpdated(w, r, data)

	return data.Permissions, nil
}

// HasPermission checks if the current user has such permission.
func (s *OAuthSession) HasPermission(w http.ResponseWriter, r *http.Request, permission string) bool {
	data := s.getAuthSessionDataFromRequest(r)
	if data == nil || data.isExpired() {
		return false
	}

	s.ensurePermUpdated(w, r, data)

	perms := data.Permissions

	id := sort.SearchStrings(perms, permission)
	result := id < len(perms) && perms[id] == permission

	return result
}

func (s *OAuthSession) getAuthSessionDataFromRequest(r *http.Request) *authSessionData {
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

func (s *OAuthSession) StartOAuth(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.client.AuthCodeURL(r.RequestURI), 303)
}

// CallbackView is a http handler for the authentication redirection of the
// auth server.
func (s *OAuthSession) CallbackView(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	cont := q.Get("state")

	jr, err := s.client.Exchange(oauth2.NoContext, code)

	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.issueAuthCookie(w, r, newAuthSessionData(*jr))
	http.Redirect(w, r, cont, 303)
}

func (s *OAuthSession) issueAuthCookie(w http.ResponseWriter, r *http.Request, data *authSessionData) {
	session, err := s.cookieStore.New(r, s.name)
	if err != nil {
		//don't care
	}
	session.Values["data"] = data
	session.Save(r, w)
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
