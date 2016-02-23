package osecure

import (
	"encoding/base64"
	"encoding/gob"
	"github.com/gorilla/sessions"
	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

func init() {
	gob.Register(&time.Time{})
	gob.Register(&AuthSessionData{})
}

type AuthSessionData struct {
	AccessToken oauth2.Token
	IssuedAt    time.Time
}

type CookieConfig struct {
	SigningKey    string `yaml:"signing_key" env:"skey"`
	EncryptionKey string `yaml:"encryption_key" env:"ekey"`
}

type OAuthConfig struct {
	ClientID string `yaml:"client_id" env:"client_id"`
	Secret   string `yaml:"secret" env:"secret"`
	AuthURL  string `yaml:"auth_url" env:"auth_url"`
	TokenURL string `yaml:"token_url" env:"token_url"`
}

func NewAuthSessionData(token oauth2.Token) *AuthSessionData {
	return &AuthSessionData{
		AccessToken: token,
		IssuedAt:    time.Now()}
}

func (data *AuthSessionData) IsExpired() bool {
	expiresAt := data.IssuedAt.Add(time.Duration(86400 * time.Second))
	return expiresAt.Before(time.Now())
}

type OAuthSession struct {
	name        string
	cookieStore *sessions.CookieStore
	client      *oauth2.Config
}

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
	return &OAuthSession{
		name:        name,
		cookieStore: newCookieStore(cookieConf),
		client:      client,
	}
}

func (s *OAuthSession) Secured(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorized(r) {
			s.startOAuth(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (s *OAuthSession) isAuthorized(r *http.Request) bool {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		panic(err)
	}

	v, found := session.Values["data"]
	if !found {
		return false
	}

	data, ok := v.(*AuthSessionData)
	if !ok {
		return false
	}

	if data.IsExpired() {
		return false
	}

	return true
}

func (s *OAuthSession) startOAuth(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.client.AuthCodeURL(r.RequestURI), 303)
}

func (s *OAuthSession) CallbackView(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	cont := q.Get("state")

	jr, err := s.client.Exchange(oauth2.NoContext, code)

	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.issueAuthCookie(w, r, *jr)
	http.Redirect(w, r, cont, 303)
}

func (s *OAuthSession) issueAuthCookie(w http.ResponseWriter, r *http.Request, token oauth2.Token) {
	session, err := s.cookieStore.Get(r, "redeem")
	if err != nil {
		panic(err)
	}
	session.Values["data"] = NewAuthSessionData(token)
	session.Save(r, w)
}

func newCookieStore(conf *CookieConfig) *sessions.CookieStore {

	var signingKey, encryptionKey []byte
	var err error

	signingKey, err = base64.StdEncoding.DecodeString(conf.SigningKey)
	if err != nil {
		panic(err)
	}

	encryptionKey, err = base64.StdEncoding.DecodeString(conf.EncryptionKey)
	if err != nil {
		panic(err)
	}

	return sessions.NewCookieStore(signingKey, encryptionKey)
}
