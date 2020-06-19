// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var (
	ErrorInvalidSession                   = errors.New("invalid session")
	ErrorInvalidAuthorizationHeaderFormat = errors.New("invalid authorization header format")
	ErrorUnsupportedAuthorizationType     = errors.New("unsupported authorization type")
	ErrorInvalidClientID                  = errors.New("invalid client ID (audience of token)")
	ErrorInvalidUserID                    = errors.New("invalid user ID (subject of token)")
	ErrorInvalidState                     = errors.New("invalid state")
)

const (
	ErrorStringFailedToExchangeAuthorizationCode = "failed to exchange authorization code"
	ErrorStringUnableToSetCookie                 = "unable to set cookie"
)

func WrapError(msg string, err error) error {
	return fmt.Errorf("%s: %w", msg, err)
}

func CompareErrorMessage(err error, msg string) bool {
	return strings.HasPrefix(err.Error(), msg+":")
}

var (
	SessionExpireTime    = 86400
	PermissionExpireTime = 600
)

type contextKey int

const (
	contextKeySessionData = contextKey(1)
)

type set map[string]struct{}

func (s set) add(x string) {
	s[x] = struct{}{}
}

func (s set) contain(x string) bool {
	_, ok := s[x]
	return ok
}

func init() {
	//gob.Register(&time.Time{})
	gob.Register(&AuthSessionCookieData{})
}

type AuthSessionData struct {
	UserID   string //
	ClientID string //
	*AuthSessionCookieData
}

type AuthSessionCookieData struct {
	//UserID              string
	//ClientID            string
	Token               *oauth2.Token
	Permissions         []string
	PermissionsExpireAt time.Time
}

//func newAuthSessionCookieData(userID string, clientID string, token *oauth2.Token) *AuthSessionCookieData {
func newAuthSessionCookieData(token *oauth2.Token) *AuthSessionCookieData {
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().Add(time.Duration(SessionExpireTime) * time.Second)
	}
	return &AuthSessionCookieData{
		//UserID:              userID,
		//ClientID:            clientID,
		Token:               token,
		Permissions:         []string{},
		PermissionsExpireAt: time.Time{}, // Zero time
	}
}

func (cookieData *AuthSessionCookieData) isTokenExpired() bool {
	return cookieData.Token.Expiry.Before(time.Now())
}

func (cookieData *AuthSessionCookieData) isPermissionsExpired() bool {
	return cookieData.PermissionsExpireAt.Before(time.Now())
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
	ClientID     string   `yaml:"client_id" env:"client_id"`
	ClientSecret string   `yaml:"client_secret" env:"client_secret"`
	Scopes       []string `yaml:"scopes" env:"scopes"`
	AuthURL      string   `yaml:"auth_url" env:"auth_url"`
	TokenURL     string   `yaml:"token_url" env:"token_url"`
	AppIDList    []string `yaml:"app_id_list" env:"app_id_list"`
}

type OAuthSession struct {
	name          string
	cookieStore   *sessions.CookieStore
	client        *oauth2.Config
	appIDSet      set
	tokenVerifier *TokenVerifier
	stateHandler  *StateHandler
}

// NewOAuthSession creates osecure session.
func NewOAuthSession(name string, cookieConf *CookieConfig, oauthConf *OAuthConfig, tokenVerifier *TokenVerifier, callbackURL string, stateHandler *StateHandler) *OAuthSession {
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

	appIDSet := make(set)
	for _, appID := range oauthConf.AppIDList {
		appIDSet.add(appID)
	}

	return &OAuthSession{
		name:          name,
		cookieStore:   newCookieStore(cookieConf),
		client:        client,
		appIDSet:      appIDSet,
		tokenVerifier: tokenVerifier,
		stateHandler:  stateHandler,
	}
}

// SecuredH is a http middleware for http.Handler to check if the current user has logged in.
func (s *OAuthSession) SecuredH(h http.Handler) http.Handler {
	return s.SecuredF(h.ServeHTTP)
}

// SecuredF is a http middleware for http.HandlerFunc to check if the current user has logged in.
func (s *OAuthSession) SecuredF(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionData, err := s.Authorize(w, r)
		if err != nil {
			s.StartOAuth(w, r)
		} else {
			requestInner := AttachRequestWithSessionData(r, sessionData)
			h(w, requestInner)
		}
	}
}

// ExpireSession is a http function to log out the user.
func (s *OAuthSession) ExpireSession(redirect string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.expireAuthCookie(w, r)
		http.Redirect(w, r, redirect, 303)
	}
}

// AttachRequestWithSessionData append session data into request context
func AttachRequestWithSessionData(r *http.Request, sessionData *AuthSessionData) *http.Request {
	contextWithSessionData := context.WithValue(r.Context(), contextKeySessionData, sessionData)
	return r.WithContext(contextWithSessionData)
}

// GetRequestSessionData get session data from request context
func GetRequestSessionData(r *http.Request) (*AuthSessionData, bool) {
	sessionData, ok := r.Context().Value(contextKeySessionData).(*AuthSessionData)
	return sessionData, ok
}

// HasPermission checks if the current user has such permission.
func (data *AuthSessionData) HasPermission(permission string) bool {
	perms := data.GetPermissions()

	id := sort.SearchStrings(perms, permission)
	result := id < len(perms) && perms[id] == permission

	return result
}

// GetPermissions lists the permissions of the current user and client.
func (data *AuthSessionData) GetPermissions() []string {
	return data.Permissions
}

// GetUserID get user ID of the current user session.
func (data *AuthSessionData) GetUserID() string {
	return data.UserID
}

// GetClientID get client ID of the current user session.
func (data *AuthSessionData) GetClientID() string {
	return data.ClientID
}

// Authorize authorize user by verifying cookie or bearer token.
// if user is authorized, return session data. else, return error.
func (s *OAuthSession) Authorize(w http.ResponseWriter, r *http.Request) (*AuthSessionData, error) {
	data, isTokenFromAuthorizationHeader, err := s.getAuthSessionDataFromRequest(r)
	if err != nil {
		return nil, err
	}
	if data == nil || data.isTokenExpired() {
		return nil, ErrorInvalidSession
	}

	isPermissionUpdated, err := s.ensurePermUpdated(data)
	if err != nil {
		return nil, err
	}

	if isTokenFromAuthorizationHeader || isPermissionUpdated {
		err = s.issueAuthCookie(w, r, data.AuthSessionCookieData)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

func (s *OAuthSession) ensurePermUpdated(data *AuthSessionData) (bool, error) {
	if !data.isPermissionsExpired() {
		return false, nil
	}

	permissions, err := s.tokenVerifier.GetPermissionsFunc(data.UserID, data.ClientID, data.Token)
	if err != nil {
		return false, err
	}

	data.Permissions = permissions
	data.PermissionsExpireAt = time.Now().Add(time.Duration(PermissionExpireTime) * time.Second)

	// Sort the string, as sort.SearchStrings needs sorted []string.
	sort.Strings(data.Permissions)

	return true, nil
}

func (s *OAuthSession) getAuthSessionDataFromRequest(r *http.Request) (*AuthSessionData, bool, error) {
	var accessToken string
	var isTokenFromAuthorizationHeader bool

	cookieData := s.retrieveAuthCookie(r)
	if cookieData == nil || cookieData.isTokenExpired() {
		var err error
		accessToken, err = s.getBearerToken(r)
		if err != nil {
			return nil, false, err
		}

		isTokenFromAuthorizationHeader = true
	} else {
		accessToken = cookieData.Token.AccessToken
		isTokenFromAuthorizationHeader = false
	}

	userID, clientID, expireAt, extra, err := s.tokenVerifier.IntrospectTokenFunc(accessToken)
	if err != nil {
		return nil, false, err
	}

	// restore token extra data whenever token is new or retrieved from cookie
	var token *oauth2.Token
	if isTokenFromAuthorizationHeader {
		token = makeBearerToken(accessToken, expireAt)
	} else {
		token = cookieData.Token
	}
	token = token.WithExtra(extra)
	if isTokenFromAuthorizationHeader {
		cookieData = newAuthSessionCookieData(token)
	} else {
		cookieData.Token = token
	}

	data := &AuthSessionData{
		UserID:                userID,
		ClientID:              clientID,
		AuthSessionCookieData: cookieData,
	}

	if !s.isValidClientID(data.ClientID) {
		return nil, false, ErrorInvalidClientID
	}

	return data, isTokenFromAuthorizationHeader, nil
}

/*
func (s *OAuthSession) getAuthSessionDataFromRequest(r *http.Request) (*AuthSessionData, bool, error) {
	var isTokenFromAuthorizationHeader bool

	cookieData := s.retrieveAuthCookie(r)
	if cookieData == nil || cookieData.isTokenExpired() {
		userID, clientID, token, err := s.getAndIntrospectBearerToken(r)
		if err != nil {
			return nil, false, err
		}

		cookieData = newAuthSessionCookieData(userID, clientID, token)

		isTokenFromAuthorizationHeader = true
	} else {
		isTokenFromAuthorizationHeader = false
	}

	data := &AuthSessionData{
		AuthSessionCookieData: cookieData,
	}

	if !s.isValidClientID(data.ClientID) {
		return nil, false, ErrorInvalidClientID
	}

	return data, isTokenFromAuthorizationHeader, nil
}

func (s *OAuthSession) getAndIntrospectBearerToken(r *http.Request) (userID string, clientID string, token *oauth2.Token, err error) {
	var bearerToken string
	bearerToken, err = s.getBearerToken(r)
	if err != nil {
		return
	}

	var expireAt int64
	var extra map[string]interface{}
	userID, clientID, expireAt, extra, err = s.tokenVerifier.IntrospectTokenFunc(bearerToken)
	if err != nil {
		return
	}

	token = makeBearerToken(bearerToken, expireAt).WithExtra(extra)
	return
}
*/

func (s *OAuthSession) isValidClientID(clientID string) bool {
	return clientID == s.client.ClientID || s.appIDSet.contain(clientID)
}

// StartOAuth redirect to endpoint of OAuth service provider for OAuth flow.
func (s *OAuthSession) StartOAuth(w http.ResponseWriter, r *http.Request) {
	state := s.stateHandler.StateGenerator(w, r)
	http.Redirect(w, r, s.client.AuthCodeURL(state), 303)
}

func (s *OAuthSession) EndOAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	ok, continueURI := s.stateHandler.StateVerifier(r, state)
	if !ok {
		return "", ErrorInvalidState
	}

	token, err := s.client.Exchange(oauth2.NoContext, code)
	if err != nil {
		return "", WrapError(ErrorStringFailedToExchangeAuthorizationCode, err)
	}

	// OAuth flow is already completed, error after that should not relate to OAuth flow

	// TODO: how to get subject (account ID) when using exchange code only?
	/*userID, clientID, _, _, err := s.tokenVerifier.IntrospectTokenFunc(token.AccessToken)
	if err != nil {
		return "", err
	}*/

	//err = s.issueAuthCookie(w, r, newAuthSessionCookieData(userID, clientID, token))
	err = s.issueAuthCookie(w, r, newAuthSessionCookieData(token))
	if err != nil {
		return "", WrapError(ErrorStringUnableToSetCookie, err)
	}

	return continueURI, nil
}

// CallbackView is a http handler for the authentication redirection of the
// auth server.
func (s *OAuthSession) CallbackView(w http.ResponseWriter, r *http.Request) {
	continueURI, err := s.EndOAuth(w, r)
	if err != nil {
		var statusCode int
		switch {
		case err == ErrorInvalidState:
			fallthrough
		case CompareErrorMessage(err, ErrorStringFailedToExchangeAuthorizationCode):
			statusCode = 400
		default:
			statusCode = 500
		}
		http.Error(w, err.Error(), statusCode)
		return
	}

	http.Redirect(w, r, continueURI, 303)
}

func makeToken(tokenType string, accessToken string, expireAt int64) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   tokenType,
		Expiry:      time.Unix(expireAt, 0),
	}
}

func makeBearerToken(accessToken string, expireAt int64) *oauth2.Token {
	return makeToken("Bearer", accessToken, expireAt)
}

func (s *OAuthSession) getBearerToken(r *http.Request) (string, error) {
	authorizationHeaderValue := r.Header.Get("Authorization")

	authorizationData := strings.SplitN(authorizationHeaderValue, " ", 2)
	if len(authorizationData) != 2 {
		return "", ErrorInvalidAuthorizationHeaderFormat
	}

	tokenType := authorizationData[0]
	if !strings.EqualFold(tokenType, "bearer") {
		return "", ErrorUnsupportedAuthorizationType
	}

	bearerToken := authorizationData[1]
	return bearerToken, nil
}

func (s *OAuthSession) retrieveAuthCookie(r *http.Request) *AuthSessionCookieData {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		return nil
	}

	v, found := session.Values["data"]
	if !found {
		return nil
	}

	cookieData, ok := v.(*AuthSessionCookieData)
	if !ok {
		return nil
	}

	return cookieData
}

func (s *OAuthSession) issueAuthCookie(w http.ResponseWriter, r *http.Request, cookieData *AuthSessionCookieData) error {
	session, err := s.cookieStore.New(r, s.name)
	if err != nil {
		return err
	}
	session.Values["data"] = cookieData
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
