// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	SessionExpireTime    = 86400
	PermissionExpireTime = 600
)

type contextKey int

const (
	contextKeySessionData = contextKey(1)
)

func init() {
	gob.Register(&AuthSessionCookieData{})
}

type AuthSessionCookieData struct {
	Token                *oauth2.Token
	Permissions          StringSet
	PermissionsExpiresAt time.Time
}

func newAuthSessionCookieData(token *oauth2.Token) *AuthSessionCookieData {
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().Add(time.Duration(SessionExpireTime) * time.Second)
	}
	return &AuthSessionCookieData{
		Token:                token,
		Permissions:          NewStringSet(nil),
		PermissionsExpiresAt: time.Time{}, // Zero time
	}
}

func (cookieData *AuthSessionCookieData) isTokenExpired() bool {
	return !cookieData.Token.Expiry.After(time.Now())
}

func (cookieData *AuthSessionCookieData) isPermissionsExpired() bool {
	return !cookieData.PermissionsExpiresAt.After(time.Now())
}

// GetPermissions lists the permissions of the current user and client.
func (cookieData *AuthSessionCookieData) GetPermissions() []string {
	return cookieData.Permissions.List()
}

// HasPermission checks if the current user has such permission.
func (cookieData *AuthSessionCookieData) HasPermission(permission string) bool {
	return cookieData.Permissions.Contain(permission)
}

type AuthSessionData struct {
	UserID   string
	ClientID string
	*AuthSessionCookieData
}

// GetUserID get user ID of the current user session.
func (data *AuthSessionData) GetUserID() string {
	return data.UserID
}

// GetClientID get client ID of the current user session.
func (data *AuthSessionData) GetClientID() string {
	return data.ClientID
}

// GetRequestSessionData get session data from request context.
func GetRequestSessionData(r *http.Request) (*AuthSessionData, bool) {
	sessionData, ok := r.Context().Value(contextKeySessionData).(*AuthSessionData)
	return sessionData, ok
}

// AttachRequestWithSessionData append session data into request context.
func AttachRequestWithSessionData(r *http.Request, sessionData *AuthSessionData) *http.Request {
	contextWithSessionData := context.WithValue(r.Context(), contextKeySessionData, sessionData)
	return r.WithContext(contextWithSessionData)
}

// CookieConfig is a config of github.com/gorilla/securecookie.
// Recommended configurations are base64 of 64 bytes key for AuthenticationKey,
// and base64 of 32 bytes key for EncryptionKey.
type CookieConfig struct {
	AuthenticationKey string `yaml:"authentication_key" env:"akey"`
	EncryptionKey     string `yaml:"encryption_key" env:"ekey"`
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
	appIDSet      StringSet
	tokenVerifier *TokenVerifier
	stateHandler  StateHandler
}

// NewOAuthSession creates osecure session.
func NewOAuthSession(name string, cookieConf *CookieConfig, oauthConf *OAuthConfig, tokenVerifier *TokenVerifier, callbackURL string, stateHandler StateHandler) *OAuthSession {
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

	return &OAuthSession{
		name:          name,
		cookieStore:   newCookieStore(cookieConf),
		client:        client,
		appIDSet:      NewStringSet(oauthConf.AppIDList),
		tokenVerifier: tokenVerifier,
		stateHandler:  stateHandler,
	}
}

func (s *OAuthSession) isValidClientID(clientID string) bool {
	return clientID == s.client.ClientID || s.appIDSet.Contain(clientID)
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

	userID, clientID, expiresAt, extra, err := s.tokenVerifier.IntrospectTokenFunc(r.Context(), accessToken)
	if err != nil {
		return nil, false, WrapError(ErrorStringCannotIntrospectToken, err)
	}

	// restore token extra data whenever token is new or retrieved from cookie
	var token *oauth2.Token
	if isTokenFromAuthorizationHeader {
		token = makeBearerToken(accessToken, expiresAt)
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

func (s *OAuthSession) ensurePermUpdated(ctx context.Context, data *AuthSessionData) (bool, error) {
	if !data.isPermissionsExpired() {
		return false, nil
	}

	permissions, err := s.tokenVerifier.GetPermissionsFunc(ctx, data.UserID, data.ClientID, data.Token)
	if err != nil {
		return false, WrapError(ErrorStringCannotGetPermission, err)
	}

	data.Permissions = NewStringSet(permissions)
	data.PermissionsExpiresAt = time.Now().Add(time.Duration(PermissionExpireTime) * time.Second)

	return true, nil
}

// Authorize authorize user by verifying cookie or bearer token.
// if user is authorized, return valid session data. else, return error.
func (s *OAuthSession) Authorize(w http.ResponseWriter, r *http.Request) (*AuthSessionData, error) {
	data, isTokenFromAuthorizationHeader, err := s.getAuthSessionDataFromRequest(r)
	if err != nil {
		return nil, WrapError(ErrorStringUnauthorized, err)
	}
	if data == nil || data.isTokenExpired() {
		return nil, WrapError(ErrorStringUnauthorized, ErrorInvalidSession)
	}

	var isPermissionUpdated bool
	isPermissionUpdated, err = s.ensurePermUpdated(r.Context(), data)
	if err != nil {
		return nil, err
	}

	isCookieDataModified := isTokenFromAuthorizationHeader || isPermissionUpdated

	if isCookieDataModified {
		err = s.setAuthCookie(w, r, data.AuthSessionCookieData)
		if err != nil {
			return nil, WrapError(ErrorStringUnableToSetCookie, err)
		}
	}

	return data, nil
}

// SecuredF is a http middleware for http.HandlerFunc to check if the current user has logged in.
func (s *OAuthSession) SecuredF(isAPI bool) func(http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sessionData, err := s.Authorize(w, r)
			if err != nil {
				switch {
				case CompareErrorMessage(err, ErrorStringUnauthorized):
					if isAPI {
						http.Error(w, err.Error(), http.StatusUnauthorized)
					} else {
						err = s.StartOAuth(w, r)
						if err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
						}
					}
				case CompareErrorMessage(err, ErrorStringCannotGetPermission):
					http.Error(w, err.Error(), http.StatusForbidden)
				default:
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			} else {
				requestInner := AttachRequestWithSessionData(r, sessionData)
				h(w, requestInner)
			}
		}
	}
}

// SecuredH is a http middleware for http.Handler to check if the current user has logged in.
func (s *OAuthSession) SecuredH(isAPI bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.Handler(s.SecuredF(isAPI)(h.ServeHTTP))
	}
}

// StartOAuth redirect to endpoint of OAuth service provider for OAuth flow.
func (s *OAuthSession) StartOAuth(w http.ResponseWriter, r *http.Request) error {
	state, err := s.stateHandler.Generate(s.cookieStore, w, r)
	if err != nil {
		return err
	}

	http.Redirect(w, r, s.client.AuthCodeURL(state), http.StatusSeeOther)
	return nil
}

// EndOAuth finish OAuth flow.
// it will verify state, exchange from authorization code to token, set cookie to make user logged in.
func (s *OAuthSession) EndOAuth(w http.ResponseWriter, r *http.Request) (string, *oauth2.Token, error) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	continueURI, err := s.stateHandler.Verify(s.cookieStore, w, r, state)
	if err != nil {
		return "", nil, WrapError(ErrorStringInvalidState, err)
	}

	var token *oauth2.Token
	token, err = s.client.Exchange(r.Context(), code)
	if err != nil {
		return "", nil, WrapError(ErrorStringFailedToExchangeAuthorizationCode, err)
	}

	return continueURI, token, nil
}

func (s *OAuthSession) verifyAndSaveToken(w http.ResponseWriter, r *http.Request, token *oauth2.Token) error {
	_, err := s.tokenVerifier.GetPermissionsFunc(r.Context(), "", "", token)
	if err != nil {
		return WrapError(ErrorStringCannotGetPermission, err)
	}
	cookie := newAuthSessionCookieData(token)
	err = s.setAuthCookie(w, r, cookie)
	if err != nil {
		return WrapError(ErrorStringUnableToSetCookie, err)
	}
	return nil
}

// CallbackView is a http handler for the authentication redirection of the auth server.
func (s *OAuthSession) CallbackView(w http.ResponseWriter, r *http.Request) {
	continueURI, token, err := s.EndOAuth(w, r)
	statusCode := http.StatusOK
	if err == nil {
		err = s.verifyAndSaveToken(w, r, token)
	}
	if err != nil {
		switch {
		case CompareErrorMessage(err, ErrorStringInvalidState):
			fallthrough
		case CompareErrorMessage(err, ErrorStringFailedToExchangeAuthorizationCode),
			CompareErrorMessage(err, ErrorStringCannotGetPermission):
			statusCode = http.StatusBadRequest
		default:
			statusCode = http.StatusInternalServerError
		}
	}
	uri, _ := url.Parse(continueURI)
	qry := uri.Query()
	qry.Add("status", strconv.Itoa(statusCode))
	if err != nil {
		qry.Add("error", err.Error())
	}
	uri.Fragment += "?" + qry.Encode()
	http.Redirect(w, r, uri.String(), http.StatusSeeOther)
}

// ClearSession clear session.
func (s *OAuthSession) ClearSession(w http.ResponseWriter, r *http.Request) error {
	err := s.deleteAuthCookie(w, r)
	if err != nil {
		err = WrapError(ErrorStringUnableToSetCookie, err)
	}
	return err
}

// LogOut is a http handler to log out the user.
func (s *OAuthSession) LogOut(redirect string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := s.ClearSession(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	}
}

func makeToken(tokenType string, accessToken string, expiresAt int64) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   tokenType,
		Expiry:      time.Unix(expiresAt, 0),
	}
}

func makeBearerToken(accessToken string, expiresAt int64) *oauth2.Token {
	return makeToken("Bearer", accessToken, expiresAt)
}

func (s *OAuthSession) getBearerToken(r *http.Request) (string, error) {
	authorizationHeaderValue := r.Header.Get("Authorization")

	authorizationData := strings.SplitN(authorizationHeaderValue, " ", 2)
	if len(authorizationData) != 2 {
		return "", ErrorInvalidAuthorizationSyntax
	}

	tokenType := authorizationData[0]
	if !strings.EqualFold(tokenType, "bearer") {
		return "", ErrorUnsupportedAuthorizationScheme
	}

	bearerToken := authorizationData[1]
	return bearerToken, nil
}

func (s *OAuthSession) retrieveAuthCookie(r *http.Request) *AuthSessionCookieData {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		return nil
	}

	v, found := session.Values["auth"]
	if !found {
		return nil
	}

	cookieData, ok := v.(*AuthSessionCookieData)
	if !ok {
		return nil
	}

	return cookieData
}

func (s *OAuthSession) setAuthCookie(w http.ResponseWriter, r *http.Request, cookieData *AuthSessionCookieData) error {
	session, err := s.cookieStore.New(r, s.name)
	if err != nil {
		return err
	}
	session.Values["auth"] = cookieData
	err = session.Save(r, w)
	return err
}

func (s *OAuthSession) deleteAuthCookie(w http.ResponseWriter, r *http.Request) error {
	session, err := s.cookieStore.Get(r, s.name)
	if err != nil {
		return err
	}
	delete(session.Values, "auth")
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	return err
}

func newCookieStore(conf *CookieConfig) *sessions.CookieStore {
	var authenticationKey, encryptionKey []byte

	if conf != nil {
		var err error

		authenticationKey, err = base64.StdEncoding.DecodeString(conf.AuthenticationKey)
		if err != nil {
			panic(err)
		}

		encryptionKey, err = base64.StdEncoding.DecodeString(conf.EncryptionKey)
		if err != nil {
			panic(err)
		}
	} else {
		authenticationKey = securecookie.GenerateRandomKey(64)
		encryptionKey = securecookie.GenerateRandomKey(32)
	}

	return sessions.NewCookieStore(authenticationKey, encryptionKey)
}
