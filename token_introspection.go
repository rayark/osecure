// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	TokenEndpointURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

type TokenVerifier struct {
	IntrospectTokenFunc IntrospectTokenFunc
	GetPermissionsFunc  GetPermissionsFunc
	//IsSubjectGrantedFunc IsSubjectGrantedFunc
}

type IntrospectTokenFunc func(accessToken string) (subject string, token *oauth2.Token, err error)
type GetPermissionsFunc func(subject string, token *oauth2.Token) (permissions []string, err error)

//type IsSubjectGrantedFunc func(subject string) (bool, error)

func MakeToken(tokenType string, accessToken string, expireAt int64) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   tokenType,
		Expiry:      time.Unix(expireAt, 0),
	}
}

func MakeBearerToken(accessToken string, expireAt int64) *oauth2.Token {
	return MakeToken("Bearer", accessToken, expireAt)
}

// pre-defined implementation

/*func SubjectIsAlwaysGranted() IsSubjectGrantedFunc {
	return func(subject string) (bool, error) {
		return true, nil
	}
}*/

func SentryGrant(permissionsURL string) GetPermissionsFunc {
	return func(subject string, token *oauth2.Token) (permissions []string, err error) {
		client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

		resp, err := client.Get(permissionsURL)
		if err != nil {
			return
		}

		var result struct {
			Permissions []string `json:"permissions"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}

		permissions = result.Permissions
		return
	}

}

func GoogleGrant() GetPermissionsFunc {
	return func(subject string, token *oauth2.Token) (permissions []string, err error) {
		return []string{"user"}, nil
	}

}

func GoogleIntrospection() IntrospectTokenFunc {
	return func(accessToken string) (subject string, token *oauth2.Token, err error) {
		req, err := http.NewRequest(http.MethodGet, TokenEndpointURL, nil)
		if err != nil {
			return
		}

		query := req.URL.Query()
		query.Add("access_token", accessToken)
		req.URL.RawQuery = query.Encode()

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var respData []byte
			respData, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}

			err = errors.New(fmt.Sprintf("cannot introspect token: introspection API error: %s\n%s", resp.StatusCode, string(respData)))
			return
		}

		var result struct {
			Subject  string `json:"sub"`
			ExpireAt int64  `json:"exp,string"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}

		subject = result.Subject
		token = MakeBearerToken(accessToken, result.ExpireAt)
		return
	}
}
