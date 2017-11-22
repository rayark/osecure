// Package osecure provides simple login service based on OAuth client.
package contrib

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	//"net/url"

	"golang.org/x/oauth2"

	"github.com/rayark/osecure"
)

// predefined implementation

const (
	TokenEndpointURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

// predefined token introspection func

func GoogleIntrospection() osecure.IntrospectTokenFunc {
	return func(accessToken string) (subject string, audience string, token *oauth2.Token, err error) {
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

			err = errors.New(fmt.Sprintf("cannot introspect token: introspection API error:\nstatus code: %d\n%s", resp.StatusCode, string(respData)))
			return
		}

		var result struct {
			Subject  string `json:"sub"`
			Audience string `json:"aud"`
			ExpireAt int64  `json:"exp,string"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}

		subject = result.Subject
		audience = result.Audience
		token = osecure.MakeBearerToken(accessToken, result.ExpireAt)
		return
	}
}

// predefined permission getter func

// everyone is granted in the same way
func CommonPermissionRoles(thisAudience string, roles []string) osecure.GetPermissionsFunc {
	//prevent from mutable roles
	internalRoles := make([]string, len(roles))
	copy(internalRoles, roles)

	return func(subject string, audience string, token *oauth2.Token) (permissions []string, err error) {
		if audience != thisAudience {
			return nil, osecure.ErrorInvalidAudience
		}

		return internalRoles, nil
	}

}

// predefined permission roles (a table to represent how to grant everyone's access)
func PredefinedPermissionRoles(thisAudience string, roleSubjectsMap map[string][]string) osecure.GetPermissionsFunc {
	subjectRolesMap := make(map[string][]string)
	for role, subjects := range roleSubjectsMap {
		for _, subject := range subjects {
			subjectRolesMap[subject] = append(subjectRolesMap[subject], role)
		}
	}

	return func(subject string, audience string, token *oauth2.Token) (permissions []string, err error) {
		if audience != thisAudience {
			return nil, osecure.ErrorInvalidAudience
		}

		roles, ok := subjectRolesMap[subject]
		if !ok {
			return nil, osecure.ErrorCannotFoundCurrentSubject
		}
		return roles, nil
	}

}

// sentry permission
func SentryPermission(permissionsURL string) osecure.GetPermissionsFunc {
	return func(subject string, audience string, token *oauth2.Token) (permissions []string, err error) {
		client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

		//resp, err := client.PostForm(permissionsURL, url.Values{})
		resp, err := client.Get(permissionsURL)
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

			err = errors.New(fmt.Sprintf("cannot get permission: permission API error:\nstatus code: %d\n%s", resp.StatusCode, string(respData)))
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
