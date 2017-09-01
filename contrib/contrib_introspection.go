// Package osecure provides simple login service based on OAuth client.
package contrib

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/rayark/osecure"
)

// pre-defined implementation

const (
	TokenEndpointURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

/*func SubjectIsAlwaysGranted() IsSubjectGrantedFunc {
	return func(subject string) (bool, error) {
		return true, nil
	}
}*/

func SentryGrant(permissionsURL string) osecure.GetPermissionsFunc {
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

func PredefinedPermissionRoles(roleSubjectsMap map[string][]string) osecure.GetPermissionsFunc {
	subjectRolesMap := make(map[string][]string)
	for role, subjects := range roleSubjectsMap {
		for _, subject := range subjects {
			subjectRolesMap[subject] = append(subjectRolesMap[subject], role)
		}
	}

	return func(subject string, token *oauth2.Token) (permissions []string, err error) {
		roles, ok := subjectRolesMap[subject]
		if !ok {
			return nil, errors.New("cannot found this subject (a.k.a. user ID)")
		}
		return roles, nil
	}

}

func GoogleIntrospection() osecure.IntrospectTokenFunc {
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
		token = osecure.MakeBearerToken(accessToken, result.ExpireAt)
		return
	}
}
