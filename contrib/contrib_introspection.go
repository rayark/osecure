// Package osecure provides simple login service based on OAuth client.
package contrib

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	//"net/url"

	"golang.org/x/oauth2"

	"github.com/rayark/osecure/v3"
)

// predefined implementation

const (
	TokenEndpointURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

// predefined token introspection func

func GoogleIntrospection() osecure.IntrospectTokenFunc {
	return func(ctx context.Context, accessToken string) (userID string, clientID string, expireAt int64, extra map[string]interface{}, err error) {
		req, err := http.NewRequest(http.MethodGet, TokenEndpointURL, nil)
		if err != nil {
			return
		}
		req = req.WithContext(ctx)

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
			var errorResult struct {
				ErrorDescription string `json:"error_description"`
			}

			err = json.NewDecoder(resp.Body).Decode(&errorResult)
			if err != nil {
				return
			}

			err = fmt.Errorf("Google API error: status code: %d, description: %s", resp.StatusCode, errorResult.ErrorDescription)
			return
		}

		var result struct {
			Subject         string `json:"sub"`
			Audience        string `json:"aud"`
			AuthorizedParty string `json:"azp"`
			ExpireAt        int64  `json:"exp,string"`
			ExpireIn        int64  `json:"expires_in,string"`
			EMail           string `json:"email"`
			IsEMailVerified bool   `json:"email_verified,string"`
			AccessType      string `json:"access_type"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}

		extraData := make(map[string]interface{})
		aliases := []string{}
		if result.IsEMailVerified && len(result.EMail) > 0 {
			aliases = []string{result.EMail}
		}
		extraData["aliases"] = aliases
		extraData["azp"] = result.AuthorizedParty
		extraData["access_type"] = result.AccessType

		userID = result.Subject
		clientID = result.Audience
		expireAt = result.ExpireAt
		extra = extraData
		return
	}
}

func SentryIntrospection(tokenInfoURL string) osecure.IntrospectTokenFunc {
	return func(ctx context.Context, accessToken string) (userID string, clientID string, expireAt int64, extra map[string]interface{}, err error) {
		req, err := http.NewRequest(http.MethodPost, tokenInfoURL, nil)
		if err != nil {
			return
		}
		req = req.WithContext(ctx)

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

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

			err = fmt.Errorf("Sentry API error: status code: %d, body:\n%s", resp.StatusCode, string(respData))
			return
		}

		var result struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
			Username     string `json:"username"`
			UserID       string `json:"user_id"`
			ClientID     string `json:"client_id"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}

		extraData := make(map[string]interface{})
		extraData["user_id"] = result.UserID

		userID = result.Username
		clientID = result.ClientID
		expireAt = time.Now().Unix() + result.ExpiresIn
		extra = extraData
		return
	}
}

// predefined permission getter func

// everyone is granted in the same way
func CommonPermissionRoles(roles []string) osecure.GetPermissionsFunc {
	//prevent from mutable roles
	internalRoles := make([]string, len(roles))
	copy(internalRoles, roles)

	return func(ctx context.Context, userID string, clientID string, token *oauth2.Token) (permissions []string, err error) {
		return internalRoles, nil
	}

}

// predefined permission roles (a table to represent how to grant everyone's access)
func PredefinedPermissionRoles(userRolesMap map[string][]string) osecure.GetPermissionsFunc {
	return func(ctx context.Context, userID string, clientID string, token *oauth2.Token) (permissions []string, err error) {
		roles := userRolesMap[userID]
		return roles, nil
	}

}

// sentry permission
func SentryPermission(permissionsURL string) osecure.GetPermissionsFunc {
	return func(ctx context.Context, userID string, clientID string, token *oauth2.Token) (permissions []string, err error) {
		client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

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

			err = fmt.Errorf("Sentry API error: status code: %d, body:\n%s", resp.StatusCode, string(respData))
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
