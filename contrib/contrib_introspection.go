// Package osecure/contrib provides plugins for simple login service based on OAuth client.
package contrib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rayark/osecure/v5"
	"golang.org/x/oauth2"
)

// predefined implementation

const (
	TokenEndpointURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

// predefined token introspection func

func GoogleIntrospection() osecure.IntrospectTokenFunc {
	return func(ctx context.Context, accessToken string) (userID string, clientID string, expiresAt int64, extra map[string]interface{}, err error) {
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
			ExpiresAt       int64  `json:"exp,string"`
			ExpiresIn       int64  `json:"expires_in,string"`
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
		extraData["expires_in"] = result.ExpiresIn
		extraData["access_type"] = result.AccessType

		userID = result.Subject
		clientID = result.Audience
		expiresAt = result.ExpiresAt
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
	//prevent from mutable user roles map
	internalUserRolesMap := make(map[string][]string)
	for userID, roles := range userRolesMap {
		internalRoles := make([]string, len(roles))
		copy(internalRoles, roles)
		internalUserRolesMap[userID] = internalRoles
	}

	return func(ctx context.Context, userID string, clientID string, token *oauth2.Token) (permissions []string, err error) {
		roles := internalUserRolesMap[userID]
		return roles, nil
	}

}
