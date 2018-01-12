// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"golang.org/x/oauth2"
)

type TokenVerifier struct {
	IntrospectTokenFunc IntrospectTokenFunc
	GetPermissionsFunc  GetPermissionsFunc
}

type IntrospectTokenFunc func(accessToken string) (userID string, clientID string, expireAt int64, extra map[string]interface{}, err error)
type GetPermissionsFunc func(userID string, clientID string, token *oauth2.Token) (permissions []string, err error)
