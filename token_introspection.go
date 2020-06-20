// Package osecure provides simple login service based on OAuth client.
package osecure

import (
	"context"

	"golang.org/x/oauth2"
)

type TokenVerifier struct {
	IntrospectTokenFunc IntrospectTokenFunc
	GetPermissionsFunc  GetPermissionsFunc
}

type IntrospectTokenFunc func(ctx context.Context, accessToken string) (userID string, clientID string, expiresAt int64, extra map[string]interface{}, err error)
type GetPermissionsFunc func(ctx context.Context, userID string, clientID string, token *oauth2.Token) (permissions []string, err error)
