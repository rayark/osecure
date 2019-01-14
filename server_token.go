package osecure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrorInvalidServerToken = errors.New("invalid server token")
	ErrorPermissionDenied   = errors.New("permission denied")
)

type ServerTokenRequest struct {
	TargetClientId string `json:"target_client_id"`
	Timestamp      int64  `json:"timestamp"`
}

type ServerTokenReply struct {
	ServerToken string `json:"encrypted_server_token"`
	Timestamp   int64  `json:"timestamp"`
	ExpiryTime  int64  `json:"expiry_time"`
}

type ServerToken struct {
	Source     string `json:"source"`
	Timestamp  int64  `json:"timestamp"`
	ExpiryTime int64  `json:"expiry_time"`
}

func (s *OAuthSession) GetServerToken(targetClientId string) (*ServerTokenReply, error) {
	secret, err := s.generateServerTokenRequest(targetClientId)
	if err != nil {
		return nil, err
	}

	resp, err := http.PostForm(s.serverTokenURL, url.Values{"id": {s.interServerClientID}, "secret": {secret}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return nil, ErrorPermissionDenied
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reply, err := s.readServerTokenReply(string(body))
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *OAuthSession) DecryptServerToken(tokenString string, sourceClientId string) (*ServerToken, error) {
	token, err := s.readServerToken(tokenString)
	if err != nil {
		return nil, err
	}

	if token.Source != sourceClientId {
		return token, ErrorInvalidServerToken
	}

	if time.Now().After(time.Unix(token.ExpiryTime, 0)) {
		return token, ErrorInvalidServerToken
	}

	return token, nil
}

func (s *OAuthSession) generateServerTokenRequest(targetClientId string) (string, error) {
	serverTokenRequest := &ServerTokenRequest{
		TargetClientId: targetClientId,
		Timestamp:      time.Now().Unix(),
	}

	jsonServerTokenRequest, err := json.Marshal(serverTokenRequest)
	if err != nil {
		return "", err
	}

	encryptedServerTokenRequest, err := encryptAESCTR(s.serverTokenEncryptionKey, jsonServerTokenRequest)
	if err != nil {
		return "", err
	}

	result := base64.StdEncoding.EncodeToString(encryptedServerTokenRequest)
	return result, nil
}

func (s *OAuthSession) readServerTokenReply(secret string) (*ServerTokenReply, error) {
	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptAESCTR(s.serverTokenEncryptionKey, decodedSecret)
	if err != nil {
		return nil, err
	}

	reply := &ServerTokenReply{}
	json.Unmarshal(plaintext, reply)

	return reply, nil
}

func (s *OAuthSession) readServerToken(secret string) (*ServerToken, error) {
	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptAESCTR(s.serverTokenEncryptionKey, decodedSecret)
	if err != nil {
		return nil, err
	}

	token := &ServerToken{}
	json.Unmarshal(plaintext, token)

	return token, nil
}
