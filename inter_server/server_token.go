package inter_server

import (
	"encoding/base64"
	"encoding/hex"
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

type InterServerConfig struct {
	InterServerClientID      string `yaml:"inter_server_client_id" env:"inter_server_client_id"`
	ServerTokenURL           string `yaml:"server_token_url" env:"server_token_url"`
	ServerTokenEncryptionKey string `yaml:"server_token_encryption_key" env:"server_token_encryption_key"`
}

type InterServer struct {
	interServerClientID      string
	serverTokenURL           string
	serverTokenEncryptionKey []byte
}

type ServerTokenRequest struct {
	TargetClientID string `json:"target_client_id"`
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

func NewInterServer(interServerConf *InterServerConfig) *InterServer {
	serverTokenEncryptionKey, err := hex.DecodeString(interServerConf.ServerTokenEncryptionKey)
	if err != nil {
		panic(err)
	}

	return &InterServer{
		interServerClientID:      interServerConf.InterServerClientID,
		serverTokenURL:           interServerConf.ServerTokenURL,
		serverTokenEncryptionKey: serverTokenEncryptionKey,
	}
}

func (is *InterServer) GetServerToken(targetClientID string) (*ServerTokenReply, error) {
	secret, err := is.generateServerTokenRequest(targetClientID)
	if err != nil {
		return nil, err
	}

	resp, err := http.PostForm(is.serverTokenURL, url.Values{"id": {is.interServerClientID}, "secret": {secret}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrorPermissionDenied
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reply, err := is.readServerTokenReply(string(body))
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (is *InterServer) DecryptServerToken(tokenString string, sourceClientID string) (*ServerToken, error) {
	token, err := is.readServerToken(tokenString)
	if err != nil {
		return nil, err
	}

	if token.Source != sourceClientID {
		return token, ErrorInvalidServerToken
	}

	if time.Now().After(time.Unix(token.ExpiryTime, 0)) {
		return token, ErrorInvalidServerToken
	}

	return token, nil
}

func (is *InterServer) generateServerTokenRequest(targetClientID string) (string, error) {
	serverTokenRequest := &ServerTokenRequest{
		TargetClientID: targetClientID,
		Timestamp:      time.Now().Unix(),
	}

	jsonServerTokenRequest, err := json.Marshal(serverTokenRequest)
	if err != nil {
		return "", err
	}

	encryptedServerTokenRequest, err := encryptAESCTR(is.serverTokenEncryptionKey, jsonServerTokenRequest)
	if err != nil {
		return "", err
	}

	result := base64.StdEncoding.EncodeToString(encryptedServerTokenRequest)
	return result, nil
}

func (is *InterServer) readServerTokenReply(secret string) (*ServerTokenReply, error) {
	print(secret)
	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptAESCTR(is.serverTokenEncryptionKey, decodedSecret)
	if err != nil {
		return nil, err
	}

	reply := &ServerTokenReply{}
	json.Unmarshal(plaintext, reply)

	return reply, nil
}

func (is *InterServer) readServerToken(secret string) (*ServerToken, error) {
	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptAESCTR(is.serverTokenEncryptionKey, decodedSecret)
	if err != nil {
		return nil, err
	}

	token := &ServerToken{}
	json.Unmarshal(plaintext, token)

	return token, nil
}
