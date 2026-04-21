package did

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type KeycloakClient struct {
	Host                string
	IgnoreTlsValidation bool
}

func (c *KeycloakClient) FetchJWKS(realm string) (*JWKS, int, error) {
	keycloakURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.Host, realm)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.IgnoreTlsValidation}, //nolint:gosec
	}
	client := http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := client.Get(keycloakURL)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("identity provider unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("realm not found or Keycloak error")
	}
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("invalid response from identity provider")
	}
	return &jwks, http.StatusOK, nil
}
