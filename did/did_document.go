package did

import (
	"fmt"
)

type DIDTransformer struct{}

func NewDIDTransformer() *DIDTransformer {
	return &DIDTransformer{}
}

func (t *DIDTransformer) TransformJWKSToDID(jwks *JWKS, host string, realm string) (map[string]any, error) {
	didID := fmt.Sprintf("did:web:%s:%s", host, realm)
	return t.TransformJWKSToDIDByID(jwks, didID)
}

func (t *DIDTransformer) TransformJWKSToDIDByID(jwks *JWKS, didID string) (map[string]any, error) {
	var verificationMethods []map[string]any
	var keyIDs []string

	for _, key := range jwks.Keys {
		if key.Use == "sig" {
			currentKeyID := fmt.Sprintf("%s#%s", didID, key.Kid)

			vm := map[string]any{
				"id":         currentKeyID,
				"type":       "JsonWebKey2020",
				"controller": didID,
				"publicKeyJwk": map[string]interface{}{
					"kty":      key.Kty,
					"crv":      key.Crv,
					"x":        key.X,
					"y":        key.Y,
					"alg":      key.Alg,
					"kid":      key.Kid,
					"x5c":      key.X5c,
					"x5t#S256": key.X5tS256,
				},
			}

			verificationMethods = append(verificationMethods, vm)
			keyIDs = append(keyIDs, currentKeyID)
		}
	}

	if len(verificationMethods) == 0 {
		return nil, fmt.Errorf("no signing keys found in JWKS")
	}

	didDocument := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
		},
		"id":                 didID,
		"verificationMethod": verificationMethods,
		"assertionMethod":    keyIDs,
		"authentication":     keyIDs,
	}

	return didDocument, nil
}
