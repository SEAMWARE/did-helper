package did

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"go.uber.org/zap"
)

type DIDTransformer struct {
	Logger *zap.Logger
}

func NewDIDTransformer(logger *zap.Logger) *DIDTransformer {
	return &DIDTransformer{Logger: logger}
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

			if key.Kty == "RSA" && (key.N == "" || key.E == "") && len(key.X5c) > 0 {
				derBytes, err := base64.StdEncoding.DecodeString(key.X5c[0])
				if err != nil {
					t.Logger.Warn("Failed to decode x5c for RSA key", zap.String("kid", key.Kid), zap.Error(err))
				} else if cert, err := x509.ParseCertificate(derBytes); err != nil {
					t.Logger.Warn("Failed to parse x5c certificate for RSA key", zap.String("kid", key.Kid), zap.Error(err))
				} else if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
					t.Logger.Warn("x5c does not contain RSA public key", zap.String("kid", key.Kid))
				} else {
					key.N = base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
					eBytes := make([]byte, 4)
					binary.BigEndian.PutUint32(eBytes, uint32(rsaPub.E))
					for len(eBytes) > 1 && eBytes[0] == 0 {
						eBytes = eBytes[1:]
					}
					key.E = base64.RawURLEncoding.EncodeToString(eBytes)
					t.Logger.Info("Recovered n/e from x5c", zap.String("kid", key.Kid))
				}
			}

			vm := map[string]any{
				"id":           currentKeyID,
				"type":         "JsonWebKey2020",
				"controller":   didID,
				"publicKeyJwk": key,
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
