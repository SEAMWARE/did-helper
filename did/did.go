package did

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Did struct {
	Context            []string             `json:"@context,omitempty"`
	IssuerDid          []string             `json:"issuerDid,omitempty"`
	Id                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
}

type VerificationMethod struct {
	Id           string  `json:"id"`
	Type         string  `json:"type"`
	Controller   string  `json:"controller"`
	PublicKeyJwk jwk.Key `json:"publicKeyJwk,omitempty"`
}

type Config struct {
	KeystorePath        string       `flag:"keystorePath" default:"" usage:"Path to the keystore to be read."`
	KeystorePassword    string       `flag:"keystorePassword" default:"" usage:"Password for the keystore."`
	CertPath            string       `flag:"certPath" default:"" usage:"Path to the PEM certificate."`
	KeyPath             string       `flag:"keyPath" default:"" usage:"Path to the key PEM certificate."`
	OutputFormat        string       `flag:"outputFormat" default:"json" usage:"Output format for the DID result file. Can be json, env or json_jwk."`
	OutputFile          string       `flag:"outputFile" default:"" usage:"File to write the DID; will not write if empty."`
	DidType             string       `flag:"didType" default:"key" usage:"Type of the DID to generate. did:key and did:jwk are supported."`
	KeyType             string       `flag:"keyType" default:"P-256" usage:"Type of the DID key to be created. Supported: ED-25519, P-256, P-384."`
	HostUrl             string       `flag:"hostUrl" default:"" usage:"Base URL where the DID document will be located, excluding 'did.json'."`
	CertUrl             string       `flag:"certUrl" default:"" usage:"URL to retrieve the public certificate. Defaults to 'hostUrl' + /.well-known/tls.crt"`
	RunServer           bool         `flag:"server" default:"false" usage:"Run a server with /did.json and /.well-known/tls.crt endpoints."`
	ServerPort          int          `flag:"port" default:"8080" usage:"Server port. Default 8080."`
	Certificates        Certificates `flag:""`
	KeycloakHost        string       `flag:"keycloakHost" usage:"URL of the Keycloak instance used to construct the OIDC discovery and JWKS endpoints for the realms"`
	KeycloakRealm       string       `flag:"keycloakRealm" usage:"Fixed Keycloak realm. When set with didType=keycloak, serves a fixed DID document for this realm at the path derived from hostUrl."`
	IgnoreTlsValidation bool         `flag:"ignoreTlsValidation" default:"false" usage:"Disable TLS validation. Do not use it in production"`
}

type Certificates struct {
	PublicKey  *x509.Certificate
	PrivateKey any
}

// HasFileCert reports whether the certificate/key material is configured to be read from a
// file on disk (PEM pair or PKCS12 keystore), as opposed to e.g. a Keycloak-backed setup.
func (c Config) HasFileCert() bool {
	return c.CertPath != "" || c.KeyPath != "" || c.KeystorePath != ""
}

func ResolveDID(cfg Config) (string, error) {
	switch cfg.DidType {
	case "key":
		return GetDIDKey(cfg)
	case "jwk":
		return GetDIDJWKFromKey(cfg)
	case "web":
		return GetDIDWeb(cfg.HostUrl)
	case "keycloak":
		if cfg.KeycloakRealm != "" {
			return GetDIDWeb(cfg.HostUrl)
		}
		return "", nil
	default:
		return "", fmt.Errorf("did type %s is not supported", cfg.DidType)
	}
}

func BuildOutput(cfg *Config, resultingDid string) ([]byte, error) {
	switch cfg.OutputFormat {
	case "json":
		didJson := Did{IssuerDid: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid}
		return json.Marshal(didJson)
	case "env":
		return []byte("DID=" + resultingDid), nil
	case "json_jwk":
		if cfg.CertUrl == "" {
			cfg.CertUrl = strings.TrimSuffix(cfg.HostUrl, "/") + "/.well-known/tls.crt"
		}
		keySet, err := GenerateJWK(*cfg)
		if err != nil {
			return nil, fmt.Errorf("error generating keyset: %w", err)
		}
		verificationMethod := VerificationMethod{Id: resultingDid, Type: "JsonWebKey2020", Controller: resultingDid, PublicKeyJwk: keySet}
		didJson := Did{Context: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid, VerificationMethod: []VerificationMethod{verificationMethod}}
		return json.MarshalIndent(didJson, "", "  ")
	default:
		return nil, fmt.Errorf("output format %s is not supported", cfg.OutputFormat)
	}
}
