package did

import (
	"crypto/x509"

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
	IgnoreTlsValidation bool         `flag:"ignoreTlsValidation" default:"false" usage:"Disable TLS validation. Do not use it in production"`
}

type Certificates struct {
	PublicKey  *x509.Certificate
	PrivateKey any
}
