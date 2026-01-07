package did

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
	"go.uber.org/zap"
)

func LoadCertificates(config *Config) (err error) {

	var source string
	if config.KeyPath != "" || config.CertPath != "" {
		err = LoadCertsConfigFromPem(config)
	} else {
		config.Certificates.PrivateKey, config.Certificates.PublicKey, err = GetCertFromKeyStore(config.KeystorePath, config.KeystorePassword)
	}

	if err != nil {
		zap.L().Sugar().Warnf("Was not able to load certs from %s %s", source, config.KeystorePath, "error", err)
		return err
	}
	return nil
}

func GetDIDKey(config Config) (did string, err error) {

	switch config.KeyType {
	case "P-256":
		fallthrough
	case "P-384":
		return getECDID(config.KeyType, config.Certificates.PrivateKey)
	case "ED-25519":
		return getED25519DID(config.Certificates.PrivateKey)
	default:
		return did, errors.ErrUnsupported
	}
}

func getECDID(keyType string, privateKey interface{}) (did string, err error) {
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		zap.L().Sugar().Warnf("Unable to read a valid EC Private Key.")
		return did, errors.New("no_ec_private_key")
	}

	var code uint64

	switch keyType {
	case "P-256":
		code = fingerprint.P256PubKeyMultiCodec
	case "P-384":
		code = fingerprint.P384PubKeyMultiCodec
	}
	keyFromDid, _ := fingerprint.CreateDIDKeyByCode(code, elliptic.MarshalCompressed(ecKey.Curve, ecKey.PublicKey.X, ecKey.PublicKey.Y))
	zap.L().Sugar().Infof("Created did %s", keyFromDid)
	return keyFromDid, err

}
func getED25519DID(privateKey any) (did string, err error) {
	edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		zap.L().Sugar().Warnf("Unable to read a valid ED.25519 Private Key.")
		return did, errors.New("no_ed_private_key")
	}
	pubBytes := edPrivateKey.Public().(ed25519.PublicKey)
	keyFromDid, _ := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubBytes)
	zap.L().Sugar().Infof("Created did %s", keyFromDid)
	return keyFromDid, nil
}

func GetDIDJWKFromKey(config Config) (did string, err error) {

	jwkKey, err := generateJwk(config.Certificates.PublicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to create JWK: %v", err)
		return did, err
	}

	publicKey, err := jwkKey.PublicKey()
	if err != nil {
		zap.L().Sugar().Fatalf("failed to get the public key: %v", err)
		return did, err
	}
	jsonKey, err := json.Marshal(publicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to marshal the public key: %v", err)
		return did, err
	}

	encoded := base64.RawStdEncoding.EncodeToString(jsonKey)

	return "did:jwk:" + encoded, err
}

func GetDIDWeb(hostUrl string) (did string, err error) {

	if hostUrl == "" {
		return did, errors.New("`hostUrl` parameter cannot be null when did type is `web`")
	}

	webUrl, err := url.Parse(hostUrl)
	if err != nil {
		zap.L().Sugar().Errorf("'%s' is not a valid url")
		return did, err
	}

	did = "did:web:" + webUrl.Hostname()
	if webUrl.Path != "/" {
		did = did + strings.ReplaceAll(webUrl.Path, "/", ":")
	}
	return strings.TrimSuffix(did, ":"), err
}

func GenerateJWK(config Config) (jwkKey jwk.Key, err error) {

	jwkKey, err = generateJwk(config.Certificates.PublicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to create JWK: %v", err)
		return jwkKey, err
	}
	jwk.AssignKeyID(jwkKey, jwk.WithThumbprintHash(crypto.SHA256))
	if config.CertUrl != "" {
		jwkKey.Set(jwk.X509URLKey, config.CertUrl)
	}

	return
}

func GetCert(config Config) (certRaw []byte, err error) {

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: config.Certificates.PublicKey.Raw,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func generateJwk(cert *x509.Certificate) (jwkKey jwk.Key, err error) {
	jwkPrivkey, err := jwk.PublicKeyOf(cert.PublicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("Unable to generate jwk")
		return jwkKey, err
	}
	jwkKey, err = jwkPrivkey.PublicKey()
	return
}