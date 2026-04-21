package did

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

func GetCertFromKeyStore(path string, password string) (privateKey interface{}, cert *x509.Certificate, err error) {

	bytes, err := os.ReadFile(path)

	if err != nil {
		return nil, nil, fmt.Errorf("was not able to read the file %s. error %s", path, err)
	}

	privateKey, cert, err = pkcs12.Decode(bytes, password)
	if err != nil {

		return privateKey, cert, fmt.Errorf("was not able to decode the keystore %s. error %s", path, err)
	}
	return
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to find PEM block in certificate file")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}
	return cert, nil
}

func LoadPrivateKey(path string) (interface{}, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to find PEM block in private key file")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	privateKey, err = x509.ParseECPrivateKey(block.Bytes)

	if err == nil {
		return privateKey, nil
	}

	return nil, fmt.Errorf("unsupported private key format (not PKCS#8 or PKCS#1)")
}

func LoadCertsConfigFromPem(config *Config) (err error) {

	if config.KeyPath != "" {
		config.Certificates.PrivateKey, err = LoadPrivateKey(config.KeyPath)
		if err != nil {
			return fmt.Errorf("was not able to decode KeyCertPath %s. error %s", config.KeyPath, err)
		}
	}
	if config.CertPath != "" {
		config.Certificates.PublicKey, err = LoadCertificate(config.CertPath)
		if err != nil {
			return fmt.Errorf("was not able to decode CertPath %s. error %s", config.KeyPath, err)
		}
	}
	return
}

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

func GetCert(config Config) (certRaw []byte, err error) {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: config.Certificates.PublicKey.Raw,
	}
	return pem.EncodeToMemory(pemBlock), nil
}
