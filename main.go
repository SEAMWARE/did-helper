package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/itzg/go-flagsfiller"
	"gitlab.seamware.com/seamware/did-helper/did"

	"go.uber.org/zap"
)

func init() {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
}

func getHostPath(hostUrl string) (string, error) {
	webUrl, err := url.Parse(hostUrl)
	if err != nil {
		return "", fmt.Errorf("'%s' is not a valid url", hostUrl)
	}
	return webUrl.Path, nil
}

func resolveDID(cfg did.Config) (string, error) {
	switch cfg.DidType {
	case "key":
		return did.GetDIDKey(cfg)
	case "jwk":
		return did.GetDIDJWKFromKey(cfg)
	case "web":
		return did.GetDIDWeb(cfg.HostUrl)
	case "keycloak":
		if cfg.KeycloakRealm != "" {
			return did.GetDIDWeb(cfg.HostUrl)
		}
		return "", nil
	default:
		return "", fmt.Errorf("did type %s is not supported", cfg.DidType)
	}
}

func buildOutput(cfg *did.Config, resultingDid string) ([]byte, error) {
	switch cfg.OutputFormat {
	case "json":
		didJson := did.Did{IssuerDid: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid}
		return json.Marshal(didJson)
	case "env":
		return []byte("DID=" + resultingDid), nil
	case "json_jwk":
		if cfg.CertUrl == "" {
			cfg.CertUrl = strings.TrimSuffix(cfg.HostUrl, "/") + "/.well-known/tls.crt"
		}
		keySet, err := did.GenerateJWK(*cfg)
		if err != nil {
			return nil, fmt.Errorf("error generating keyset: %w", err)
		}
		verificationMethod := did.VerificationMethod{Id: resultingDid, Type: "JsonWebKey2020", Controller: resultingDid, PublicKeyJwk: keySet}
		didJson := did.Did{Context: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid, VerificationMethod: []did.VerificationMethod{verificationMethod}}
		return json.MarshalIndent(didJson, "", "  ")
	}
	return nil, nil
}

func startServer(cfg did.Config, fileContent []byte, resultingDid string) error {
	if cfg.DidType == "keycloak" {
		var basepath string
		if cfg.KeycloakRealm != "" {
			var err error
			basepath, err = getHostPath(cfg.HostUrl)
			if err != nil {
				return err
			}
		}
		server := did.NewKeycloakServer(cfg.KeycloakHost, cfg.ServerPort, cfg.IgnoreTlsValidation, cfg.KeycloakRealm, resultingDid, basepath)
		return server.Start()
	}

	cert, _ := did.GetCert(cfg)
	didFilename := "did.json"
	if cfg.OutputFormat == "env" {
		didFilename = "did.env"
	}
	hostPath, err := getHostPath(cfg.HostUrl)
	if err != nil {
		return err
	}
	server := did.NewDidServer(string(fileContent), string(cert), cfg.ServerPort, hostPath, didFilename)
	return server.Start()
}

func main() {
	var cfg did.Config

	filler := flagsfiller.New(flagsfiller.WithEnv(""))
	if err := filler.Fill(flag.CommandLine, &cfg); err != nil {
		zap.L().Sugar().Fatalf("error reading config: %s", err)
	}
	flag.Parse()

	if cfg.DidType != "keycloak" {
		if err := did.LoadCertificates(&cfg); err != nil {
			os.Exit(1)
		}
	}

	resultingDid, err := resolveDID(cfg)
	if err != nil {
		zap.L().Sugar().Fatalf("was not able to resolve did: %s", err)
	}
	if resultingDid != "" {
		fmt.Println("Did key is: ", resultingDid)
	}

	fileContent, err := buildOutput(&cfg, resultingDid)
	if err != nil {
		zap.L().Sugar().Fatalf("was not able to build output: %s", err)
	}

	switch {
	case cfg.OutputFile != "":
		if err := os.WriteFile(cfg.OutputFile, fileContent, 0644); err != nil {
			zap.L().Sugar().Fatalf("was not able to write to %s: %s", cfg.OutputFile, err)
		}
	case cfg.RunServer:
		if err := startServer(cfg, fileContent, resultingDid); err != nil {
			zap.L().Sugar().Fatalf("server error: %s", err)
		}
	default:
		fmt.Println("Output: ", string(fileContent))
	}
}
