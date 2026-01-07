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

func main() {
	var cfg did.Config
	var fileContent []byte
	var resultingDid string
	var err error

	filler := flagsfiller.New()
	err = filler.Fill(flag.CommandLine, &cfg)
	if err != nil {
		zap.L().Sugar().Fatal("error reading config. error %s", err)
		os.Exit(1)
	}
	flag.Parse()

	err = did.LoadCertificates(&cfg)
	if err != nil {
		os.Exit(1)
	}
	switch cfg.DidType {
	case "key":
		resultingDid, err = did.GetDIDKey(cfg)
	case "jwk":
		resultingDid, err = did.GetDIDJWKFromKey(cfg)
	case "web":
		resultingDid, err = did.GetDIDWeb(cfg.HostUrl)
	default:
		zap.L().Sugar().Warnf("Did type %s is not supported.", cfg.DidType)
		os.Exit(2)
	}

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
		os.Exit(3)
	} else {
		fmt.Println("Did key is: ", resultingDid)
	}

	switch cfg.OutputFormat {
	case "json":
		didJson := did.Did{IssuerDid: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid}
		fileContent, err = json.Marshal(didJson)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to marshal the did-json. Err: %s", err)
			os.Exit(4)
		}
	case "env":
		fileContent = ([]byte("DID=" + resultingDid))
	case "json_jwk":
		if cfg.CertUrl == "" {
			cfg.CertUrl = strings.TrimSuffix(cfg.HostUrl, "/") + "/.well-known/tls.crt"
		}
		keySet, err := did.GenerateJWK(cfg)
		if err != nil {
			zap.L().Sugar().Warnf("Error generating keyset. Err: %s", err)
			os.Exit(5)
		}
		verificationMethod := did.VerificationMethod{Id: resultingDid, Type: "JsonWebKey2020", Controller: resultingDid, PublicKeyJwk: keySet}
		didJson := did.Did{Context: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid, VerificationMethod: []did.VerificationMethod{verificationMethod}}
		fileContent, err = json.MarshalIndent(didJson, "", "  ")
		if err != nil {
			zap.L().Sugar().Warnf("Error printing keyset")
			os.Exit(6)
		}
	}
	if cfg.OutputFile != "" {

		err = os.WriteFile(cfg.OutputFile, fileContent, 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-json to %s. Err: %s", cfg.OutputFile, err)
			os.Exit(7)
		}
	} else if cfg.RunServer {
		// Error is detected genering the content
		cert, _ := did.GetCert(cfg)
		webUrl, err := url.Parse(cfg.HostUrl)
		if err != nil {
			zap.L().Sugar().Errorf("'%s' is not a valid url")
			os.Exit(7)
		}
		didFilename := "did.json"
		if cfg.OutputFormat == "env" {
			didFilename = "did.env"
		}

		server := did.NewDidServer(string(fileContent), string(cert), cfg.ServerPort, webUrl.Path, didFilename)
		server.Start()
	} else {
		fmt.Println("Output: ", string(fileContent))
	}
}


