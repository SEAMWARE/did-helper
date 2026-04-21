package did

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type KeycloakServer struct {
	BaseServer
	Client      *KeycloakClient
	Realm       string
	DID         string
	Transformer *DIDTransformer
}

// NewKeycloakServer creates a Keycloak-backed DID server.
// Dynamic mode (realm == ""): registers /{realm}/did.json; realm and DID are derived from each request.
// Fixed mode (realm != ""): registers a static path from basepath and uses the pre-computed didID.
func NewKeycloakServer(keycloakHost string, port int, ignoreTlsValidation bool, realm, didID, basepath string) *KeycloakServer {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize Zap logger: %v", err)
	}
	if ignoreTlsValidation {
		logger.Warn("Ignore TLS Validation is enabled. Do not use it in production")
	}
	mux := http.NewServeMux()
	s := &KeycloakServer{
		Client:      &KeycloakClient{Host: keycloakHost, IgnoreTlsValidation: ignoreTlsValidation},
		Realm:       realm,
		DID:         didID,
		Transformer: NewDIDTransformer(logger),
		BaseServer: BaseServer{
			Logger: logger,
			Server: &http.Server{
				Addr:         fmt.Sprintf(":%d", port),
				Handler:      mux,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
			},
		},
	}

	if realm == "" {
		mux.HandleFunc("/{realm}/did.json", s.handlerRealm)
		mux.HandleFunc("/{realm}/.well-known/tls.crt", s.handlerCert)
	} else {
		didPath := buildDidPath(basepath, "did.json")
		certPath := strings.TrimSuffix(basepath, "/") + "/.well-known/tls.crt"
		logger.Info("Keycloak fixed realm server initialized",
			zap.String("realm", realm),
			zap.String("didPath", didPath),
			zap.String("certPath", certPath),
			zap.String("did", didID),
		)
		mux.HandleFunc(didPath, s.handlerRealm)
		mux.HandleFunc(certPath, s.handlerCert)
	}
	return s
}

// resolveRealm returns the realm name: from the fixed config (fixed mode) or decoded from the path (dynamic mode).
func (s *KeycloakServer) resolveRealm(r *http.Request) (string, error) {
	if s.Realm != "" {
		return s.Realm, nil
	}
	realm := r.PathValue("realm")
	if realm == "" {
		return "", fmt.Errorf("missing realm")
	}
	return realm, nil
}

func (s *KeycloakServer) handlerRealm(w http.ResponseWriter, r *http.Request) {
	realm, err := s.resolveRealm(r)
	if err != nil {
		s.Logger.Warn("Could not resolve realm", zap.Error(err))
		s.BaseServer.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var didID string
	if s.Realm != "" {
		didID = s.DID
	} else {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		didID = fmt.Sprintf("did:web:%s:%s", host, realm)
	}

	jwks, statusCode, err := s.Client.FetchJWKS(realm)
	if err != nil {
		s.Logger.Error("Failed to fetch JWKS", zap.Error(err), zap.String("realm", realm))
		s.BaseServer.respondWithError(w, statusCode, err.Error())
		return
	}

	didDoc, err := s.Transformer.TransformJWKSToDIDByID(jwks, didID)
	if err != nil {
		s.Logger.Warn("Transformation failed", zap.Error(err))
		s.BaseServer.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(didDoc); err != nil {
		s.Logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (s *KeycloakServer) handlerCert(w http.ResponseWriter, r *http.Request) {
	realm, err := s.resolveRealm(r)
	if err != nil {
		s.Logger.Warn("Could not resolve realm", zap.Error(err))
		s.BaseServer.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	jwks, statusCode, err := s.Client.FetchJWKS(realm)
	if err != nil {
		s.Logger.Error("Failed to fetch JWKS", zap.Error(err), zap.String("realm", realm))
		s.BaseServer.respondWithError(w, statusCode, err.Error())
		return
	}

	for _, key := range jwks.Keys {
		if key.Use == "sig" && len(key.X5c) > 0 {
			certDER, err := base64.StdEncoding.DecodeString(key.X5c[0])
			if err != nil {
				s.Logger.Error("Failed to decode x5c certificate", zap.Error(err))
				s.BaseServer.respondWithError(w, http.StatusInternalServerError, "Invalid certificate in JWKS")
				return
			}
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
			return
		}
	}
	s.BaseServer.respondWithError(w, http.StatusNotFound, "No signing certificate found in JWKS")
}
