package did

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"os/signal"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"go.uber.org/zap"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}
type JWK struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n,omitempty"`
	E       string   `json:"e,omitempty"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
	Crv     string   `json:"crv,omitempty"`
	X       string   `json:"x,omitempty"`
	Y       string   `json:"y,omitempty"`
}

type BaseServer struct {
	Server *http.Server
	Logger *zap.Logger
}
type KeycloakServer struct {
	BaseServer
	KeycloakHost        string
	Realm               string // fixed realm; empty means dynamic (read from path)
	DID                 string // pre-computed DID ID for fixed realm mode
	Transformer         *DIDTransformer
	IgnoreTlsValidation bool
}
type DidServer struct {
	BaseServer
	DidJSONContent string
	TlsCRTContent  string
}
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func buildDidPath(basepath, filename string) string {
	basepath = strings.TrimSuffix(basepath, "/")
	if basepath == "" {
		return "/.well-known/" + filename
	}
	return basepath + "/" + filename
}

func NewDidServer(didJSON string, tlsCRT string, port int, basepath string, didFilename string) *DidServer {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize Zap logger: %v", err)
	}
	mux := http.NewServeMux()

	didPath := buildDidPath(basepath, didFilename)
	certPath := strings.TrimSuffix(basepath, "/") + "/.well-known/tls.crt"

	s := &DidServer{
		DidJSONContent: didJSON,
		TlsCRTContent:  tlsCRT,
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
	logger.Info("Base path: " + basepath)
	logger.Info("Server initialized", zap.String("didPath", didPath), zap.String("certPath", certPath))
	mux.HandleFunc(didPath, s.handleDidJSON)
	mux.HandleFunc(certPath, s.handleTlsCRT)

	return s
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
		KeycloakHost:        keycloakHost,
		Realm:               realm,
		DID:                 didID,
		Transformer:         NewDIDTransformer(logger),
		IgnoreTlsValidation: ignoreTlsValidation,
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

func (s *DidServer) handleDidJSON(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request details
	s.Logger.Info("Request received",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("remote_addr", r.RemoteAddr),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(s.DidJSONContent)); err != nil {
		s.Logger.Error("Error writing response for /did.json", zap.Error(err))
	} else {
		s.Logger.Debug("Response sent successfully", zap.Int("status", http.StatusOK))
	}
}

func (s *DidServer) handleTlsCRT(w http.ResponseWriter, r *http.Request) {
	s.Logger.Info("Request received", zap.String("path", r.URL.Path))

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(s.TlsCRTContent)); err != nil {
		s.Logger.Error("Error writing response for /tls.crt", zap.Error(err))
	} else {
		s.Logger.Debug("Response sent successfully", zap.Int("status", http.StatusOK))
	}
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

// fetchJWKS fetches and decodes the JWKS from Keycloak for the given realm.
// Returns the JWKS, an HTTP status code for error responses, and any error.
func (s *KeycloakServer) fetchJWKS(realm string) (*JWKS, int, error) {
	keycloakURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", s.KeycloakHost, realm)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.IgnoreTlsValidation},
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

	jwks, statusCode, err := s.fetchJWKS(realm)
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

	jwks, statusCode, err := s.fetchJWKS(realm)
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

func (s *BaseServer) Start() error {
	s.Logger.Info("Starting server", zap.String("address", s.Server.Addr))

	// Create context to listen for OS signals.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop() // Ensures context cancellation resource is released

	// 1. Run the server in a goroutine
	go func() {
		if err := s.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Use Zap logger for the fatal start error
			s.Logger.Fatal("Could not start server listener", zap.Error(err))
		}
	}()

	// Sync the logger before exiting, ensuring all buffered logs are written.
	// This defer is placed here to ensure it runs when the function exits (after shutdown).
	defer s.Logger.Sync()

	// 2. Block until context is canceled (i.e., SIGTERM/SIGINT is received)
	<-ctx.Done()

	// 3. Graceful Shutdown initiated
	s.Logger.Info("Shutdown signal received. Initiating graceful shutdown...")

	// 4. Create a timeout context for the shutdown (e.g., 10 seconds)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the graceful shutdown
	if err := s.Shutdown(shutdownCtx); err != nil {
		s.Logger.Error("Server forced to shutdown after timeout", zap.Error(err))
		// Kubernetes will still kill the pod, but we log the forced shutdown.
		return fmt.Errorf("server shutdown error: %w", err)
	}

	s.Logger.Info("Server successfully shut down.")
	return nil
}

func (s *BaseServer) Shutdown(ctx context.Context) error {
	s.Logger.Info("Shutting down server...")
	return s.Server.Shutdown(ctx)
}

func (s *BaseServer) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
	})
}
