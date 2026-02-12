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
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
	Crv     string   `json:"crv"`
	X       string   `json:"x"`
	Y       string   `json:"y"`
}

type BaseServer struct {
	Server *http.Server
	Logger *zap.Logger
}
type KeycloakServer struct {
	BaseServer
	KeycloakHost        string
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

func NewDidServer(didJSON string, tlsCRT string, port int, basepath string, didFilename string) *DidServer {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize Zap logger: %v", err)
	}
	basepath = strings.TrimSuffix(basepath, "/")
	mux := http.NewServeMux()

	var didPath string
	var certPath = basepath + "/.well-known/tls.crt"
	// Ensure basepath has no trailing slash
	if basepath == "" {
		didPath = "/.well-known/" + didFilename
	} else {
		didPath = basepath + "/" + didFilename
	}

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

func NewKeycloakServer(keycloakHost string, port int, ignoreTlsValidation bool) *KeycloakServer {

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
		Transformer:         NewDIDTransformer(),
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

	mux.HandleFunc("/{realm}/did.json", s.handlerRealm)
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

func (s *KeycloakServer) handlerRealm(w http.ResponseWriter, r *http.Request) {

	realmBase64 := r.PathValue("realm")
	if realmBase64 == "" {
		s.Logger.Warn("Request received without realm")
		http.Error(w, "Missing realm", http.StatusBadRequest)
		return
	}
	realmBytes, err := base64.StdEncoding.DecodeString(realmBase64)
	if err != nil {
		s.Logger.Warn("Error decoding realm")
		http.Error(w, "Realm is not a valid realm", http.StatusBadRequest)
		return
	}
	realm := string(realmBytes)
	keycloakURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", s.KeycloakHost, realm)
	tr := &http.Transport{
		// Configuración de TLS para ignorar la verificación
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.IgnoreTlsValidation},
	}
	client := http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	resp, err := client.Get(keycloakURL)
	if err != nil {
		s.Logger.Error("Failed to connect to Keycloak", zap.Error(err), zap.String("url", keycloakURL))
		s.BaseServer.respondWithError(w, http.StatusBadGateway, "Indentity provider unreachable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.Logger.Warn("Keycloak returned non-OK status", zap.Int("status", resp.StatusCode), zap.String("realm", realm))
		s.BaseServer.respondWithError(w, resp.StatusCode, "Realm not found or Keycloak error")
		return
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		s.Logger.Error("Failed to decode JWKS body", zap.Error(err))
		s.BaseServer.respondWithError(w, http.StatusInternalServerError, "Invalid response from identity provider")
		return
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	didDoc, err := s.Transformer.TransformJWKSToDID(&jwks, host, realm)
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
