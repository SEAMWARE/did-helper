package did

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"syscall"
	"time"

	"os/signal"

	"go.uber.org/zap"
)

type DidServer struct {
	DidJSONContent string
	TlsCRTContent  string
	Server         *http.Server
	Logger         *zap.Logger
}

func NewDidServer(didJSON string, tlsCRT string, port int, basepath string, didFilename string) *DidServer {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize Zap logger: %v", err)
	}
	s := &DidServer{
		DidJSONContent: didJSON,
		TlsCRTContent:  tlsCRT,
		Logger:         logger,
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

	mux.HandleFunc(didPath, s.handleDidJSON)
	mux.HandleFunc(certPath, s.handleTlsCRT)

	s.Server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
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
func (s *DidServer) Start() error {
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

func (s *DidServer) Shutdown(ctx context.Context) error {
	s.Logger.Info("Shutting down server...")
	return s.Server.Shutdown(ctx)
}
