package did

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DidSnapshot is the immutable pair of served documents. A new snapshot is built off to the
// side and swapped in atomically, so readers never observe a torn mix of old/new content.
type DidSnapshot struct {
	DidJSON []byte
	TlsCRT  []byte
}

type DidServer struct {
	BaseServer
	content atomic.Pointer[DidSnapshot]
}

func NewDidServer(initial DidSnapshot, cfg Config, resultingDid string, port int, basepath string, didFilename string) *DidServer {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize Zap logger: %v", err)
	}
	mux := http.NewServeMux()

	didPath := buildDidPath(basepath, didFilename)
	certPath := strings.TrimSuffix(basepath, "/") + "/.well-known/tls.crt"

	s := &DidServer{
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
	s.content.Store(&initial)

	if cfg.CertPath != "" || cfg.KeyPath != "" || cfg.KeystorePath != "" {
		watcher, err := NewCertWatcher(cfg, resultingDid, &s.content, logger)
		if err != nil {
			logger.Warn("Could not start certificate watcher; live cert rotation is disabled", zap.Error(err))
		} else {
			watcher.Start(context.Background())
			s.BaseServer.Cleanup = func() {
				if err := watcher.Close(); err != nil {
					logger.Warn("Error closing certificate watcher", zap.Error(err))
				}
			}
		}
	}

	logger.Info("Base path: " + basepath)
	logger.Info("Server initialized", zap.String("didPath", didPath), zap.String("certPath", certPath))
	mux.HandleFunc(didPath, s.handleDidJSON)
	mux.HandleFunc(certPath, s.handleTlsCRT)

	return s
}

func (s *DidServer) handleDidJSON(w http.ResponseWriter, r *http.Request) {
	s.Logger.Info("Request received",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("remote_addr", r.RemoteAddr),
	)

	snapshot := s.content.Load()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(snapshot.DidJSON); err != nil {
		s.Logger.Error("Error writing response for /did.json", zap.Error(err))
	} else {
		s.Logger.Debug("Response sent successfully", zap.Int("status", http.StatusOK))
	}
}

func (s *DidServer) handleTlsCRT(w http.ResponseWriter, r *http.Request) {
	s.Logger.Info("Request received", zap.String("path", r.URL.Path))

	snapshot := s.content.Load()

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(snapshot.TlsCRT); err != nil {
		s.Logger.Error("Error writing response for /tls.crt", zap.Error(err))
	} else {
		s.Logger.Debug("Response sent successfully", zap.Int("status", http.StatusOK))
	}
}
