package did

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type DidServer struct {
	BaseServer
	DidJSONContent string
	TlsCRTContent  string
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

func (s *DidServer) handleDidJSON(w http.ResponseWriter, r *http.Request) {
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
