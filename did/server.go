package did

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type BaseServer struct {
	Server  *http.Server
	Logger  *zap.Logger
	Cleanup func()
}

func buildDidPath(basepath, filename string) string {
	basepath = strings.TrimSuffix(basepath, "/")
	if basepath == "" {
		return "/.well-known/" + filename
	}
	return basepath + "/" + filename
}

func (s *BaseServer) Start() error {
	s.Logger.Info("Starting server", zap.String("address", s.Server.Addr))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := s.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.Logger.Fatal("Could not start server listener", zap.Error(err))
		}
	}()

	defer s.Logger.Sync()

	<-ctx.Done()

	s.Logger.Info("Shutdown signal received. Initiating graceful shutdown...")

	if s.Cleanup != nil {
		cleanupDone := make(chan struct{})
		go func() {
			s.Cleanup()
			close(cleanupDone)
		}()
		select {
		case <-cleanupDone:
		case <-time.After(5 * time.Second):
			s.Logger.Warn("Cleanup did not complete within timeout, proceeding with shutdown anyway")
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		s.Logger.Error("Server forced to shutdown after timeout", zap.Error(err))
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
