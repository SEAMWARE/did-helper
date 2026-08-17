package did

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const reloadDebounceWindow = 500 * time.Millisecond

// dataSymlinkName is the atomic-writer symlink Kubernetes re-points on Secret/ConfigMap
// volume rotation. The mounted file names themselves (e.g. tls.crt) are static symlinks
// through this entry, so the real rotation event arrives on "..data", not on the file name.
const dataSymlinkName = "..data"

// CertWatcher watches the directories backing a Config's certificate/key/keystore paths
// and, on a relevant change, regenerates the DID document and cert PEM and stores them
// into target so DidServer can serve the new content without recomputing per request.
type CertWatcher struct {
	watcher  *fsnotify.Watcher
	cfg      Config
	target   *atomic.Pointer[DidSnapshot]
	logger   *zap.Logger
	relevant map[string]struct{}
	lastDid  string
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewCertWatcher(cfg Config, initialDid string, target *atomic.Pointer[DidSnapshot], logger *zap.Logger) (*CertWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	paths := []string{cfg.CertPath, cfg.KeyPath, cfg.KeystorePath}

	dirs := map[string]struct{}{}
	relevant := map[string]struct{}{dataSymlinkName: {}}
	for _, path := range paths {
		if path == "" {
			continue
		}
		dirs[filepath.Dir(path)] = struct{}{}
		relevant[filepath.Base(path)] = struct{}{}
	}

	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			watcher.Close()
			return nil, err
		}
		if _, err := os.Lstat(filepath.Join(dir, dataSymlinkName)); err != nil {
			logger.Warn(
				"Watched directory has no '..data' atomic-writer entry; if it is mounted via subPath, "+
					"Kubernetes will never propagate Secret/ConfigMap rotations here and this watcher will not see updates. "+
					"Mount the whole volume (no subPath) for live certificate reload to work.",
				zap.String("dir", dir),
			)
		}
	}

	return &CertWatcher{
		watcher:  watcher,
		cfg:      cfg,
		target:   target,
		logger:   logger,
		relevant: relevant,
		lastDid:  initialDid,
	}, nil
}

// Start runs the debounced event loop in a background goroutine and returns immediately.
func (w *CertWatcher) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})

	go func() {
		defer close(w.done)

		var pending *time.Timer
		var pendingC <-chan time.Time

		for {
			select {
			case <-ctx.Done():
				if pending != nil {
					pending.Stop()
				}
				return

			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				}
				if _, ok := w.relevant[filepath.Base(event.Name)]; !ok {
					continue
				}
				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
					continue
				}

				if pending == nil {
					pending = time.NewTimer(reloadDebounceWindow)
				} else {
					if !pending.Stop() {
						select {
						case <-pending.C:
						default:
						}
					}
					pending.Reset(reloadDebounceWindow)
				}
				pendingC = pending.C

			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				}
				w.logger.Warn("Certificate watcher error", zap.Error(err))

			case <-pendingC:
				pending = nil
				pendingC = nil
				if err := w.reload(); err != nil {
					w.logger.Warn("Failed to reload certificate; keeping previous content", zap.Error(err))
				} else {
					w.logger.Info("Certificate rotation detected, served content refreshed")
				}
			}
		}
	}()
}

func (w *CertWatcher) reload() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during certificate reload: %v", r)
		}
	}()

	cfgCopy := w.cfg

	if err := LoadCertificates(&cfgCopy); err != nil {
		return err
	}

	resultingDid, err := ResolveDID(cfgCopy)
	if err != nil {
		return err
	}

	if resultingDid != w.lastDid {
		w.logger.Warn(
			"Certificate rotation changed the resulting DID; anything that pinned the previous DID (trusted issuer lists, counterparties) will break",
			zap.String("previousDid", w.lastDid),
			zap.String("newDid", resultingDid),
		)
		w.lastDid = resultingDid
	}

	didJSON, err := BuildOutput(&cfgCopy, resultingDid)
	if err != nil {
		return err
	}

	certPEM, err := GetCert(cfgCopy)
	if err != nil {
		return err
	}

	w.target.Store(&DidSnapshot{DidJSON: didJSON, TlsCRT: certPEM})
	return nil
}

// Close stops the event loop and releases the underlying fsnotify watcher.
func (w *CertWatcher) Close() error {
	if w.cancel != nil {
		w.cancel()
		<-w.done
	}
	return w.watcher.Close()
}
