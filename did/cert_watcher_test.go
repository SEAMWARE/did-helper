package did

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func generateTestKeyPair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert-watcher-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeVersionedPair writes a cert/key pair into a fresh "..<version>" directory, mimicking
// the versioned directories the kubelet atomic writer uses under a Secret/ConfigMap mount.
func writeVersionedPair(t *testing.T, dir, version string, certPEM, keyPEM []byte) string {
	t.Helper()

	versionDir := filepath.Join(dir, ".."+version)
	if err := os.Mkdir(versionDir, 0755); err != nil {
		t.Fatalf("failed to create %s: %v", versionDir, err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "tls.crt"), certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "tls.key"), keyPEM, 0644); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return versionDir
}

// TestCertWatcherK8sRotation replays the Kubernetes atomic-writer sequence used by
// Secret/ConfigMap volumes: write the new content into a fresh versioned directory, point a
// temporary symlink at it, atomically rename it over "..data", then remove the old versioned
// directory. This is the one assumption the whole live-reload feature rests on.
func TestCertWatcherK8sRotation(t *testing.T) {
	dir := t.TempDir()

	certPEM1, keyPEM1 := generateTestKeyPair(t)
	v1 := writeVersionedPair(t, dir, "2026_v1", certPEM1, keyPEM1)

	if err := os.Symlink("..2026_v1", filepath.Join(dir, dataSymlinkName)); err != nil {
		t.Fatalf("failed to create ..data symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(dataSymlinkName, "tls.crt"), filepath.Join(dir, "tls.crt")); err != nil {
		t.Fatalf("failed to create tls.crt symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(dataSymlinkName, "tls.key"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatalf("failed to create tls.key symlink: %v", err)
	}

	cfg := Config{
		CertPath:     filepath.Join(dir, "tls.crt"),
		KeyPath:      filepath.Join(dir, "tls.key"),
		DidType:      "key",
		KeyType:      "P-256",
		OutputFormat: "json",
	}
	if err := LoadCertificates(&cfg); err != nil {
		t.Fatalf("initial LoadCertificates failed: %v", err)
	}
	initialDid, err := ResolveDID(cfg)
	if err != nil {
		t.Fatalf("initial ResolveDID failed: %v", err)
	}

	initialDidJSON, err := BuildOutput(&cfg, initialDid)
	if err != nil {
		t.Fatalf("initial BuildOutput failed: %v", err)
	}
	initialCertPEM, err := GetCert(cfg)
	if err != nil {
		t.Fatalf("initial GetCert failed: %v", err)
	}

	var content atomic.Pointer[DidSnapshot]
	content.Store(&DidSnapshot{DidJSON: initialDidJSON, TlsCRT: initialCertPEM})

	watcher, err := NewCertWatcher(cfg, initialDid, &content, zap.NewNop())
	if err != nil {
		t.Fatalf("NewCertWatcher failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer func() {
		if err := watcher.Close(); err != nil {
			t.Errorf("watcher.Close() failed: %v", err)
		}
	}()

	// Rotate: write the new keypair into a fresh versioned dir, atomically swap "..data" over
	// to it via a temporary symlink + rename (exactly like the kubelet atomic writer), then
	// remove the old version.
	certPEM2, keyPEM2 := generateTestKeyPair(t)
	writeVersionedPair(t, dir, "2026_v2", certPEM2, keyPEM2)

	dataTmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("..2026_v2", dataTmp); err != nil {
		t.Fatalf("failed to create temporary data symlink: %v", err)
	}
	if err := os.Rename(dataTmp, filepath.Join(dir, dataSymlinkName)); err != nil {
		t.Fatalf("failed to atomically swap ..data: %v", err)
	}
	if err := os.RemoveAll(v1); err != nil {
		t.Fatalf("failed to remove old version dir: %v", err)
	}

	expectedCertPEM := certPEM2

	deadline := time.Now().Add(3 * time.Second)
	for {
		snap := content.Load()
		if string(snap.TlsCRT) == string(expectedCertPEM) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificate was not reloaded within deadline; last served:\n%s", snap.TlsCRT)
		}
		time.Sleep(50 * time.Millisecond)
	}

	freshCfg := cfg
	if err := LoadCertificates(&freshCfg); err != nil {
		t.Fatalf("failed to reload certificates for verification: %v", err)
	}
	newDid, err := ResolveDID(freshCfg)
	if err != nil {
		t.Fatalf("ResolveDID for rotated key failed: %v", err)
	}
	if newDid == initialDid {
		t.Fatalf("expected the DID to change after rotating the key material, both are %s", initialDid)
	}
}
