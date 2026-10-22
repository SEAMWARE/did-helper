package did

import (
	"strings"
	"testing"
)

func TestInsecureUrlWarnings(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		expected []string
	}{
		{
			name:     "https urls produce no warnings",
			cfg:      Config{HostUrl: "https://example.org/did", CertUrl: "https://example.org/did/.well-known/tls.crt", OutputFormat: "json_jwk"},
			expected: nil,
		},
		{
			name:     "no urls produce no warnings",
			cfg:      Config{OutputFormat: "json"},
			expected: nil,
		},
		{
			name:     "http hostUrl and derived certUrl are reported",
			cfg:      Config{HostUrl: "http://example.org/did", CertUrl: "http://example.org/did/.well-known/tls.crt", OutputFormat: "json_jwk"},
			expected: []string{"hostUrl 'http://example.org/did'", "certUrl 'http://example.org/did/.well-known/tls.crt'"},
		},
		{
			name:     "explicit http certUrl is reported with an https hostUrl",
			cfg:      Config{HostUrl: "https://example.org/did", CertUrl: "http://certs.example.org/tls.crt", OutputFormat: "json_jwk"},
			expected: []string{"certUrl 'http://certs.example.org/tls.crt'"},
		},
		{
			name:     "certUrl is ignored when it is not published",
			cfg:      Config{HostUrl: "https://example.org/did", CertUrl: "http://certs.example.org/tls.crt", OutputFormat: "json"},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warnings := InsecureUrlWarnings(tc.cfg)
			if len(warnings) != len(tc.expected) {
				t.Fatalf("expected %d warnings, got %d: %v", len(tc.expected), len(warnings), warnings)
			}
			for i, expected := range tc.expected {
				if !strings.Contains(warnings[i], expected) {
					t.Errorf("warning %d: expected to contain %q, got %q", i, expected, warnings[i])
				}
			}
		})
	}
}
