package verify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"skillguard/internal/extract"
	"skillguard/internal/model"
)

func npmDocument(name string) string {
	return fmt.Sprintf(`{"name":%q,"dist-tags":{"latest":"1.2.3"},"versions":{"1.2.3":{"version":"1.2.3","repository":{"url":"https://user:repository-secret@code.example.org/repo?token=query-secret"},"dist":{"attestations":{"url":"https://untrusted.example/attestation"}}}},"time":{"1.2.3":"2026-10-19T00:00:00Z"}}`, name)
}

func localVerifier(t *testing.T, ecosystem string, handler http.HandlerFunc, change func(*Policy, *Options)) (*Verifier, *httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	certs := x509.NewCertPool()
	certs.AddCert(server.Certificate())
	metadata, install := server.URL, server.URL
	if ecosystem == "pypi" {
		metadata += "/pypi"
		install += "/simple"
	}
	policy := Policy{SchemaVersion: 1, Registries: []Registry{{ID: "test-registry", Ecosystem: ecosystem, MetadataURL: metadata, InstallURL: install, Default: true, Packages: []string{"*"}, AllowPrivateNetwork: true}}}
	options := Options{TLSConfig: &tls.Config{RootCAs: certs, MinVersion: tls.VersionTLS12}, Wait: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }, Now: func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }}
	if change != nil {
		change(&policy, &options)
	}
	v, err := New(policy, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v, server, hits
}

func onePackage(t *testing.T, v *Verifier, text string) model.PackageObservation {
	t.Helper()
	result := v.Verify(context.Background(), extract.Extract("llms.txt", text, ""))
	if len(result.Packages) != 1 {
		t.Fatalf("observations = %+v", result)
	}
	return result.Packages[0]
}

func TestNPMMetadataStatesAndNoTrustClaim(t *testing.T) {
	tests := []struct {
		name, text, body, state, version string
		code                             int
	}{
		{"found", "npm install helper@1.2.3", npmDocument("helper"), "found", "found", 200},
		{"version absent", "npm install helper@9.9.9", npmDocument("helper"), "found", "missing", 200},
		{"missing", "npm install helper@1.2.3", "{}", "missing", "unknown", 404},
		{"unauthorized", "npm install helper@1.2.3", "{}", "unauthorized", "unknown", 401},
		{"forbidden", "npm install helper@1.2.3", "{}", "unauthorized", "unknown", 403},
		{"rate limited", "npm install helper@1.2.3", "{}", "rate_limited", "unknown", 429},
		{"unavailable", "npm install helper@1.2.3", "{}", "unavailable", "unknown", 503},
		{"server timeout", "npm install helper@1.2.3", "{}", "timeout", "unknown", 504},
		{"malformed", "npm install helper@1.2.3", "{bad", "malformed_response", "unknown", 200},
		{"wrong identity", "npm install helper@1.2.3", npmDocument("other"), "malformed_response", "unknown", 200},
		{"trailing payload", "npm install helper@1.2.3", npmDocument("helper") + "{}", "malformed_response", "unknown", 200},
		{"range unresolved", "npm install 'helper@^1.0.0'", npmDocument("helper"), "found", "unsupported_specifier", 200},
		{"mutable tag", "npm install helper@latest", npmDocument("helper"), "found", "found", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _, hits := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tt.code); _, _ = w.Write([]byte(tt.body)) }, nil)
			p := onePackage(t, v, tt.text)
			if p.State != tt.state || p.VersionState != tt.version || hits.Load() != 1 {
				t.Fatalf("observation = %+v, hits %d", p, hits.Load())
			}
			if p.Identity != "unverified" || p.MalwareCheck != "not_performed" {
				t.Fatalf("existence promoted to trust: %+v", p)
			}
			data, _ := json.Marshal(p)
			for _, secret := range []string{"repository-secret", "query-secret", "user:"} {
				if strings.Contains(string(data), secret) {
					t.Fatalf("metadata evidence leaks %s", secret)
				}
			}
			if p.State == "found" && p.VersionState == "found" && (p.PublishedAt == nil || p.Provenance != "claimed_attestation_not_verified") {
				t.Fatalf("missing attributed metadata: %+v", p)
			}
		})
	}
}

func TestScopedNPMAndPyPINormalization(t *testing.T) {
	v, _, _ := localVerifier(t, "npm", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/@scope%2Fhelper" {
			t.Errorf("scoped path = %q", r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(npmDocument("@scope/helper")))
	}, nil)
	if p := onePackage(t, v, "npm install @scope/helper@1.2.3"); p.State != "found" {
		t.Fatalf("scoped package = %+v", p)
	}
	v, _, _ = localVerifier(t, "pypi", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/other-pkg/json" {
			t.Errorf("normalized path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"info":{"name":"Other.Pkg","version":"1.2.0","project_urls":{"Source":"https://code.example.org/repo"}},"releases":{"1.2.0":[{"upload_time_iso_8601":"2026-10-19T00:00:00Z"}]}}`))
	}, nil)
	for _, spec := range []string{"Other_Pkg==1.2", "Other_Pkg[extra]==1.2.0"} {
		p := onePackage(t, v, "pip install '"+spec+"'")
		if p.State != "found" || p.Name != "other-pkg" || p.VersionState != "found" || p.Version != "1.2.0" {
			t.Fatalf("PyPI = %+v", p)
		}
	}
	if p := onePackage(t, v, "pip install Other_Pkg==9.0"); p.VersionState != "missing" {
		t.Fatalf("absent Python version = %+v", p)
	}
	if p := onePackage(t, v, "pip install 'Other_Pkg>=1'"); p.VersionState != "unsupported_specifier" {
		t.Fatalf("range silently resolved = %+v", p)
	}
}

func TestPrivateNameDisclosureAndSourceSelection(t *testing.T) {
	var publicHits atomic.Int32
	v, server, hits := localVerifier(t, "pypi", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-test-secret" {
			t.Error("operator credential not applied")
		}
		_, _ = w.Write([]byte(`{"info":{"name":"company-helper","version":"1"},"releases":{"1":[]}}`))
	}, func(p *Policy, _ *Options) {
		p.Registries[0].Default = false
		p.Registries[0].Packages = []string{"company-*"}
		p.Registries[0].AuthEnv = "SKILLGUARD_TEST_REGISTRY_TOKEN"
		p.Registries = append(p.Registries, Registry{ID: "public", Ecosystem: "pypi", MetadataURL: "https://public.invalid/pypi", InstallURL: "https://public.invalid/simple", Default: true, Packages: []string{"public-helper"}})
	})
	t.Setenv("SKILLGUARD_TEST_REGISTRY_TOKEN", "private-test-secret")
	v.broker.resolver = resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		publicHits.Add(1)
		return nil, errors.New("unexpected lookup")
	})
	p := onePackage(t, v, "pip install company-helper==1")
	if p.State != "blocked" || hits.Load() != 0 || publicHits.Load() != 0 {
		t.Fatalf("private name disclosed: %+v", p)
	}
	p = onePackage(t, v, "pip install company-helper==1 --index-url "+server.URL+"/simple")
	if p.State != "found" || p.Registry != "test-registry" || hits.Load() != 1 || publicHits.Load() != 0 {
		t.Fatalf("private routing = %+v", p)
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), "private-test-secret") {
		t.Fatal("credential leaked")
	}
	p = onePackage(t, v, "pip install company-helper==1 --index-url https://attacker.invalid/simple")
	if p.State != "unsupported_source" || hits.Load() != 1 || publicHits.Load() != 0 {
		t.Fatalf("documentation authorized a new registry: %+v", p)
	}
}

func TestCacheFreshnessBudgetAndFailedRefresh(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	var unavailable atomic.Bool
	v, _, hits := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(npmDocument("helper")))
	}, func(p *Policy, o *Options) { p.CacheTTLSeconds = 1; o.Now = func() time.Time { return now } })
	first := onePackage(t, v, "npm install helper@1.2.3")
	second := onePackage(t, v, "npm install helper@1.2.3")
	if first.FromCache || !second.FromCache || hits.Load() != 1 || second.ExpiresAt == nil {
		t.Fatal("fresh cache not used")
	}
	now = now.Add(2 * time.Second)
	unavailable.Store(true)
	p := onePackage(t, v, "npm install helper@1.2.3")
	if p.State != "unavailable" || !p.StaleEvidenceDiscarded || p.Version != "" || p.FromCache || hits.Load() != 2 {
		t.Fatalf("stale success reused after failure: %+v", p)
	}
	v, _, hits = localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(npmDocument("helper"))) }, func(p *Policy, _ *Options) { p.MaxRequests = 1; p.CacheTTLSeconds = 1 })
	onePackage(t, v, "npm install helper@1.2.3")
	p = onePackage(t, v, "npm install helper@9.9.9")
	if p.State != "request_limit" || hits.Load() != 1 {
		t.Fatalf("budget exceeded: %+v", p)
	}
}

func TestTimeoutCancellationAndResponseBounds(t *testing.T) {
	v, _, _ := localVerifier(t, "npm", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}, func(p *Policy, _ *Options) { p.TimeoutSeconds = 1 })
	if p := onePackage(t, v, "npm install helper@1.2.3"); p.State != "timeout" {
		t.Fatalf("timeout = %+v", p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := v.Verify(ctx, extract.Extract("docs", "npm install helper@1.2.3", ""))
	if result.Status != "partial" {
		t.Fatalf("canceled verification complete: %+v", result)
	}
	v, _, _ = localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(npmDocument("helper") + strings.Repeat(" ", maxResponseBytes)))
	}, nil)
	if p := onePackage(t, v, "npm install helper@1.2.3"); p.State != "malformed_response" || p.Reason != "response_limit" {
		t.Fatalf("oversized response = %+v", p)
	}
}

type fakeIntelligence struct{}

func (fakeIntelligence) Check(context.Context, string, string, string) (IntelligenceObservation, error) {
	return IntelligenceObservation{KnownMalicious: true, SourceID: "test-fixture"}, nil
}

func TestOptionalIntelligenceNeverRunsByDefault(t *testing.T) {
	v, _, _ := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(npmDocument("helper"))) }, func(_ *Policy, o *Options) { o.Intelligence = fakeIntelligence{} })
	p := onePackage(t, v, "npm install helper@1.2.3")
	if p.MalwareCheck != "matched" || p.Identity != "unverified" || p.IntelligenceSource != "test-fixture" {
		t.Fatalf("intelligence = %+v", p)
	}
}

func TestUnresolvedGlobalSourcesNeverQueryPolicyDefault(t *testing.T) {
	v, _, hits := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(npmDocument("helper"))) }, nil)
	result := v.Verify(context.Background(), extract.Extract("docs", "```sh\nexport NPM_CONFIG_REGISTRY=https://private.example\nnpm install helper@1.2.3\n```", ""))
	if len(result.Packages) != 1 || result.Packages[0].State != "blocked" || result.Status != "partial" || hits.Load() != 0 {
		t.Fatalf("global override ignored: %+v", result)
	}
}

func FuzzRegistryMetadata(f *testing.F) {
	f.Add(npmDocument("helper"), "1.2.3")
	f.Add(`{"info":{"name":"helper","version":"1.0"},"releases":{"1.0":[]}}`, "==1.0")
	f.Add(`{"name":"helper","versions":{}}`, "latest")
	f.Fuzz(func(t *testing.T, data, spec string) {
		if len(data) > 64<<10 || len(spec) > 256 {
			t.Skip()
		}
		for _, adapter := range []RegistryClient{NPMClient{}, PyPIClient{}} {
			m := adapter.Inspect([]byte(data), "helper", spec)
			if len(m.Repository) > 515 || len(m.Version) > 128 {
				t.Fatal("unbounded metadata evidence")
			}
			if m.State == "found" && m.VersionState == "" {
				t.Fatal("missing version coverage state")
			}
		}
	})
}
