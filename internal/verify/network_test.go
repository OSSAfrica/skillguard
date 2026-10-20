package verify

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"skillguard/internal/extract"
)

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

func TestPrivateNetworkDefaultAndRedirects(t *testing.T) {
	v, _, hits := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(npmDocument("helper"))) }, func(p *Policy, _ *Options) { p.Registries[0].AllowPrivateNetwork = false })
	if p := onePackage(t, v, "npm install helper@1.2.3"); p.State != "blocked" || hits.Load() != 0 {
		t.Fatalf("private endpoint contacted by default: %+v", p)
	}
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	v, _, _ = localVerifier(t, "npm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}, nil)
	if p := onePackage(t, v, "npm install helper@1.2.3"); p.State != "unsupported_source" || redirected.Load() != 0 {
		t.Fatalf("redirect followed: %+v", p)
	}
}

func TestAddressBoundariesAndRebinding(t *testing.T) {
	for _, text := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2001:db8::1", "64:ff9b::7f00:1"} {
		if allowedAddress(netip.MustParseAddr(text), false) {
			t.Errorf("nonpublic address accepted: %s", text)
		}
	}
	if !allowedAddress(netip.MustParseAddr("8.8.8.8"), false) || !allowedAddress(netip.MustParseAddr("127.0.0.1"), true) || allowedAddress(netip.MustParseAddr("169.254.169.254"), true) {
		t.Fatal("public/private/metadata boundary mismatch")
	}
	var resolutions, connections int
	b := &broker{resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		resolutions++
		if resolutions == 1 {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}), connect: func(_ context.Context, _ string, address string) (net.Conn, error) {
		connections++
		if address != "8.8.8.8:443" {
			t.Errorf("redialed hostname or unchecked address: %s", address)
		}
		return nil, errors.New("fixture connection stopped")
	}}
	r := Registry{MetadataURL: "https://registry.example"}
	_, _ = b.dial(context.Background(), "tcp", "registry.example:443", r)
	if resolutions != 1 || connections != 1 {
		t.Fatal("unexpected extra resolution")
	}
	if _, err := b.dial(context.Background(), "tcp", "registry.example:443", r); !errors.Is(err, errUnsafeAddress) || connections != 1 {
		t.Fatal("rebinding to private destination accepted")
	}
	b.resolver = resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("10.0.0.1")}}, nil
	})
	if _, err := b.dial(context.Background(), "tcp", "registry.example:443", r); !errors.Is(err, errUnsafeAddress) {
		t.Fatal("mixed DNS answers accepted")
	}
}

func TestDestinationFactsAreNotOwnershipOrReachability(t *testing.T) {
	var calls int
	resolver := resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		calls++
		if host == "absent.example" {
			return nil, &net.DNSError{IsNotFound: true, Name: host}
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	})
	v, err := New(Policy{SchemaVersion: 1, DNSHosts: []string{"downloads.example", "absent.example"}}, Options{Resolver: resolver, Wait: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, tt := range []struct{ host, state string }{{"unapproved.example", "not_requested"}, {"downloads.example", "resolved"}, {"absent.example", "not_found"}, {"169.254.169.254", "literal"}} {
		result := v.Verify(context.Background(), extract.Extract("docs", "curl https://"+tt.host+"/install.sh", ""))
		if len(result.Destinations) != 1 {
			t.Fatalf("destination omitted: %+v", result)
		}
		d := result.Destinations[0]
		if d.Resolution != tt.state || d.Ownership != "unverified" || d.RegistrationAvailability != "unknown" || d.Reachability != "not_checked" {
			t.Fatalf("false destination claim: %+v", d)
		}
	}
	if calls != 2 {
		t.Fatalf("unauthorized DNS lookup: %d", calls)
	}
}

func TestRateLimitCancellationAndTLSValidation(t *testing.T) {
	var delays []time.Duration
	v, _, hits := localVerifier(t, "npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(npmDocument("helper"))) }, func(p *Policy, o *Options) {
		p.MinIntervalMS = 100
		o.Wait = func(ctx context.Context, d time.Duration) error { delays = append(delays, d); return ctx.Err() }
	})
	onePackage(t, v, "npm install helper@1.2.3")
	onePackage(t, v, "npm install helper@9.9.9")
	if len(delays) != 2 || delays[1] < 100*time.Millisecond || hits.Load() != 2 {
		t.Fatalf("rate budget not enforced: %v", delays)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(waitContext(ctx, time.Hour), context.Canceled) {
		t.Fatal("rate wait ignored cancellation")
	}
	if _, err := New(Policy{SchemaVersion: 1}, Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}}); err == nil {
		t.Fatal("TLS verification disabled")
	} // #nosec G402 -- explicit rejection test
}

func TestPublicCDNAnswerSetsAreBoundedAndFullyChecked(t *testing.T) {
	answers := make([]net.IPAddr, 24)
	for i := range answers {
		answers[i] = net.IPAddr{IP: net.ParseIP("8.8.8.8")}
	}
	var connections int
	b := &broker{resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return answers, nil }), connect: func(context.Context, string, string) (net.Conn, error) {
		connections++
		return nil, errors.New("fixture stopped")
	}}
	r := Registry{MetadataURL: "https://registry.example"}
	_, err := b.dial(context.Background(), "tcp", "registry.example:443", r)
	if errors.Is(err, errUnsafeAddress) || errors.Is(err, errDNSLimit) || connections != 24 {
		t.Fatalf("ordinary CDN set blocked: %v, connections %d", err, connections)
	}
	answers = append(answers, net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	connections = 0
	if _, err := b.dial(context.Background(), "tcp", "registry.example:443", r); !errors.Is(err, errUnsafeAddress) || connections != 0 {
		t.Fatal("late private answer not checked before connecting")
	}
	answers = make([]net.IPAddr, maxDNSAnswers+1)
	if _, err := b.addresses(context.Background(), "registry.example"); !errors.Is(err, errDNSLimit) {
		t.Fatal("DNS response budget not enforced")
	}
}
