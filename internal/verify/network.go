package verify

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20
const maxDNSAnswers = 64

var errUnsafeAddress = errors.New("network destination is outside policy boundaries")
var errBudget = errors.New("verification request budget exhausted")
var errDNSLimit = errors.New("DNS answer limit exceeded")

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// Fetcher is the bounded metadata transport shared by registry adapters.
type Fetcher interface {
	Fetch(context.Context, Registry, string) ([]byte, string, string)
}

type broker struct {
	resolver  Resolver
	connect   func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config
	owner     *Verifier
	clients   map[string]*http.Client
}

func (b *broker) dial(ctx context.Context, network, address string, r Registry) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errUnsafeAddress
	}
	u, err := url.Parse(r.MetadataURL)
	if err != nil || !strings.EqualFold(host, u.Hostname()) {
		return nil, errUnsafeAddress
	}
	expectedPort := u.Port()
	if expectedPort == "" {
		expectedPort = "443"
	}
	if port != expectedPort {
		return nil, errUnsafeAddress
	}
	ips, err := b.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !allowedAddress(ip, r.AllowPrivateNetwork) {
			return nil, errUnsafeAddress
		}
	}
	var last error
	for _, ip := range ips {
		// Dial the validated numeric address, not the hostname: there is no
		// second DNS resolution between the SSRF check and connection.
		conn, err := b.connect(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no addresses available")
	}
	return nil, last
}

func (b *broker) addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	answers, err := b.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(answers) > maxDNSAnswers {
		return nil, errDNSLimit
	}
	if len(answers) == 0 {
		return nil, errors.New("no DNS addresses available")
	}
	result := make([]netip.Addr, 0, len(answers))
	for _, a := range answers {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || a.Zone != "" {
			return nil, errUnsafeAddress
		}
		result = append(result, ip.Unmap())
	}
	return result, nil
}

var specialRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2002::/16"),
}

func allowedAddress(ip netip.Addr, allowPrivate bool) bool {
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return allowPrivate
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range specialRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (b *broker) client(r Registry) *http.Client {
	if c := b.clients[r.ID]; c != nil {
		return c
	}
	t := &http.Transport{
		Proxy: nil, TLSClientConfig: b.tlsConfig.Clone(), MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2,
		TLSHandshakeTimeout:   time.Duration(b.owner.policy.TimeoutSeconds) * time.Second,
		ResponseHeaderTimeout: time.Duration(b.owner.policy.TimeoutSeconds) * time.Second,
		IdleConnTimeout:       30 * time.Second, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return b.dial(ctx, network, address, r)
		},
	}
	c := &http.Client{Transport: t, Timeout: time.Duration(b.owner.policy.TimeoutSeconds) * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	b.clients[r.ID] = c
	return c
}

func (b *broker) Fetch(ctx context.Context, r Registry, target string) ([]byte, string, string) {
	if err := b.owner.reserve(ctx); err != nil {
		return nil, errorState(err), "request_not_started"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "unsupported_source", "invalid_metadata_endpoint"
	}
	configured, _ := url.Parse(r.MetadataURL)
	if configured == nil || req.URL.Scheme != "https" || req.URL.Host != configured.Host || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.Fragment != "" {
		return nil, "blocked", "metadata_endpoint_outside_policy"
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SkillGuard-metadata-verifier")
	if r.AuthEnv != "" {
		token, ok := os.LookupEnv(r.AuthEnv)
		if !ok || token == "" || strings.ContainsAny(token, "\r\n") {
			return nil, "unauthorized", "operator_credential_unavailable"
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := b.client(r).Do(req)
	if err != nil {
		return nil, errorState(err), networkFailureReason(err)
	}
	defer func() { _ = response.Body.Close() }()
	state := statusState(response.StatusCode)
	if state != "found" {
		return nil, state, "registry_http_status"
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "json") {
		return nil, "malformed_response", "non_json_content_type"
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errorState(err), "metadata_body_incomplete"
	}
	if len(body) > maxResponseBytes {
		return nil, "malformed_response", "response_limit"
	}
	return body, "found", ""
}

func statusState(code int) string {
	switch {
	case code == 200:
		return "found"
	case code == 404:
		return "missing"
	case code == 401 || code == 403:
		return "unauthorized"
	case code == 429:
		return "rate_limited"
	case code == 408 || code == 504:
		return "timeout"
	case code >= 300 && code < 400:
		return "unsupported_source"
	default:
		return "unavailable"
	}
}

func errorState(err error) string {
	if errors.Is(err, errUnsafeAddress) || errors.Is(err, errDNSLimit) {
		return "blocked"
	}
	if errors.Is(err, errBudget) {
		return "request_limit"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "unavailable"
}

func networkFailureReason(err error) string {
	if errors.Is(err, errDNSLimit) {
		return "dns_answer_limit"
	}
	if errors.Is(err, errUnsafeAddress) {
		return "network_boundary"
	}
	return "metadata_request_failed"
}
