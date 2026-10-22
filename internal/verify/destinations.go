package verify

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"skillguard/internal/extract"
	"skillguard/internal/model"
)

func (v *Verifier) destination(ctx context.Context, d model.Destination, location model.SourceSpan) model.DestinationObservation {
	observation := model.DestinationObservation{URL: extract.SafeSource(d.URL), Resolution: "not_requested", AddressScope: "unknown", Ownership: "unverified", RegistrationAvailability: "unknown", Reachability: "not_checked", ObservedAt: v.now().UTC(), Location: location}
	u, err := url.Parse(d.URL)
	if err != nil || u.Hostname() == "" {
		observation.Resolution = "unsupported_source"
		return observation
	}
	observation.Host = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, err := netip.ParseAddr(observation.Host); err == nil {
		observation.Resolution = "literal"
		observation.AddressScope = addressScope([]netip.Addr{ip.Unmap()})
		return observation
	}
	authorized := false
	for _, host := range v.policy.DNSHosts {
		if host == observation.Host {
			authorized = true
			break
		}
	}
	if !authorized {
		return observation
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(v.policy.TimeoutSeconds)*time.Second)
	defer cancel()
	if err := v.reserve(ctx); err != nil {
		observation.Resolution = errorState(err)
		return observation
	}
	ips, err := v.broker.addresses(ctx, observation.Host)
	if err != nil {
		observation.Resolution = errorState(err)
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			observation.Resolution = "not_found"
		}
		return observation
	}
	observation.Resolution = "resolved"
	observation.AddressScope = addressScope(ips)
	observation.Signals = []model.VerificationSignal{{ID: "SG_DESTINATION_IDENTITY_UNVERIFIED", Message: "DNS resolution does not establish ownership, registration availability, or network reachability.", NextStep: "Confirm the destination independently; do not treat a DNS response as artifact trust."}}
	return observation
}

func addressScope(ips []netip.Addr) string {
	public, nonpublic := false, false
	for _, ip := range ips {
		if allowedAddress(ip, false) {
			public = true
		} else {
			nonpublic = true
		}
	}
	if public && nonpublic {
		return "mixed"
	}
	if public {
		return "public"
	}
	return "non_public"
}
