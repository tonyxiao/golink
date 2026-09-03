// Copyright 2026 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

package golink

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeDiscoveryClient struct {
	status                 *ipnstate.Status
	services               map[tailcfg.ServiceName]tailcfg.ServiceDetails
	statusErr, servicesErr error
}

type fakeServiceDescriptionClient struct {
	descriptions map[tailcfg.ServiceName]string
	err          error
}

func (f fakeServiceDescriptionClient) ServiceDescriptions(context.Context) (map[tailcfg.ServiceName]string, error) {
	return f.descriptions, f.err
}

func (f fakeDiscoveryClient) Status(context.Context) (*ipnstate.Status, error) {
	return f.status, f.statusErr
}

func (f fakeDiscoveryClient) GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error) {
	return f.services, f.servicesErr
}

func discoveryFixture(t *testing.T) fakeDiscoveryClient {
	t.Helper()
	ports, err := tailcfg.ParseProtoPortRanges([]string{"tcp:443"})
	if err != nil {
		t.Fatal(err)
	}
	peer := func(id, dns string, online bool) *ipnstate.PeerStatus {
		return &ipnstate.PeerStatus{
			ID: tailcfg.StableNodeID(id), DNSName: dns, Online: online,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")},
		}
	}
	peers := map[key.NodePublic]*ipnstate.PeerStatus{}
	add := func(p *ipnstate.PeerStatus) {
		peers[key.NewNode().Public()] = p
	}
	add(peer("regular", "app.example.ts.net.", false))
	sharee := peer("sharee", "shared.example.ts.net.", true)
	sharee.ShareeNode = true
	add(sharee)
	mullvad := peer("mullvad", "us-sea-wg-001.mullvad.ts.net.", true)
	mullvad.ExitNodeOption = true
	add(mullvad)
	selectedMullvad := peer("selected", "us-lax-wg-001.mullvad.ts.net.", true)
	selectedMullvad.ExitNodeOption = true
	selectedMullvad.ExitNode = true
	add(selectedMullvad)

	return fakeDiscoveryClient{
		status: &ipnstate.Status{
			Self:           peer("self", "self.example.ts.net.", true),
			Peer:           peers,
			CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "example.ts.net"},
		},
		services: map[tailcfg.ServiceName]tailcfg.ServiceDetails{
			"svc:app": {
				Name: "svc:app", DisplayName: "The application", Ports: ports,
				Addrs: []netip.Addr{netip.MustParseAddr("100.100.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
			},
		},
	}
}

func TestDiscoverTailscaleLinks(t *testing.T) {
	got, err := discoverTailscaleLinks(context.Background(), discoveryFixture(t), map[string]string{linkID("self"): "https://stored.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 {
		t.Fatalf("got %d Services; want 1", len(got.Services))
	}
	service := got.Services[0]
	if service.Short != "app" || service.Long != "https://app.example.ts.net/" || service.Description != "The application" {
		t.Errorf("Service = %+v", service)
	}
	if len(service.IPs) != 1 || service.IPs[0] != "100.100.0.1" {
		t.Errorf("Service IPs = %v; want only IPv4", service.IPs)
	}

	// Self, a regular offline peer, and a selected Mullvad exit node are shown.
	// A sharee and an unselected Mullvad exit node are hidden, matching the CLI.
	if len(got.Devices) != 3 {
		t.Fatalf("got %d Devices; want 3: %+v", len(got.Devices), got.Devices)
	}
	if got.Devices[0].Short != "device-app" { // svc:app owns the natural alias
		t.Errorf("colliding device alias = %q; want device-app", got.Devices[0].Short)
	}
	if got.Devices[1].Short != "device-self" { // stored link owns the natural alias
		t.Errorf("reserved self alias = %q; want device-self", got.Devices[1].Short)
	}
	if got.Devices[0].Online {
		t.Error("offline device reported online")
	}
	for _, device := range got.Devices {
		if strings.Contains(device.Short, "shared") || strings.Contains(device.Short, "sea") {
			t.Errorf("hidden status entry included: %+v", device)
		}
	}
}

func TestServiceDescriptions(t *testing.T) {
	fixture := discoveryFixture(t)
	descriptions := fakeServiceDescriptionClient{descriptions: map[tailcfg.ServiceName]string{
		"svc:app": "Description from the admin API",
	}}
	got, err := discoverTailscaleLinksWithDescriptions(context.Background(), fixture, descriptions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Services[0].Description != "Description from the admin API" {
		t.Fatalf("description = %q", got.Services[0].Description)
	}

	// Description lookup is optional enrichment and may not prevent LocalAPI
	// Services from being listed or resolved.
	descriptions.err = errors.New("API unavailable")
	got, err = discoverTailscaleLinksWithDescriptions(context.Background(), fixture, descriptions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Services[0].Description != "The application" {
		t.Fatalf("fallback description = %q", got.Services[0].Description)
	}
}

func TestTailscaleAPIServiceDescriptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/tailnet/-/vip-services" {
			t.Errorf("path = %q", r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "secret" || password != "" {
			t.Errorf("unexpected API authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vipServices":[{"name":"svc:app","comment":"The admin description"},{"name":"svc:empty"}]}`))
	}))
	defer server.Close()

	client := &tailscaleAPIServiceDescriptionClient{
		apiKey: "secret", tailnet: "-", baseURL: server.URL, httpClient: server.Client(),
	}
	got, err := client.ServiceDescriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got["svc:app"] != "The admin description" {
		t.Fatalf("description = %q", got["svc:app"])
	}
	if _, ok := got["svc:empty"]; ok {
		t.Fatal("empty description unexpectedly included")
	}
}

func TestServiceCollisionAliases(t *testing.T) {
	fixture := discoveryFixture(t)

	matching, err := discoverTailscaleLinks(context.Background(), fixture, map[string]string{
		linkID("app"): "https://app.example.ts.net/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := matching.Services[0].Short; got != "app" {
		t.Errorf("matching stored Service alias = %q; want app", got)
	}

	conflicting, err := discoverTailscaleLinks(context.Background(), fixture, map[string]string{
		linkID("app"): "https://different.example/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := conflicting.Services[0].Short; got != "app-service" {
		t.Errorf("conflicting stored Service alias = %q; want app-service", got)
	}
}

func TestDynamicLinkResolutionAndHome(t *testing.T) {
	var err error
	db, err = NewSQLiteDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	oldClient := discoveryClient
	discoveryClient = discoveryFixture(t)
	t.Cleanup(func() { discoveryClient = oldClient })

	r := httptest.NewRequest(http.MethodGet, "/app/path?q=1", nil)
	w := httptest.NewRecorder()
	serveHandler().ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://app.example.ts.net/path?q=1" {
		t.Fatalf("dynamic redirect = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	if _, err := db.Load("app"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dynamic link was persisted: Load(app) returned %v", err)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	serveHandler().ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{"Services (1)", "Devices (3)", "The application", "100.100.0.1", "offline"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
	if strings.Contains(body, "fd7a:115c:a1e0::") {
		t.Error("home page unexpectedly contains an IPv6 address")
	}

	if err := db.Save(&Link{Short: "app", Long: "https://manual.example/"}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/app", nil)
	w = httptest.NewRecorder()
	serveHandler().ServeHTTP(w, r)
	if got := w.Header().Get("Location"); got != "https://manual.example/" {
		t.Errorf("manual link did not win collision: got %q", got)
	}
}
