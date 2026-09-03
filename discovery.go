// Copyright 2026 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

package golink

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

const mullvadDNSNameSuffix = "mullvad.ts.net."

type tailscaleDiscoveryClient interface {
	Status(context.Context) (*ipnstate.Status, error)
	GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error)
}

type tailscaleServiceDescriptionClient interface {
	ServiceDescriptions(context.Context) (map[tailcfg.ServiceName]string, error)
}

// tailscaleAPIServiceDescriptionClient reads the Service comments displayed
// as "Description" in the Tailscale admin console. This metadata is only
// exposed by the control-plane API, not the LocalAPI used by GetServices.
type tailscaleAPIServiceDescriptionClient struct {
	apiKey     string
	tailnet    string
	baseURL    string
	httpClient *http.Client
}

func newTailscaleAPIServiceDescriptionClient(apiKey, tailnet string) tailscaleServiceDescriptionClient {
	if apiKey == "" {
		return nil
	}
	if tailnet == "" {
		tailnet = "-"
	}
	return &tailscaleAPIServiceDescriptionClient{
		apiKey: apiKey, tailnet: tailnet, baseURL: "https://api.tailscale.com",
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *tailscaleAPIServiceDescriptionClient) ServiceDescriptions(ctx context.Context) (map[tailcfg.ServiceName]string, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/api/v2/tailnet/" + url.PathEscape(c.tailnet) + "/vip-services"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiKey, "")
	req.Header.Set("User-Agent", "tailscale-golink")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("Tailscale API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var result struct {
		VIPServices []struct {
			Name    tailcfg.ServiceName `json:"name"`
			Comment string              `json:"comment"`
		} `json:"vipServices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, err
	}
	descriptions := make(map[tailcfg.ServiceName]string, len(result.VIPServices))
	for _, service := range result.VIPServices {
		if service.Comment != "" {
			descriptions[service.Name] = service.Comment
		}
	}
	return descriptions, nil
}

// discoveredLink is a live link derived from the Tailscale LocalAPI. It is
// never stored in the golink database.
type discoveredLink struct {
	Short       string
	Long        string
	Kind        string
	Description string
	IPs         []string
	Online      bool
}

type discoveredLinks struct {
	Services []discoveredLink
	Devices  []discoveredLink
}

func (d discoveredLinks) lookup(short string) (discoveredLink, bool) {
	id := linkID(short)
	for _, links := range [][]discoveredLink{d.Services, d.Devices} {
		for _, link := range links {
			if linkID(link.Short) == id {
				return link, true
			}
		}
	}
	return discoveredLink{}, false
}

// discoverTailscaleLinks returns the same device set shown by `tailscale
// status`, plus every Service shown by `tailscale service list`. The provided
// reserved names (normally the stored golinks) always keep their aliases.
func discoverTailscaleLinks(ctx context.Context, client tailscaleDiscoveryClient, reserved map[string]string) (discoveredLinks, error) {
	return discoverTailscaleLinksWithDescriptions(ctx, client, nil, reserved)
}

func discoverTailscaleLinksWithDescriptions(ctx context.Context, client tailscaleDiscoveryClient, descriptionClient tailscaleServiceDescriptionClient, reserved map[string]string) (discoveredLinks, error) {
	status, err := client.Status(ctx)
	if err != nil {
		return discoveredLinks{}, fmt.Errorf("tailscale status: %w", err)
	}
	services, err := client.GetServices(ctx)
	if err != nil {
		return discoveredLinks{}, fmt.Errorf("tailscale service list: %w", err)
	}
	// Descriptions are optional enrichment. A control-plane API failure must
	// never hide LocalAPI Services or prevent their golinks from resolving.
	var descriptions map[tailcfg.ServiceName]string
	if descriptionClient != nil {
		if liveDescriptions, err := descriptionClient.ServiceDescriptions(ctx); err == nil {
			descriptions = liveDescriptions
		}
	}

	var suffix string
	if status.CurrentTailnet != nil {
		suffix = strings.TrimSuffix(status.CurrentTailnet.MagicDNSSuffix, ".")
	}

	var result discoveredLinks
	for name, service := range services {
		short := name.WithoutPrefix()
		host := short
		if suffix != "" {
			host += "." + suffix
		}
		description := service.DisplayName
		if descriptions[name] != "" {
			description = descriptions[name]
		}
		result.Services = append(result.Services, discoveredLink{
			Short:       short,
			Long:        serviceURL(host, service),
			Kind:        "Service",
			Description: description,
			IPs:         addressStrings(service.Addrs),
			Online:      true,
		})
	}

	addDevice := func(peer *ipnstate.PeerStatus) {
		if peer == nil {
			return
		}
		fqdn := strings.TrimSuffix(peer.DNSName, ".")
		short, _, _ := strings.Cut(fqdn, ".")
		if short == "" {
			short = peer.HostName
		}
		if short == "" {
			short = "device-" + string(peer.ID)
		}
		host := fqdn
		if host == "" && len(peer.TailscaleIPs) > 0 {
			host = peer.TailscaleIPs[0].String()
			if peer.TailscaleIPs[0].Is6() {
				host = "[" + host + "]"
			}
		}
		result.Devices = append(result.Devices, discoveredLink{
			Short:  short,
			Long:   "http://" + host + "/",
			Kind:   "Device",
			IPs:    addressStrings(peer.TailscaleIPs),
			Online: peer.Online,
		})
	}

	addDevice(status.Self)
	for _, key := range status.Peers() {
		peer := status.Peer[key]
		if peer.ShareeNode {
			continue
		}
		if peer.ExitNodeOption && !peer.ExitNode && strings.HasSuffix(peer.DNSName, mullvadDNSNameSuffix) {
			continue
		}
		addDevice(peer)
	}

	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Short < result.Services[j].Short })
	sort.Slice(result.Devices, func(i, j int) bool { return result.Devices[i].Short < result.Devices[j].Short })
	assignDiscoveredAliases(&result, reserved)
	return result, nil
}

func assignDiscoveredAliases(links *discoveredLinks, reserved map[string]string) {
	used := make(map[string]bool)
	for id := range reserved {
		used[id] = true
	}
	assign := func(link *discoveredLink, prefix, suffix string) {
		preferred := link.Short
		if !used[linkID(preferred)] {
			used[linkID(preferred)] = true
			return
		}
		base := prefix + preferred + suffix
		candidate := base
		for n := 2; used[linkID(candidate)]; n++ {
			candidate = fmt.Sprintf("%s-%d", base, n)
		}
		link.Short = candidate
		used[linkID(candidate)] = true
	}
	// A stored link that already points to a Service represents the same alias;
	// don't invent a second service-prefixed name for it. A genuine conflict
	// gets a suffix so Service names remain natural in the usual case.
	for i := range links.Services {
		service := &links.Services[i]
		if long, ok := reserved[linkID(service.Short)]; ok && long == service.Long {
			continue
		}
		assign(service, "", "-service")
	}
	// Services own the natural name when they collide with a device.
	for i := range links.Devices {
		assign(&links.Devices[i], "device-", "")
	}
}

func addressStrings(addrs []netip.Addr) []string {
	var result []string
	for _, addr := range addrs {
		if addr.Is4() {
			result = append(result, addr.String())
		}
	}
	return result
}

func serviceURL(host string, service tailcfg.ServiceDetails) string {
	var port uint16
	for _, action := range service.Actions {
		if action.Type == tailcfg.ServiceActionTypeHTTP {
			port = action.Port
			if port == 443 {
				break
			}
		}
	}
	if port == 0 {
		for _, p := range service.Ports {
			if p.Proto != 0 && p.Proto != int(ipproto.TCP) || p.Ports.First != p.Ports.Last {
				continue
			}
			if p.Ports.First == 443 {
				port = 443
				break
			}
			if port == 0 || p.Ports.First == 80 {
				port = p.Ports.First
			}
		}
	}

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	if port != 0 && port != 80 && port != 443 {
		host = net.JoinHostPort(host, fmt.Sprint(port))
	}
	return scheme + "://" + host + "/"
}
