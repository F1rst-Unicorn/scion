// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"github.com/grandcat/zeroconf"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/miekg/dns"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"net"
	"os"
	"strings"
	"time"
)

const (
	discoveryPort uint16 = 8041
)

var (
	channel = make(chan string)
	dnsServersChannel = make(chan DNSInfo)
)

func tryBootstrapping() (*topology.Topo, error) {
	hintGenerators := []HintGenerator{
		&StaticHintGenerator{},
		&DHCPHintGenerator{},
		&RouterAdvertisementHintGenerator{},
		&DNSSDHintGenerator{},
		&MDNSSDHintGenerator{}}
	var topo *topology.Topo

	for i := 0; i < len(hintGenerators); i++ {
		generator := hintGenerators[i]
		go func() {
			defer log.LogPanicAndExit()
			generator.Generate(channel)
		}()
	}

	for {
		log.Debug("Bootstrapper is waiting for hints")
		address := <-channel
		topo = fetchTopology(address)

		if topo != nil {
			err := fetchTRC(topo)
			if err != nil {
				return nil, err
			}
			return topo, nil
		}
	}
}

func fetchTRC(topo *topology.Topo) error {
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return err
	}
	defer trustDB.Close()
	provider := providerFunc(func() *topology.Topo { return topo })
	trustConf := trust.Config{TopoProvider: provider}
	trustStore := trust.NewStore(trustDB, topo.ISD_AS, trustConf, log.Root())
	nc := infraenv.NetworkConfig{
		IA:					topo.ISD_AS,
		Public:				cfg.SD.Public,
		Bind:				  cfg.SD.Bind,
		SVC:				   addr.SvcNone,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		TrustStore:			trustStore,
		SVCRouter:			 messenger.NewSVCRouter(provider),
	}
	_, err = nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return err
	}
	err = trustStore.LoadAuthoritativeTRCWithNetwork("")
	if err != nil {
		log.Crit("Unable to load local TRC", "err", err)
		return err
	}

	err = verifyTopology(topo)
	if err != nil {
		return err
	}
	return nil
}

func fetchTopology(address string) *topology.Topo {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	params := discovery.FetchParams{Mode: discovery.Static, File: discovery.Endhost}

	ip := addr.HostFromIPStr(address)

	if ip == nil {
		log.Debug("Discovered invalid address", "address", address)
		return nil
	}
	log.Debug("Trying to fetch from " + address)

	topo, err := discovery.FetchTopo(ctx, params, &addr.AppAddr{L3: ip, L4: addr.NewL4TCPInfo(discoveryPort)}, nil)

	if err != nil {
		log.Debug("Nothing was found")
		return nil
	}

	log.Debug("candidate topology found")
	return topo
}

func verifyTopology(topo *topology.Topo) error {
	// TODO (veenj)
	return nil
}

type HintGenerator interface {
	Generate(resultChannel chan string)
}

var _ HintGenerator = (*DHCPHintGenerator)(nil)

type DHCPHintGenerator struct{}

func (g *DHCPHintGenerator) Generate(channel chan string) {
	interfaces, err := net.Interfaces()

	if err != nil {
		log.Crit("DHCP could not list interfaces", "err", err)
		return
	}

	for _, intf := range interfaces {
		currentInterface := intf
		go func() {
			defer log.LogPanicAndExit()
			probeInterface(currentInterface, channel)
		}()
	}
}

func probeInterface(currentInterface net.Interface, channel chan string) {
	log.Debug("DHCP Probing", "interface", currentInterface.Name)
	client := client4.NewClient()
	localIPs, err := dhcpv4.IPv4AddrsForInterface(&currentInterface)
	if err != nil || len(localIPs) == 0 {
		log.Warn("DHCP could not get local IPs", "interface", currentInterface.Name, "err", err)
		return
	}
	p, err := dhcpv4.NewInform(currentInterface.HardwareAddr, localIPs[0], dhcpv4.WithRequestedOptions(
		dhcpv4.OptionDefaultWorldWideWebServer,
		dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDNSDomainSearchList))
	if err != nil {
		log.Crit("DHCP hinter failed to build network packet", "interface", currentInterface.Name, "err", err)
		return
	}
	p.SetBroadcast()
	sender, err := client4.MakeBroadcastSocket(currentInterface.Name)
	if err != nil {
		log.Crit("DHCP hinter failed to open broadcast sender socket", "interface", currentInterface.Name, "err", err)
		return
	}
	receiver, err := client4.MakeListeningSocket(currentInterface.Name)
	if err != nil {
		log.Crit("DHCP hinter failed to open receiver socket", "interface", currentInterface.Name, "err", err)
		return
	}
	ack, err := client.SendReceive(sender, receiver, p, dhcpv4.MessageTypeAck)
	if err != nil {
		log.Warn("DHCP hinter failed to send inform request", "interface", currentInterface.Name, "err", err)
		return
	}
	channel <- dhcpv4.GetIP(dhcpv4.OptionDefaultWorldWideWebServer, ack.Options).String()

	resolvers := dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options)
	rawSearchDomains := ack.Options.Get(dhcpv4.OptionDNSDomainSearchList)
	searchDomains, err := rfc1035label.FromBytes(rawSearchDomains)

	dnsInfo := DNSInfo{}

	for _, item := range resolvers {
		dnsInfo.resolvers = append(dnsInfo.resolvers, item.String())
	}
	for _, item := range searchDomains.Labels {
		dnsInfo.searchDomains = append(dnsInfo.searchDomains, item)
	}

	dnsServersChannel <- dnsInfo
}

var _ HintGenerator = (*DNSSDHintGenerator)(nil)

// Domain Name System Service Discovery
type DNSSDHintGenerator struct{}

func (g *DNSSDHintGenerator) Generate(channel chan string) {
	for {
		dnsServer := <- dnsServersChannel
		dnsServer.searchDomains = append(dnsServer.searchDomains, getDomainName())

		for _, resolver := range dnsServer.resolvers {
			for _, domain:= range dnsServer.searchDomains {
				doServiceDiscovery(resolver, domain)
				doSNAPTRDiscovery(resolver, domain)
			}
		}
	}
}

type DNSInfo struct {
	resolvers     []string
	searchDomains []string
}

// Straightforward Naming Authority Pointer
func doSNAPTRDiscovery(dnsServer, domain string) {
	// TODO
}

func doServiceDiscovery(resolver, domain string) {
	queryString := "_sciondiscovery._tcp." + domain + "."
	log.Debug("DNS-SD", "query", queryString, "resolver", resolver)

	msg := new(dns.Msg)
	msg.SetQuestion(queryString, dns.TypePTR)
	msg.RecursionDesired = true
	result, err := dns.Exchange(msg, resolver+":53")
	if err != nil {
		log.Warn("DNS-SD failed", "err", err)
		return
	}
	sections := append(result.Answer, result.Ns...)
	sections = append(sections, result.Extra...)
	for _, answer := range sections {
		log.Debug("DNS-SD Found record", "answer", answer)
		switch rr := answer.(type) {
		case *dns.A:
		}
	}
}

var _ HintGenerator = (*StaticHintGenerator)(nil)

type StaticHintGenerator struct{}

func (g *StaticHintGenerator) Generate(channel chan string) {
	channel <- "127.0.0.252"
}

var _ HintGenerator = (*RouterAdvertisementHintGenerator)(nil)

type RouterAdvertisementHintGenerator struct{}

func (g *RouterAdvertisementHintGenerator) Generate(channel chan string) {
	// TODO (veenj)

}

var _ HintGenerator = (*MDNSSDHintGenerator)(nil)

// Multicast Domain Name System Service Discovery
type MDNSSDHintGenerator struct{}

func (g *MDNSSDHintGenerator) Generate(channel chan string) {
	resolver, err := zeroconf.NewResolver(nil)
	if err!= nil{
		log.Warn("mDNS could not construct dns resolver", "err", err)
		return
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		defer log.LogPanicAndExit()
		for entry := range results {
			for _, address := range entry.AddrIPv4 {
				channel <- address.String()
			}
			for _, address := range entry.AddrIPv6 {
				channel <- address.String()
			}
		}
		log.Debug("mDNS has no more entries.")
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = resolver.Browse(ctx, "_sciondiscovery._tcp", "local.", entries)
	if err != nil {
		log.Warn("mDNS could not lookup", "err", err)
		return
	}
	<-ctx.Done()
}

func getDomainName() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Warn("Bootstrapper could not get hostname", "err", err)
		return ""
	}
	split := strings.SplitAfterN(hostname, ".", 2)
	if len(split) < 2 {
		log.Warn("Bootstrapper could not get domain name", "hostname", hostname, "split", split)
		return ""
	} else {
		log.Debug("Bootstrapper", "domain", split[1])
	}
	return split[1]
}

type providerFunc func() *topology.Topo

func (f providerFunc) Get() *topology.Topo {
	return f()
}
