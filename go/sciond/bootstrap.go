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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"time"
)

const (
	discoveryPort uint16 = 8041
)

var (
	channel = make(chan string)
)

func tryBootstrapping() (*topology.Topo, error) {
	hintGenerators := []HintGenerator{
		&StaticHintGenerator{},
		&DHCPHintGenerator{},
		&RouterAdvertisementHintGenerator{},
		&DNSServiceDiscoveryHintGenerator{}}
	var topo *topology.Topo

	for i := 0; i < len(hintGenerators); i++ {
		x := hintGenerators[i]
		go func() {
			defer log.LogPanicAndExit()
			x.Generate(channel)
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
		IA:                    topo.ISD_AS,
		Public:                cfg.SD.Public,
		Bind:                  cfg.SD.Bind,
		SVC:                   addr.SvcNone,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		TrustStore:            trustStore,
		SVCRouter:             messenger.NewSVCRouter(provider),
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
	log.Debug("Trying to fetch from " + address)

	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	params := discovery.FetchParams{Mode: discovery.Static, File: discovery.Endhost}

	ip := addr.HostFromIPStr(address)

	if ip == nil {
		return nil
	}

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
	// TODO (veenj)

}

var _ HintGenerator = (*DNSSNAPTRHintGenerator)(nil)

type DNSSNAPTRHintGenerator struct{}

func (g *DNSSNAPTRHintGenerator) Generate(channel chan string) {
	// TODO (veenj)

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

var _ HintGenerator = (*DNSServiceDiscoveryHintGenerator)(nil)

type DNSServiceDiscoveryHintGenerator struct{}

func (g *DNSServiceDiscoveryHintGenerator) Generate(channel chan string) {
	// TODO (veenj)

}

type providerFunc func() *topology.Topo

func (f providerFunc) Get() *topology.Topo {
	return f()
}
