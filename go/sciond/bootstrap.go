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
	"bytes"
	"context"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"io/ioutil"
	"time"
)

const (
	discoveryPort uint16 = 8041
)

func tryBootstrapping(hintDirectory string) (*topology.Topo, error) {
	addresses := readLinesFromAllFiles(hintDirectory)
	log.Trace("hint addresses: ", "addresses", addresses)
	var topologies []*topology.Topo

	for i := 0; i < len(addresses); i++ {
		topo := fetchTopology(addresses[i])
		if topo != nil {
			topologies = append(topologies, topo)
		}
	}

	switch len(topologies) {
	case 0:
		return nil, common.NewBasicError("Bootstrapping failed, no topologies found in '" + hintDirectory + "'", nil)
	case 1:
		return topologies[0], nil
	default:
		log.Info("Found several topologies, using first one")
		return topologies[0], nil
	}
}

func fetchTopology(address string) *topology.Topo {
	log.Debug("Trying to fetch from " + address)

	ctx, cancelF := context.WithTimeout(context.Background(), 2 * time.Second)
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

func readLinesFromAllFiles(hintDirectory string) []string {
	var result []string

	if hintDirectory == "" {
		return result
	}

	files, err := ioutil.ReadDir(hintDirectory)

	log.Trace("Reading directory '" + hintDirectory + "'")

	if err != nil {
		return result
	}

	for i := 0; i < len(files); i++ {
		if files[i].IsDir() {
			continue
		}
		log.Trace("Reading file '" + files[i].Name() + "'")

		path := hintDirectory + "/" + files[i].Name()
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Warn("Bootstrapping skips file ", path)
		}

		lines := bytes.Split(content, []byte{ byte('\n') })
		for j := 0; j < len(lines); j++ {
			if len(lines[j]) > 0 {
				result = append(result, string(lines[j]))
			}
		}
	}
	return result
}
