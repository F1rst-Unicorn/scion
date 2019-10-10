// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/config"
	"github.com/scionproto/scion/go/sciond/internal/drkey"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/metrics"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

var (
	cfg         config.Config
	discRunners idiscovery.Runners
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("SD", cfg.General.ID)
	defer log.LogPanicAndExit()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	if err := startDiscovery(); err != nil {
		log.Crit("Unable to start topology fetcher", "err", err)
		return 1
	}
	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.SD.PathDB, cfg.SD.RevCache)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	defer pathDB.Close()
	defer revCache.Close()
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	defer trustDB.Close()
	trustConf := trust.Config{TopoProvider: itopo.Provider()}
	trustStore := trust.NewStore(trustDB, itopo.Get().ISD_AS, trustConf, log.Root())
	tracer, trCloser, err := cfg.Tracing.NewTracer(cfg.General.ID)
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)
	nc := infraenv.NetworkConfig{
		IA:                    itopo.Get().ISD_AS,
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
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
	}
	msger, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	trcPath := filepath.Join(cfg.General.ConfigDir, "certs")
	err = trustStore.LoadAuthoritativeTRC(trcPath)
	if err != nil {
		log.Crit("Unable to load local TRC", "err", err)
		return 1
	}

	// Route messages to their correct handlers
	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: fetcher.NewFetcher(
				msger,
				pathDB,
				trustStore,
				revCache,
				cfg.SD,
				log.Root(),
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			ASInspector: trustStore,
		},
		proto.SCIONDMsg_Which_ifInfoRequest:      &servers.IFInfoRequestHandler{},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache:        revCache,
			VerifierFactory: trustStore,
		},
	}

	drkeyEnabled := cfg.SD.DRKeyDB.Connection() != ""
	log.Info("DRKey", "enabled", drkeyEnabled)
	if drkeyEnabled {
		drkeyDB, err := cfg.SD.DRKeyDB.NewLvl2DB()
		if err != nil {
			log.Crit("Unable to initialize drkey storage", "err", err)
			return 1
		}
		defer drkeyDB.Close()
		drkeyStore := drkey.NewClientStore(itopo.Get().ISD_AS, drkeyDB, msger)
		drkeyCleaner := periodic.StartPeriodicTask(drkeystorage.NewStoreCleaner(drkeyStore),
			periodic.NewTicker(time.Hour), 10*time.Minute)
		defer drkeyCleaner.Stop()
		handlers[proto.SCIONDMsg_Which_drkeyLvl2Req] = &servers.DrKeyLvl2RequestHandler{
			Store: drkeyStore,
		}
	}
	cleaner := periodic.StartPeriodicTask(pathdb.NewCleaner(pathDB),
		periodic.NewTicker(300*time.Second), 295*time.Second)
	defer cleaner.Stop()
	rcCleaner := periodic.StartPeriodicTask(revcache.NewCleaner(revCache),
		periodic.NewTicker(10*time.Second), 10*time.Second)
	defer rcCleaner.Stop()
	// Start servers
	rsockServer, shutdownF := NewServer("rsock", cfg.SD.Reliable, handlers, log.Root())
	defer shutdownF()
	StartServer("ReliableSockServer", cfg.SD.Reliable, rsockServer)
	unixpacketServer, shutdownF := NewServer("unixpacket", cfg.SD.Unix, handlers, log.Root())
	defer shutdownF()
	StartServer("UnixServer", cfg.SD.Unix, unixpacketServer)
	cfg.Metrics.StartPrometheus()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	metrics.Init(cfg.General.ID)
	return env.LogAppStarted("SD", cfg.General.ID)
}

func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	itopo.Init("", proto.ServiceType_unset, itopo.Callbacks{})
	var topo *topology.Topo
	var err error
	if cfg.Discovery.Bootstrap.Enable {
		topo, err = tryBootstrapping()
		if err != nil {
			return common.NewBasicError("Unable to load topology", err)
		}
	} else {
		topo, err = topology.LoadFromFile(cfg.General.Topology)
		if err != nil {
			return common.NewBasicError("Unable to load topology", err)
		}
	}
	if _, _, err := itopo.SetStatic(topo, false); err != nil {
		return common.NewBasicError("Unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology)
	return cfg.SD.CreateSocketDirs()
}

func startDiscovery() error {
	var err error
	discRunners, err = idiscovery.StartRunners(cfg.Discovery, discovery.Default,
		idiscovery.TopoHandlers{}, nil)
	return err
}

func NewServer(network string, rsockPath string, handlers servers.HandlerMap,
	logger log.Logger) (*servers.Server, func()) {

	server := servers.NewServer(network, rsockPath, os.FileMode(cfg.SD.SocketFileMode), handlers,
		logger)
	shutdownF := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
		server.Shutdown(ctx)
		cancelF()
	}
	return server, shutdownF
}

func StartServer(name, sockPath string, server *servers.Server) {
	go func() {
		defer log.LogPanicAndExit()
		if cfg.SD.DeleteSocket {
			if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
				fatal.Fatal(common.NewBasicError(name+" SocketRemoval error", err))
			}
		}
		if err := server.ListenAndServe(); err != nil {
			fatal.Fatal(common.NewBasicError(name+" ListenAndServe error", err))
		}
	}()
}
