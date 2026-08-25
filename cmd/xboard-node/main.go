package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cedar2025/xboard-node/internal/buildinfo"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/machine"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/service"
)

var (
	version   = buildinfo.Version
	buildTime = buildinfo.BuildTime
)

func main() {
	configPath := flag.String("c", "config.yml", "config file path")
	showVersion := flag.Bool("v", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("xboard-node %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	rootCfg, err := config.LoadRoot(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	instances, err := rootCfg.NormalizeInstances()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to normalize config: %v\n", err)
		os.Exit(1)
	}
	config.InitLogger(instances[0].Log)

	// Apply runtime memory tuning before anything else allocates.
	applyRuntimeConfig(instances[0].Runtime)

	runWithReload(rootCfg, *configPath)
}

// runWithReload restarts all node services when the config file changes.
func runWithReload(initialRoot *config.RootConfig, configPath string) {
	var healthSrv *http.Server
	var healthPort int
	startHealth := func(port int) {
		if port <= 0 {
			return
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			nlog.Core().Error("failed to start health check listener", "port", port, "error", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})
		healthSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		healthPort = port
		go func() {
			nlog.Core().Debug(fmt.Sprintf("health check listening on :%d", port))
			if err := healthSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				nlog.Core().Warn("health check server stopped", "error", err)
			}
		}()
	}

	initialInstances, err := initialRoot.NormalizeInstances()
	if err != nil {
		nlog.Core().Error("failed to normalize initial config", "error", err)
		os.Exit(1)
	}
	startHealth(initialInstances[0].HealthPort)
	defer func() {
		if healthSrv != nil {
			healthSrv.Close()
		}
	}()

	for root := initialRoot; ; {
		ctx, cancel := context.WithCancel(context.Background())

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		reloadCh := make(chan *config.RootConfig, 1)

		watcher, err := config.WatchConfigRoot(ctx, configPath, func(newCfg *config.RootConfig) {
			select {
			case reloadCh <- newCfg:
			default:
			}
		})
		if err != nil {
			nlog.Core().Warn("config watcher unavailable, hot-reload disabled", "error", err)
		}

		go func() {
			select {
			case sig := <-sigCh:
				nlog.Core().Info(fmt.Sprintf("received %v, shutting down...", sig))
				cancel()

				select {
				case sig = <-sigCh:
					nlog.Core().Warn("received second signal, forcing exit", "signal", sig)
					os.Exit(1)
				case <-time.After(15 * time.Second):
					nlog.Core().Error("shutdown timed out after 15s, forcing exit")
					os.Exit(2)
				}
			case <-ctx.Done():
			}
		}()

		instances, err := root.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize config", "error", err)
			os.Exit(1)
		}
		if err := config.ValidateStartupLayout(instances); err != nil {
			nlog.Core().Error("startup layout validation failed", "error", err)
			os.Exit(1)
		}

		if instances[0].HealthPort != healthPort {
			if healthSrv != nil {
				healthSrv.Close()
				healthSrv = nil
			}
			startHealth(instances[0].HealthPort)
		}

		errCh := make(chan error, len(instances))
		doneCh := make(chan struct{})
		var wg sync.WaitGroup
		for _, instanceCfg := range instances {
			instanceCfg := instanceCfg
			wg.Add(1)
			go func() {
				defer wg.Done()
				if instanceCfg.IsMachineMode() {
					nlog.Core().Info("starting machine instance", "instance", instanceCfg.InstanceID, "machine_id", instanceCfg.Machine.MachineID, "panel_url", instanceCfg.Panel.URL)
				orch := machine.New(instanceCfg)
				orch.SetSelfRestart(func() {
					cancel()
					nlog.Core().Info("agent self-restarting via supervisor")
					os.Exit(0)
				})
				if err := orch.Run(ctx); err != nil {
						nlog.Core().Error("machine instance exited with error", "instance", instanceCfg.InstanceID, "error", err)
						errCh <- err
						cancel()
					}
					return
				}
				nodes := instanceCfg.ExpandNodes()
				nlog.Core().Info("starting node instance", "instance", instanceCfg.InstanceID, "nodes", len(nodes), "panel_url", instanceCfg.Panel.URL)
				var instanceWG sync.WaitGroup
				for idx, nodeCfg := range nodes {
					nodeCfg := nodeCfg
					instanceWG.Add(1)
					go func(idx int) {
						defer instanceWG.Done()
						if idx > 0 {
							delay := time.Duration(idx) * 250 * time.Millisecond
							if delay > 2*time.Second {
								delay = 2 * time.Second
							}
							select {
							case <-time.After(delay):
							case <-ctx.Done():
								return
							}
						}
						svc := service.New(nodeCfg)
						if err := svc.Run(ctx); err != nil {
							nlog.Core().Error("node service exited with error", "instance", nodeCfg.InstanceID, "node_id", nodeCfg.Panel.NodeID, "error", err)
							errCh <- err
							cancel()
						}
					}(idx)
				}
				instanceWG.Wait()
			}()
		}
		go func() { wg.Wait(); close(doneCh) }()

		var newRoot *config.RootConfig
		select {
		case newRoot = <-reloadCh:
			nlog.Core().Info("config changed, restarting all services...")
			cancel()
			<-doneCh
		case <-doneCh:
		}

		signal.Stop(sigCh)
		if watcher != nil {
			watcher.Stop()
		}

		if newRoot == nil {
			close(errCh)
			if err := <-errCh; err != nil {
				os.Exit(1)
			}
			nlog.Core().Info("stopped")
			return
		}

		newInstances, err := newRoot.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize reloaded config", "error", err)
			os.Exit(1)
		}
		config.InitLogger(newInstances[0].Log)
		applyRuntimeConfig(newInstances[0].Runtime)
		root = newRoot
		nlog.Core().Info("reload complete, services restarting with new config")
	}
}

// applyRuntimeConfig wires up Go runtime memory limits from the config file.
// Both settings can also be overridden by environment variables (GOMEMLIMIT /
// GOGC) — the env vars take precedence because Go's runtime reads them before
// we can call these functions, but we set them here for completeness and so
// the values are logged.
func applyRuntimeConfig(rt config.RuntimeConfig) {
	// GOGC
	if rt.GoGCPercent > 0 {
		prev := debug.SetGCPercent(rt.GoGCPercent)
		nlog.Core().Info("runtime: GOGC set", "gogc", rt.GoGCPercent, "prev", prev)
	}

	// GOMEMLIMIT — parse human-readable size string (e.g. "30MiB")
	if rt.GoMemLimit != "" {
		limit, err := parseMemLimit(rt.GoMemLimit)
		if err != nil {
			nlog.Core().Warn("runtime: invalid gomemlimit, ignoring", "value", rt.GoMemLimit, "error", err)
		} else {
			prev := debug.SetMemoryLimit(limit)
			nlog.Core().Info("runtime: GOMEMLIMIT set",
				"limit", rt.GoMemLimit,
				"bytes", limit,
				"prev_bytes", prev,
			)
		}
	}
}

// parseMemLimit converts a human-readable size string to bytes.
// Supported suffixes: B, KiB, MiB, GiB, TiB (case-insensitive).
func parseMemLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	}
	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, strings.ToUpper(sf.suffix)) {
			numStr := strings.TrimSuffix(upper, strings.ToUpper(sf.suffix))
			numStr = strings.TrimSpace(numStr)
			var n int64
			if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil {
				return 0, fmt.Errorf("parse number %q: %w", numStr, err)
			}
			return n * sf.mult, nil
		}
	}
	// No suffix: treat as raw bytes.
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("unrecognised size format %q", s)
	}
	return n, nil
}
