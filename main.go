// hushwire - ARP-based LAN discovery and per-device traffic cut.
//
// One agent runs on a machine with L2 access to the segment and serves a web
// UI, so any phone, tablet or laptop on the same network can drive it from a
// browser. Only the agent itself needs raw-socket privileges.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"hushwire/internal/api"
	"hushwire/internal/engine"
)

// version can be overridden at build time with
// -ldflags "-X main.version=<v>".
var version = "0.1.0"

//go:embed web
var embeddedWeb embed.FS

func main() {
	var (
		iface    = flag.String("iface", "", "network interface name (default: first usable IPv4 interface)")
		cidr     = flag.String("cidr", "", "override the scan subnet, e.g. 192.168.1.0/24")
		ouiPath  = flag.String("oui", "", "optional IEEE oui.csv for vendor lookup")
		addr     = flag.String("addr", ":8080", "listen address for the web UI")
		token    = flag.String("token", "", "require this token for the web UI (empty = open on the LAN)")
		interval = flag.Duration("interval", 1500*time.Millisecond, "re-poison period")
		state    = flag.String("state", "hushwire-state.json", "block list file (empty = memory only)")
		watch    = flag.Duration("watch", 20*time.Second, "watchdog sweep period for blocked devices (0 = off)")
		scanOnly = flag.Bool("scan", false, "scan once, print the table and exit")
		cutIPs   = flag.String("cut", "", "comma separated IPs to cut headlessly, then exit")
		mode     = flag.String("mode", "gateway", "cut mode: gateway | both")
		duration = flag.Duration("duration", 0, "headless cut duration (0 = until Ctrl-C)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("hushwire", version)
		return
	}

	log.SetFlags(log.Ltime)

	eng, err := engine.Open(*iface, *ouiPath)
	if err != nil {
		fatalf("open engine: %v", err)
	}
	if *cidr != "" {
		_, n, err := net.ParseCIDR(*cidr)
		if err != nil {
			fatalf("bad --cidr %q: %v", *cidr, err)
		}
		eng.CIDR = n
	}

	printBanner(eng)

	if *scanOnly {
		runScan(eng)
		return
	}

	mgr := engine.NewManager(eng, *interval)
	mgr.Logs().Add("info", "hushwire %s on %s (%s)", version, eng.Iface.Name, eng.CIDR)

	blocks, err := engine.LoadBlockList(*state)
	if err != nil {
		fatalf("load block list: %v", err)
	}
	mgr.UseBlocks(blocks)
	if n := blocks.Len(); n > 0 {
		mgr.Logs().Add("info", "block list: %d mac(s) from %s", n, blocks.Path())
	}

	if *cutIPs != "" {
		runHeadless(mgr, *cutIPs, engine.Mode(*mode), *duration)
		return
	}

	runServer(mgr, *addr, *token, *watch)
}

func printBanner(e *engine.Engine) {
	fmt.Printf("iface   %s\n", e.Iface.Name)
	fmt.Printf("self    %s  %s\n", e.SelfIP, e.SelfMAC)
	gwMac := "unknown"
	if e.GatewayMAC != nil {
		gwMac = e.GatewayMAC.String()
	}
	fmt.Printf("gateway %s  %s\n", e.GatewayIP, gwMac)
	fmt.Printf("subnet  %s\n", e.CIDR)
	if !e.GatewayReachable() {
		fmt.Println("warning: gateway MAC not resolved - poisoning will fail until it is")
	}
	fmt.Println()
}

func runScan(e *engine.Engine) {
	devs, err := e.Scan(3 * time.Second)
	if err != nil {
		fatalf("scan: %v", err)
	}
	fmt.Printf("%-16s%-19s%s\n", "IP", "MAC", "VENDOR")
	for _, d := range devs {
		fmt.Printf("%-16s%-19s%s\n", d.IP, d.MAC, d.Vendor)
	}
	fmt.Printf("\n%d host(s)\n", len(devs))
}

func runHeadless(mgr *engine.Manager, list string, mode engine.Mode, dur time.Duration) {
	e := mgr.Engine()
	if mode != engine.ModeGateway && mode != engine.ModeBoth {
		fatalf("bad --mode %q (gateway|both)", mode)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nrestoring...")
		mgr.StopAll()
		os.Exit(0)
	}()

	for _, raw := range strings.Split(list, ",") {
		ipStr := strings.TrimSpace(raw)
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			fmt.Printf("skip %s: invalid IPv4\n", ipStr)
			continue
		}
		mac, err := e.ResolveMAC(ip, 2*time.Second)
		if err != nil {
			fmt.Printf("skip %s: %v\n", ipStr, err)
			continue
		}
		if _, err := mgr.Start(engine.Device{IP: ip, MAC: mac, Vendor: e.OUI.Lookup(mac.String())}, mode, dur); err != nil {
			fmt.Printf("skip %s: %v\n", ipStr, err)
			continue
		}
		fmt.Printf("cutting %s (%s) mode=%s\n", ip, mac, mode)
	}

	if dur > 0 {
		time.Sleep(dur)
		mgr.StopAll()
		return
	}
	select {}
}

func runServer(mgr *engine.Manager, addr, token string, watch time.Duration) {
	web, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		fatalf("embed: %v", err)
	}

	srv := api.New(mgr, web, token, version)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: the SSE stream is long-lived.
	}

	printURLs(addr, token)

	// The watchdog runs for the whole server lifetime: an empty list makes
	// each sweep a no-op, so a block added from the UI is picked up without
	// restarting the agent.
	stopWatch := make(chan struct{})
	if watch > 0 {
		go watchLoop(mgr, watch, stopWatch)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		close(stopWatch)
		mgr.StopAll()
		fatalf("serve: %v", err)
	case <-sig:
		fmt.Println("\nshutting down...")
		close(stopWatch)
		mgr.StopAll()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}
}

func watchLoop(mgr *engine.Manager, every time.Duration, stop <-chan struct{}) {
	// A sweep walks the whole subnet, so refuse intervals that would flood the
	// segment and overlap with the previous sweep.
	const minEvery = 5 * time.Second
	if every < minEvery {
		every = minEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			mgr.WatchOnce(2 * time.Second)
		}
	}
}

func printURLs(addr, token string) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "8080"
	}
	hosts := []string{"127.0.0.1"}
	ifs, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifs {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				v4 := ipn.IP.To4()
				if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
					continue
				}
				hosts = append(hosts, v4.String())
			}
		}
	}
	sort.Strings(hosts)

	suffix := ""
	if token != "" {
		suffix = "?t=" + token
	}
	fmt.Println("web UI:")
	for _, h := range hosts {
		fmt.Printf("  http://%s:%s/%s\n", h, port, suffix)
	}
	fmt.Println()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hushwire: "+format+"\n", args...)
	os.Exit(1)
}
