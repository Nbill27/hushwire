package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"hushwire/internal/engine"
)

// Server exposes the manager over HTTP plus the embedded UI.
type Server struct {
	mgr     *engine.Manager
	web     fs.FS
	token   string
	version string
	started time.Time
}

func New(mgr *engine.Manager, web fs.FS, token, version string) *Server {
	return &Server{
		mgr:     mgr,
		web:     web,
		token:   token,
		version: version,
		started: time.Now(),
	}
}

// Handler wires every route. Go 1.22 method patterns are used so the
// static handler can live on "/" without swallowing the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("POST /api/cut", s.handleCut)
	mux.HandleFunc("POST /api/restore", s.handleRestore)
	mux.HandleFunc("GET /api/blocks", s.handleBlocks)
	mux.HandleFunc("POST /api/blocks", s.handleBlockAdd)
	mux.HandleFunc("POST /api/blocks/remove", s.handleBlockRemove)
	mux.Handle("GET /", noStore(http.FileServer(http.FS(s.web))))
	return s.auth(mux)
}

// noStore keeps the browser from caching the embedded UI, so a rebuilt binary
// always serves the matching app.js/style.css without a hard refresh.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// tokenOK compares in constant time so a wrong guess cannot be timed.
func (s *Server) tokenOK(v string) bool {
	return subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

// auth is a no-op unless a token was configured. When a token arrives in the
// query string it is promoted to a cookie, because EventSource cannot set
// custom headers.
func (s *Server) auth(next http.Handler) http.Handler {
	if s.token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("hushwire_token"); err == nil && s.tokenOK(c.Value) {
			next.ServeHTTP(w, r)
			return
		}
		if s.tokenOK(r.Header.Get("X-Token")) {
			next.ServeHTTP(w, r)
			return
		}
		if q := r.URL.Query().Get("t"); q != "" && s.tokenOK(q) {
			http.SetCookie(w, &http.Cookie{
				Name:     "hushwire_token",
				Value:    s.token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	})
}

type deviceDTO struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Vendor   string    `json:"vendor"`
	LastSeen time.Time `json:"lastSeen"`
}

func toDTO(d engine.Device) deviceDTO {
	return deviceDTO{
		IP:       d.IP.String(),
		MAC:      d.MAC.String(),
		Vendor:   d.Vendor,
		LastSeen: d.LastSeen,
	}
}

type statusResp struct {
	Iface      string           `json:"iface"`
	SelfIP     string           `json:"selfIp"`
	SelfMAC    string           `json:"selfMac"`
	GatewayIP  string           `json:"gatewayIp"`
	GatewayMAC string           `json:"gatewayMac"`
	CIDR       string           `json:"cidr"`
	Ready      bool             `json:"ready"`
	IntervalMS int64            `json:"intervalMs"`
	Version    string           `json:"version"`
	UptimeSec  int64            `json:"uptimeSec"`
	Cuts       []engine.CutInfo `json:"cuts"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	e := s.mgr.Engine()
	resp := statusResp{
		Iface:      e.Iface.Name,
		SelfIP:     e.SelfIP.String(),
		SelfMAC:    e.SelfMAC.String(),
		GatewayIP:  e.GatewayIP.String(),
		GatewayMAC: "",
		CIDR:       e.CIDR.String(),
		Ready:      e.GatewayReachable(),
		IntervalMS: s.mgr.Interval().Milliseconds(),
		Version:    s.version,
		UptimeSec:  int64(time.Since(s.started).Seconds()),
		Cuts:       s.mgr.List(),
	}
	if e.GatewayMAC != nil {
		resp.GatewayMAC = e.GatewayMAC.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	timeout := 3 * time.Second
	if v := r.URL.Query().Get("timeout"); v != "" {
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil && f > 0 {
			if f > 15 {
				f = 15
			}
			timeout = time.Duration(f * float64(time.Second))
		}
	}

	devs, err := s.mgr.Scan(timeout)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]deviceDTO, 0, len(devs))
	for _, d := range devs {
		out = append(out, toDTO(d))
	}
	autoCut := s.mgr.EnforceBlocks(devs)
	e := s.mgr.Engine()
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":   out,
		"count":     len(out),
		"selfIp":    e.SelfIP.String(),
		"gatewayIp": e.GatewayIP.String(),
		"cidr":      e.CIDR.String(),
		"autoCut":   autoCut,
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.mgr.Logs().Snapshot()})
}

type cutReq struct {
	IPs      []string `json:"ips"`
	Mode     string   `json:"mode"`
	Duration int      `json:"duration"`
}

type skip struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

func (s *Server) handleCut(w http.ResponseWriter, r *http.Request) {
	var req cutReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IPs) == 0 {
		writeErr(w, http.StatusBadRequest, "no ips given")
		return
	}
	mode := engine.Mode(req.Mode)
	if mode == "" {
		mode = engine.ModeGateway
	}
	if mode != engine.ModeGateway && mode != engine.ModeBoth {
		writeErr(w, http.StatusBadRequest, "mode must be gateway or both")
		return
	}
	if req.Duration < 0 {
		writeErr(w, http.StatusBadRequest, "duration must be >= 0")
		return
	}

	e := s.mgr.Engine()
	started := make([]engine.CutInfo, 0, len(req.IPs))
	skipped := make([]skip, 0)

	for _, raw := range req.IPs {
		ipStr := strings.TrimSpace(raw)
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			skipped = append(skipped, skip{IP: ipStr, Reason: "invalid IPv4"})
			continue
		}
		if ip.Equal(e.SelfIP) {
			skipped = append(skipped, skip{IP: ipStr, Reason: "that is this host"})
			continue
		}
		if e.GatewayIP != nil && ip.Equal(e.GatewayIP) {
			skipped = append(skipped, skip{IP: ipStr, Reason: "that is the gateway"})
			continue
		}
		mac, err := e.ResolveMAC(ip, 2*time.Second)
		if err != nil {
			skipped = append(skipped, skip{IP: ipStr, Reason: "no ARP reply"})
			continue
		}
		info, err := s.mgr.Start(engine.Device{IP: ip, MAC: mac, Vendor: e.OUI.Lookup(mac.String())}, mode, time.Duration(req.Duration)*time.Second)
		if err != nil {
			skipped = append(skipped, skip{IP: ipStr, Reason: err.Error()})
			continue
		}
		started = append(started, info)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"started": started,
		"skipped": skipped,
	})
}

type restoreReq struct {
	IPs []string `json:"ips"`
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req restoreReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IPs) == 0 {
		s.mgr.StopAll()
		writeJSON(w, http.StatusOK, map[string]any{"restored": "all"})
		return
	}

	restored := make([]string, 0, len(req.IPs))
	failed := make([]skip, 0)
	for _, raw := range req.IPs {
		ipStr := strings.TrimSpace(raw)
		if err := s.mgr.Stop(ipStr); err != nil {
			failed = append(failed, skip{IP: ipStr, Reason: err.Error()})
			continue
		}
		restored = append(restored, ipStr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored": restored, "failed": failed})
}

// blockReq is the body for POST /api/blocks. Either a MAC or an IP is enough;
// when only the IP is known the MAC is resolved with one ARP probe.
type blockReq struct {
	MAC   string `json:"mac"`
	IP    string `json:"ip"`
	Mode  string `json:"mode"`
	Label string `json:"label"`
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	bl := s.mgr.Blocks()
	if bl == nil {
		writeErr(w, http.StatusServiceUnavailable, "block list disabled")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocks": bl.List(),
		"path":   bl.Path(),
	})
}

func (s *Server) handleBlockAdd(w http.ResponseWriter, r *http.Request) {
	bl := s.mgr.Blocks()
	if bl == nil {
		writeErr(w, http.StatusServiceUnavailable, "block list disabled")
		return
	}
	var req blockReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	mode := engine.Mode(req.Mode)
	if mode == "" {
		mode = engine.ModeGateway
	}
	if mode != engine.ModeGateway && mode != engine.ModeBoth {
		writeErr(w, http.StatusBadRequest, "mode must be gateway or both")
		return
	}

	e := s.mgr.Engine()
	var ip net.IP
	if raw := strings.TrimSpace(req.IP); raw != "" {
		ip = net.ParseIP(raw).To4()
		if ip == nil {
			writeErr(w, http.StatusBadRequest, "invalid IPv4 "+raw)
			return
		}
		if ip.Equal(e.SelfIP) {
			writeErr(w, http.StatusBadRequest, "that is this host")
			return
		}
		if e.GatewayIP != nil && ip.Equal(e.GatewayIP) {
			writeErr(w, http.StatusBadRequest, "that is the gateway")
			return
		}
	}

	macStr := strings.TrimSpace(req.MAC)
	if macStr == "" {
		if ip == nil {
			writeErr(w, http.StatusBadRequest, "need a mac or an ip")
			return
		}
		hw, err := e.ResolveMAC(ip, 2*time.Second)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "no ARP reply from "+ip.String())
			return
		}
		macStr = hw.String()
	}
	norm, err := engine.NormalizeMAC(macStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if e.SelfMAC != nil && norm == e.SelfMAC.String() {
		writeErr(w, http.StatusBadRequest, "that is this host")
		return
	}
	if e.GatewayMAC != nil && norm == e.GatewayMAC.String() {
		writeErr(w, http.StatusBadRequest, "that is the gateway")
		return
	}

	block, err := bl.Add(engine.Block{
		MAC:    norm,
		Label:  strings.TrimSpace(req.Label),
		Mode:   mode,
		IP:     ipString(ip),
		Vendor: e.OUI.Lookup(norm),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := map[string]any{"block": block, "cut": nil}
	if ip != nil {
		dev := engine.Device{IP: ip, MAC: mustMAC(norm), Vendor: block.Vendor}
		if info, err := s.mgr.Start(dev, mode, 0); err == nil {
			resp["cut"] = info
		} else {
			resp["cutError"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type blockRemoveReq struct {
	MAC string `json:"mac"`
}

func (s *Server) handleBlockRemove(w http.ResponseWriter, r *http.Request) {
	bl := s.mgr.Blocks()
	if bl == nil {
		writeErr(w, http.StatusServiceUnavailable, "block list disabled")
		return
	}
	var req blockRemoveReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	norm, err := engine.NormalizeMAC(req.MAC)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := bl.Has(norm); !ok {
		writeErr(w, http.StatusNotFound, norm+" is not blocked")
		return
	}
	// Restore first: if the ARP repair fails the device must stay on the watch
	// list, otherwise it would be left poisoned with no way to clear it.
	restored, err := s.mgr.StopMAC(norm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := bl.Remove(norm); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":    err.Error(),
			"mac":      norm,
			"restored": restored,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mac": norm, "restored": restored})
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func mustMAC(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return hw
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	ch, cancel := s.mgr.Logs().Subscribe()
	defer cancel()

	// Replay the tail so a fresh browser tab is not blind.
	for _, e := range s.mgr.Logs().Snapshot() {
		writeSSE(w, e)
	}
	fl.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			writeSSE(w, e)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e engine.LogEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
