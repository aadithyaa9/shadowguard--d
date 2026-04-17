// package main

// import (
// 	"bufio"
// 	"context"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"log"
// 	"math"
// 	"net"
// 	"net/http"
// 	"os"
// 	"os/exec"
// 	"os/signal"
// 	"strconv"
// 	"strings"
// 	"sync"
// 	"syscall"
// 	"time"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	"github.com/google/gopacket/pcap"
// )

// // ─────────────────────────────────────────────
// //  Constants
// // ─────────────────────────────────────────────

// const FeatureDimension = 17
// const PortScanWindowSecs = 5
// const PortScanThreshold = 15
// const FlowExpirySecs = 60.0
// const BatchIntervalDefault = 2 * time.Second
// const LogChannelBuffer = 4096

// // ─────────────────────────────────────────────
// //  Global metrics for REST dashboard
// // ─────────────────────────────────────────────

// type SystemMetrics struct {
// 	mu              sync.RWMutex
// 	PacketsTotal    int64
// 	FlowsActive     int
// 	FlowsTotal      int64
// 	AlertsTotal     int64
// 	BlockedIPs      int
// 	InferenceLatMS  float64 // rolling average
// 	latSum          float64
// 	latCount        int64
// 	PacketsPerSec   float64
// 	pktCountWindow  int64
// 	windowStart     time.Time
// 	CalibrationMode bool
// 	CalibSamples    int
// 	Uptime          time.Time
// }

// var metrics = &SystemMetrics{windowStart: time.Now(), Uptime: time.Now()}

// func (m *SystemMetrics) RecordPacket() {
// 	m.mu.Lock()
// 	m.PacketsTotal++
// 	m.pktCountWindow++
// 	elapsed := time.Since(m.windowStart).Seconds()
// 	if elapsed >= 1.0 {
// 		m.PacketsPerSec = float64(m.pktCountWindow) / elapsed
// 		m.pktCountWindow = 0
// 		m.windowStart = time.Now()
// 	}
// 	m.mu.Unlock()
// }

// func (m *SystemMetrics) RecordLatency(ms float64) {
// 	m.mu.Lock()
// 	m.latSum += ms
// 	m.latCount++
// 	m.InferenceLatMS = m.latSum / float64(m.latCount)
// 	m.mu.Unlock()
// }

// func (m *SystemMetrics) RecordAlert() {
// 	m.mu.Lock()
// 	m.AlertsTotal++
// 	m.mu.Unlock()
// }

// func (m *SystemMetrics) Snapshot() map[string]interface{} {
// 	m.mu.RLock()
// 	defer m.mu.RUnlock()
// 	return map[string]interface{}{
// 		"uptime_seconds":       time.Since(m.Uptime).Seconds(),
// 		"packets_total":        m.PacketsTotal,
// 		"packets_per_second":   m.PacketsPerSec,
// 		"flows_active":         m.FlowsActive,
// 		"flows_total":          m.FlowsTotal,
// 		"alerts_total":         m.AlertsTotal,
// 		"blocked_ips":          m.BlockedIPs,
// 		"inference_latency_ms": m.InferenceLatMS,
// 		"calibration_mode":     m.CalibrationMode,
// 		"calib_samples":        m.CalibSamples,
// 		"timestamp":            time.Now().UTC().Format(time.RFC3339),
// 	}
// }

// // ─────────────────────────────────────────────
// //  Async Logger
// // ─────────────────────────────────────────────

// type AlertLogger struct {
// 	ch      chan string
// 	logFile *os.File
// }

// func NewAlertLogger(path string) *AlertLogger {
// 	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("[LOGGER] Cannot open log file %s: %v", path, err)
// 	}
// 	al := &AlertLogger{ch: make(chan string, LogChannelBuffer), logFile: f}
// 	go al.worker()
// 	return al
// }

// // worker drains the channel — never blocks the capture goroutine
// func (al *AlertLogger) worker() {
// 	for msg := range al.ch {
// 		ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
// 		line := fmt.Sprintf("%s %s\n", ts, msg)
// 		al.logFile.WriteString(line)
// 	}
// }

// // Log is non-blocking: drops if buffer full rather than stalling capture
// func (al *AlertLogger) Log(msg string) {
// 	select {
// 	case al.ch <- msg:
// 	default:
// 		// buffer full — discard rather than block packet capture
// 	}
// }

// func (al *AlertLogger) Close() {
// 	close(al.ch)
// 	al.logFile.Close()
// }

// // ─────────────────────────────────────────────
// //  Firewall / Active Defense
// // ─────────────────────────────────────────────

// var blockedIPs = make(map[string]bool)
// var blockMutex sync.Mutex

// // safeIPs are IPs that must never be blocked (localhost, the operator's own IP)
// var safeIPs = map[string]bool{
// 	"127.0.0.1": true,
// 	"::1":       true,
// }

// func SetSafeIP(ip string) { safeIPs[ip] = true }

// func blockAttacker(ip string, logger *AlertLogger) {
// 	blockMutex.Lock()
// 	defer blockMutex.Unlock()

// 	if blockedIPs[ip] || safeIPs[ip] {
// 		return
// 	}

// 	msg := fmt.Sprintf("[FIREWALL] 🛡️  Active Defense triggered — blocking %s", ip)
// 	fmt.Println(msg)
// 	logger.Log(msg)

// 	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
// 	if err := cmd.Run(); err != nil {
// 		errMsg := fmt.Sprintf("[FIREWALL ERROR] Failed to block %s: %v", ip, err)
// 		log.Println(errMsg)
// 		logger.Log(errMsg)
// 		return
// 	}

// 	blockedIPs[ip] = true
// 	metrics.mu.Lock()
// 	metrics.BlockedIPs++
// 	metrics.mu.Unlock()

// 	ok := fmt.Sprintf("[FIREWALL] ✅ %s isolated at kernel level.", ip)
// 	fmt.Println(ok)
// 	logger.Log(ok)

// 	// Push a firewall event into the alert ring so the dashboard
// 	// blocked-IPs table can display the reason and timestamp.
// 	alertRing.Push(map[string]string{
// 		"type":      "FIREWALL",
// 		"src_ip":    ip,
// 		"dst_ip":    "-",
// 		"dst_port":  "-",
// 		"detail":    "iptables DROP applied",
// 		"timestamp": time.Now().UTC().Format(time.RFC3339),
// 	})
// }

// // ─────────────────────────────────────────────
// //  Heuristic Port-Scan Detector
// // ─────────────────────────────────────────────

// var scanTracker = make(map[string]map[string]time.Time)
// var scanMutex sync.Mutex

// func checkPortScan(srcIP, dstPort string, logger *AlertLogger) {
// 	if safeIPs[srcIP] {
// 		return
// 	}

// 	scanMutex.Lock()
// 	defer scanMutex.Unlock()

// 	if scanTracker[srcIP] == nil {
// 		scanTracker[srcIP] = make(map[string]time.Time)
// 	}

// 	now := time.Now()
// 	scanTracker[srcIP][dstPort] = now

// 	activePorts := 0
// 	for port, lastSeen := range scanTracker[srcIP] {
// 		if now.Sub(lastSeen) < PortScanWindowSecs*time.Second {
// 			activePorts++
// 		} else {
// 			delete(scanTracker[srcIP], port)
// 		}
// 	}

// 	if activePorts > PortScanThreshold {
// 		alert := fmt.Sprintf("[HEURISTIC ALERT] 🚨 Port Scan from %s! (%d unique ports in %ds)", srcIP, activePorts, PortScanWindowSecs)
// 		fmt.Println(alert)
// 		logger.Log(alert)
// 		metrics.RecordAlert()

// 		alertRing.Push(map[string]string{
// 			"type":      "HEURISTIC",
// 			"src_ip":    srcIP,
// 			"dst_ip":    "-",
// 			"dst_port":  "-",
// 			"detail":    fmt.Sprintf("%d unique ports in %ds", activePorts, PortScanWindowSecs),
// 			"timestamp": time.Now().UTC().Format(time.RFC3339),
// 		})

// 		scanTracker[srcIP] = make(map[string]time.Time) // reset window
// 		go blockAttacker(srcIP, logger)
// 	}
// }

// // ─────────────────────────────────────────────
// //  Flow Management (Welford's Algorithm)
// // ─────────────────────────────────────────────

// type FlowKey struct {
// 	SrcIP, DstIP, SrcPort, DstPort, Protocol string
// }

// type FlowStats struct {
// 	ServerPort float64
// 	Dirty      bool

// 	FwdPackets, BwdPackets, FwdBytes, BwdBytes int
// 	StartTime, LastSeenTime, LastPktTime       time.Time

// 	MinLen, MaxLen int
// 	MeanLen, M2Len float64
// 	TotalPackets   int

// 	MeanIAT, M2IAT float64
// 	IATCount       int

// 	SYN, ACK, FIN, RST, PSH int
// }

// type FlowManager struct {
// 	flows map[FlowKey]*FlowStats
// 	mutex sync.RWMutex
// }

// func NewFlowManager() *FlowManager {
// 	return &FlowManager{flows: make(map[FlowKey]*FlowStats)}
// }

// func boolToInt(b bool) int {
// 	if b {
// 		return 1
// 	}
// 	return 0
// }

// func parsePort(portStr string) float64 {
// 	portOnly := strings.Split(portStr, "(")[0]
// 	p, err := strconv.Atoi(portOnly)
// 	if err != nil {
// 		return 0
// 	}
// 	return float64(p)
// }

// func shouldIgnoreTraffic(srcStr, dstStr string) bool {
// 	src := net.ParseIP(srcStr)
// 	dst := net.ParseIP(dstStr)
// 	if src == nil || dst == nil {
// 		return false
// 	}
// 	if src.IsLoopback() || dst.IsLoopback() {
// 		return true
// 	}
// 	if src.IsMulticast() || dst.IsMulticast() {
// 		return true
// 	}
// 	if src.IsLinkLocalMulticast() || dst.IsLinkLocalMulticast() {
// 		return true
// 	}
// 	if src.IsLinkLocalUnicast() || dst.IsLinkLocalUnicast() {
// 		return true
// 	}
// 	if dst.Equal(net.IPv4bcast) {
// 		return true
// 	}
// 	return false
// }

// func (fm *FlowManager) ProcessPacket(packet gopacket.Packet, logger *AlertLogger) {
// 	networkLayer := packet.NetworkLayer()
// 	transportLayer := packet.TransportLayer()
// 	if networkLayer == nil || transportLayer == nil {
// 		return
// 	}

// 	srcEndpoint, dstEndpoint := networkLayer.NetworkFlow().Endpoints()
// 	if shouldIgnoreTraffic(srcEndpoint.String(), dstEndpoint.String()) {
// 		return
// 	}

// 	metrics.RecordPacket()

// 	packetLength := len(packet.Data())
// 	timestamp := packet.Metadata().Timestamp

// 	var srcPort, dstPort, protocol string
// 	var syn, ack, fin, rst, psh bool

// 	switch layer := transportLayer.(type) {
// 	case *layers.TCP:
// 		protocol = "TCP"
// 		srcPort = layer.SrcPort.String()
// 		dstPort = layer.DstPort.String()
// 		syn, ack, fin, rst, psh = layer.SYN, layer.ACK, layer.FIN, layer.RST, layer.PSH
// 	case *layers.UDP:
// 		protocol = "UDP"
// 		srcPort = layer.SrcPort.String()
// 		dstPort = layer.DstPort.String()
// 	default:
// 		return
// 	}

// 	// Heuristic runs BEFORE ML — catches port scans that evade flow-based ML
// 	checkPortScan(srcEndpoint.String(), dstPort, logger)

// 	key := FlowKey{srcEndpoint.String(), dstEndpoint.String(), srcPort, dstPort, protocol}
// 	reverseKey := FlowKey{dstEndpoint.String(), srcEndpoint.String(), dstPort, srcPort, protocol}

// 	fm.mutex.Lock()
// 	defer fm.mutex.Unlock()

// 	flow, exists := fm.flows[key]
// 	forward := true

// 	if !exists {
// 		if flow, exists = fm.flows[reverseKey]; exists {
// 			forward = false
// 		}
// 	}

// 	if !exists {
// 		flow = &FlowStats{
// 			ServerPort:   parsePort(dstPort),
// 			Dirty:        true,
// 			FwdPackets:   1,
// 			FwdBytes:     packetLength,
// 			StartTime:    timestamp,
// 			LastSeenTime: timestamp,
// 			LastPktTime:  timestamp,
// 			MinLen:       packetLength,
// 			MaxLen:       packetLength,
// 			MeanLen:      float64(packetLength),
// 			TotalPackets: 1,
// 			SYN:          boolToInt(syn),
// 			ACK:          boolToInt(ack),
// 			FIN:          boolToInt(fin),
// 			RST:          boolToInt(rst),
// 			PSH:          boolToInt(psh),
// 		}
// 		fm.flows[key] = flow
// 		metrics.mu.Lock()
// 		metrics.FlowsTotal++
// 		metrics.FlowsActive = len(fm.flows)
// 		metrics.mu.Unlock()
// 		return
// 	}

// 	flow.Dirty = true
// 	if forward {
// 		flow.FwdPackets++
// 		flow.FwdBytes += packetLength
// 	} else {
// 		flow.BwdPackets++
// 		flow.BwdBytes += packetLength
// 	}

// 	// Welford's Online Algorithm for IAT
// 	iat := timestamp.Sub(flow.LastPktTime).Seconds()
// 	if flow.TotalPackets > 0 {
// 		flow.IATCount++
// 		delta := iat - flow.MeanIAT
// 		flow.MeanIAT += delta / float64(flow.IATCount)
// 		flow.M2IAT += delta * (iat - flow.MeanIAT)
// 	}
// 	flow.LastPktTime = timestamp
// 	flow.LastSeenTime = timestamp
// 	flow.TotalPackets++

// 	if packetLength < flow.MinLen {
// 		flow.MinLen = packetLength
// 	}
// 	if packetLength > flow.MaxLen {
// 		flow.MaxLen = packetLength
// 	}

// 	// Welford's Online Algorithm for packet length
// 	delta := float64(packetLength) - flow.MeanLen
// 	flow.MeanLen += delta / float64(flow.TotalPackets)
// 	flow.M2Len += delta * (float64(packetLength) - flow.MeanLen)

// 	flow.SYN += boolToInt(syn)
// 	flow.ACK += boolToInt(ack)
// 	flow.FIN += boolToInt(fin)
// 	flow.RST += boolToInt(rst)
// 	flow.PSH += boolToInt(psh)

// 	if fin || rst {
// 		delete(fm.flows, key)
// 		metrics.mu.Lock()
// 		metrics.FlowsActive = len(fm.flows)
// 		metrics.mu.Unlock()
// 	}
// }

// // Snapshot collects all dirty flows into a feature-vector batch
// func (fm *FlowManager) Snapshot() map[FlowKey][]float64 {
// 	fm.mutex.Lock()
// 	defer fm.mutex.Unlock()

// 	now := time.Now()
// 	batch := make(map[FlowKey][]float64)

// 	for key, flow := range fm.flows {
// 		if now.Sub(flow.LastSeenTime).Seconds() > FlowExpirySecs {
// 			delete(fm.flows, key)
// 			continue
// 		}
// 		if !flow.Dirty {
// 			continue
// 		}

// 		stdLen, stdIAT := 0.0, 0.0
// 		if flow.TotalPackets > 1 {
// 			stdLen = math.Sqrt(flow.M2Len / float64(flow.TotalPackets-1))
// 		}
// 		if flow.IATCount > 1 {
// 			stdIAT = math.Sqrt(flow.M2IAT / float64(flow.IATCount-1))
// 		}

// 		duration := flow.LastSeenTime.Sub(flow.StartTime).Seconds()

// 		vector := []float64{
// 			flow.ServerPort,
// 			float64(flow.FwdPackets), float64(flow.BwdPackets),
// 			float64(flow.FwdBytes), float64(flow.BwdBytes),
// 			float64(flow.MinLen), float64(flow.MaxLen),
// 			flow.MeanLen, stdLen, duration,
// 			flow.MeanIAT, stdIAT,
// 			float64(flow.SYN), float64(flow.ACK),
// 			float64(flow.FIN), float64(flow.RST), float64(flow.PSH),
// 		}

// 		if len(vector) == FeatureDimension {
// 			batch[key] = vector
// 		}
// 		flow.Dirty = false
// 	}

// 	metrics.mu.Lock()
// 	metrics.FlowsActive = len(fm.flows)
// 	metrics.mu.Unlock()

// 	return batch
// }

// // ─────────────────────────────────────────────
// //  Calibration Mode
// // ─────────────────────────────────────────────

// // CalibWriter writes safe-traffic samples to a CSV for AE retraining
// type CalibWriter struct {
// 	mu     sync.Mutex
// 	file   *os.File
// 	count  int
// 	target int
// 	done   chan struct{}
// }

// func NewCalibWriter(path string, target int) (*CalibWriter, error) {
// 	f, err := os.Create(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// Write CSV header matching the 17 features
// 	header := "server_port,fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,min_len,max_len,mean_len,std_len,duration,mean_iat,std_iat,syn,ack,fin,rst,psh\n"
// 	f.WriteString(header)
// 	return &CalibWriter{file: f, target: target, done: make(chan struct{})}, nil
// }

// func (cw *CalibWriter) Write(vector []float64) bool {
// 	cw.mu.Lock()
// 	defer cw.mu.Unlock()
// 	if cw.count >= cw.target {
// 		return false
// 	}
// 	strs := make([]string, len(vector))
// 	for i, v := range vector {
// 		strs[i] = fmt.Sprintf("%f", v)
// 	}
// 	cw.file.WriteString(strings.Join(strs, ",") + "\n")
// 	cw.count++
// 	metrics.mu.Lock()
// 	metrics.CalibSamples = cw.count
// 	metrics.mu.Unlock()
// 	if cw.count >= cw.target {
// 		cw.file.Close()
// 		close(cw.done)
// 	}
// 	return true
// }

// func (cw *CalibWriter) Done() <-chan struct{} { return cw.done }

// // ─────────────────────────────────────────────
// //  Python ML Service IPC
// // ─────────────────────────────────────────────

// func startPythonMLService(pythonBin, scriptPath, workDir string) (io.WriteCloser, *bufio.Reader, *exec.Cmd) {
// 	cmd := exec.Command(pythonBin, scriptPath)
// 	cmd.Dir = workDir
// 	cmd.Stderr = os.Stderr

// 	stdin, err := cmd.StdinPipe()
// 	if err != nil {
// 		log.Fatalf("[IPC] Failed to create stdin pipe: %v", err)
// 	}
// 	stdout, err := cmd.StdoutPipe()
// 	if err != nil {
// 		log.Fatalf("[IPC] Failed to create stdout pipe: %v", err)
// 	}
// 	if err := cmd.Start(); err != nil {
// 		log.Fatalf("[IPC] Failed to start Python ML service: %v", err)
// 	}

// 	reader := bufio.NewReader(stdout)
// 	fmt.Println("[IPC] Waiting for ML models to load into RAM...")
// 	for {
// 		line, err := reader.ReadString('\n')
// 		if err != nil {
// 			log.Fatalf("[IPC] Error reading from Python during startup: %v", err)
// 		}
// 		if strings.TrimSpace(line) == "READY" {
// 			fmt.Println("[IPC] ✅ ML Service is READY and listening.")
// 			break
// 		}
// 	}
// 	return stdin, reader, cmd
// }

// // ─────────────────────────────────────────────
// //  REST API Dashboard
// // ─────────────────────────────────────────────

// // recentAlerts is a circular buffer for the /alerts endpoint
// type AlertRing struct {
// 	mu    sync.Mutex
// 	items []map[string]string
// 	cap   int
// }

// func NewAlertRing(cap int) *AlertRing { return &AlertRing{cap: cap} }

// func (r *AlertRing) Push(alert map[string]string) {
// 	r.mu.Lock()
// 	defer r.mu.Unlock()
// 	if len(r.items) >= r.cap {
// 		r.items = r.items[1:]
// 	}
// 	r.items = append(r.items, alert)
// }

// func (r *AlertRing) All() []map[string]string {
// 	r.mu.Lock()
// 	defer r.mu.Unlock()
// 	out := make([]map[string]string, len(r.items))
// 	copy(out, r.items)
// 	return out
// }

// var alertRing = NewAlertRing(200)

// func startRESTAPI(addr string) {
// 	mux := http.NewServeMux()

// 	// CORS helper
// 	cors := func(w http.ResponseWriter) {
// 		w.Header().Set("Access-Control-Allow-Origin", "*")
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	// GET /metrics — live system metrics
// 	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
// 		cors(w)
// 		json.NewEncoder(w).Encode(metrics.Snapshot())
// 	})

// 	// GET /alerts — recent threat alerts (circular buffer)
// 	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
// 		cors(w)
// 		json.NewEncoder(w).Encode(alertRing.All())
// 	})

// 	// GET /blocked — list of blocked IPs
// 	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
// 		cors(w)
// 		blockMutex.Lock()
// 		ips := make([]string, 0, len(blockedIPs))
// 		for ip := range blockedIPs {
// 			ips = append(ips, ip)
// 		}
// 		blockMutex.Unlock()
// 		json.NewEncoder(w).Encode(map[string]interface{}{"blocked_ips": ips})
// 	})

// 	// GET /health
// 	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
// 		cors(w)
// 		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
// 	})

// 	// Serve the live dashboard HTML
// 	mux.HandleFunc("/", serveDashboard)

// 	fmt.Printf("[REST API] 🌐 Dashboard available at http://%s\n", addr)
// 	if err := http.ListenAndServe(addr, mux); err != nil {
// 		log.Fatalf("[REST API] Server failed: %v", err)
// 	}
// }

// func serveDashboard(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	w.Write([]byte(dashboardHTML()))
// }

// // ─────────────────────────────────────────────
// //  Main
// // ─────────────────────────────────────────────

// func main() {
// 	iface      := flag.String("interface", "wlan0", "Network interface to monitor")
// 	pyBin      := flag.String("python", "../nids-ml/venv/bin/python", "Path to Python executable")
// 	pyScript   := flag.String("script", "detect_stream.py", "Path to continuous detection script")
// 	workDir    := flag.String("workdir", "../nids-ml", "Working directory for ML script")
// 	interval   := flag.Duration("interval", BatchIntervalDefault, "Micro-batch processing interval")
// 	apiAddr    := flag.String("api", ":8080", "REST API / dashboard listen address")
// 	logPath    := flag.String("log", "shadowguard_alerts.log", "Alert log file path")
// 	calibMode  := flag.Bool("calibrate", false, "Run calibration mode to capture safe-traffic baseline")
// 	calibOut   := flag.String("calib-out", "../nids-ml/calib_baseline.csv", "Calibration output CSV path")
// 	calibCount := flag.Int("calib-count", 500, "Number of safe-flow samples to capture for calibration")
// 	selfIP     := flag.String("self-ip", "", "Operator's own IP — will never be blocked")
// 	flag.Parse()

// 	if *selfIP != "" {
// 		SetSafeIP(*selfIP)
// 	}

// 	// ── Async logger
// 	logger := NewAlertLogger(*logPath)
// 	defer logger.Close()
// 	logger.Log("[SYSTEM] ShadowGuard-D starting up")

// 	// ── Calibration mode
// 	var calibWriter *CalibWriter
// 	if *calibMode {
// 		var err error
// 		calibWriter, err = NewCalibWriter(*calibOut, *calibCount)
// 		if err != nil {
// 			log.Fatalf("[CALIB] Cannot create calibration file: %v", err)
// 		}
// 		metrics.mu.Lock()
// 		metrics.CalibrationMode = true
// 		metrics.mu.Unlock()
// 		fmt.Printf("[CALIB] 🎯 Calibration mode: recording %d safe-traffic samples to %s\n", *calibCount, *calibOut)
// 		fmt.Println("[CALIB]    ML inference is DISABLED during calibration.")

// 		go func() {
// 			<-calibWriter.Done()
// 			fmt.Printf("[CALIB] ✅ Calibration complete! %d samples saved to %s\n", *calibCount, *calibOut)
// 			fmt.Println("[CALIB]    Run `python retrain_autoencoder.py` to adapt the model.")
// 			logger.Log(fmt.Sprintf("[CALIB] Calibration complete: %d samples → %s", *calibCount, *calibOut))
// 		}()
// 	}

// 	// ── REST API (non-blocking)
// 	go startRESTAPI(*apiAddr)

// 	// ── Python ML service (only when not calibrating)
// 	var pyStdin  io.WriteCloser
// 	var pyStdout *bufio.Reader
// 	var pyCmd    *exec.Cmd
// 	if !*calibMode {
// 		pyStdin, pyStdout, pyCmd = startPythonMLService(*pyBin, *pyScript, *workDir)
// 		defer pyStdin.Close()
// 		defer pyCmd.Process.Kill()
// 	}

// 	// ── Signal handler
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
// 	go func() {
// 		<-sigChan
// 		fmt.Println("\n[SYSTEM] Received interrupt — shutting down safely...")
// 		logger.Log("[SYSTEM] Graceful shutdown initiated")
// 		cancel()
// 	}()

// 	// ── libpcap
// 	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
// 	if err != nil {
// 		log.Fatalf("[PCAP] Failed to open interface %s: %v", *iface, err)
// 	}
// 	defer handle.Close()

// 	bpfFilter := "not broadcast and not multicast"
// 	if err := handle.SetBPFFilter(bpfFilter); err != nil {
// 		log.Fatalf("[PCAP] Failed to set BPF filter: %v", err)
// 	}
// 	fmt.Printf("[PCAP] Kernel-level BPF filter active: \"%s\"\n", bpfFilter)
// 	fmt.Printf("[PCAP] Listening on interface: %s\n", *iface)
// 	fmt.Printf("[SYSTEM] ShadowGuard-D ▶ RUNNING\n\n")

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 	flowManager  := NewFlowManager()

// 	// ── Capture goroutine
// 	go func() {
// 		for {
// 			select {
// 			case <-ctx.Done():
// 				return
// 			case packet, ok := <-packetSource.Packets():
// 				if !ok {
// 					return
// 				}
// 				flowManager.ProcessPacket(packet, logger)
// 			}
// 		}
// 	}()

// 	// ── Micro-batch ticker
// 	ticker := time.NewTicker(*interval)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			fmt.Println("[SYSTEM] Shutdown complete.")
// 			return

// 		case <-ticker.C:
// 			batch := flowManager.Snapshot()
// 			if len(batch) == 0 {
// 				continue
// 			}

// 			for flowKey, row := range batch {
// 				// ── Calibration mode: record sample and skip ML
// 				if calibWriter != nil {
// 					calibWriter.Write(row)
// 					continue
// 				}

// 				// ── ML inference via IPC
// 				strRow := make([]string, len(row))
// 				for i, val := range row {
// 					strRow[i] = fmt.Sprintf("%f", val)
// 				}
// 				csvLine := strings.Join(strRow, ",") + "\n"

// 				t0 := time.Now()
// 				if _, err := pyStdin.Write([]byte(csvLine)); err != nil {
// 					log.Printf("[IPC] Write error: %v", err)
// 					continue
// 				}

// 				result, err := pyStdout.ReadString('\n')
// 				if err != nil {
// 					log.Printf("[IPC] Read error: %v", err)
// 					continue
// 				}
// 				latencyMS := float64(time.Since(t0).Microseconds()) / 1000.0
// 				metrics.RecordLatency(latencyMS)

// 				result = strings.TrimSpace(result)

// 				if strings.HasPrefix(result, "0") {
// 					fmt.Printf("[BENIGN]    %s → %s:%s | lat=%.1fms\n",
// 						flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, latencyMS)
// 				} else if strings.HasPrefix(result, "1") {
// 					alert := fmt.Sprintf("[ML ALERT] 🚨 MALICIOUS flow from %s → %s:%s | %s | lat=%.1fms",
// 						flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, result, latencyMS)
// 					fmt.Println(alert)
// 					logger.Log(alert)
// 					metrics.RecordAlert()

// 					alertRing.Push(map[string]string{
// 						"type":      "ML",
// 						"src_ip":    flowKey.SrcIP,
// 						"dst_ip":    flowKey.DstIP,
// 						"dst_port":  flowKey.DstPort,
// 						"detail":    result,
// 						"timestamp": time.Now().UTC().Format(time.RFC3339),
// 					})

// 					go blockAttacker(flowKey.SrcIP, logger)
// 				}
// 			}
// 		}
// 	}
// }

// // ─────────────────────────────────────────────
// //  Embedded Dashboard HTML
// // ─────────────────────────────────────────────

// // dashboardHTML returns the live dashboard page.
// // It is a function (not a const) to avoid embedding a JS template literal
// // backtick inside a Go raw-string-literal backtick, which is a syntax error.
// func dashboardHTML() string {
// 	return "<!DOCTYPE html>\n" +
// 		"<html lang=\"en\">\n" +
// 		"<head>\n" +
// 		"<meta charset=\"UTF-8\">\n" +
// 		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
// 		"<title>ShadowGuard-D Dashboard</title>\n" +
// 		"<style>\n" +
// 		"  :root {\n" +
// 		"    --bg: #0d1117; --card: #161b22; --border: #30363d;\n" +
// 		"    --green: #3fb950; --red: #f85149; --yellow: #d29922;\n" +
// 		"    --blue: #58a6ff; --text: #e6edf3; --muted: #8b949e;\n" +
// 		"    --orange: #e3771a;\n" +
// 		"  }\n" +
// 		"  * { box-sizing: border-box; margin: 0; padding: 0; }\n" +
// 		"  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; padding: 24px; }\n" +
// 		"  h1 { color: var(--blue); font-size: 1.6rem; margin-bottom: 4px; }\n" +
// 		"  .subtitle { color: var(--muted); font-size: 0.85rem; margin-bottom: 24px; }\n" +
// 		"  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }\n" +
// 		"  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }\n" +
// 		"  .card-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; }\n" +
// 		"  .card-value { font-size: 2rem; font-weight: 700; margin-top: 4px; }\n" +
// 		"  .green { color: var(--green); } .red { color: var(--red); }\n" +
// 		"  .yellow { color: var(--yellow); } .blue { color: var(--blue); }\n" +
// 		"  /* ── panels ── */\n" +
// 		"  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; }\n" +
// 		"  .panel-title { font-size: 1rem; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }\n" +
// 		"  .panel-title .count-badge { font-size: 0.75rem; background: var(--border); color: var(--muted); padding: 2px 8px; border-radius: 10px; }\n" +
// 		"  /* ── two-column layout for lower panels ── */\n" +
// 		"  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }\n" +
// 		"  @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } }\n" +
// 		"  /* ── alert list ── */\n" +
// 		"  .scroll-list { max-height: 340px; overflow-y: auto; font-family: monospace; font-size: 0.78rem; }\n" +
// 		"  .alert-row { padding: 7px 8px; border-bottom: 1px solid var(--border); display: flex; align-items: baseline; gap: 6px; }\n" +
// 		"  .alert-row.ml { border-left: 3px solid var(--red); }\n" +
// 		"  .alert-row.heuristic { border-left: 3px solid var(--yellow); }\n" +
// 		"  .alert-row .ts { color: var(--muted); font-size: 0.7rem; margin-left: auto; white-space: nowrap; }\n" +
// 		"  /* ── blocked IPs table ── */\n" +
// 		"  .blocked-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }\n" +
// 		"  .blocked-table thead tr { border-bottom: 1px solid var(--border); }\n" +
// 		"  .blocked-table th { text-align: left; padding: 6px 8px; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: .04em; font-weight: 500; }\n" +
// 		"  .blocked-table td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }\n" +
// 		"  .blocked-table tr:last-child td { border-bottom: none; }\n" +
// 		"  .blocked-table tr:hover td { background: rgba(255,255,255,0.03); }\n" +
// 		"  .ip-chip { font-family: monospace; font-size: 0.82rem; color: var(--text); font-weight: 600; }\n" +
// 		"  .reason-chip { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 0.68rem; font-weight: 600; }\n" +
// 		"  .reason-ml      { background: #2d1117; color: var(--red);    border: 1px solid var(--red); }\n" +
// 		"  .reason-portscan{ background: #1c1a10; color: var(--yellow); border: 1px solid var(--yellow); }\n" +
// 		"  .reason-unknown { background: #1a1f2e; color: var(--blue);   border: 1px solid var(--blue); }\n" +
// 		"  .firewall-chip { display: inline-flex; align-items: center; gap: 4px; font-size: 0.72rem; color: var(--green); }\n" +
// 		"  .empty-msg { color: var(--muted); font-size: 0.82rem; padding: 16px 8px; text-align: center; }\n" +
// 		"  /* ── misc ── */\n" +
// 		"  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }\n" +
// 		"  .badge-red    { background: #2d1117; color: var(--red);    border: 1px solid var(--red); }\n" +
// 		"  .badge-yellow { background: #1c1a10; color: var(--yellow); border: 1px solid var(--yellow); }\n" +
// 		"  .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 6px; }\n" +
// 		"  .dot-green { background: var(--green); box-shadow: 0 0 6px var(--green); }\n" +
// 		"  .calib-banner { background: #1c1a10; border: 1px solid var(--yellow); border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; color: var(--yellow); display: none; }\n" +
// 		"  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: var(--bg); } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }\n" +
// 		"</style>\n" +
// 		"</head>\n" +
// 		"<body>\n" +
// 		"<h1>\xF0\x9F\x9B\xA1\xEF\xB8\x8F ShadowGuard-D</h1>\n" +
// 		"<p class=\"subtitle\">Distributed NIDS/IPS \xE2\x80\x94 Live Observability Dashboard</p>\n" +
// 		"<div class=\"calib-banner\" id=\"calib-banner\">\n" +
// 		"  \xF0\x9F\x8E\xAF <strong>Calibration Mode Active</strong> \xE2\x80\x94 Recording safe-traffic baseline.\n" +
// 		"  Samples captured: <span id=\"calib-count\">0</span>\n" +
// 		"</div>\n" +
// 		// ── metric cards ──
// 		"<div class=\"grid\">\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Status</div><div class=\"card-value green\" style=\"font-size:1.1rem;margin-top:8px\"><span class=\"status-dot dot-green\"></span>RUNNING</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Uptime</div><div class=\"card-value blue\" id=\"uptime\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Packets / s</div><div class=\"card-value green\" id=\"pps\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Active Flows</div><div class=\"card-value blue\" id=\"flows\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Total Alerts</div><div class=\"card-value red\" id=\"alerts\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Blocked IPs</div><div class=\"card-value red\" id=\"blocked\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Inference Latency</div><div class=\"card-value yellow\" id=\"latency\">--</div></div>\n" +
// 		"  <div class=\"card\"><div class=\"card-label\">Total Packets</div><div class=\"card-value blue\" id=\"packets\">--</div></div>\n" +
// 		"</div>\n" +
// 		// ── two-column: alerts + blocked IPs ──
// 		"<div class=\"two-col\">\n" +
// 		// left: alerts
// 		"  <div class=\"panel\">\n" +
// 		"    <div class=\"panel-title\">\xF0\x9F\x9A\xA8 Recent Threat Alerts <span class=\"count-badge\" id=\"alert-count\">0</span></div>\n" +
// 		"    <div class=\"scroll-list\" id=\"alert-list\"><div class=\"empty-msg\">No alerts yet.</div></div>\n" +
// 		"  </div>\n" +
// 		// right: blocked IPs
// 		"  <div class=\"panel\">\n" +
// 		"    <div class=\"panel-title\">\xF0\x9F\x94\x92 Blocked IPs <span class=\"count-badge\" id=\"blocked-count\">0</span></div>\n" +
// 		"    <div class=\"scroll-list\">\n" +
// 		"      <table class=\"blocked-table\">\n" +
// 		"        <thead><tr><th>#</th><th>IP Address</th><th>Reason</th><th>Firewall</th><th>Blocked At</th></tr></thead>\n" +
// 		"        <tbody id=\"blocked-body\"><tr><td colspan=\"5\" class=\"empty-msg\">No IPs blocked yet.</td></tr></tbody>\n" +
// 		"      </table>\n" +
// 		"    </div>\n" +
// 		"  </div>\n" +
// 		"</div>\n" +
// 		// ── javascript ──
// 		"<script>\n" +
// 		"function fmtUptime(s) {\n" +
// 		"  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = Math.floor(s%60);\n" +
// 		"  return (h>0?h+'h ':' ')+(m>0?m+'m ':' ')+sec+'s';\n" +
// 		"}\n" +
// 		"function fmtTime(ts) {\n" +
// 		"  if (!ts) return '';\n" +
// 		"  const d = new Date(ts);\n" +
// 		"  return d.toLocaleTimeString();\n" +
// 		"}\n" +
// 		// alert row builder
// 		"function buildAlertRow(a) {\n" +
// 		"  const cls = a.type === 'ML' ? 'ml' : 'heuristic';\n" +
// 		"  const badge = a.type === 'ML'\n" +
// 		"    ? '<span class=\"badge badge-red\">ML</span>'\n" +
// 		"    : '<span class=\"badge badge-yellow\">HEURISTIC</span>';\n" +
// 		"  return '<div class=\"alert-row ' + cls + '\">' + badge +\n" +
// 		"    '<strong>' + a.src_ip + '</strong> &rarr; ' + a.dst_ip + ':' + a.dst_port +\n" +
// 		"    '<span class=\"ts\">' + fmtTime(a.timestamp) + '</span></div>';\n" +
// 		"}\n" +
// 		// blocked IP table row builder — reason inferred from alert ring
// 		"var blockedMeta = {};\n" + // map ip -> {reason, timestamp}
// 		"function updateBlockedMeta(alerts) {\n" +
// 		"  alerts.forEach(function(a) {\n" +
// 		"    if (!blockedMeta[a.src_ip]) {\n" +
// 		"      blockedMeta[a.src_ip] = { reason: a.type, timestamp: a.timestamp };\n" +
// 		"    }\n" +
// 		"  });\n" +
// 		"}\n" +
// 		"function buildBlockedRow(ip, idx) {\n" +
// 		"  const meta = blockedMeta[ip] || {};\n" +
// 		"  const reason = meta.reason || 'UNKNOWN';\n" +
// 		"  const ts = fmtTime(meta.timestamp) || 'unknown';\n" +
// 		"  const reasonCls = reason === 'ML' ? 'reason-ml' : reason === 'HEURISTIC' ? 'reason-portscan' : 'reason-unknown';\n" +
// 		"  const reasonLabel = reason === 'ML' ? 'ML Detection' : reason === 'HEURISTIC' ? 'Port Scan' : reason;\n" +
// 		"  return '<tr>' +\n" +
// 		"    '<td style=\"color:var(--muted);font-size:0.72rem\">' + (idx+1) + '</td>' +\n" +
// 		"    '<td><span class=\"ip-chip\">' + ip + '</span></td>' +\n" +
// 		"    '<td><span class=\"reason-chip ' + reasonCls + '\">' + reasonLabel + '</span></td>' +\n" +
// 		"    '<td><span class=\"firewall-chip\">\xE2\x9C\x94 iptables DROP</span></td>' +\n" +
// 		"    '<td style=\"color:var(--muted);font-size:0.72rem\">' + ts + '</td>' +\n" +
// 		"    '</tr>';\n" +
// 		"}\n" +
// 		"async function refresh() {\n" +
// 		"  try {\n" +
// 		"    const [mRes, aRes, bRes] = await Promise.all([fetch('/metrics'), fetch('/alerts'), fetch('/blocked')]);\n" +
// 		"    const m = await mRes.json();\n" +
// 		"    const alerts = await aRes.json();\n" +
// 		"    const blockedData = await bRes.json();\n" +
// 		"    const blockedIPs = (blockedData && blockedData.blocked_ips) ? blockedData.blocked_ips : [];\n" +
// 		// update metric cards
// 		"    document.getElementById('uptime').textContent = fmtUptime(m.uptime_seconds);\n" +
// 		"    document.getElementById('pps').textContent = m.packets_per_second.toFixed(0);\n" +
// 		"    document.getElementById('flows').textContent = m.flows_active;\n" +
// 		"    document.getElementById('alerts').textContent = m.alerts_total;\n" +
// 		"    document.getElementById('blocked').textContent = m.blocked_ips;\n" +
// 		"    document.getElementById('latency').textContent = m.inference_latency_ms.toFixed(1) + ' ms';\n" +
// 		"    document.getElementById('packets').textContent = m.packets_total.toLocaleString();\n" +
// 		"    if (m.calibration_mode) {\n" +
// 		"      document.getElementById('calib-banner').style.display = 'block';\n" +
// 		"      document.getElementById('calib-count').textContent = m.calib_samples;\n" +
// 		"    }\n" +
// 		// update alert list
// 		"    const alertArr = Array.isArray(alerts) ? alerts : [];\n" +
// 		"    document.getElementById('alert-count').textContent = alertArr.length;\n" +
// 		"    const list = document.getElementById('alert-list');\n" +
// 		"    if (alertArr.length === 0) {\n" +
// 		"      list.innerHTML = '<div class=\"empty-msg\">No alerts yet.</div>';\n" +
// 		"    } else {\n" +
// 		"      list.innerHTML = alertArr.slice().reverse().map(buildAlertRow).join('');\n" +
// 		"    }\n" +
// 		// update blocked meta from alerts (to know reason+time per IP)
// 		"    updateBlockedMeta(alertArr);\n" +
// 		// update blocked IPs table
// 		"    document.getElementById('blocked-count').textContent = blockedIPs.length;\n" +
// 		"    const tbody = document.getElementById('blocked-body');\n" +
// 		"    if (blockedIPs.length === 0) {\n" +
// 		"      tbody.innerHTML = '<tr><td colspan=\"5\" class=\"empty-msg\">No IPs blocked yet.</td></tr>';\n" +
// 		"    } else {\n" +
// 		"      tbody.innerHTML = blockedIPs.map(buildBlockedRow).join('');\n" +
// 		"    }\n" +
// 		"  } catch(e) { console.warn('fetch failed', e); }\n" +
// 		"}\n" +
// 		"refresh();\n" +
// 		"setInterval(refresh, 1500);\n" +
// 		"</script>\n" +
// 		"</body>\n" +
// 		"</html>\n"
// }




package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ─────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────

const FeatureDimension = 17
const PortScanWindowSecs = 5
const PortScanThreshold = 15
const FlowExpirySecs = 60.0
const BatchIntervalDefault = 2 * time.Second
const LogChannelBuffer = 4096

// ─────────────────────────────────────────────
//  Global metrics for REST dashboard
// ─────────────────────────────────────────────

type SystemMetrics struct {
	mu              sync.RWMutex
	PacketsTotal    int64
	FlowsActive     int
	FlowsTotal      int64
	AlertsTotal     int64
	BlockedIPs      int
	InferenceLatMS  float64 // rolling average
	latSum          float64
	latCount        int64
	PacketsPerSec   float64
	pktCountWindow  int64
	windowStart     time.Time
	CalibrationMode bool
	CalibSamples    int
	Uptime          time.Time
}

var metrics = &SystemMetrics{windowStart: time.Now(), Uptime: time.Now()}

func (m *SystemMetrics) RecordPacket() {
	m.mu.Lock()
	m.PacketsTotal++
	m.pktCountWindow++
	elapsed := time.Since(m.windowStart).Seconds()
	if elapsed >= 1.0 {
		m.PacketsPerSec = float64(m.pktCountWindow) / elapsed
		m.pktCountWindow = 0
		m.windowStart = time.Now()
	}
	m.mu.Unlock()
}

func (m *SystemMetrics) RecordLatency(ms float64) {
	m.mu.Lock()
	m.latSum += ms
	m.latCount++
	m.InferenceLatMS = m.latSum / float64(m.latCount)
	m.mu.Unlock()
}

func (m *SystemMetrics) RecordAlert() {
	m.mu.Lock()
	m.AlertsTotal++
	m.mu.Unlock()
}

func (m *SystemMetrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"uptime_seconds":       time.Since(m.Uptime).Seconds(),
		"packets_total":        m.PacketsTotal,
		"packets_per_second":   m.PacketsPerSec,
		"flows_active":         m.FlowsActive,
		"flows_total":          m.FlowsTotal,
		"alerts_total":         m.AlertsTotal,
		"blocked_ips":          m.BlockedIPs,
		"inference_latency_ms": m.InferenceLatMS,
		"calibration_mode":     m.CalibrationMode,
		"calib_samples":        m.CalibSamples,
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
	}
}

// ─────────────────────────────────────────────
//  Async Logger
// ─────────────────────────────────────────────

type AlertLogger struct {
	ch      chan string
	logFile *os.File
}

func NewAlertLogger(path string) *AlertLogger {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("[LOGGER] Cannot open log file %s: %v", path, err)
	}
	al := &AlertLogger{ch: make(chan string, LogChannelBuffer), logFile: f}
	go al.worker()
	return al
}

// worker drains the channel — never blocks the capture goroutine
func (al *AlertLogger) worker() {
	for msg := range al.ch {
		ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		line := fmt.Sprintf("%s %s\n", ts, msg)
		al.logFile.WriteString(line)
	}
}

// Log is non-blocking: drops if buffer full rather than stalling capture
func (al *AlertLogger) Log(msg string) {
	select {
	case al.ch <- msg:
	default:
		// buffer full — discard rather than block packet capture
	}
}

func (al *AlertLogger) Close() {
	close(al.ch)
	al.logFile.Close()
}

// ─────────────────────────────────────────────
//  Firewall / Active Defense
// ─────────────────────────────────────────────

var blockedIPs = make(map[string]bool)
var blockMutex sync.Mutex

// safeIPs are IPs that must never be blocked (localhost, the operator's own IP)
var safeIPs = map[string]bool{
	"127.0.0.1": true,
	"::1":       true,
}

func SetSafeIP(ip string) { safeIPs[ip] = true }

func blockAttacker(ip string, logger *AlertLogger) {
	blockMutex.Lock()
	defer blockMutex.Unlock()

	if blockedIPs[ip] || safeIPs[ip] {
		return
	}

	msg := fmt.Sprintf("[FIREWALL] 🛡️  Active Defense triggered — blocking %s", ip)
	fmt.Println(msg)
	logger.Log(msg)

	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		errMsg := fmt.Sprintf("[FIREWALL ERROR] Failed to block %s: %v", ip, err)
		log.Println(errMsg)
		logger.Log(errMsg)
		return
	}

	blockedIPs[ip] = true
	metrics.mu.Lock()
	metrics.BlockedIPs++
	metrics.mu.Unlock()

	ok := fmt.Sprintf("[FIREWALL] ✅ %s isolated at kernel level.", ip)
	fmt.Println(ok)
	logger.Log(ok)

	// Push a firewall event into the alert ring so the dashboard
	// blocked-IPs table can display the reason and timestamp.
	alertRing.Push(map[string]string{
		"type":      "FIREWALL",
		"src_ip":    ip,
		"dst_ip":    "-",
		"dst_port":  "-",
		"detail":    "iptables DROP applied",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ─────────────────────────────────────────────
//  Heuristic Port-Scan Detector
// ─────────────────────────────────────────────

var scanTracker = make(map[string]map[string]time.Time)
var scanMutex sync.Mutex

func checkPortScan(srcIP, dstPort string, logger *AlertLogger) {
	if safeIPs[srcIP] {
		return
	}

	scanMutex.Lock()
	defer scanMutex.Unlock()

	if scanTracker[srcIP] == nil {
		scanTracker[srcIP] = make(map[string]time.Time)
	}

	now := time.Now()
	scanTracker[srcIP][dstPort] = now

	activePorts := 0
	for port, lastSeen := range scanTracker[srcIP] {
		if now.Sub(lastSeen) < PortScanWindowSecs*time.Second {
			activePorts++
		} else {
			delete(scanTracker[srcIP], port)
		}
	}

	if activePorts > PortScanThreshold {
		alert := fmt.Sprintf("[HEURISTIC ALERT] 🚨 Port Scan from %s! (%d unique ports in %ds)", srcIP, activePorts, PortScanWindowSecs)
		fmt.Println(alert)
		logger.Log(alert)
		metrics.RecordAlert()

		alertRing.Push(map[string]string{
			"type":      "HEURISTIC",
			"src_ip":    srcIP,
			"dst_ip":    "-",
			"dst_port":  "-",
			"detail":    fmt.Sprintf("%d unique ports in %ds", activePorts, PortScanWindowSecs),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})

		scanTracker[srcIP] = make(map[string]time.Time) // reset window
		go blockAttacker(srcIP, logger)
	}
}

// ─────────────────────────────────────────────
//  Flow Management (Welford's Algorithm)
// ─────────────────────────────────────────────

type FlowKey struct {
	SrcIP, DstIP, SrcPort, DstPort, Protocol string
}

type FlowStats struct {
	ServerPort float64
	Dirty      bool

	FwdPackets, BwdPackets, FwdBytes, BwdBytes int
	StartTime, LastSeenTime, LastPktTime       time.Time

	MinLen, MaxLen int
	MeanLen, M2Len float64
	TotalPackets   int

	MeanIAT, M2IAT float64
	IATCount       int

	SYN, ACK, FIN, RST, PSH int
}

type FlowManager struct {
	flows map[FlowKey]*FlowStats
	mutex sync.RWMutex
}

func NewFlowManager() *FlowManager {
	return &FlowManager{flows: make(map[FlowKey]*FlowStats)}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parsePort(portStr string) float64 {
	portOnly := strings.Split(portStr, "(")[0]
	p, err := strconv.Atoi(portOnly)
	if err != nil {
		return 0
	}
	return float64(p)
}

func shouldIgnoreTraffic(srcStr, dstStr string) bool {
	src := net.ParseIP(srcStr)
	dst := net.ParseIP(dstStr)
	if src == nil || dst == nil {
		return false
	}
	if src.IsLoopback() || dst.IsLoopback() {
		return true
	}
	if src.IsMulticast() || dst.IsMulticast() {
		return true
	}
	if src.IsLinkLocalMulticast() || dst.IsLinkLocalMulticast() {
		return true
	}
	if src.IsLinkLocalUnicast() || dst.IsLinkLocalUnicast() {
		return true
	}
	if dst.Equal(net.IPv4bcast) {
		return true
	}
	return false
}

func (fm *FlowManager) ProcessPacket(packet gopacket.Packet, logger *AlertLogger) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	if networkLayer == nil || transportLayer == nil {
		return
	}

	srcEndpoint, dstEndpoint := networkLayer.NetworkFlow().Endpoints()
	if shouldIgnoreTraffic(srcEndpoint.String(), dstEndpoint.String()) {
		return
	}

	metrics.RecordPacket()

	packetLength := len(packet.Data())
	timestamp := packet.Metadata().Timestamp

	var srcPort, dstPort, protocol string
	var syn, ack, fin, rst, psh bool

	switch layer := transportLayer.(type) {
	case *layers.TCP:
		protocol = "TCP"
		srcPort = layer.SrcPort.String()
		dstPort = layer.DstPort.String()
		syn, ack, fin, rst, psh = layer.SYN, layer.ACK, layer.FIN, layer.RST, layer.PSH
	case *layers.UDP:
		protocol = "UDP"
		srcPort = layer.SrcPort.String()
		dstPort = layer.DstPort.String()
	default:
		return
	}

	// Heuristic runs BEFORE ML — catches port scans that evade flow-based ML
	checkPortScan(srcEndpoint.String(), dstPort, logger)

	key := FlowKey{srcEndpoint.String(), dstEndpoint.String(), srcPort, dstPort, protocol}
	reverseKey := FlowKey{dstEndpoint.String(), srcEndpoint.String(), dstPort, srcPort, protocol}

	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	flow, exists := fm.flows[key]
	forward := true

	if !exists {
		if flow, exists = fm.flows[reverseKey]; exists {
			forward = false
		}
	}

	if !exists {
		flow = &FlowStats{
			ServerPort:   parsePort(dstPort),
			Dirty:        true,
			FwdPackets:   1,
			FwdBytes:     packetLength,
			StartTime:    timestamp,
			LastSeenTime: timestamp,
			LastPktTime:  timestamp,
			MinLen:       packetLength,
			MaxLen:       packetLength,
			MeanLen:      float64(packetLength),
			TotalPackets: 1,
			SYN:          boolToInt(syn),
			ACK:          boolToInt(ack),
			FIN:          boolToInt(fin),
			RST:          boolToInt(rst),
			PSH:          boolToInt(psh),
		}
		fm.flows[key] = flow
		metrics.mu.Lock()
		metrics.FlowsTotal++
		metrics.FlowsActive = len(fm.flows)
		metrics.mu.Unlock()
		return
	}

	flow.Dirty = true
	if forward {
		flow.FwdPackets++
		flow.FwdBytes += packetLength
	} else {
		flow.BwdPackets++
		flow.BwdBytes += packetLength
	}

	// Welford's Online Algorithm for IAT
	iat := timestamp.Sub(flow.LastPktTime).Seconds()
	if flow.TotalPackets > 0 {
		flow.IATCount++
		delta := iat - flow.MeanIAT
		flow.MeanIAT += delta / float64(flow.IATCount)
		flow.M2IAT += delta * (iat - flow.MeanIAT)
	}
	flow.LastPktTime = timestamp
	flow.LastSeenTime = timestamp
	flow.TotalPackets++

	if packetLength < flow.MinLen {
		flow.MinLen = packetLength
	}
	if packetLength > flow.MaxLen {
		flow.MaxLen = packetLength
	}

	// Welford's Online Algorithm for packet length
	delta := float64(packetLength) - flow.MeanLen
	flow.MeanLen += delta / float64(flow.TotalPackets)
	flow.M2Len += delta * (float64(packetLength) - flow.MeanLen)

	flow.SYN += boolToInt(syn)
	flow.ACK += boolToInt(ack)
	flow.FIN += boolToInt(fin)
	flow.RST += boolToInt(rst)
	flow.PSH += boolToInt(psh)

	if fin || rst {
		delete(fm.flows, key)
		metrics.mu.Lock()
		metrics.FlowsActive = len(fm.flows)
		metrics.mu.Unlock()
	}
}

// Snapshot collects all dirty flows into a feature-vector batch
func (fm *FlowManager) Snapshot() map[FlowKey][]float64 {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	now := time.Now()
	batch := make(map[FlowKey][]float64)

	for key, flow := range fm.flows {
		if now.Sub(flow.LastSeenTime).Seconds() > FlowExpirySecs {
			delete(fm.flows, key)
			continue
		}
		if !flow.Dirty {
			continue
		}

		stdLen, stdIAT := 0.0, 0.0
		if flow.TotalPackets > 1 {
			stdLen = math.Sqrt(flow.M2Len / float64(flow.TotalPackets-1))
		}
		if flow.IATCount > 1 {
			stdIAT = math.Sqrt(flow.M2IAT / float64(flow.IATCount-1))
		}

		duration := flow.LastSeenTime.Sub(flow.StartTime).Seconds()

		vector := []float64{
			flow.ServerPort,
			float64(flow.FwdPackets), float64(flow.BwdPackets),
			float64(flow.FwdBytes), float64(flow.BwdBytes),
			float64(flow.MinLen), float64(flow.MaxLen),
			flow.MeanLen, stdLen, duration,
			flow.MeanIAT, stdIAT,
			float64(flow.SYN), float64(flow.ACK),
			float64(flow.FIN), float64(flow.RST), float64(flow.PSH),
		}

		if len(vector) == FeatureDimension {
			batch[key] = vector
		}
		flow.Dirty = false
	}

	metrics.mu.Lock()
	metrics.FlowsActive = len(fm.flows)
	metrics.mu.Unlock()

	return batch
}

// ─────────────────────────────────────────────
//  Calibration Mode
// ─────────────────────────────────────────────

// CalibWriter writes safe-traffic samples to a CSV for AE retraining
type CalibWriter struct {
	mu     sync.Mutex
	file   *os.File
	count  int
	target int
	done   chan struct{}
}

func NewCalibWriter(path string, target int) (*CalibWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	// Write CSV header matching the 17 features
	header := "server_port,fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,min_len,max_len,mean_len,std_len,duration,mean_iat,std_iat,syn,ack,fin,rst,psh\n"
	f.WriteString(header)
	return &CalibWriter{file: f, target: target, done: make(chan struct{})}, nil
}

func (cw *CalibWriter) Write(vector []float64) bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.count >= cw.target {
		return false
	}
	strs := make([]string, len(vector))
	for i, v := range vector {
		strs[i] = fmt.Sprintf("%f", v)
	}
	cw.file.WriteString(strings.Join(strs, ",") + "\n")
	cw.count++
	metrics.mu.Lock()
	metrics.CalibSamples = cw.count
	metrics.mu.Unlock()
	if cw.count >= cw.target {
		cw.file.Close()
		close(cw.done)
	}
	return true
}

func (cw *CalibWriter) Done() <-chan struct{} { return cw.done }

// ─────────────────────────────────────────────
//  Python ML Service IPC
// ─────────────────────────────────────────────

func startPythonMLService(pythonBin, scriptPath, workDir string) (io.WriteCloser, *bufio.Reader, *exec.Cmd) {
	cmd := exec.Command(pythonBin, scriptPath)
	cmd.Dir = workDir
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatalf("[IPC] Failed to create stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("[IPC] Failed to create stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("[IPC] Failed to start Python ML service: %v", err)
	}

	reader := bufio.NewReader(stdout)
	fmt.Println("[IPC] Waiting for ML models to load into RAM...")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("[IPC] Error reading from Python during startup: %v", err)
		}
		if strings.TrimSpace(line) == "READY" {
			fmt.Println("[IPC] ✅ ML Service is READY and listening.")
			break
		}
	}
	return stdin, reader, cmd
}

// ─────────────────────────────────────────────
//  REST API Dashboard
// ─────────────────────────────────────────────

// recentAlerts is a circular buffer for the /alerts endpoint
type AlertRing struct {
	mu    sync.Mutex
	items []map[string]string
	cap   int
}

func NewAlertRing(cap int) *AlertRing { return &AlertRing{cap: cap} }

func (r *AlertRing) Push(alert map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.cap {
		r.items = r.items[1:]
	}
	r.items = append(r.items, alert)
}

func (r *AlertRing) All() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]string, len(r.items))
	copy(out, r.items)
	return out
}

var alertRing = NewAlertRing(200)

func startRESTAPI(addr string) {
	mux := http.NewServeMux()

	// CORS helper
	cors := func(w http.ResponseWriter) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
	}

	// GET /metrics — live system metrics
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		json.NewEncoder(w).Encode(metrics.Snapshot())
	})

	// GET /alerts — recent threat alerts (circular buffer)
	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		json.NewEncoder(w).Encode(alertRing.All())
	})

	// GET /blocked — list of blocked IPs
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		blockMutex.Lock()
		ips := make([]string, 0, len(blockedIPs))
		for ip := range blockedIPs {
			ips = append(ips, ip)
		}
		blockMutex.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"blocked_ips": ips})
	})

	// GET /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Serve the live dashboard HTML
	mux.HandleFunc("/", serveDashboard)

	fmt.Printf("[REST API] 🌐 Dashboard available at http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[REST API] Server failed: %v", err)
	}
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML()))
}

// ─────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────

func main() {
	iface      := flag.String("interface", "wlan0", "Network interface to monitor")
	pyBin      := flag.String("python", "../nids-ml/venv/bin/python", "Path to Python executable")
	pyScript   := flag.String("script", "detect_stream.py", "Path to continuous detection script")
	workDir    := flag.String("workdir", "../nids-ml", "Working directory for ML script")
	interval   := flag.Duration("interval", BatchIntervalDefault, "Micro-batch processing interval")
	apiAddr    := flag.String("api", ":8080", "REST API / dashboard listen address")
	logPath    := flag.String("log", "shadowguard_alerts.log", "Alert log file path")
	calibMode  := flag.Bool("calibrate", false, "Run calibration mode to capture safe-traffic baseline")
	calibOut   := flag.String("calib-out", "../nids-ml/calib_baseline.csv", "Calibration output CSV path")
	calibCount := flag.Int("calib-count", 500, "Number of safe-flow samples to capture for calibration")
	selfIP     := flag.String("self-ip", "", "Operator's own IP — will never be blocked")
	flag.Parse()

	if *selfIP != "" {
		SetSafeIP(*selfIP)
	}

	// ── Async logger
	logger := NewAlertLogger(*logPath)
	defer logger.Close()
	logger.Log("[SYSTEM] ShadowGuard-D starting up")

	// ── Calibration mode
	var calibWriter *CalibWriter
	if *calibMode {
		var err error
		calibWriter, err = NewCalibWriter(*calibOut, *calibCount)
		if err != nil {
			log.Fatalf("[CALIB] Cannot create calibration file: %v", err)
		}
		metrics.mu.Lock()
		metrics.CalibrationMode = true
		metrics.mu.Unlock()
		fmt.Printf("[CALIB] 🎯 Calibration mode: recording %d safe-traffic samples to %s\n", *calibCount, *calibOut)
		fmt.Println("[CALIB]    ML inference is DISABLED during calibration.")

		go func() {
			<-calibWriter.Done()
			fmt.Printf("[CALIB] ✅ Calibration complete! %d samples saved to %s\n", *calibCount, *calibOut)
			fmt.Println("[CALIB]    Run `python retrain_autoencoder.py` to adapt the model.")
			logger.Log(fmt.Sprintf("[CALIB] Calibration complete: %d samples → %s", *calibCount, *calibOut))
		}()
	}

	// ── REST API (non-blocking)
	go startRESTAPI(*apiAddr)

	// ── Python ML service (only when not calibrating)
	var pyStdin  io.WriteCloser
	var pyStdout *bufio.Reader
	var pyCmd    *exec.Cmd
	if !*calibMode {
		pyStdin, pyStdout, pyCmd = startPythonMLService(*pyBin, *pyScript, *workDir)
		defer pyStdin.Close()
		defer pyCmd.Process.Kill()
	}

	// ── Signal handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[SYSTEM] Received interrupt — shutting down safely...")
		logger.Log("[SYSTEM] Graceful shutdown initiated")
		cancel()
	}()

	// ── libpcap
	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[PCAP] Failed to open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	bpfFilter := "not broadcast and not multicast"
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("[PCAP] Failed to set BPF filter: %v", err)
	}
	fmt.Printf("[PCAP] Kernel-level BPF filter active: \"%s\"\n", bpfFilter)
	fmt.Printf("[PCAP] Listening on interface: %s\n", *iface)
	fmt.Printf("[SYSTEM] ShadowGuard-D ▶ RUNNING\n\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	flowManager  := NewFlowManager()

	// ── Capture goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				flowManager.ProcessPacket(packet, logger)
			}
		}
	}()

	// ── Micro-batch ticker
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[SYSTEM] Shutdown complete.")
			return

		case <-ticker.C:
			batch := flowManager.Snapshot()
			if len(batch) == 0 {
				continue
			}

			for flowKey, row := range batch {
				// ── Calibration mode: record sample and skip ML
				if calibWriter != nil {
					calibWriter.Write(row)
					continue
				}

				// ── ML inference via IPC
				strRow := make([]string, len(row))
				for i, val := range row {
					strRow[i] = fmt.Sprintf("%f", val)
				}
				csvLine := strings.Join(strRow, ",") + "\n"

				t0 := time.Now()
				if _, err := pyStdin.Write([]byte(csvLine)); err != nil {
					log.Printf("[IPC] Write error: %v", err)
					continue
				}

				result, err := pyStdout.ReadString('\n')
				if err != nil {
					log.Printf("[IPC] Read error: %v", err)
					continue
				}
				latencyMS := float64(time.Since(t0).Microseconds()) / 1000.0
				metrics.RecordLatency(latencyMS)

				result = strings.TrimSpace(result)

				if strings.HasPrefix(result, "0") {
					fmt.Printf("[BENIGN]    %s → %s:%s | lat=%.1fms\n",
						flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, latencyMS)
				} else if strings.HasPrefix(result, "1") {
					alert := fmt.Sprintf("[ML ALERT] 🚨 MALICIOUS flow from %s → %s:%s | %s | lat=%.1fms",
						flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, result, latencyMS)
					fmt.Println(alert)
					logger.Log(alert)
					metrics.RecordAlert()

					alertRing.Push(map[string]string{
						"type":      "ML",
						"src_ip":    flowKey.SrcIP,
						"dst_ip":    flowKey.DstIP,
						"dst_port":  flowKey.DstPort,
						"detail":    result,
						"timestamp": time.Now().UTC().Format(time.RFC3339),
					})

					go blockAttacker(flowKey.SrcIP, logger)
				}
			}
		}
	}
}

// ─────────────────────────────────────────────
//  Embedded Dashboard HTML
// ─────────────────────────────────────────────

// dashboardHTML returns the live dashboard page.
func dashboardHTML() string {
	return "<!DOCTYPE html>\n" +
		"<html lang=\"en\">\n" +
		"<head>\n" +
		"<meta charset=\"UTF-8\">\n" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
		"<title>ShadowGuard-D Dashboard</title>\n" +
		"<style>\n" +
		"  :root {\n" +
		"    --bg: #0d1117; --card: #161b22; --border: #30363d;\n" +
		"    --green: #3fb950; --red: #f85149; --yellow: #d29922;\n" +
		"    --blue: #58a6ff; --text: #e6edf3; --muted: #8b949e;\n" +
		"    --orange: #e3771a;\n" +
		"  }\n" +
		"  * { box-sizing: border-box; margin: 0; padding: 0; }\n" +
		"  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; padding: 24px; }\n" +
		"  h1 { color: var(--blue); font-size: 1.6rem; margin-bottom: 4px; }\n" +
		"  .subtitle { color: var(--muted); font-size: 0.85rem; margin-bottom: 24px; }\n" +
		"  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }\n" +
		"  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }\n" +
		"  .card-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; }\n" +
		"  .card-value { font-size: 2rem; font-weight: 700; margin-top: 4px; }\n" +
		"  .green { color: var(--green); } .red { color: var(--red); }\n" +
		"  .yellow { color: var(--yellow); } .blue { color: var(--blue); }\n" +
		"  /* ── panels ── */\n" +
		"  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; }\n" +
		"  .panel-title { font-size: 1rem; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }\n" +
		"  .panel-title .count-badge { font-size: 0.75rem; background: var(--border); color: var(--muted); padding: 2px 8px; border-radius: 10px; }\n" +
		"  /* ── two-column layout for lower panels ── */\n" +
		"  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }\n" +
		"  @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } }\n" +
		"  /* ── alert list ── */\n" +
		"  .scroll-list { max-height: 340px; overflow-y: auto; font-family: monospace; font-size: 0.78rem; }\n" +
		"  .alert-row { padding: 7px 8px; border-bottom: 1px solid var(--border); display: flex; align-items: baseline; gap: 6px; }\n" +
		"  .alert-row.ml { border-left: 3px solid var(--red); }\n" +
		"  .alert-row.heuristic { border-left: 3px solid var(--yellow); }\n" +
		"  .alert-row .ts { color: var(--muted); font-size: 0.7rem; margin-left: auto; white-space: nowrap; }\n" +
		"  /* ── blocked IPs table ── */\n" +
		"  .blocked-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }\n" +
		"  .blocked-table thead tr { border-bottom: 1px solid var(--border); }\n" +
		"  .blocked-table th { text-align: left; padding: 6px 8px; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: .04em; font-weight: 500; }\n" +
		"  .blocked-table td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }\n" +
		"  .blocked-table tr:last-child td { border-bottom: none; }\n" +
		"  .blocked-table tr:hover td { background: rgba(255,255,255,0.03); }\n" +
		"  .ip-chip { font-family: monospace; font-size: 0.82rem; color: var(--text); font-weight: 600; }\n" +
		"  .reason-chip { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 0.68rem; font-weight: 600; }\n" +
		"  .reason-ml      { background: #2d1117; color: var(--red);    border: 1px solid var(--red); }\n" +
		"  .reason-portscan{ background: #1c1a10; color: var(--yellow); border: 1px solid var(--yellow); }\n" +
		"  .reason-unknown { background: #1a1f2e; color: var(--blue);   border: 1px solid var(--blue); }\n" +
		"  .firewall-chip { display: inline-flex; align-items: center; gap: 4px; font-size: 0.72rem; color: var(--green); }\n" +
		"  .empty-msg { color: var(--muted); font-size: 0.82rem; padding: 16px 8px; text-align: center; }\n" +
		"  /* ── misc ── */\n" +
		"  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }\n" +
		"  .badge-red    { background: #2d1117; color: var(--red);    border: 1px solid var(--red); }\n" +
		"  .badge-yellow { background: #1c1a10; color: var(--yellow); border: 1px solid var(--yellow); }\n" +
		"  .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 6px; }\n" +
		"  .dot-green { background: var(--green); box-shadow: 0 0 6px var(--green); }\n" +
		"  .calib-banner { background: #1c1a10; border: 1px solid var(--yellow); border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; color: var(--yellow); display: none; }\n" +
		"  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: var(--bg); } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }\n" +
		"</style>\n" +
		"</head>\n" +
		"<body>\n" +
		"<h1>\xF0\x9F\x9B\xA1\xEF\xB8\x8F ShadowGuard-D</h1>\n" +
		"<p class=\"subtitle\">Distributed NIDS/IPS \xE2\x80\x94 Live Observability Dashboard</p>\n" +
		"<div class=\"calib-banner\" id=\"calib-banner\">\n" +
		"  \xF0\x9F\x8E\xAF <strong>Calibration Mode Active</strong> \xE2\x80\x94 Recording safe-traffic baseline.\n" +
		"  Samples captured: <span id=\"calib-count\">0</span>\n" +
		"</div>\n" +
		"<div class=\"grid\">\n" +
		"  <div class=\"card\"><div class=\"card-label\">Status</div><div class=\"card-value green\" style=\"font-size:1.1rem;margin-top:8px\"><span class=\"status-dot dot-green\"></span>RUNNING</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Uptime</div><div class=\"card-value blue\" id=\"uptime\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Packets / s</div><div class=\"card-value green\" id=\"pps\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Active Flows</div><div class=\"card-value blue\" id=\"flows\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Total Alerts</div><div class=\"card-value red\" id=\"alerts\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Blocked IPs</div><div class=\"card-value red\" id=\"blocked\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Inference Latency</div><div class=\"card-value yellow\" id=\"latency\">--</div></div>\n" +
		"  <div class=\"card\"><div class=\"card-label\">Total Packets</div><div class=\"card-value blue\" id=\"packets\">--</div></div>\n" +
		"</div>\n" +
		"<div class=\"two-col\">\n" +
		"  <div class=\"panel\">\n" +
		"    <div class=\"panel-title\">\xF0\x9F\x9A\xA8 Recent Threat Alerts <span class=\"count-badge\" id=\"alert-count\">0</span></div>\n" +
		"    <div class=\"scroll-list\" id=\"alert-list\"><div class=\"empty-msg\">No alerts yet.</div></div>\n" +
		"  </div>\n" +
		"  <div class=\"panel\">\n" +
		"    <div class=\"panel-title\">\xF0\x9F\x94\x92 Blocked IPs <span class=\"count-badge\" id=\"blocked-count\">0</span></div>\n" +
		"    <div class=\"scroll-list\">\n" +
		"      <table class=\"blocked-table\">\n" +
		"        <thead><tr><th>#</th><th>IP Address</th><th>Reason</th><th>Firewall</th><th>Blocked At</th></tr></thead>\n" +
		"        <tbody id=\"blocked-body\"><tr><td colspan=\"5\" class=\"empty-msg\">No IPs blocked yet.</td></tr></tbody>\n" +
		"      </table>\n" +
		"    </div>\n" +
		"  </div>\n" +
		"</div>\n" +
		"<script>\n" +
		"function fmtUptime(s) {\n" +
		"  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = Math.floor(s%60);\n" +
		"  return (h>0?h+'h ':' ')+(m>0?m+'m ':' ')+sec+'s';\n" +
		"}\n" +
		"function fmtTime(ts) {\n" +
		"  if (!ts) return '';\n" +
		"  const d = new Date(ts);\n" +
		"  return d.toLocaleTimeString();\n" +
		"}\n" +
		"function buildAlertRow(a) {\n" +
		"  const cls = a.type === 'ML' ? 'ml' : 'heuristic';\n" +
		"  const badge = a.type === 'ML'\n" +
		"    ? '<span class=\"badge badge-red\">ML</span>'\n" +
		"    : '<span class=\"badge badge-yellow\">HEURISTIC</span>';\n" +
		"  return '<div class=\"alert-row ' + cls + '\">' + badge +\n" +
		"    '<strong>' + a.src_ip + '</strong> &rarr; ' + a.dst_ip + ':' + a.dst_port +\n" +
		"    '<span class=\"ts\">' + fmtTime(a.timestamp) + '</span></div>';\n" +
		"}\n" +
		"var blockedMeta = {};\n" +
		"function updateBlockedMeta(alerts) {\n" +
		"  alerts.forEach(function(a) {\n" +
		"    if (!blockedMeta[a.src_ip]) {\n" +
		"      blockedMeta[a.src_ip] = { reason: a.type, timestamp: a.timestamp };\n" +
		"    }\n" +
		"  });\n" +
		"}\n" +
		"function buildBlockedRow(ip, idx) {\n" +
		"  const meta = blockedMeta[ip] || {};\n" +
		"  const reason = meta.reason || 'UNKNOWN';\n" +
		"  const ts = fmtTime(meta.timestamp) || 'unknown';\n" +
		"  const reasonCls = reason === 'ML' ? 'reason-ml' : reason === 'HEURISTIC' ? 'reason-portscan' : 'reason-unknown';\n" +
		"  const reasonLabel = reason === 'ML' ? 'ML Detection' : reason === 'HEURISTIC' ? 'Port Scan' : reason;\n" +
		"  return '<tr>' +\n" +
		"    '<td style=\"color:var(--muted);font-size:0.72rem\">' + (idx+1) + '</td>' +\n" +
		"    '<td><span class=\"ip-chip\">' + ip + '</span></td>' +\n" +
		"    '<td><span class=\"reason-chip ' + reasonCls + '\">' + reasonLabel + '</span></td>' +\n" +
		"    '<td><span class=\"firewall-chip\">\xE2\x9C\x94 iptables DROP</span></td>' +\n" +
		"    '<td style=\"color:var(--muted);font-size:0.72rem\">' + ts + '</td>' +\n" +
		"    '</tr>';\n" +
		"}\n" +
		"async function refresh() {\n" +
		"  try {\n" +
		"    const [mRes, aRes, bRes] = await Promise.all([fetch('/metrics'), fetch('/alerts'), fetch('/blocked')]);\n" +
		"    const m = await mRes.json();\n" +
		"    const alerts = await aRes.json();\n" +
		"    const blockedData = await bRes.json();\n" +
		"    const blockedIPs = (blockedData && blockedData.blocked_ips) ? blockedData.blocked_ips : [];\n" +
		"    document.getElementById('uptime').textContent = fmtUptime(m.uptime_seconds);\n" +
		"    document.getElementById('pps').textContent = m.packets_per_second.toFixed(0);\n" +
		"    document.getElementById('flows').textContent = m.flows_active;\n" +
		"    document.getElementById('alerts').textContent = m.alerts_total;\n" +
		"    document.getElementById('blocked').textContent = m.blocked_ips;\n" +
		"    document.getElementById('latency').textContent = m.inference_latency_ms.toFixed(1) + ' ms';\n" +
		"    document.getElementById('packets').textContent = m.packets_total.toLocaleString();\n" +
		"    if (m.calibration_mode) {\n" +
		"      document.getElementById('calib-banner').style.display = 'block';\n" +
		"      document.getElementById('calib-count').textContent = m.calib_samples;\n" +
		"    }\n" +
		"    const alertArr = Array.isArray(alerts) ? alerts : [];\n" +
		"    document.getElementById('alert-count').textContent = alertArr.length;\n" +
		"    const list = document.getElementById('alert-list');\n" +
		"    if (alertArr.length === 0) {\n" +
		"      list.innerHTML = '<div class=\"empty-msg\">No alerts yet.</div>';\n" +
		"    } else {\n" +
		"      list.innerHTML = alertArr.slice().reverse().map(buildAlertRow).join('');\n" +
		"    }\n" +
		"    updateBlockedMeta(alertArr);\n" +
		"    document.getElementById('blocked-count').textContent = blockedIPs.length;\n" +
		"    const tbody = document.getElementById('blocked-body');\n" +
		"    if (blockedIPs.length === 0) {\n" +
		"      tbody.innerHTML = '<tr><td colspan=\"5\" class=\"empty-msg\">No IPs blocked yet.</td></tr>';\n" +
		"    } else {\n" +
		"      tbody.innerHTML = blockedIPs.map(buildBlockedRow).join('');\n" +
		"    }\n" +
		"  } catch(e) { console.warn('fetch failed', e); }\n" +
		"}\n" +
		"refresh();\n" +
		"setInterval(refresh, 1500);\n" +
		"</script>\n" +
		"</body>\n" +
		"</html>\n"
}