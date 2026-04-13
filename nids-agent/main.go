package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
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

const FeatureDimension = 17

// Global variables for the Firewall Active Defense
var blockedIPs = make(map[string]bool)
var blockMutex sync.Mutex

// Global variables for the Port Scan Heuristic Detector
var scanTracker = make(map[string]map[string]time.Time)
var scanMutex sync.Mutex

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
	if src.IsLoopback() || dst.IsLoopback() || src.IsMulticast() || dst.IsMulticast() {
		return true
	}
	if src.IsLinkLocalMulticast() || dst.IsLinkLocalMulticast() || src.IsLinkLocalUnicast() || dst.IsLinkLocalUnicast() {
		return true
	}
	if dst.Equal(net.IPv4bcast) {
		return true
	}
	return false
}

// Active Defense: Dynamically adds an iptables rule to drop the attacker
func blockAttacker(ip string) {
	blockMutex.Lock()
	defer blockMutex.Unlock()

	// Safety check + duplicate block check
	if blockedIPs[ip] || ip == "10.31.21.84" || ip == "127.0.0.1" {
		return
	}

	fmt.Printf("\n[FIREWALL] 🛡️ Executing Active Defense! Dropping all packets from %s\n", ip)

	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()

	if err != nil {
		log.Printf("[FIREWALL ERROR] Failed to block IP %s: %v", ip, err)
	} else {
		blockedIPs[ip] = true
		fmt.Printf("[FIREWALL] ✅ IP %s successfully isolated. Attack neutralized.\n\n", ip)
	}
}

// HEURISTIC ENGINE: Tracks connections to detect stealthy Port Scans
func checkPortScan(srcIP, dstPort string) {
	if srcIP == "10.31.21.84" || srcIP == "127.0.0.1" {
		return
	}

	scanMutex.Lock()
	defer scanMutex.Unlock()

	if scanTracker[srcIP] == nil {
		scanTracker[srcIP] = make(map[string]time.Time)
	}
	
	now := time.Now()
	scanTracker[srcIP][dstPort] = now

	// Count unique ports hit in the last 5 seconds
	activePorts := 0
	for port, lastSeen := range scanTracker[srcIP] {
		if now.Sub(lastSeen) < 5*time.Second {
			activePorts++
		} else {
			delete(scanTracker[srcIP], port)
		}
	}

	// If they hit more than 15 unique ports in 5 seconds, it is definitely a scan!
	if activePorts > 15 {
		fmt.Printf("\n[HEURISTIC ALERT] 🚨 Port Scan detected from %s! (>15 ports in 5s)\n", srcIP)
		
		// Clear their tracking map so we don't spam the alert
		scanTracker[srcIP] = make(map[string]time.Time) 
		
		// Trigger the firewall asynchronously
		go blockAttacker(srcIP)
	}
}

func (fm *FlowManager) ProcessPacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	if networkLayer == nil || transportLayer == nil {
		return
	}

	srcEndpoint, dstEndpoint := networkLayer.NetworkFlow().Endpoints()
	if shouldIgnoreTraffic(srcEndpoint.String(), dstEndpoint.String()) {
		return
	}

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

	// TRIGGER THE PORT SCAN HEURISTIC BEFORE ML
	checkPortScan(srcEndpoint.String(), dstPort)

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
	}
}

func (fm *FlowManager) Snapshot() map[FlowKey][]float64 {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	now := time.Now()
	expire := 60.0
	batch := make(map[FlowKey][]float64)

	for key, flow := range fm.flows {
		if now.Sub(flow.LastSeenTime).Seconds() > expire {
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
			flow.ServerPort, float64(flow.FwdPackets), float64(flow.BwdPackets),
			float64(flow.FwdBytes), float64(flow.BwdBytes), float64(flow.MinLen),
			float64(flow.MaxLen), flow.MeanLen, stdLen, duration,
			flow.MeanIAT, stdIAT, float64(flow.SYN), float64(flow.ACK),
			float64(flow.FIN), float64(flow.RST), float64(flow.PSH),
		}

		if len(vector) == FeatureDimension {
			batch[key] = vector
		}
		flow.Dirty = false
	}
	return batch
}

func startPythonMLService(pythonBin, scriptPath, workDir string) (io.WriteCloser, *bufio.Reader, *exec.Cmd) {
	cmd := exec.Command(pythonBin, scriptPath)
	cmd.Dir = workDir
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatalf("Failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start Python ML service: %v", err)
	}

	reader := bufio.NewReader(stdout)

	fmt.Println("Waiting for ML models to load into RAM...")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Error reading from Python during startup: %v", err)
		}
		if strings.TrimSpace(line) == "READY" {
			fmt.Println("ML Service is READY and listening.")
			break
		}
	}

	return stdin, reader, cmd
}

func main() {
	iface := flag.String("interface", "wlan0", "Network interface to monitor")
	pyBin := flag.String("python", "../nids-ml/venv/bin/python", "Path to Python executable")
	pyScript := flag.String("script", "detect_stream.py", "Path to continuous detection script")
	workDir := flag.String("workdir", "../nids-ml", "Working directory for ML script")
	interval := flag.Duration("interval", 2*time.Second, "Batch processing interval")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pyStdin, pyStdout, pyCmd := startPythonMLService(*pyBin, *pyScript, *workDir)
	defer pyStdin.Close()
	defer pyCmd.Process.Kill()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal. Shutting down NIDS agent safely...")
		cancel()
	}()

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("not broadcast and not multicast")
	if err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}
	fmt.Println("Kernel-level BPF Filter applied: Ignoring broadcast and multicast.")

	fmt.Printf("Integrated Hybrid NIDS Running on %s\n", *iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	flowManager := NewFlowManager()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				flowManager.ProcessPacket(packet)
			}
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Shutdown complete.")
			return
		case <-ticker.C:
			batch := flowManager.Snapshot()
			if len(batch) > 0 {
				for flowKey, row := range batch {
					strRow := make([]string, len(row))
					for i, val := range row {
						strRow[i] = fmt.Sprintf("%f", val)
					}
					csvLine := strings.Join(strRow, ",") + "\n"

					_, err := pyStdin.Write([]byte(csvLine))
					if err != nil {
						log.Printf("Failed to send data to Python: %v", err)
						continue
					}

					result, err := pyStdout.ReadString('\n')
					if err != nil {
						log.Printf("Failed to read prediction from Python: %v", err)
						continue
					}

					result = strings.TrimSpace(result)

					if strings.HasPrefix(result, "0") {
						fmt.Printf("[BENIGN] Flow: %s -> %s:%s | Stats: %s\n", flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, result)
					} else if strings.HasPrefix(result, "1") {
						fmt.Printf("[MALICIOUS - ML DETECTED] Flow: %s -> %s:%s | Stats: %s\n", flowKey.SrcIP, flowKey.DstIP, flowKey.DstPort, result)
						go blockAttacker(flowKey.SrcIP)
					}
				}
			}
		}
	}
}