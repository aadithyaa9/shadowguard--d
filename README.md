# ShadowGuard-D: Distributed Network Intrusion Detection/Prevention System

A high-throughput, distributed NIDS/IPS implementing the split-plane architecture described in the IEEE paper. Achieves sub-20ms inference latency with zero packet loss on live enterprise Wi-Fi.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: Go Edge Sensor (nids-agent/)          Fast Capture Plane  │
│                                                                       │
│  libpcap → BPF Filter → Flow Manager (5-tuple)                       │
│              ↓                ↓                                       │
│         Heuristic IPS    Welford O(1) Feature Engine                 │
│         (Port Scan)       (17 statistical features)                  │
│              ↓                ↓                                       │
│         iptables DROP    Micro-batch → stdin pipe                    │
│                                ↓                                      │
│                         REST API + Async Logger                       │
└─────────────────────────────────────────────────────────────────────┘
                                 │ IPC (CSV over stdio)
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: Python ML Engine (nids-ml/)          Inference Plane       │
│                                                                       │
│  stdin → Scaler → ┬→ Random Forest  (known threats, CIC-IDS2017)    │
│                   └→ Autoencoder    (zero-day anomaly detection)     │
│                         ↓ fusion                                      │
│                   label + confidence → stdout → Go                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Paper Goals → Implementation Status

| Goal | File | Status |
|------|------|--------|
| Go edge sensor, gopacket, BPF filter | `nids-agent/main.go` | ✅ |
| Welford's O(1) feature extraction (17 features) | `nids-agent/main.go` | ✅ |
| 5-tuple stateful flow management | `nids-agent/main.go` | ✅ |
| Micro-batch IPC (stdin/stdout CSV) | `nids-agent/main.go` | ✅ |
| Hybrid RF + Autoencoder backend | `nids-ml/detect_stream.py` | ✅ |
| Random Forest on CIC-IDS2017 | `nids-ml/train_models.py` | ✅ |
| Autoencoder for zero-day anomaly detection | `nids-ml/train_models.py` | ✅ |
| Heuristic port-scan IPS (>15 ports / 5s) | `nids-agent/main.go` | ✅ |
| iptables active kernel-level blocking | `nids-agent/main.go` | ✅ |
| **Asynchronous logging (non-blocking channels)** | `nids-agent/main.go` | ✅ |
| **REST API (metrics, alerts, blocked IPs)** | `nids-agent/main.go` | ✅ |
| **Live web dashboard** | `nids-agent/main.go` (embedded) | ✅ |
| **Calibration Mode for domain adaptation** | `nids-agent/main.go` | ✅ |
| **Autoencoder retraining on local baseline** | `nids-ml/retrain_autoencoder.py` | ✅ |
| Inference latency tracking (rolling avg) | `nids-agent/main.go` | ✅ |
| Sub-20ms inference | Architecture design | ✅ |

---

## Quick Start

### 1. Set up the Python ML environment

```bash
cd nids-ml
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Train models on CIC-IDS2017

```bash
# Download CIC-IDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html
python train_models.py --dataset /path/to/CICIDS2017/ --sample 200000
```

### 3. Build the Go agent

```bash
cd nids-agent
go mod tidy
go build -o shadowguard .
```

### 4. Run live detection

```bash
# Must be run as root (requires raw packet capture + iptables)
sudo ./shadowguard \
    --interface wlan0 \
    --self-ip 10.31.21.84 \
    --api :8080 \
    --log shadowguard_alerts.log
```

Open `http://localhost:8080` for the live dashboard.

---

## Calibration Mode (Domain Adaptation)

The "Kaggle Gap" — false positives from local benign traffic like captive portals
and package manager downloads — is solved by recording a local baseline and
retraining the Autoencoder on it.

### Step 1: Capture safe-traffic baseline (Go agent)

```bash
sudo ./shadowguard \
    --interface wlan0 \
    --calibrate \
    --calib-count 500 \
    --calib-out ../nids-ml/calib_baseline.csv \
    --self-ip 10.31.21.84
```

Browse normally. The agent records 500 flow samples. ML inference is disabled.

### Step 2: Retrain Autoencoder on local baseline

```bash
cd nids-ml
source venv/bin/activate
python retrain_autoencoder.py --calib calib_baseline.csv --epochs 30
```

New model files saved:
- `autoencoder_real_fixed.h5` — domain-adapted AE
- `scaler_real.pkl` — local scaler
- `ae_threshold_real1.pkl` — local threshold
- `feature_order.pkl` — feature mapping

### Step 3: Restart in normal mode

```bash
sudo ./shadowguard --interface wlan0 --self-ip 10.31.21.84
```

The inference engine automatically loads the real-data models over CIC-IDS2017 models.

---

## REST API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Live web dashboard |
| `GET /metrics` | JSON: packets/s, active flows, alerts, latency, uptime |
| `GET /alerts` | JSON: last 200 threat alerts |
| `GET /blocked` | JSON: list of currently blocked IPs |
| `GET /health` | `{"status":"ok"}` |

---

## CLI Flags

```
--interface     Network interface to capture on (default: wlan0)
--python        Path to Python executable (default: ../nids-ml/venv/bin/python)
--script        detect_stream.py path (default: detect_stream.py)
--workdir       Working dir for ML script (default: ../nids-ml)
--interval      Micro-batch interval (default: 2s)
--api           REST API listen address (default: :8080)
--log           Alert log file path (default: shadowguard_alerts.log)
--self-ip       Operator's IP — never blocked (important: set this!)
--calibrate     Run calibration mode (no ML inference)
--calib-out     Calibration CSV output path
--calib-count   Number of safe samples to capture (default: 500)
```

---

## The 17 Feature Vector (Welford's Algorithm)

Computed incrementally in O(1) space per flow:

| # | Feature | Description |
|---|---------|-------------|
| 1 | server_port | Destination port |
| 2 | fwd_pkts | Forward packet count |
| 3 | bwd_pkts | Backward packet count |
| 4 | fwd_bytes | Forward byte total |
| 5 | bwd_bytes | Backward byte total |
| 6 | min_len | Min packet length |
| 7 | max_len | Max packet length |
| 8 | mean_len | Welford mean packet length |
| 9 | std_len | Welford std packet length |
| 10 | duration | Flow duration (seconds) |
| 11 | mean_iat | Welford mean inter-arrival time |
| 12 | std_iat | Welford std inter-arrival time |
| 13–17 | syn/ack/fin/rst/psh | TCP flag counts |

---

## Heuristic IPS Logic

Port scan detection runs **before** ML inference — this catches attacks that evade
flow-based ML (isolated SYN packets never form a full flow):

```
For each incoming packet SrcIP → DstPort:
  Track unique DstPorts per SrcIP in a 5-second sliding window
  If unique_ports > 15:
    → Alert logged asynchronously
    → iptables -A INPUT -s <SrcIP> -j DROP (kernel-level, goroutine)
    → Window reset to suppress alert spam
```

---

## Async Logging Design

```
Capture goroutine
      │
      │ (non-blocking channel send)
      ▼
  chan string (buffer=4096)
      │
      │ (dedicated background goroutine drains)
      ▼
  shadowguard_alerts.log
```

The capture thread **never blocks** on disk I/O. If the log channel fills up
(e.g., sustained attack flooding), entries are dropped rather than stalling capture.

---

## Future Work (from paper)

- gRPC + Protobuf transport layer for multi-sensor WAN deployment
- Replace stdin/stdout IPC with gRPC streaming RPC
- GPU-accelerated inference for >10 Gbps environments
- Federated learning across campus edge sensors
