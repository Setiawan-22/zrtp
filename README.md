<div align="center">
  <h1>🛡️ ZRTP Hybrid Protocol</h1>
  <p><strong>General-Purpose Real-Time Engine for Ultra-Low Latency Streaming & Control</strong></p>
  
  [![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
  [![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](#)
  [![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg?style=flat-square)](#)
</div>

---

**ZRTP Hybrid Protocol** acts as a secure, high-performance middleware between Clients and Hosts. It is heavily optimized to run as a containerized daemon and is perfectly suited for use cases demanding absolute minimum latency.

> [!NOTE]
> This repository contains the **core protocol library** only. Mock clients, web gateways, and dashboard UI used for testing are explicitly excluded to maintain the purity of the protocol logic.

## 🎯 Use Cases
- 🎮 **Cloud Gaming** (High framerate, zero micro-stutter)
- 💻 **Remote Desktop** (Fluid interaction, lossless input)
- 🚁 **Drone & Robotics FPV** (High resilience over radio/LTE)
- 📡 **IoT Telemetry** (Rapid sensor data transmission)

## 🚀 Architecture: Dual-Protocol Engine

ZRTP utilizes a **Hybrid Multiplexing** architecture, separating data paths based on latency tolerance and reliability requirements:

| Channel | Protocol | Characteristics | Use Case |
| :--- | :--- | :--- | :--- |
| **Reliable** | `TCP` | Guaranteed delivery, zero fragmentation (`LengthDelimitedCodec`). | Signaling (Handshake), Chat, Input Injection. |
| **Zero-Latency**| `UDP` | Pure speed, drops retransmissions in favor of FEC. | Video Streaming (Screen Capture), Audio. |

> [!IMPORTANT]
> The UDP pipeline enforces strict **Max 1200 Bytes (MTU Safe)** payload splitting to avoid OS-level IP fragmentation.

## 🛡️ Security & Reliability Features

Our production-grade pipeline guarantees top-tier security without sacrificing latency:

- 🔑 **X25519 Ephemeral Handshake**: Generates mathematically secure, unique session keys per connection.
- 🔒 **ChaCha20-Poly1305 Encryption**: Lightweight and incredibly fast streaming encryption for all payloads.
- 🚫 **Anti-Replay Attack Defense**: Implements strict `nonce` validation and tracking on TCP layers.
- 🧹 **Zero-Cost Garbage Collector**: Utilizes a `BTreeMap` with O(log N) `split_off` to instantly prune obsolete UDP frames, ensuring zero memory leaks.

## 📊 Adaptive Forward Error Correction (FEC)

Powered by `reed-solomon-erasure`, ZRTP allows clients to dynamically negotiate the desired FEC ratio during the initial Handshake based on their network conditions:

| Profile | Ratio (Data:Parity) | Overhead | Drop Tolerance | Target Environment |
| :--- | :--- | :--- | :--- | :--- |
| **The Fortress** | 20 : 2 | ~10% | ~9% | LAN, Enterprise Datacenters |
| **The Daily Driver**| 10 : 3 | ~30% | ~23% | Public Internet, 4G, Cloud Gaming |
| **The Survivalist**| 4 : 2 | ~50% | ~33% | Drone FPV, IoT in bad signal areas |

## 📦 Tech Stack

- **Async Runtime**: `tokio`, `tokio-util`
- **Serialization**: `bincode` (Zero-cost byte transformation)
- **Cryptography**: `ring`
- **Error Recovery**: `reed-solomon-erasure`
- **Input Injection**: `evdev` (Linux `/dev/uinput`)

## ⚙️ Getting Started

*(Add instructions here on how to integrate the ZRTP core library into your Rust project)*

```toml
[dependencies]
zrtp = { path = "path/to/zrtp" }
```

> [!WARNING]
> The input injection module requires access to `/dev/uinput`. The application must be run with sufficient privileges (e.g., `root` or `sudo`) on a Linux environment.
