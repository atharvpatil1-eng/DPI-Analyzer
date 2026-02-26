# PyDPI: Professional Deep Packet Inspection Tool

PyDPI is a high-performance, modular Deep Packet Inspection (DPI) tool written in Python. It is designed for network analysis, security monitoring, and protocol research.

## Features

- **Real-time Traffic Analysis**: Capture and analyze packets in real-time from network interfaces.
- **Deep Protocol Decoding**: Support for multiple protocol layers:
    - **Layer 2**: Ethernet
    - **Layer 3**: IPv4, IPv6, ICMP
    - **Layer 4**: TCP, UDP
    - **Layer 7 (Deep Inspection)**: HTTP, DNS, TLS (SNI extraction)
- **Flow Tracking**: Automatic session reconstruction and flow state management.
- **Performance Optimized**: Uses a producer-consumer architecture with multiprocessing to handle high traffic volumes.
- **Professional CLI**: A rich, interactive command-line interface with real-time dashboards and structured logging.
- **Extensible Architecture**: Easily add new protocol decoders using a plugin-based system.

## Installation

```bash
pip install .
```

*Note: Capturing raw packets requires root/administrator privileges.*

## Usage

### Basic Capture
```bash
sudo pydpi capture --interface eth0
```

### File Analysis (PCAP)
```bash
pydpi analyze --file capture.pcap
```

### Filtered Inspection
```bash
sudo pydpi capture --filter "tcp port 443" --json-output logs.json
```

## Architecture

PyDPI follows a pipeline architecture:
1. **Engine**: Handles raw packet capture using Scapy and manages the worker pool.
2. **Decoders**: A chain of protocol-specific decoders that normalize packet data.
3. **Flow Manager**: Groups packets into bidirectional flows (5-tuples).
4. **Output Handler**: Formats and exports data to the console or log files.
