# DLL Flowlyzer - Enhanced Network Flow Analyzer

A comprehensive network flow analysis tool focused on Layer 2 (DataLink Layer) protocol feature extraction with advanced machine learning features. Analyzes PCAP files to extract 350+ detailed features from network flows, supporting all major Layer 2 protocols with real-time processing and advanced visualization.

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run analysis:
```bash
python -m src.flowlyzer.main -i Input/your_capture.pcap
```

## Core Features

- **352+ Comprehensive Features**: Statistical, protocol-specific, advanced entropy/jitter features, and flow timing
- **Multi-Protocol Support**: TCP, UDP, QUIC, and Layer 2 protocols (STP, CDP, LLDP, ARP, DHCP, LLC, DTP, VTP, ISL)  
- **Enhanced Layer 2 Analysis**: Deep packet inspection for CDP TLVs, STP identifiers, DHCP options, ARP details
- **Advanced Statistical Analysis**: Entropy, jitter, burstiness, temporal concentration, protocol diversity
- **Real-time Processing**: Batched CSV export with memory optimization
- **Automatic Visualization**: Layer 2 protocol distribution plots and comprehensive analysis charts
- **Flow Detection**: Bidirectional flow detection with configurable timeouts
- **Multi-threaded Processing**: Parallel packet processing with optimized queuing

## New Advanced Features

### Statistical Analysis Features
- **Packet Length Entropy**: Shannon entropy of packet sizes for randomness detection
- **Inter-arrival Jitter**: Packet timing variance analysis  
- **Burstiness Factor**: Ratio of maximum to mean inter-arrival time
- **Temporal Concentration**: Distribution of packets across time bins
- **Protocol Diversity**: Protocol switching and diversity within flows
- **Payload Size Regularity**: Consistency analysis of payload sizes

### Enhanced Layer 2 Features
- **ARP Protocol**: Hardware/protocol types, opcodes, address mappings, gratuitous detection
- **DHCP Protocol**: BOOTP fields, flags, options parsing, message types, transaction analysis
- **STP Protocol**: Root/bridge identifiers with priorities, timing fields, topology flags
- **CDP Protocol**: Complete TLV parsing, device capabilities, power management
- **LLDP Protocol**: TLV structure analysis, chassis/port ID extraction
- **DTP/ISL Protocol**: Dynamic Trunking and Inter-Switch Link analysis

## Usage Examples

### Simple Commands (Easy Interface)
```bash
python -m src.flowlyzer.main -i file.pcap                    # Analyze single file
python -m src.flowlyzer.main -i Input/                       # Analyze directory
python -m src.flowlyzer.main -i Input/ --multi-folder        # Process multiple folders
python -m src.flowlyzer.main -i Input/ --separate-layers     # Separate Layer 2/3 files
python -m src.flowlyzer.main -i Input/ --workers 8           # Use more threads
python -m src.flowlyzer.main -i Input/ -o MyResults          # Custom output directory
python -m src.flowlyzer.main -i Input/ --quiet               # Suppress detailed output
```

## Project Structure

```
DLLFlowlyzerV1/
├── Input/                          # Directory for input PCAP files
├── Results/                        # Directory for output CSV files and plots
├── config.ini                     # Configuration file
├── requirements.txt               # Python dependencies
├── src/
│   └── flowlyzer/                 # Main package
│       ├── main.py                # Entry point and orchestration
│       ├── packets/               # Packet analysis classes
│       │   ├── base_packet.py     # Base packet class
│       │   ├── tcp_packet.py      # TCP packet analysis
│       │   ├── udp_packet.py      # UDP packet analysis
│       │   ├── layer2_packet.py   # Layer 2 protocols
│       │   └── llc_packet.py      # LLC and related protocols
│       ├── flows/                 # Flow management
│       │   ├── flow.py            # Flow class with feature extraction
│       │   └── flow_manager.py    # Flow lifecycle management
│       ├── features/              # Feature extraction and export
│       │   ├── feature_extractor.py # Main feature extraction engine
│       │   ├── labeling.py        # Labeling system (always UnLabeled)
│       │   └── csv_exporter.py    # CSV export with batching
│       └── utils/                 # Utility classes
│           ├── config_manager.py  # Configuration management
│           ├── logger.py          # Logging system
│           ├── memory_monitor.py  # Memory optimization
│           ├── packet_queue.py    # Packet processing queue
│           └── plotting.py        # Visualization system
```

## Feature Categories (352+ Total Features)

| Category | Count | Description |
|----------|-------|-------------|
| **Flow Identifiers** | 5 | Basic flow identification and timing |
| **MAC Address Features** | 14 | Source/destination MAC analysis with vendor info |
| **Network Layer** | 5 | IP addresses, ports, Ethernet types |
| **Frame Statistics** | 32 | Packet size, direction, quality metrics |
| **Advanced Statistical** | 10 | Entropy, jitter, burstiness, temporal features |
| **LLC Features** | 15 | Logical Link Control protocol analysis |
| **STP Features** | 25 | Spanning Tree Protocol comprehensive analysis |
| **CDP Features** | 69 | Cisco Discovery Protocol extensive features |
| **ARP Features** | 36 | Address Resolution Protocol detailed analysis |
| **DHCP Features** | 37 | DHCP protocol comprehensive features |
| **DTP Features** | 15 | Dynamic Trunking Protocol analysis |
| **ISL Features** | 18 | Inter-Switch Link protocol analysis |
| **Additional Protocols** | 71+ | LLDP, VTP, Loop Detection, and statistical combinations |

## Key Feature Examples

### Basic Flow Features
- `connection`: Unique flow identifier
- `protocol`: Primary protocol type
- `num_frame`: Total packets in flow
- `time_delta`: Flow duration
- `flow_start_time`: Unix timestamp when flow started
- `flow_end_time`: Unix timestamp when flow ended
- `sum_frame_len`: Total bytes

### Advanced Statistical Features  
- `packet_length_entropy`: Shannon entropy of packet sizes
- `inter_arrival_jitter`: Packet timing variance
- `burstiness_factor`: Traffic burstiness indicator
- `temporal_concentration`: Packet distribution over time
- `protocol_diversity_ratio`: Protocol variety within flow

### Layer 2 Protocol Features
- `stp_*`: Spanning Tree Protocol features (25 features)
- `cdp_*`: Cisco Discovery Protocol features (69 features)
- `arp_*`: ARP protocol features (36 features)
- `dhcp_*`: DHCP protocol features (37 features)
- `llc_*`: LLC protocol features (15 features)

## Output Files

### CSV Files
- `features_combined_YYYYMMDD_HHMMSS.csv` - All flows with 350+ features
- `features_layer2_YYYYMMDD_HHMMSS.csv` - Layer 2 flows (optional)
- `features_layer3_YYYYMMDD_HHMMSS.csv` - Layer 3 flows (optional)

### Visualization Files (Automatic)
- `protocol_statistics_YYYYMMDD_HHMMSS.png` - Protocol distribution
- `layer2_protocol_distribution_YYYYMMDD_HHMMSS.png` - Layer 2 analysis
- `layer2_analysis_YYYYMMDD_HHMMSS.png` - Protocol breakdown
- `layer2_heatmap_analysis_YYYYMMDD_HHMMSS.png` - Correlation analysis
- `flow_statistics_YYYYMMDD_HHMMSS.png` - Flow characteristics
- `feature_correlation_YYYYMMDD_HHMMSS.png` - Feature correlations

### Log Files
- `log.txt` - Comprehensive processing log

## Performance Optimizations

- **Multi-Level Threading**: Packet processing, feature extraction, and folder processing
- **Memory Optimization**: Batched processing prevents OOM errors
- **Real-time CSV Export**: Incremental saving prevents data loss
- **Automatic Cleanup**: Memory-aware flow management
- **Progress Tracking**: Real-time processing updates

## Missing Value Handling

All features use `-100` as the default value for missing or unavailable data, ensuring:
- Consistent data format for machine learning
- Clear distinction between zero values and missing data
- Compatibility with ML algorithms

## Label System

**Important**: All flows are automatically labeled as `UnLabeled` regardless of input configuration. This ensures consistent unlabeled datasets for unsupervised learning or custom labeling workflows.

## Requirements

- Python 3.8+
- scapy>=2.5.0
- pandas>=1.5.0  
- numpy>=1.21.0
- matplotlib>=3.5.0
- seaborn>=0.11.0
- scipy (optional, for advanced statistics)

## Installation

```bash
git clone <repository>
cd DLLFlowlyzerV1
pip install -r requirements.txt
```

## Simple Command Interface

The tool now features a **greatly simplified** command-line interface for easier interaction. No more complex configuration arguments needed!

```bash
# Basic usage
python -m src.flowlyzer.main -i file.pcap                    # Single file
python -m src.flowlyzer.main -i Input/                       # Directory  

# Advanced options
python -m src.flowlyzer.main -i Input/ --multi-folder        # Multiple folders
python -m src.flowlyzer.main -i Input/ --separate-layers     # Layer 2/3 separation
python -m src.flowlyzer.main -i Input/ --workers 8           # Performance tuning
python -m src.flowlyzer.main -i Input/ -o Results --quiet    # Custom output, less verbose
```

## Architecture Highlights

- **Production-Ready**: Optimized code with removed development comments
- **Scalable**: Handles large PCAP files with memory optimization
- **Extensible**: Modular design for easy feature additions
- **Robust**: Comprehensive error handling and fallback mechanisms
- **Automated**: Automatic visualization generation after processing

This enhanced version provides comprehensive network flow analysis with advanced statistical features, optimized performance, and automatic visualization generation.