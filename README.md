

# DLL Flowlyzer - Enhanced Network Flow Analyzer

This is a network flow analysis tool that extracts features from packet capture files. It focuses on analyzing Layer 2 protocols and generates detailed statistics about network traffic patterns.

## Getting Started

First, install the required dependencies:

```bash
pip install -r requirements.txt
```

Then run the analyzer on your PCAP files:

```bash
python -m src.flowlyzer.main -i Input/your_capture.pcap
```

## What It Does

The tool examines network packet captures and extracts over 350 different features that describe the traffic flows. It works with various network protocols including TCP, UDP, and specialized Layer 2 protocols like STP, CDP, ARP, and DHCP.

The analyzer processes packets to identify flow patterns, timing characteristics, and protocol-specific behaviors. It can handle both individual files and entire directories of capture files.

## Basic Usage

Here are some common ways to use the tool:

```bash
# Analyze a single file
python -m src.flowlyzer.main -i capture.pcap

# Process all files in a directory
python -m src.flowlyzer.main -i Input/

# Use multiple threads for faster processing
python -m src.flowlyzer.main -i Input/ --workers 8

# Save results to a specific directory
python -m src.flowlyzer.main -i Input/ -o MyResults
```

## Output

The tool generates several types of output:

- CSV files containing extracted features for each network flow
- Statistics about protocol usage and traffic patterns  
- Visualization charts showing protocol distributions and correlations
- Log files documenting the processing steps

All output files include timestamps in their names to avoid conflicts between runs.

## Features

The analyzer extracts features in several categories:

- Basic flow information (duration, packet count, byte count)
- MAC address and vendor details
- Protocol-specific characteristics for Layer 2 protocols
- Statistical measures like entropy and timing variance
- Network topology and switching protocol data

Missing values in the output are represented as -100 to maintain consistency for analysis tools.

## Project Structure

The code is organized into several modules:

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

# Copyright (c) 2025

For citation in your works and also understanding ALFlowLyzer completely, you can find below published papers:

-

# Contributing

Any contribution is welcome in the form of pull requests.


# Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Amirhossein Ahmadnejad Roudsari:**](https://github.com/aahmadnejad) Graduate researcher and developer - York University


# Acknowledgement
This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701), Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari and Mitacs Global Research Internship (MGRI) program for summer student.
