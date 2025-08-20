# DLL Flowlyzer

Comprehensive DataLink Layer Network Flow Analyzer for extracting 200+ features from PCAP files for machine learning analysis. Specializes in Layer 2 protocol analysis with enhanced attack detection capabilities.

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run analysis:
```bash
python -m src.flowlyzer.main -i Input/your_capture.pcap
```

## Features

### Core Capabilities
- **222 Comprehensive Features**: Statistical, protocol-specific, and enhanced Layer 2 features
- **Multi-Protocol Support**: TCP, UDP, QUIC, and Layer 2 protocols (STP, CDP, LLDP, ARP, DHCP, LLC, DTP, VTP, ISL)
- **Enhanced Layer 2 Analysis**: Deep packet inspection for CDP TLVs, STP identifiers, DHCP options, ARP details
- **Accurate Protocol Detection**: Improved CDP/DTP differentiation with SNAP OUI/PID analysis
- **Flow Detection**: Bidirectional flow detection with configurable timeouts
- **Multi-threaded Processing**: Parallel packet processing with optimized queuing
- **Flexible Labeling**: Support for IP, MAC, time-based, and text file configuration
- **CSV-Only Output**: Clean CSV exports with optional Layer 2/3 separation
- **Visualization**: Comprehensive plotting and statistics generation
- **Comprehensive Logging**: Detailed progress tracking and statistics with real-time protocol detection

### Enhanced Layer 2 Features
- **ARP Protocol**: Hardware/protocol types, opcodes, address mappings
- **DHCP Protocol**: BOOTP fields, flags, options parsing, message types
- **STP Protocol**: Root/bridge identifiers with priorities, timing fields, topology flags
- **CDP Protocol**: Complete TLV parsing, device information, capabilities flags, power management
  - Enhanced detection with SNAP OUI/PID analysis (differentiates from DTP)
  - Real-time CDP packet counting in logs
- **LLC Protocol**: SAP values, control fields, command/response bits
- **DTP Protocol**: Dynamic Trunking negotiation, sender information
- **ISL Protocol**: Inter-Switch Link encapsulation, VLAN information
- **VTP Protocol**: VLAN Trunking management domain information
- **Loop Detection**: Network loop indicators and skip count analysis

## Usage

### Basic Analysis
```bash
# Analyze single PCAP file
python -m src.flowlyzer.main -i Input/capture.pcap

# Analyze directory of PCAP files
python -m src.flowlyzer.main -i Input/

# Generate visualization plots
python -m src.flowlyzer.main -i Input/ --plot
```

### Multi-Folder Processing
```bash
# Process multiple folders with related PCAP files (e.g., daily captures split into chunks)
python -m src.flowlyzer.main -i Input_Directory --multi-folder

# Multi-folder with layer separation and custom output
python -m src.flowlyzer.main -i Input_Directory --multi-folder --separate-layers -o Results

# Multi-folder with attack labeling
python -m src.flowlyzer.main -i Input_Directory --multi-folder --label-file attack_config.txt
```

### Layer Separation
```bash
# Separate Layer 2 and Layer 3 flows
python -m src.flowlyzer.main -i Input/ --separate-layers

# Custom output filename
python -m src.flowlyzer.main -i Input/ --csv-file my_features
```

### Attack Labeling
```bash
# Text file configuration (recommended)
python -m src.flowlyzer.main -i Input/ --label-file sample_labeling.txt

# Direct command-line labeling
python -m src.flowlyzer.main -i Input/ --label-ip "192.168.1.100=ARP Spoofing"
python -m src.flowlyzer.main -i Input/ --label-mac "aa:bb:cc:dd:ee:ff=ARP Poisoning"
python -m src.flowlyzer.main -i Input/ --label-time "10:00 AM-11:00 AM=DHCP Starvation"
```

### Performance Tuning
```bash
# Custom processing parameters
python -m src.flowlyzer.main -i Input/ --flow-timeout 600 --max-flows 50000 --workers 8

# Large file processing with memory optimization
python -m src.flowlyzer.main -i Input/ --queue-size 20000 --workers 12 --batch-size 50

# Memory-conservative processing with custom CSV batch size
python -m src.flowlyzer.main -i Input/ --batch-size 20 --csv-batch-size 25 --workers 2 --max-flows 5000

# Frequent CSV updates with smaller batches
python -m src.flowlyzer.main -i Input/ --csv-batch-size 15 --batch-size 30

# Disable batching for small datasets
python -m src.flowlyzer.main -i Input/ --disable-batching
```

## Text File Labeling Format

Create a text file (e.g., `sample_labeling.txt`) with attack definitions:

```
# Time-based attacks
10:13 AM- 11:00 AM : ARP Spoofing
2:00 PM- 3:30 PM : DHCP Starvation

# MAC-based attacks
mac: 12:1C:1F:11:12:2C ARP Poisoning
mac: aa:bb:cc:dd:ee:ff CAM Flood

# IP-based attacks
ip: 192.168.1.19 ARP Spoofing
ip: 192.168.1.100 DHCP Starvation

# Combined attacks
mac: 19:1A:12:1C:FF:12 ip: 192.168.1.19 DHCP Starvation
```

## Output Files

### CSV Files
- `features_combined_YYYYMMDD_HHMMSS.csv` - All flows with 222 features
- `features_layer2_YYYYMMDD_HHMMSS.csv` - Layer 2 flows only (optional)
- `features_layer3_YYYYMMDD_HHMMSS.csv` - Layer 3 flows only (optional)

### Visualization Files (Optional)
- Protocol distribution charts
- Flow characteristics analysis
- Layer 2 protocol detailed breakdown
- Attack distribution and timeline plots
- Bidirectional traffic analysis

## Feature Categories (222 Total)

### Basic Flow Features (15)
- Connection identifiers, protocol types, endpoint information

### MAC Address Features (14)
- Vendor information, OUI parsing, Individual/Group flags

### Frame Statistics (28)
- Size distributions, directional statistics, marked/ignored packets

### Enhanced Layer 2 Features (165+)
- **ARP Features (15)**: Hardware types, opcodes, protocol information
- **DHCP Features (17)**: BOOTP fields, flags, options, message types
- **STP Features (21)**: Root/bridge identifiers, timing, topology flags
- **CDP Features (27)**: Complete TLV parsing, capabilities, power management
- **LLC Features (12)**: SAP values, control fields, C/R bits
- **DTP Features (8)**: Trunking negotiation, version, sender information
- **ISL Features (15)**: Inter-Switch Link encapsulation, VLAN data
- **VTP Features (6)**: VLAN management domain information
- **Loop Detection Features (8)**: Network loop analysis
- **Protocol Counters (42)**: Per-protocol packet and percentage counts

## Supported Attack Types

- **ARP Spoofing/Poisoning**: IP/MAC address manipulation detection
- **CAM Flood**: Switch MAC address table overflow
- **CDP Flood**: Excessive CDP advertisement packets
- **STP Attack**: Spanning Tree Protocol manipulation
- **DHCP Starvation/Spoof**: DHCP pool exhaustion and rogue servers
- **Switch Spoofing**: Switch impersonation attacks
- **VLAN Attacks**: 802.1Q manipulation and hopping

## Multi-Folder Processing

Process multiple directories containing related PCAP files from continuous capture sessions that were split into smaller files.

### Input Structure
Your input directory should contain subdirectories, each representing a capture session:
```
Input_Directory/
├── Day1/
│   ├── Aug17.pcap1    # Split files from same TCPDump session
│   ├── Aug17.pcap2
│   └── Aug17.pcap3
├── Day2/
│   ├── capture.pcap
│   └── capture.pcap.1
└── Day3/
    ├── morning.pcap1
    ├── morning.pcap2
    └── morning.pcap3
```

### Output Structure  
Each folder gets its own analysis results:
```
Results/
├── Day1/
│   ├── Day1_features_YYYYMMDD_HHMMSS.csv
│   ├── [visualization files]
│   └── [statistics files]
├── Day2/
│   └── [complete analysis for Day2]
├── Day3/
│   └── [complete analysis for Day3]  
└── log.txt
```

### Key Benefits
- **Independent Analysis**: Each folder maintains separate flow contexts
- **Per-Folder Labeling**: Each folder can have its own `labeling.txt` file with different attack criteria
- **Batch Processing**: Analyze multiple capture sessions in one command
- **Memory Efficient**: Processes folders sequentially to manage memory usage
- **Complete Results**: Each folder gets full feature extraction and visualizations

### Per-Folder Labeling
Each folder can have its own labeling configuration:

```
Input_Directory/
├── Day1/
│   ├── capture.pcap1
│   ├── capture.pcap2
│   └── labeling.txt          # MAC-based attacks
├── Day2/
│   ├── capture.pcap
│   └── labeling.txt          # Time-based attacks  
└── Day3/
    ├── capture.pcap          # No labeling.txt = all Benign
```

**Example labeling.txt files:**

Day1 (MAC-based):
```
mac: aa:bb:cc:dd:ee:ff ARP Spoofing
mac: 11:22:33:44:55:66 CAM Flood
```

Day2 (Time-based):
```
10:00 AM - 11:30 AM : DHCP Starvation
2:15 PM - 3:45 PM : STP Attack
```

Day3 (No labeling.txt):
- All flows automatically labeled as "Benign"

## Performance

- **Multi-Level Threading**: 
  - Packet processing: Configurable worker threads (default: 4)
  - Feature extraction: Parallel feature computation threads (default: 4) 
  - Multi-folder: Optional parallel folder processing (default: 1)
- **Memory Optimized**: 
  - **Batched Processing**: Process flows in configurable batches (default: 30)
  - **Automatic Memory Cleanup**: Clear packet data after feature extraction
  - **Memory Monitoring**: Real-time memory usage tracking with automatic cleanup
  - **Pressure Detection**: Automatic flow completion when memory thresholds exceeded
- **Scalable**: Handles large PCAP files and multi-file datasets with optimized memory usage
- **Flow Management**: Automatic timeout and cleanup mechanisms with memory-aware batching

### Threading Configuration
```bash
# Configure different threading levels
python -m src.flowlyzer.main -i Input/ \
  --workers 8 \            # Packet processing threads
  --feature-threads 6 \    # Feature extraction threads
  --folder-threads 2 \     # Parallel folder processing (multi-folder mode only)
  --batch-size 30 \        # Flows per batch for memory optimization
  --max-flows 10000        # Limit concurrent flows

# Memory optimization options
python -m src.flowlyzer.main -i Input/ \
  --batch-size 50 \        # Larger processing batches for better performance
  --csv-batch-size 40 \    # Number of flows per CSV write operation
  --disable-batching \     # Disable batching for small datasets
  --workers 4              # Reduce workers to save memory

# Fine-tune CSV writing frequency
python -m src.flowlyzer.main -i Input/ \
  --csv-batch-size 20 \    # Write to CSV every 20 flows (more frequent updates)
  --batch-size 30 \        # Process 30 flows before memory cleanup
  --workers 6
```

See PROJECT_STRUCTURE.md for detailed technical documentation.