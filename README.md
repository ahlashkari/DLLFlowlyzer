# DLL Flowlyzer

Comprehensive DataLink Layer Network Flow Analyzer for extracting 282 features from PCAP files for machine learning analysis. Specializes in Layer 2 protocol analysis with direct packet parsing and robust attack detection capabilities using consistent -100 missing value handling.

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
pip install pyshark  # For enhanced protocol analysis
```

2. Run analysis:
```bash
python -m src.flowlyzer.main -i Input/your_capture.pcap
```

## Features

### Core Capabilities
- **350+ Comprehensive Features**: Statistical, protocol-specific, direct-parsed Layer 2 features, and advanced statistical combinations
- **Multi-Protocol Support**: TCP, UDP, QUIC, and Layer 2 protocols (STP, CDP, LLDP, ARP, DHCP, LLC, DTP, VTP, ISL)
- **Enhanced Layer 2 Analysis**: Deep packet inspection for CDP TLVs, STP identifiers, DHCP options, ARP details
- **Enhanced Protocol Detection**: Advanced CDP/LLDP/DTP separation using payload-based analysis independent of MAC addresses
- **Payload-Based Protocol Analysis**: CDP and DTP detection using SNAP OUI/PID analysis and TLV structure validation, eliminating dependency on Cisco MAC addresses
- **Flow Detection**: Bidirectional flow detection with configurable timeouts
- **Multi-threaded Processing**: Parallel packet processing with optimized queuing
- **Flexible Labeling**: Support for IP, MAC, time-based, and text file configuration
- **CSV-Only Output**: Clean CSV exports with optional Layer 2/3 separation
- **Visualization**: Comprehensive plotting and statistics generation
- **Comprehensive Logging**: Detailed progress tracking and statistics with real-time protocol detection
- **Advanced Visualization**: Layer 2 protocol heatmaps, correlation matrices, and statistical analysis charts

### Enhanced Layer 2 Features
- **ARP Protocol**: Hardware/protocol types, opcodes, address mappings
- **DHCP Protocol**: BOOTP fields, flags, options parsing, message types
- **STP Protocol**: Root/bridge identifiers with priorities, timing fields, topology flags
- **CDP Protocol**: Complete TLV parsing, device information, capabilities flags, power management
  - MAC-independent detection using SNAP OUI (00:00:0c) and PID (0x2000) analysis
  - Multi-method validation: LLC/SNAP headers, payload structure, and TLV pattern matching
  - Robust separation from DTP and other Cisco protocols using different PIDs
- **LLDP Protocol**: Comprehensive TLV structure analysis, chassis/port ID extraction
  - Enhanced detection with TLV structure validation
  - Clear separation from CDP despite potential packet tagging ambiguity
  - System capabilities and management address parsing
- **LLC Protocol**: SAP values, control fields, command/response bits
- **DTP Protocol**: Dynamic Trunking negotiation, sender information
  - Payload-based detection using SNAP OUI (00:00:0c) and PID (0x2004) analysis
  - TLV structure validation for Domain, Status, Type, and Neighbor information
  - Independent of MAC address patterns for broader compatibility
- **ISL Protocol**: Inter-Switch Link encapsulation, VLAN information
- **VTP Protocol**: VLAN Trunking management domain information
- **Loop Detection**: Network loop indicators and skip count analysis

### Advanced Statistical Features
- **Protocol Count Ratios**: STP/ARP, CDP/ARP, STP/DHCP count-based relationships for better ML analysis
- **Cross-Protocol Analysis**: Direct protocol activity comparisons (e.g., `stp_over_arp_count_ratio`)
- **Protocol Diversity Metrics**: Entropy-based measures of protocol distribution
- **Temporal Analysis**: Inter-arrival time analysis, burst detection, and temporal clustering
- **Network Activity Scoring**: Weighted activity scores for different Layer 2 protocols
- **Protocol Imbalance Detection**: Gini coefficient-inspired protocol distribution analysis
- **Enhanced Feature Quality**: Meaningful defaults and robust extraction ensure no null values

## Recent Updates (2025)

### 🚀 NEW: --justlayertwo Option (September 2025)
- **🎯 Layer 2-Only Analysis**: New specialized mode that extracts 200+ Layer 2 features from all packets (MAC addresses, Layer 2 protocols, frame analysis)
- **⚡ Enhanced Performance**: Optimized processing for Layer 2-focused security analysis and network infrastructure monitoring  
- **📊 Complete Statistical Analysis**: Includes ALL aggregated features - STP timing analysis, CDP capability tracking, ARP request/reply ratios, DHCP transaction analysis
- **🔍 Advanced Protocol Analysis**: Full statistical aggregation for 8 Layer 2 protocols with 114+ aggregated statistical features
- **🔧 Works with --separate-layers**: Generate separate Layer 2 CSV files with specialized Layer 2 flow analysis
- **📊 Automatic Visualization**: Dedicated Layer 2 charts automatically generated for MAC analysis, protocol distribution, and security indicators
- **🔍 Attack Detection**: Perfect for detecting ARP spoofing, MAC flooding, VLAN attacks, and other Layer 2 threats

### Critical Layer 2 Feature Extraction Fixes (September 2025)
- **🚨 MAJOR FIX**: Completely resolved Layer 2 feature extraction issues - CDP, DHCP, and ISL features now contain actual extracted values instead of empty/null data
- **🔧 Consistent Missing Values**: Implemented global -100 missing value standard across ALL output files (layer2, layer3, combined)
- **⚡ ISL Aggregation Fixed**: Added missing ISL flow aggregation functionality with 17 comprehensive ISL features
- **📊 Enhanced Visualization**: Fixed plotting system to properly handle -100 missing values in all charts
- **📁 JSON Folder Labeling**: Enhanced per-folder labeling with JSON priority over text files
- **🎯 Direct Packet Parsing**: Replaced broken PyShark integration with robust direct packet parsing for all Layer 2 protocols

See `CRITICAL_LAYER2_FIXES_SEP2025.md` for comprehensive technical details.

### Critical Bug Fixes & New Features (August 2025)
- **Fixed Dictionary Iteration Error**: Resolved runtime crashes during flow cleanup that caused incomplete processing
- **Enhanced DHCP Detection Accuracy**: Fixed false positive DHCP classification - reduced incorrect DHCP flows from thousands to actual DHCP packets only
- **Improved System Stability**: Eliminated "dictionary changed size during iteration" crashes during large PCAP processing
- **Enhanced Data Quality**: More accurate protocol detection and feature extraction for better ML model training
- **🆕 Layer 2-Only Labeling**: New option to apply labels only to Layer 2 flows for focused Layer 2 attack analysis
- **🆕 Protocol-Specific Labeling**: Target specific protocols (ARP, STP, CDP, etc.) during specific time windows
- **🆕 Enhanced JSON Configuration**: Comprehensive labeling configuration files for all Layer 2 attack types

See `BUG_FIXES_AND_IMPROVEMENTS_AUG2025.md` for detailed technical information.

### Direct Packet Parsing Enhancement (Latest)
- **Fixed Layer 2 Extraction**: Replaced broken PyShark integration with direct packet parsing for reliable feature extraction
- **Real Protocol Values**: CDP, DHCP, ISL, STP, and ARP features now extract actual protocol field values instead of defaults
- **Consistent Missing Values**: All missing protocol features now use -100 consistently across layer2, layer3, and combined output files
- **Complete ISL Support**: Added missing ISL aggregation functionality with comprehensive VLAN and frame analysis
- **Enhanced Detection**: Multi-method protocol detection using SNAP OUI/PID analysis, payload structure validation, and layer presence confirmation

### Fixed Protocol Features (September 2025)
- **CDP**: Complete TLV parsing with actual device information, capabilities, and power data from direct packet analysis
- **DHCP**: Real BOOTP fields, transaction IDs, flags, and options from enhanced Scapy integration  
- **ISL**: NEW - VLAN IDs, frame types, user bits, and BPDU flags from direct frame parsing
- **STP**: Actual timing values, bridge IDs, and topology flags from BPDU analysis
- **ARP**: Real hardware/protocol types, addresses, and operation codes from header parsing

### Enhanced Feature Set
- **Total Features**: Increased from 240+ to 282 features per flow
- **Protocol-Specific**: 93 features renamed to protocol-first naming convention
- **Real Values**: 50+ new features extracted from actual protocol fields instead of defaults
- **Statistical Features**: Enhanced null handling for insufficient data scenarios

## Usage

### Basic Analysis
```bash
# Analyze single PCAP file
python -m src.flowlyzer.main -i Input/capture.pcap

# Analyze directory of PCAP files
python -m src.flowlyzer.main -i Input/

# Layer 2-only analysis with separate layer files (NEW!)
python -m src.flowlyzer.main -i Input/ --justlayertwo --separate-layers

# Layer 2-only analysis (NEW!)
python -m src.flowlyzer.main -i Input/ --justlayertwo
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

### Layer Separation & Layer 2-Only Analysis
```bash
# Separate Layer 2 and Layer 3 flows
python -m src.flowlyzer.main -i Input/ --separate-layers

# Layer 2-only analysis with specialized features
python -m src.flowlyzer.main -i Input/ --justlayertwo

# Layer 2 analysis with custom output filename
python -m src.flowlyzer.main -i Input/ --justlayertwo --csv-file layer2_analysis
```

### Attack Labeling

#### Layer 2 Attack Detection (NEW!)
```bash
# Layer 2-only analysis with attack detection
python -m src.flowlyzer.main -i arp_attack_data/ --justlayertwo --label-config arp_attack.json

# MAC flooding detection with separate layer files
python -m src.flowlyzer.main -i cam_flood_data/ --justlayertwo --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooder" --separate-layers

# VLAN hopping attack analysis
python -m src.flowlyzer.main -i vlan_attack_data/ --justlayertwo --label-time "14:00-15:00=VLAN Attack"
```

#### Enhanced JSON Configuration
```bash
# Layer 2-specific attack labeling with pre-configured files
python -m src.flowlyzer.main -i arp_attack_data/ --label-config labels/arp_spoof_labels.json --separate-layers

# Protocol-specific labeling for CDP attacks
python -m src.flowlyzer.main -i cdp_attack_data/ --label-config labels/cdp_attack_labels.json --separate-layers

# DHCP attacks (affects both Layer 2 and Layer 3)
python -m src.flowlyzer.main -i dhcp_attack_data/ --label-config labels/dhcp_spoof_attack_labels.json --separate-layers

# Combine JSON config with manual MAC labeling
python -m src.flowlyzer.main -i vlan_attack_data/ \
    --label-config labels/vlan_attack_labels.json \
    --label-mac "aa:bb:cc:dd:ee:ff=VLAN Attacker" \
    --separate-layers

# Per-folder labeling with JSON files (New!)
# Place labeling.json files in each data folder for automatic detection
python -m src.flowlyzer.main -i multi_attack_data/ --multi-folder --separate-layers
```

#### Traditional Configuration
```bash
# Text file configuration
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

# Configure missing value handling (Fixed!)
python -m src.flowlyzer.main -i Input/ --missing-value nan    # Use NaN for missing features
python -m src.flowlyzer.main -i Input/ --missing-value -100   # Use -100 for missing features (default and recommended)
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

### Standard Mode CSV Files
- `features_combined_YYYYMMDD_HHMMSS.csv` - All flows with 282+ features
- `features_layer2_YYYYMMDD_HHMMSS.csv` - Layer 2 flows only (optional)
- `features_layer3_YYYYMMDD_HHMMSS.csv` - Layer 3 flows only (optional)

### Layer 2-Only Mode (--justlayertwo) Files
- `layer2_features_YYYYMMDD_HHMMSS.csv` - Layer 2-only features (MAC addresses, protocols, frame analysis)
- `layer2_statistics_YYYYMMDD_HHMMSS.csv` - Layer 2-specific statistics

### Standard Visualization Files (--plot)
- Protocol distribution charts
- Flow characteristics analysis
- Layer 2 protocol detailed breakdown
- Attack distribution and timeline plots
- Bidirectional traffic analysis

### Layer 2-Only Visualization Files (--justlayertwo automatic plotting)
- MAC address analysis charts
- Layer 2 protocol distribution and activity
- Frame size and timing analysis
- Security indicator visualizations
- Layer 2 feature correlation heatmaps

## Feature Categories (350+ Total)

### Basic Flow Features (15)
- Connection identifiers, protocol types, endpoint information

### MAC Address Features (14)
- Vendor information, OUI parsing, Individual/Group flags

### Frame Statistics (28)
- Size distributions, directional statistics, marked/ignored packets

### Enhanced Layer 2 Features (230+)
- **ARP Features (19)**: Hardware types, opcodes, protocol information, request/reply analysis, gratuitous ARP detection
- **DHCP Features (16)**: BOOTP fields, flags, options, message types, transaction analysis
- **STP Features (17)**: Root/bridge identifiers, timing, topology flags, statistical aggregation
- **CDP Features (15)**: Complete TLV parsing, capabilities, power management, statistical aggregation
- **LLC Features (15)**: SAP values, control fields, C/R bits, statistical analysis
- **DTP Features (11)**: Trunking negotiation, version, sender information, frame type analysis
- **ISL Features (17)**: Inter-Switch Link encapsulation, VLAN data, diversity metrics
- **LLDP Features (4)**: Network discovery protocol, chassis/port identification
- **VTP Features (6)**: VLAN management domain information
- **Loop Detection Features (8)**: Network loop analysis
- **Protocol Counters (50+)**: Per-protocol packet and percentage counts, statistical aggregations
- **Advanced Statistical Features (100+)**: Sum, mean, max, min, median, standard deviation for all Layer 2 protocol fields

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

# High-Performance Configuration for 32GB RAM Systems
python -m src.flowlyzer.main -i Input/ --multi-folder \
  --workers 16 \           # Maximum packet processing threads
  --feature-threads 12 \   # High parallelism for feature extraction
  --folder-threads 4 \     # Process multiple folders simultaneously
  --batch-size 200 \       # Large batches for memory efficiency
  --csv-batch-size 500 \   # Less frequent CSV writes for performance
  --max-flows 50000 \      # Higher flow capacity
  --queue-size 100000      # Large queue for high-throughput processing
```

## Recent Improvements (2025)

### Critical Bug Fixes
- **Fixed Dictionary Iteration Error**: Resolved runtime crashes during flow cleanup that caused incomplete processing
- **Enhanced Multi-folder Error Handling**: Improved resilience when processing multiple directories
- **Better Data Quality**: Replace zero values with NaN for missing packet data to improve ML model accuracy

### Layer 2 Feature Extraction - Completely Fixed (September 2025)
- **🎯 CRITICAL FIX**: Completely resolved the core issue where Layer 2 features (CDP, DHCP, ISL) appeared empty/null despite packet detection
- **Direct Packet Parsing**: Replaced broken PyShark integration with robust direct parsing using SNAP OUI/PID analysis and raw byte processing
- **ISL Aggregation Added**: Fixed missing ISL flow aggregation functionality - ISL features now properly calculated across flows
- **Consistent -100 Values**: All missing values now consistently use -100 across layer2, layer3, and combined CSV outputs
- **Enhanced Flow Detection**: Multi-method protocol detection ensures packets are properly classified and features extracted
- **Fixed Visualization**: All charts and plots now properly handle -100 missing values with automatic filtering

### Enhanced Layer 2 Protocol Analysis (Fixed)
- **Direct Parsing**: Robust packet parsing without PyShark dependency using raw byte analysis
- **Complete Feature Extraction**: All Layer 2 protocols now extract actual field values instead of defaults
- **ISL Protocol Fixed**: Added comprehensive ISL parsing with VLAN analysis and frame type detection
- **Reliable Detection**: Multi-method protocol detection using SNAP headers, payload analysis, and structure validation
- **Production Ready**: All Layer 2 features now provide meaningful data for machine learning analysis

### Performance and Reliability
- **Robust Error Handling**: Processing continues even when individual files fail
- **Memory Optimization**: Better handling of large datasets with NaN values
- **Enhanced Logging**: More detailed CDP detection and protocol statistics

See `ADVANCED_LAYER2_UPDATE_SEP2025.md` for complete documentation on the new --justlayertwo option and enhancements.
See `CRITICAL_LAYER2_FIXES_SEP2025.md` for comprehensive technical details on the Layer 2 fixes.
See `BUG_FIXES_AND_IMPROVEMENTS_AUG2025.md` for previous stability improvements.
See `PROJECT_STRUCTURE.md` for detailed technical documentation.