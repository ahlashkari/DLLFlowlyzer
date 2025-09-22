# DLL Flowlyzer Usage Examples

Real-world usage examples and scenarios for network analysis, security research, and attack detection using DLL Flowlyzer.

## Table of Contents
- [Basic Usage Examples](#basic-usage-examples)
- [Network Security Analysis](#network-security-analysis)
- [Research and Development](#research-and-development)
- [Performance Optimization](#performance-optimization)
- [Attack Detection Scenarios](#attack-detection-scenarios)
- [Multi-folder Dataset Processing](#multi-folder-dataset-processing)
- [Advanced Configurations](#advanced-configurations)

## Basic Usage Examples

### Single File Analysis
```bash
# Analyze a single PCAP file
python -m src.flowlyzer.main -i /path/to/capture.pcap

# Expected output structure:
Results/
├── features_20250922_143021.csv                    # 343+ features per flow
├── protocol_statistics_20250922_143021.png         # Protocol distribution
├── layer2_analysis_20250922_143021.png            # Layer 2 breakdown
├── flow_statistics_20250922_143021.png            # Flow characteristics
├── attack_analysis_20250922_143021.png            # Attack vs benign
├── feature_correlation_20250922_143021.png        # Feature correlations
├── layer2_heatmap_analysis_20250922_143021.png    # Layer 2 heatmap
├── analysis_statistics_20250922_143021.csv        # Summary statistics
└── log.txt                                         # Processing log
```

### Directory Processing
```bash
# Analyze all PCAP files in a directory
python -m src.flowlyzer.main -i /data/network_captures/

# Custom output directory
python -m src.flowlyzer.main -i /data/captures/ -o /results/analysis_2025/

# With performance tuning
python -m src.flowlyzer.main -i /data/large_captures/ \
    --workers 8 \
    --csv-batch-size 100 \
    --batch-size 200
```

## Network Security Analysis

### ARP Spoofing Detection

#### Scenario: Detect ARP spoofing attacks in enterprise network
```bash
# Dataset structure:
enterprise_network/
├── morning_capture.pcap
├── afternoon_capture.pcap
└── evening_capture.pcap

# Analysis with IP-based labeling
python -m src.flowlyzer.main -i enterprise_network/ \
    --label-ip "192.168.1.50=ARP Spoofing" \
    --label-ip "10.0.0.100=ARP Spoofing" \
    --csv-batch-size 50 \
    --output arp_analysis/

# Expected results:
arp_analysis/
├── features_20250922_143500.csv           # Features with ARP spoofing labels
├── protocol_statistics_20250922_143500.png # Shows ARP packet distribution
├── layer2_analysis_20250922_143500.png    # ARP protocol breakdown
└── attack_analysis_20250922_143500.png    # Attack timeline and distribution
```

#### Using JSON Configuration for Complex ARP Analysis
```json
{
  "ip_attacks": [
    {
      "label": "ARP Spoofing",
      "ips": ["192.168.1.50", "192.168.1.51", "192.168.1.52"]
    }
  ],
  "mac_attacks": [
    {
      "label": "ARP Poisoning",
      "macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    }
  ],
  "time_attacks": [
    {
      "label": "Coordinated ARP Attack",
      "time_ranges": [
        {"start": "10:15 AM", "end": "10:45 AM"},
        {"start": "2:30 PM", "end": "3:00 PM"}
      ]
    }
  ]
}
```

```bash
python -m src.flowlyzer.main -i enterprise_network/ \
    --label-config arp_attack_labels.json \
    --workers 12 \
    --csv-batch-size 75 \
    --output comprehensive_arp_analysis/
```

### STP Attack Detection

#### Scenario: Campus network with STP manipulation
```bash
# High-performance analysis for large campus network data
python -m src.flowlyzer.main -i campus_network_data/ \
    --label-time "09:15-09:45=STP Attack" \
    --label-time "14:30-15:00=STP Attack" \
    --workers 16 \
    --feature-threads 12 \
    --csv-batch-size 100 \
    --max-flows 50000 \
    --output stp_security_analysis/

# Focus on Layer 2 protocols only
python -m src.flowlyzer.main -i stp_attack_data/ \
    --label-mac "00:1a:2b:3c:4d:5e=Rogue Bridge" \
    --csv-batch-size 25 \
    --output layer2_stp_analysis/
```

### CDP Flooding Detection

#### Scenario: Cisco network infrastructure monitoring
```bash
# Multi-threaded analysis for CDP flood detection
python -m src.flowlyzer.main -i cisco_network/ \
    --label-ip "172.16.1.100=CDP Flood" \
    --label-time "11:00-12:00=CDP Flood" \
    --workers 8 \
    --feature-threads 6 \
    --csv-batch-size 50 \
    --output cdp_flood_analysis/

# Expected CDP features in results:
# - num_cdp_frame: Number of CDP packets
# - cdp_sum_tlvs: Total TLV count
# - cdp_capabilities_*: Device capability flags  
# - cdp_mean_power_sum: Power consumption data
# - cdp_device_id_tlv_len: Device identification lengths
```

## Research and Development

### Protocol Analysis Research

#### Scenario: Academic research on Layer 2 protocols
```bash
# Comprehensive feature extraction for research
python -m src.flowlyzer.main -i research_dataset/ \
    --multi-folder \
    --workers 20 \
    --feature-threads 16 \
    --csv-batch-size 200 \
    --batch-size 500 \
    --max-flows 100000 \
    --missing-value -100 \
    --output comprehensive_research/

# Dataset structure for research:
research_dataset/
├── baseline_traffic/
│   ├── normal_day1.pcap
│   ├── normal_day2.pcap
│   └── labeling.json          # All flows labeled as "Benign"
├── arp_attacks/
│   ├── arp_spoofing.pcap1
│   ├── arp_spoofing.pcap2
│   └── labeling.json          # ARP attack labeling
├── stp_attacks/
│   ├── topology_manipulation.pcap
│   └── labeling.json          # STP attack labeling
└── cdp_attacks/
    ├── cdp_flooding.pcap
    └── labeling.json          # CDP attack labeling
```

#### Machine Learning Dataset Preparation
```bash
# Generate ML-ready dataset with consistent missing values
python -m src.flowlyzer.main -i ml_training_data/ \
    --multi-folder \
    --missing-value -100 \
    --workers 12 \
    --csv-batch-size 100 \
    --output ml_dataset/

# Post-processing for ML
# Results will have 343+ features with -100 for missing values
# Perfect for scikit-learn, TensorFlow, or PyTorch preprocessing
```

### Network Behavior Analysis

#### Scenario: Long-term network monitoring study
```bash
# Process monthly network captures
python -m src.flowlyzer.main -i monthly_captures/ \
    --multi-folder \
    --workers 16 \
    --feature-threads 12 \
    --csv-batch-size 150 \
    --flow-timeout 1800 \
    --max-flows 75000 \
    --output monthly_analysis/

# Dataset structure:
monthly_captures/
├── week1/
│   ├── monday.pcap1, monday.pcap2, ...
│   └── labeling.json
├── week2/
│   ├── monday.pcap1, tuesday.pcap1, ...
│   └── labeling.json
├── week3/
└── week4/
```

## Performance Optimization

### High-Performance Processing

#### Scenario: Large-scale enterprise analysis (>100GB data)
```bash
# Maximum performance configuration
python -m src.flowlyzer.main -i enterprise_data/ \
    --multi-folder \
    --workers 20 \
    --feature-threads 16 \
    --csv-batch-size 500 \
    --batch-size 1000 \
    --max-flows 200000 \
    --queue-size 200000 \
    --flow-timeout 2400 \
    --output high_performance_analysis/

# Expected performance:
# - 50,000+ packets per minute
# - 200,000 concurrent flows
# - 16GB+ memory usage
# - Multiple CSV files with 500-flow batches
```

### Memory-Optimized Processing

#### Scenario: Processing on limited hardware (8GB RAM)
```bash
# Memory-conservative configuration
python -m src.flowlyzer.main -i limited_memory_data/ \
    --workers 4 \
    --feature-threads 3 \
    --csv-batch-size 25 \
    --batch-size 50 \
    --max-flows 5000 \
    --queue-size 10000 \
    --output memory_optimized/

# Benefits:
# - Peak memory usage <4GB
# - Frequent CSV saves (every 25 flows)
# - Small batches prevent memory pressure
# - Reduced concurrent flows
```

### Real-time Processing Simulation

#### Scenario: Near real-time network monitoring
```bash
# Optimized for frequent updates
python -m src.flowlyzer.main -i monitoring_data/ \
    --csv-batch-size 10 \
    --batch-size 20 \
    --workers 8 \
    --flow-timeout 300 \
    --output realtime_monitoring/

# Results:
# - CSV updated every 10 completed flows
# - Short flow timeout (5 minutes)
# - Rapid processing and export
# - Suitable for monitoring dashboards
```

## Attack Detection Scenarios

### MAC Flooding Attack

#### Scenario: Switch CAM table overflow attack
```bash
# Dataset preparation
mkdir cam_flood_analysis
cd cam_flood_analysis

# Create labeling configuration
cat > mac_flood_labels.json << 'EOF'
{
  "mac_attacks": [
    {
      "label": "MAC Flooding",
      "macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]
    }
  ],
  "time_attacks": [
    {
      "label": "Coordinated MAC Flood",
      "time_ranges": [
        {"start": "2:00 PM", "end": "2:15 PM"}
      ]
    }
  ]
}
EOF

# Analysis
python -m src.flowlyzer.main -i ../mac_flood_pcaps/ \
    --label-config mac_flood_labels.json \
    --workers 6 \
    --csv-batch-size 50 \
    --output ./

# Key features to examine:
# - src_mac_addr, dst_mac_addr: MAC address patterns
# - num_frame: Packet counts per flow
# - mean_frame_len: Average packet sizes
# - arp_*: ARP-related features for MAC flooding
```

### DHCP Starvation Attack

#### Scenario: DHCP pool exhaustion
```bash
# Multi-folder analysis with time-based labeling
python -m src.flowlyzer.main -i dhcp_attack_dataset/ \
    --multi-folder \
    --workers 8 \
    --csv-batch-size 75 \
    --output dhcp_starvation_analysis/

# Folder structure with per-folder labeling:
dhcp_attack_dataset/
├── baseline/
│   ├── normal_dhcp.pcap
│   └── labeling.json    # {"time_attacks": []}
├── attack_phase1/
│   ├── dhcp_requests.pcap
│   └── labeling.json    # DHCP starvation: 10:00-11:00
└── attack_phase2/
    ├── dhcp_exhaustion.pcap
    └── labeling.json    # DHCP starvation: 11:00-12:00

# Key DHCP features analyzed:
# - num_dhcp_frame: DHCP packet count
# - dhcp_message_type: Message type distribution
# - dhcp_mean_transaction_id: Transaction patterns
# - dhcp_sum_lease_time: Lease time analysis
```

### VLAN Hopping Attack

#### Scenario: 802.1Q double tagging attack
```bash
# Create comprehensive VLAN attack labeling
cat > vlan_attack_config.json << 'EOF'
{
  "ip_attacks": [
    {
      "label": "VLAN Hopping",
      "ips": ["192.168.100.50", "10.0.1.200"]
    }
  ],
  "time_attacks": [
    {
      "label": "Double Tagging Attack", 
      "time_ranges": [
        {"start": "3:15 PM", "end": "3:45 PM"}
      ]
    }
  ]
}
EOF

python -m src.flowlyzer.main -i vlan_attack_pcaps/ \
    --label-config vlan_attack_config.json \
    --workers 10 \
    --csv-batch-size 100 \
    --output vlan_security_analysis/

# Important features for VLAN analysis:
# - eth_type: Ethernet type (0x8100 for 802.1Q)
# - Frame statistics: Unusual frame sizes
# - Protocol distribution: Anomalous protocol patterns
```

## Multi-folder Dataset Processing

### Large-Scale Security Dataset

#### Scenario: Process multi-day security dataset with different attack types per day
```bash
# Dataset organization:
security_research_data/
├── Day1_Baseline/
│   ├── normal_traffic.pcap1
│   ├── normal_traffic.pcap2
│   └── labeling.json           # All benign
├── Day2_ARP_Attacks/
│   ├── arp_spoofing.pcap1
│   ├── arp_spoofing.pcap2
│   └── labeling.json           # ARP attack labeling
├── Day3_STP_Attacks/
│   ├── stp_manipulation.pcap1
│   └── labeling.json           # STP attack labeling
├── Day4_Mixed_Attacks/
│   ├── mixed_layer2.pcap1
│   ├── mixed_layer2.pcap2
│   └── labeling.json           # Multiple attack types
└── Day5_CDP_Attacks/
    ├── cdp_flooding.pcap1
    └── labeling.json           # CDP attack labeling

# High-performance multi-folder processing
python -m src.flowlyzer.main -i security_research_data/ \
    --multi-folder \
    --workers 16 \
    --feature-threads 12 \
    --csv-batch-size 200 \
    --batch-size 400 \
    --max-flows 100000 \
    --output comprehensive_security_analysis/

# Results structure:
comprehensive_security_analysis/
├── Day1_Baseline/
│   ├── Day1_Baseline_features_20250922_150000.csv
│   ├── [visualization files]
│   └── [statistics files]
├── Day2_ARP_Attacks/
│   ├── Day2_ARP_Attacks_features_20250922_150500.csv
│   └── [complete analysis files]
├── Day3_STP_Attacks/
├── Day4_Mixed_Attacks/
├── Day5_CDP_Attacks/
└── log.txt                     # Combined processing log
```

### Network Performance Study

#### Scenario: Analyze network performance across different time periods
```bash
# Processing network performance dataset
python -m src.flowlyzer.main -i performance_study/ \
    --multi-folder \
    --workers 12 \
    --feature-threads 8 \
    --csv-batch-size 150 \
    --flow-timeout 600 \
    --output network_performance_analysis/

# Dataset with temporal organization:
performance_study/
├── Peak_Hours_0800_1000/
├── Normal_Hours_1400_1600/
├── Low_Traffic_2200_0000/
└── Weekend_Traffic/

# Analysis focuses on:
# - Flow duration patterns
# - Protocol distribution changes
# - Frame size variations
# - Timing characteristics
```

## Advanced Configurations

### Custom Feature Analysis

#### Scenario: Focus on specific Layer 2 protocols
```bash
# Configuration for specialized Layer 2 analysis
python -m src.flowlyzer.main -i layer2_focused_data/ \
    --multi-folder \
    --workers 10 \
    --csv-batch-size 50 \
    --missing-value -100 \
    --output layer2_specialized/

# Examine specific feature categories:
# STP Features (19 total):
# - stp_sum_msg_age, stp_mean_msg_age, stp_max_msg_age
# - stp_root_identifier_prio, stp_bridge_identifier_prio
# - stp_count_flags_tc_1, stp_percent_flags_tc_1

# CDP Features (69 total):
# - cdp_sum_tlvs, cdp_sum_addresses_count
# - cdp_capabilities_router, cdp_capabilities_switch
# - cdp_mean_power_sum, cdp_device_id_tlv_len

# ARP Features (36 total):
# - arp_sum_hw_type, arp_mean_opcode
# - arp_request_count, arp_reply_count
# - arp_gratuitous_count, arp_request_ratio
```

### Production Network Monitoring

#### Scenario: Continuous monitoring of production network
```bash
# Production-ready configuration
python -m src.flowlyzer.main -i production_captures/ \
    --multi-folder \
    --label-config security_baseline.json \
    --workers 8 \
    --csv-batch-size 25 \
    --batch-size 50 \
    --max-flows 25000 \
    --flow-timeout 900 \
    --log-level INFO \
    --output production_monitoring/

# Security baseline configuration (security_baseline.json):
{
  "ip_attacks": [
    {
      "label": "Suspicious Internal Host",
      "ips": ["192.168.1.99", "10.0.0.200"]
    }
  ],
  "mac_attacks": [
    {
      "label": "Unauthorized Device",
      "macs": ["aa:bb:cc:dd:ee:99"]
    }
  ]
}

# Benefits:
# - Frequent CSV updates (every 25 flows) for monitoring
# - Conservative memory usage
# - Production-appropriate timeout (15 minutes)
# - Detailed logging for operations
```

### Research Validation Study

#### Scenario: Validate DLL Flowlyzer against known attack signatures
```bash
# Validation study with ground truth data
python -m src.flowlyzer.main -i validation_dataset/ \
    --multi-folder \
    --workers 20 \
    --feature-threads 16 \
    --csv-batch-size 300 \
    --batch-size 600 \
    --max-flows 150000 \
    --missing-value -100 \
    --output validation_study/

# Validation dataset structure:
validation_dataset/
├── Known_ARP_Spoofing/
│   └── labeling.json    # {"ip_attacks": [{"label": "ARP Spoofing", "ips": ["...]}]}
├── Known_STP_Attack/
│   └── labeling.json    # {"time_attacks": [{"label": "STP Attack", ...}]}
├── Known_CDP_Flooding/
│   └── labeling.json    # {"mac_attacks": [{"label": "CDP Flood", ...}]}
└── Verified_Benign/
    └── labeling.json    # No attacks defined - all flows labeled "Benign"

# Post-analysis validation:
# 1. Check attack detection accuracy
# 2. Validate feature extraction completeness
# 3. Confirm protocol classification accuracy
# 4. Verify timing and statistical features
```

## Expected Outputs and Analysis

### Feature Analysis
After processing, examine key features for different attack types:

#### ARP Attacks
- `num_arp_frame`: Should be high for ARP-based attacks
- `arp_request_ratio`: Unusual request/reply ratios
- `arp_gratuitous_count`: High for ARP poisoning
- `src_mac_addr`, `dst_mac_addr`: MAC address patterns

#### STP Attacks  
- `num_stp_frame`: Elevated STP traffic
- `stp_root_identifier_prio`: Suspicious priority values
- `stp_count_flags_tc_1`: Topology change flags
- `stp_mean_msg_age`: Timing anomalies

#### CDP Attacks
- `num_cdp_frame`: Abnormally high CDP traffic
- `cdp_sum_tlvs`: Excessive TLV counts
- `cdp_capabilities_*`: Unusual device capabilities
- `cdp_sum_addresses_count`: Address flooding indicators

### Visualization Analysis
Generated plots provide insights:
- **Protocol Statistics**: Protocol distribution anomalies
- **Layer 2 Analysis**: Detailed Layer 2 protocol breakdown  
- **Attack Analysis**: Attack vs. benign traffic patterns
- **Feature Correlation**: Feature relationships and importance
- **Flow Statistics**: Flow size and timing characteristics

### Performance Metrics
Monitor processing performance:
- Processing speed: 5,000+ packets/second typical
- Memory usage: Varies with configuration (2-20GB)
- Feature extraction: 343+ features per flow
- Real-time CSV: Batched every 10-500 flows
- Concurrent flows: 5,000-200,000 depending on configuration

---

These examples demonstrate the versatility and power of DLL Flowlyzer for various network analysis scenarios. The tool's flexibility in configuration allows adaptation to different use cases, from academic research to production security monitoring.