# DLL Flowlyzer Configuration Guide

Comprehensive guide to configuring DLL Flowlyzer for attack labeling, performance tuning, and specialized analysis scenarios.

## Table of Contents
- [Labeling Configuration](#labeling-configuration)
- [Performance Configuration](#performance-configuration)
- [Processing Configuration](#processing-configuration)
- [Output Configuration](#output-configuration)
- [Multi-folder Configuration](#multi-folder-configuration)
- [Configuration Files](#configuration-files)
- [Environment Setup](#environment-setup)

## Labeling Configuration

DLL Flowlyzer supports multiple methods for labeling flows as benign or attack traffic, essential for machine learning training and security analysis.

### Command-Line Labeling

#### IP-Based Labeling
Label flows by attacker IP addresses:

```bash
# Single IP attack
python -m src.flowlyzer.main -i capture.pcap \
    --label-ip "192.168.1.100=ARP Spoofing"

# Multiple IP attacks
python -m src.flowlyzer.main -i capture.pcap \
    --label-ip "192.168.1.100=ARP Spoofing" \
    --label-ip "192.168.1.200=DHCP Starvation" \
    --label-ip "10.0.0.50=STP Attack"
```

#### MAC-Based Labeling
Label flows by attacker MAC addresses:

```bash
# Single MAC attack
python -m src.flowlyzer.main -i capture.pcap \
    --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooding"

# Multiple MAC attacks
python -m src.flowlyzer.main -i capture.pcap \
    --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooding" \
    --label-mac "11:22:33:44:55:66=ARP Poisoning"
```

#### Time-Based Labeling
Label flows during specific time windows:

```bash
# Single time range
python -m src.flowlyzer.main -i capture.pcap \
    --label-time "10:00-11:00=STP Attack"

# Multiple time ranges
python -m src.flowlyzer.main -i capture.pcap \
    --label-time "09:15-09:45=ARP Spoofing" \
    --label-time "14:30-15:30=CDP Flooding" \
    --label-time "16:00-17:00=DHCP Starvation"
```

#### Combined Labeling
Combine different labeling methods:

```bash
python -m src.flowlyzer.main -i capture.pcap \
    --label-ip "192.168.1.100=ARP Spoofing" \
    --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooding" \
    --label-time "10:00-11:00=STP Attack"
```

### JSON Configuration Files

JSON configuration provides structured, version-controllable labeling with advanced options.

#### Basic JSON Structure
```json
{
  "ip_attacks": [
    {
      "label": "Attack Type",
      "ips": ["ip1", "ip2", "ip3"]
    }
  ],
  "mac_attacks": [
    {
      "label": "Attack Type",
      "macs": ["mac1", "mac2", "mac3"]
    }
  ],
  "time_attacks": [
    {
      "label": "Attack Type",
      "time_ranges": [
        {"start": "HH:MM AM/PM", "end": "HH:MM AM/PM"}
      ]
    }
  ]
}
```

#### Comprehensive ARP Attack Configuration
```json
{
  "ip_attacks": [
    {
      "label": "ARP Spoofing",
      "ips": ["192.168.1.100", "192.168.1.200", "192.168.1.300"]
    },
    {
      "label": "DHCP Starvation",
      "ips": ["192.168.1.50", "10.0.0.100"]
    }
  ],
  "mac_attacks": [
    {
      "label": "ARP Poisoning",
      "macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    },
    {
      "label": "MAC Flooding",
      "macs": ["de:ad:be:ef:ca:fe", "ba:ad:f0:0d:ca:fe"]
    }
  ],
  "time_attacks": [
    {
      "label": "Coordinated ARP Attack",
      "time_ranges": [
        {"start": "10:15 AM", "end": "10:45 AM"},
        {"start": "2:30 PM", "end": "3:00 PM"},
        {"start": "4:15 PM", "end": "4:45 PM"}
      ]
    }
  ]
}
```

#### Layer 2 Security Configuration
```json
{
  "ip_attacks": [
    {
      "label": "STP Attack",
      "ips": ["192.168.1.10"]
    }
  ],
  "mac_attacks": [
    {
      "label": "Rogue Bridge",
      "macs": ["00:1a:2b:3c:4d:5e"]
    },
    {
      "label": "CDP Flooding",
      "macs": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"]
    }
  ],
  "time_attacks": [
    {
      "label": "VLAN Hopping",
      "time_ranges": [
        {"start": "11:00 AM", "end": "11:30 AM"}
      ]
    },
    {
      "label": "Switch Spoofing",
      "time_ranges": [
        {"start": "3:15 PM", "end": "3:45 PM"}
      ]
    }
  ]
}
```

#### Enterprise Network Configuration
```json
{
  "ip_attacks": [
    {
      "label": "Internal Reconnaissance",
      "ips": ["10.0.1.50", "10.0.2.100", "10.0.3.200"]
    },
    {
      "label": "Privilege Escalation",
      "ips": ["172.16.1.100"]
    }
  ],
  "mac_attacks": [
    {
      "label": "Unauthorized Device",
      "macs": ["ff:ff:ff:ff:ff:01", "ff:ff:ff:ff:ff:02"]
    }
  ],
  "time_attacks": [
    {
      "label": "After Hours Activity",
      "time_ranges": [
        {"start": "6:00 PM", "end": "8:00 AM"}
      ]
    },
    {
      "label": "Maintenance Window Abuse",
      "time_ranges": [
        {"start": "2:00 AM", "end": "4:00 AM"}
      ]
    }
  ]
}
```

### Text File Configuration

Text files provide simple, human-readable labeling configuration.

#### Basic Text Format
```text
# Time-based attacks (format: HH:MM AM/PM - HH:MM AM/PM : Attack Label)
10:13 AM- 11:00 AM : ARP Spoofing
2:00 PM- 3:30 PM : DHCP Starvation
4:15 PM- 5:00 PM : CDP Flooding

# MAC-based attacks (format: mac: MAC_ADDRESS Attack Label)
mac: aa:bb:cc:dd:ee:ff ARP Poisoning
mac: 11:22:33:44:55:66 MAC Flooding
mac: de:ad:be:ef:ca:fe CAM Table Overflow

# IP-based attacks (format: ip: IP_ADDRESS Attack Label)
ip: 192.168.1.100 ARP Spoofing
ip: 192.168.1.200 DHCP Starvation
ip: 10.0.0.50 STP Attack

# Combined attacks (format: mac: MAC ip: IP Attack Label)
mac: 19:1A:12:1C:FF:12 ip: 192.168.1.19 Coordinated Attack
```

#### Complex Text Configuration
```text
# Enterprise security monitoring configuration

# Reconnaissance activities
10:00 AM - 12:00 PM : Network Scanning
2:00 PM - 4:00 PM : Port Scanning

# Layer 2 attacks
mac: aa:bb:cc:dd:ee:01 ARP Spoofing Campaign
mac: aa:bb:cc:dd:ee:02 ARP Spoofing Campaign
mac: aa:bb:cc:dd:ee:03 ARP Spoofing Campaign

# Infrastructure attacks
ip: 192.168.1.10 STP Root Bridge Attack
ip: 192.168.1.11 STP Topology Manipulation
ip: 172.16.1.100 CDP Information Disclosure

# VLAN security
11:30 AM - 12:30 PM : VLAN Hopping Attempt
3:45 PM - 4:15 PM : Double Tagging Attack

# Insider threats
mac: 00:11:22:33:44:55 ip: 10.0.1.200 Insider Data Exfiltration
```

### Per-Folder Labeling

For multi-folder datasets, each folder can have its own labeling configuration.

#### Directory Structure
```
dataset/
├── Day1_Baseline/
│   ├── normal_traffic.pcap1
│   ├── normal_traffic.pcap2
│   └── labeling.json              # Baseline configuration
├── Day2_ARP_Attacks/
│   ├── arp_attacks.pcap1
│   ├── arp_attacks.pcap2
│   └── labeling.json              # ARP-specific labeling
├── Day3_STP_Attacks/
│   ├── stp_attacks.pcap
│   └── labeling.txt               # Text format labeling
└── Day4_Mixed/
    ├── mixed_attacks.pcap1
    ├── mixed_attacks.pcap2
    └── labeling.json              # Complex multi-attack labeling
```

#### Day1_Baseline/labeling.json (Benign Traffic)
```json
{
  "ip_attacks": [],
  "mac_attacks": [],
  "time_attacks": []
}
```

#### Day2_ARP_Attacks/labeling.json
```json
{
  "ip_attacks": [
    {
      "label": "ARP Spoofing",
      "ips": ["192.168.1.100", "192.168.1.101"]
    }
  ],
  "mac_attacks": [
    {
      "label": "ARP Poisoning",
      "macs": ["aa:bb:cc:dd:ee:ff"]
    }
  ],
  "time_attacks": [
    {
      "label": "Sustained ARP Attack",
      "time_ranges": [
        {"start": "9:00 AM", "end": "5:00 PM"}
      ]
    }
  ]
}
```

#### Day3_STP_Attacks/labeling.txt
```text
# STP-focused attack day
9:00 AM - 10:00 AM : STP Root Bridge Attack
ip: 192.168.1.10 Rogue Bridge
mac: 00:1a:2b:3c:4d:5e Topology Manipulation
2:00 PM - 3:00 PM : STP Hello Flooding
```

#### Processing Per-Folder Configuration
```bash
# Automatic per-folder labeling detection
python -m src.flowlyzer.main -i dataset/ --multi-folder --output analysis_results/

# Each folder processed independently with its own labeling
# Results organized by folder with appropriate labels applied
```

## Performance Configuration

### Threading Configuration

#### Basic Threading
```bash
# Default configuration (balanced)
python -m src.flowlyzer.main -i input/ \
    --workers 4 \
    --feature-threads 4

# High-performance configuration
python -m src.flowlyzer.main -i input/ \
    --workers 16 \
    --feature-threads 12 \
    --folder-threads 4

# Memory-conservative configuration
python -m src.flowlyzer.main -i input/ \
    --workers 2 \
    --feature-threads 2 \
    --folder-threads 1
```

#### Advanced Threading Scenarios
```bash
# Large enterprise dataset (32GB RAM)
python -m src.flowlyzer.main -i enterprise_data/ \
    --multi-folder \
    --workers 20 \
    --feature-threads 16 \
    --folder-threads 4 \
    --max-flows 100000 \
    --queue-size 200000

# Research dataset (16GB RAM)
python -m src.flowlyzer.main -i research_data/ \
    --multi-folder \
    --workers 12 \
    --feature-threads 8 \
    --folder-threads 2 \
    --max-flows 50000 \
    --queue-size 100000

# Small system (8GB RAM)
python -m src.flowlyzer.main -i small_dataset/ \
    --workers 4 \
    --feature-threads 3 \
    --max-flows 10000 \
    --queue-size 20000
```

### Memory Management

#### Batch Processing Configuration
```bash
# High-frequency updates (monitoring)
python -m src.flowlyzer.main -i monitoring_data/ \
    --csv-batch-size 10 \
    --batch-size 20 \
    --max-flows 5000

# Balanced performance (standard analysis)
python -m src.flowlyzer.main -i standard_data/ \
    --csv-batch-size 50 \
    --batch-size 100 \
    --max-flows 25000

# High-performance (large datasets)
python -m src.flowlyzer.main -i large_data/ \
    --csv-batch-size 200 \
    --batch-size 400 \
    --max-flows 100000

# Memory-critical (limited resources)
python -m src.flowlyzer.main -i critical_data/ \
    --csv-batch-size 5 \
    --batch-size 10 \
    --max-flows 1000
```

#### Flow Management
```bash
# Long-duration flows (persistent connections)
python -m src.flowlyzer.main -i persistent_data/ \
    --flow-timeout 3600 \
    --max-flows 50000

# Short-duration flows (burst traffic)
python -m src.flowlyzer.main -i burst_data/ \
    --flow-timeout 300 \
    --max-flows 100000

# Real-time processing simulation
python -m src.flowlyzer.main -i realtime_data/ \
    --flow-timeout 60 \
    --max-flows 10000 \
    --csv-batch-size 5
```

## Processing Configuration

### Missing Value Handling
```bash
# Use -100 for missing values (recommended for ML)
python -m src.flowlyzer.main -i input/ --missing-value -100

# Use NaN for missing values (pandas/scikit-learn compatible)
python -m src.flowlyzer.main -i input/ --missing-value nan
```

### Logging Configuration
```bash
# Debug logging (development/troubleshooting)
python -m src.flowlyzer.main -i input/ --log-level DEBUG

# Standard logging (default)
python -m src.flowlyzer.main -i input/ --log-level INFO

# Quiet operation (minimal output)
python -m src.flowlyzer.main -i input/ --log-level WARNING --quiet

# Error-only logging (critical issues)
python -m src.flowlyzer.main -i input/ --log-level ERROR
```

### Protocol Processing
```bash
# Enable all protocols (default behavior)
python -m src.flowlyzer.main -i input/

# Focus on specific protocols via labeling
python -m src.flowlyzer.main -i input/ \
    --label-config protocol_specific.json
```

## Output Configuration

### Directory and File Configuration
```bash
# Custom output directory
python -m src.flowlyzer.main -i input/ -o /custom/output/path/

# Timestamped output directory
python -m src.flowlyzer.main -i input/ -o "Results_$(date +%Y%m%d_%H%M%S)/"

# Project-specific output organization
python -m src.flowlyzer.main -i input/ -o "ProjectX/Analysis_$(date +%Y%m%d)/"
```

### Feature Export Configuration
```bash
# Standard feature export
python -m src.flowlyzer.main -i input/

# Export with missing value preference
python -m src.flowlyzer.main -i input/ --missing-value -100

# High-frequency CSV updates
python -m src.flowlyzer.main -i input/ --csv-batch-size 10
```

## Multi-folder Configuration

### Dataset Organization Strategies

#### Temporal Organization
```
temporal_dataset/
├── Morning_Traffic_0600_1200/
├── Afternoon_Traffic_1200_1800/
├── Evening_Traffic_1800_2400/
└── Night_Traffic_0000_0600/
```

#### Attack-Type Organization
```
security_dataset/
├── Baseline_Normal_Traffic/
├── ARP_Attack_Scenarios/
├── STP_Attack_Scenarios/
├── CDP_Attack_Scenarios/
└── Mixed_Attack_Scenarios/
```

#### Geographic Organization
```
enterprise_dataset/
├── Branch_Office_NYC/
├── Branch_Office_LA/
├── Data_Center_Primary/
└── Data_Center_DR/
```

### Multi-folder Processing Strategies
```bash
# Sequential processing (memory conservative)
python -m src.flowlyzer.main -i dataset/ \
    --multi-folder \
    --folder-threads 1

# Parallel processing (high performance)
python -m src.flowlyzer.main -i dataset/ \
    --multi-folder \
    --folder-threads 4 \
    --workers 12 \
    --feature-threads 8

# Balanced processing
python -m src.flowlyzer.main -i dataset/ \
    --multi-folder \
    --folder-threads 2 \
    --workers 8 \
    --feature-threads 6
```

## Configuration Files

### config.ini Template
```ini
[DEFAULT]
flow_timeout = 1200
max_packets_per_flow = 10000
queue_size = 100000
log_level = INFO
separate_l2_l3 = false

[PROTOCOLS]
enable_tcp = true
enable_udp = true
enable_quic = true
enable_dhcp = true
enable_stp = true
enable_cdp = true
enable_icmp = true
enable_lldp = true
enable_vtp = true
enable_dtp = true
enable_dns = true
enable_isl = true
enable_ssh = true
enable_ftp = true

[FEATURES]
extract_statistical = true
extract_timing = true
extract_size = true
extract_protocol_specific = true

[OUTPUT]
output_dir = Results
log_file = log.txt
csv_file = features.csv
```

### Custom Configuration Usage
```bash
# Use custom config file
python -m src.flowlyzer.main -i input/ --config custom_config.ini

# Override config with command-line options
python -m src.flowlyzer.main -i input/ \
    --config custom_config.ini \
    --workers 16 \
    --flow-timeout 600
```

## Environment Setup

### Directory Preparation
```bash
# Create organized workspace
mkdir -p DLL_Analysis/{Input,Config,Results,Logs}
cd DLL_Analysis

# Organize input data
mkdir -p Input/{Raw_Captures,Processed_Data,Test_Data}

# Create configuration templates
mkdir -p Config/{Labeling,Performance,Protocol_Specific}
```

### Labeling Configuration Templates

#### Create Standard Templates
```bash
# ARP attack template
cat > Config/Labeling/arp_attacks.json << 'EOF'
{
  "ip_attacks": [
    {"label": "ARP Spoofing", "ips": ["REPLACE_WITH_ATTACKER_IPS"]}
  ],
  "mac_attacks": [
    {"label": "ARP Poisoning", "macs": ["REPLACE_WITH_ATTACKER_MACS"]}
  ],
  "time_attacks": [
    {"label": "ARP Campaign", "time_ranges": [
      {"start": "REPLACE_START_TIME", "end": "REPLACE_END_TIME"}
    ]}
  ]
}
EOF

# STP attack template
cat > Config/Labeling/stp_attacks.json << 'EOF'
{
  "ip_attacks": [
    {"label": "STP Attack", "ips": ["REPLACE_WITH_ATTACKER_IPS"]}
  ],
  "mac_attacks": [
    {"label": "Rogue Bridge", "macs": ["REPLACE_WITH_ROGUE_BRIDGE_MACS"]}
  ],
  "time_attacks": [
    {"label": "STP Manipulation", "time_ranges": [
      {"start": "REPLACE_START_TIME", "end": "REPLACE_END_TIME"}
    ]}
  ]
}
EOF

# Mixed attacks template
cat > Config/Labeling/mixed_attacks.json << 'EOF'
{
  "ip_attacks": [
    {"label": "ARP Spoofing", "ips": ["IP1", "IP2"]},
    {"label": "STP Attack", "ips": ["IP3"]},
    {"label": "DHCP Starvation", "ips": ["IP4", "IP5"]}
  ],
  "mac_attacks": [
    {"label": "MAC Flooding", "macs": ["MAC1", "MAC2"]},
    {"label": "CDP Flooding", "macs": ["MAC3"]}
  ],
  "time_attacks": [
    {"label": "Coordinated Attack Phase 1", "time_ranges": [
      {"start": "9:00 AM", "end": "10:00 AM"}
    ]},
    {"label": "Coordinated Attack Phase 2", "time_ranges": [
      {"start": "2:00 PM", "end": "3:00 PM"}
    ]}
  ]
}
EOF
```

### Performance Configuration Templates
```bash
# High-performance template
cat > Config/Performance/high_performance.sh << 'EOF'
#!/bin/bash
python -m src.flowlyzer.main \
    --workers 20 \
    --feature-threads 16 \
    --folder-threads 4 \
    --csv-batch-size 500 \
    --batch-size 1000 \
    --max-flows 200000 \
    --queue-size 200000 \
    --flow-timeout 1800 \
    "$@"
EOF

# Memory-optimized template  
cat > Config/Performance/memory_optimized.sh << 'EOF'
#!/bin/bash
python -m src.flowlyzer.main \
    --workers 4 \
    --feature-threads 3 \
    --folder-threads 1 \
    --csv-batch-size 25 \
    --batch-size 50 \
    --max-flows 10000 \
    --queue-size 20000 \
    --flow-timeout 600 \
    "$@"
EOF

# Real-time simulation template
cat > Config/Performance/realtime.sh << 'EOF'
#!/bin/bash
python -m src.flowlyzer.main \
    --workers 6 \
    --feature-threads 4 \
    --csv-batch-size 10 \
    --batch-size 20 \
    --max-flows 15000 \
    --flow-timeout 300 \
    "$@"
EOF

chmod +x Config/Performance/*.sh
```

### Usage Examples with Templates
```bash
# Use high-performance template
Config/Performance/high_performance.sh -i Input/large_dataset/ --multi-folder -o Results/high_perf/

# Use memory-optimized template
Config/Performance/memory_optimized.sh -i Input/small_dataset/ -o Results/memory_opt/

# Use with labeling template
python -m src.flowlyzer.main \
    -i Input/arp_attack_data/ \
    --label-config Config/Labeling/arp_attacks.json \
    -o Results/arp_analysis/
```

This comprehensive configuration guide provides the foundation for effective use of DLL Flowlyzer across various scenarios and requirements. The flexible configuration options allow adaptation to specific use cases, from academic research to enterprise security monitoring.