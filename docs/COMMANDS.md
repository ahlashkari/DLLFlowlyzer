# DLL Flowlyzer Commands Reference

Complete guide to all available commands, options, and usage examples for the DLL Flowlyzer network analysis tool.

## Table of Contents
- [Basic Commands](#basic-commands)
- [Input Options](#input-options)
- [Processing Options](#processing-options)
- [Labeling Options](#labeling-options)
- [Performance Tuning](#performance-tuning)
- [Output Configuration](#output-configuration)
- [Advanced Examples](#advanced-examples)

## Basic Commands

### Single PCAP File Analysis
```bash
# Analyze a single PCAP file
python -m src.flowlyzer.main -i capture.pcap

# Analyze with custom output directory
python -m src.flowlyzer.main -i capture.pcap -o MyResults/
```

### Directory Analysis
```bash
# Analyze all PCAP files in a directory
python -m src.flowlyzer.main -i Input/

# Analyze directory with subdirectories
python -m src.flowlyzer.main -i Dataset/ --multi-folder
```

## Input Options

### `-i, --input` (Required)
Specify the input PCAP file or directory.

**Supported file formats:**
- `.pcap`, `.pcapng`, `.cap`
- Numbered files: `.pcap1`, `.pcap2`, `.pcapng1`, etc.
- Any extension pattern: `file.pcap.old`, `capture.pcap.backup`

**Examples:**
```bash
# Single file
python -m src.flowlyzer.main -i /path/to/capture.pcap

# Directory with multiple files
python -m src.flowlyzer.main -i /path/to/pcap_files/

# Multi-folder dataset
python -m src.flowlyzer.main -i /path/to/dataset/ --multi-folder
```

### `--multi-folder`
Enable processing of multiple directories containing related PCAP files.

**Use case:** When you have datasets organized by time periods, locations, or attack types.

**Directory structure example:**
```
Dataset/
├── Jul1/
│   ├── jul1.pcap
│   ├── jul1.pcap1
│   └── labeling.json
├── Jul2/
│   ├── jul2_1.pcap
│   ├── jul2_2.pcap
│   └── labeling.json
└── Jul4_stp_Attack/
    ├── attack.pcap1
    ├── attack.pcap2
    └── labeling.json
```

**Command:**
```bash
python -m src.flowlyzer.main -i Dataset/ --multi-folder
```

## Processing Options

### `--csv-batch-size`
Number of flows to write to CSV in each batch (default: 50).

**Real-time processing:** Saves data incrementally to prevent loss in large datasets.

```bash
# Save every 25 flows (more frequent saves)
python -m src.flowlyzer.main -i capture.pcap --csv-batch-size 25

# Save every 100 flows (less frequent, better performance)
python -m src.flowlyzer.main -i capture.pcap --csv-batch-size 100
```

### `--workers`
Number of worker threads for packet processing (default: 4).

```bash
# Use 8 threads for faster processing
python -m src.flowlyzer.main -i Input/ --workers 8

# Use 2 threads for limited resources
python -m src.flowlyzer.main -i Input/ --workers 2
```

### `--feature-threads`
Number of threads for feature extraction (default: 4).

```bash
# High-performance feature extraction
python -m src.flowlyzer.main -i Input/ --feature-threads 8
```

### `--flow-timeout`
Flow timeout in seconds (default: 1200).

```bash
# Shorter timeout for real-time analysis
python -m src.flowlyzer.main -i Input/ --flow-timeout 600

# Longer timeout for connection-heavy traffic
python -m src.flowlyzer.main -i Input/ --flow-timeout 1800
```

### `--max-flows`
Maximum concurrent flows to track (default: 100000).

```bash
# For memory-constrained systems
python -m src.flowlyzer.main -i Input/ --max-flows 10000

# For high-capacity systems
python -m src.flowlyzer.main -i Input/ --max-flows 200000
```

### `--batch-size`
Number of flows to process in each batch for memory optimization (default: 30).

```bash
# Smaller batches for low memory
python -m src.flowlyzer.main -i Input/ --batch-size 10

# Larger batches for better performance
python -m src.flowlyzer.main -i Input/ --batch-size 100
```

### `--disable-batching`
Disable batched processing for small datasets.

```bash
python -m src.flowlyzer.main -i small_capture.pcap --disable-batching
```

## Labeling Options

### IP-based Labeling

#### `--label-ip`
Label flows by attacker IP address.

```bash
# Single IP
python -m src.flowlyzer.main -i Input/ --label-ip "192.168.1.100=ARP Spoofing"

# Multiple IPs
python -m src.flowlyzer.main -i Input/ \
    --label-ip "192.168.1.100=ARP Spoofing" \
    --label-ip "192.168.1.200=DHCP Starvation"
```

### MAC-based Labeling

#### `--label-mac`
Label flows by attacker MAC address.

```bash
# Single MAC
python -m src.flowlyzer.main -i Input/ --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooding"

# Multiple MACs
python -m src.flowlyzer.main -i Input/ \
    --label-mac "aa:bb:cc:dd:ee:ff=MAC Flooding" \
    --label-mac "11:22:33:44:55:66=ARP Poisoning"
```

### Time-based Labeling

#### `--label-time`
Label flows by time range.

```bash
# Single time range
python -m src.flowlyzer.main -i Input/ --label-time "10:00-11:00=STP Attack"

# Multiple time ranges
python -m src.flowlyzer.main -i Input/ \
    --label-time "10:00-11:00=STP Attack" \
    --label-time "14:30-15:45=CDP Flooding"
```

### Configuration File Labeling

#### `--label-config`
Use JSON configuration file for comprehensive labeling.

**Example JSON file (attack_labels.json):**
```json
{
  "ip_attacks": [
    {
      "label": "ARP Spoofing",
      "ips": ["192.168.1.100", "192.168.1.200"]
    }
  ],
  "mac_attacks": [
    {
      "label": "MAC Flooding",
      "macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    }
  ],
  "time_attacks": [
    {
      "label": "STP Attack",
      "time_ranges": [
        {"start": "10:00 AM", "end": "11:00 AM"},
        {"start": "2:00 PM", "end": "3:30 PM"}
      ]
    }
  ]
}
```

**Command:**
```bash
python -m src.flowlyzer.main -i Input/ --label-config attack_labels.json
```

#### `--label-file`
Use text file for labeling configuration.

**Example text file (labeling.txt):**
```
# Time-based attacks
10:13 AM- 11:00 AM : ARP Spoofing
2:00 PM- 3:30 PM : DHCP Starvation

# MAC-based attacks
mac: aa:bb:cc:dd:ee:ff MAC Flooding
mac: 11:22:33:44:55:66 ARP Poisoning

# IP-based attacks
ip: 192.168.1.100 ARP Spoofing
ip: 192.168.1.200 DHCP Starvation
```

**Command:**
```bash
python -m src.flowlyzer.main -i Input/ --label-file labeling.txt
```

## Output Configuration

### `-o, --output`
Specify output directory (default: Results).

```bash
python -m src.flowlyzer.main -i Input/ -o MyAnalysis/
```

### `--missing-value`
Value to use for missing feature data (default: -100).

```bash
# Use NaN for missing values
python -m src.flowlyzer.main -i Input/ --missing-value nan

# Use -100 for missing values (recommended for ML)
python -m src.flowlyzer.main -i Input/ --missing-value -100
```

### Logging Options

#### `--log-level`
Set logging verbosity level.

```bash
# Debug level (most verbose)
python -m src.flowlyzer.main -i Input/ --log-level DEBUG

# Info level (default)
python -m src.flowlyzer.main -i Input/ --log-level INFO

# Warning level (minimal output)
python -m src.flowlyzer.main -i Input/ --log-level WARNING

# Error level (errors only)
python -m src.flowlyzer.main -i Input/ --log-level ERROR
```

#### `--quiet`
Suppress progress logging.

```bash
python -m src.flowlyzer.main -i Input/ --quiet
```

## Performance Tuning

### High-Performance Configuration
For systems with 16GB+ RAM and 8+ CPU cores:

```bash
python -m src.flowlyzer.main -i Input/ \
    --workers 16 \
    --feature-threads 12 \
    --csv-batch-size 100 \
    --batch-size 200 \
    --max-flows 50000 \
    --queue-size 100000
```

### Memory-Optimized Configuration
For systems with 4-8GB RAM:

```bash
python -m src.flowlyzer.main -i Input/ \
    --workers 2 \
    --feature-threads 2 \
    --csv-batch-size 25 \
    --batch-size 20 \
    --max-flows 5000 \
    --queue-size 10000
```

### Real-time Processing Configuration
For frequent CSV updates and data safety:

```bash
python -m src.flowlyzer.main -i Input/ \
    --csv-batch-size 20 \
    --batch-size 30 \
    --workers 4
```

## Advanced Examples

### Complete Attack Analysis Workflow

```bash
# Step 1: Multi-folder processing with JSON labeling
python -m src.flowlyzer.main -i AttackDataset/ \
    --multi-folder \
    --label-config master_attack_config.json \
    --workers 8 \
    --csv-batch-size 50 \
    --output AttackAnalysis/

# Step 2: High-performance single folder analysis
python -m src.flowlyzer.main -i LargeCapture/ \
    --workers 16 \
    --feature-threads 12 \
    --batch-size 200 \
    --csv-batch-size 100 \
    --max-flows 100000 \
    --output HighPerformanceAnalysis/
```

### Network Security Monitoring

```bash
# Real-time analysis with frequent CSV updates
python -m src.flowlyzer.main -i MonitoringData/ \
    --label-config security_labels.json \
    --csv-batch-size 10 \
    --workers 6 \
    --log-level INFO \
    --output SecurityMonitoring/
```

### Research Dataset Processing

```bash
# Process research dataset with comprehensive labeling
python -m src.flowlyzer.main -i ResearchData/ \
    --multi-folder \
    --label-config research_labels.json \
    --workers 12 \
    --feature-threads 8 \
    --batch-size 100 \
    --csv-batch-size 75 \
    --missing-value -100 \
    --output ResearchResults/
```

### Protocol-Specific Analysis

```bash
# Focus on specific protocols with targeted labeling
python -m src.flowlyzer.main -i ProtocolData/ \
    --label-ip "192.168.1.100=STP Attack" \
    --label-mac "aa:bb:cc:dd:ee:ff=CDP Flooding" \
    --label-time "10:00-12:00=ARP Spoofing" \
    --workers 8 \
    --output ProtocolAnalysis/
```

## Command Combinations

### Memory-Safe Large Dataset Processing
```bash
python -m src.flowlyzer.main -i VeryLargeDataset/ \
    --multi-folder \
    --workers 4 \
    --batch-size 50 \
    --csv-batch-size 25 \
    --max-flows 10000 \
    --flow-timeout 600 \
    --label-config attack_labels.json \
    --output SafeProcessing/
```

### Maximum Performance Configuration
```bash
python -m src.flowlyzer.main -i Input/ \
    --workers 20 \
    --feature-threads 16 \
    --batch-size 500 \
    --csv-batch-size 200 \
    --max-flows 200000 \
    --queue-size 200000 \
    --disable-batching \
    --output MaxPerformance/
```

### Debugging and Development
```bash
python -m src.flowlyzer.main -i TestData/ \
    --workers 1 \
    --batch-size 10 \
    --csv-batch-size 5 \
    --log-level DEBUG \
    --max-flows 1000 \
    --output Debug/
```

## Output Files Generated

Each command will generate the following files in the output directory:

### CSV Files
- `features_YYYYMMDD_HHMMSS.csv` - Main features with 343+ columns
- `analysis_statistics_YYYYMMDD_HHMMSS.csv` - Protocol statistics

### Visualization Files
- `protocol_statistics_YYYYMMDD_HHMMSS.png` - Protocol distribution
- `layer2_analysis_YYYYMMDD_HHMMSS.png` - Layer 2 breakdown
- `layer2_heatmap_analysis_YYYYMMDD_HHMMSS.png` - Feature correlations
- `flow_statistics_YYYYMMDD_HHMMSS.png` - Flow analysis
- `attack_analysis_YYYYMMDD_HHMMSS.png` - Attack vs benign
- `feature_correlation_YYYYMMDD_HHMMSS.png` - Correlation matrix

### Log Files
- `log.txt` - Processing logs and performance metrics

## Best Practices

### For Large Datasets (>1GB)
- Use `--csv-batch-size 50-100` for regular saves
- Set `--workers 8-16` based on CPU cores
- Use `--batch-size 100-200` for memory efficiency
- Monitor memory usage with `--max-flows`

### For Real-time Processing
- Use `--csv-batch-size 10-25` for frequent updates
- Set appropriate `--flow-timeout` for your traffic
- Use `--workers 4-8` for responsive processing

### For Memory-Constrained Systems
- Set `--max-flows 5000-10000`
- Use `--batch-size 20-50`
- Set `--csv-batch-size 10-25`
- Reduce `--workers` to 2-4

### For Attack Detection
- Always use `--label-config` with comprehensive JSON files
- Set `--missing-value -100` for consistent ML processing
- Use `--multi-folder` for organized attack datasets
- Consider `--csv-batch-size 25-50` for data safety

---

For more detailed information, see:
- [FEATURES.md](FEATURES.md) - Complete feature documentation
- [EXAMPLES.md](EXAMPLES.md) - Real-world usage scenarios
- [CONFIGURATION.md](CONFIGURATION.md) - Labeling configuration guide