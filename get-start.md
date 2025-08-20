# DLL Flowlyzer - Getting Started Guide

This guide provides step-by-step instructions for setting up and running DLL Flowlyzer with various scenarios and example commands.

## Initial Setup

### 1. Prerequisites
- Python 3.8 or higher
- Git (for cloning the repository)
- At least 4GB RAM recommended
- Linux, macOS, or Windows with WSL

### 2. Clone and Setup Virtual Environment
```bash
# Clone the repository (if not already done)
git clone <repository_url>
cd DLLFlowlyzerV1

# Create and activate virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate

# Verify Python version
python --version
```

### 3. Install Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt

# Verify installation
python -m src.flowlyzer.main --help
```

### 4. Prepare Input Directory
```bash
# Create input directory
mkdir -p Input

# Copy your PCAP files to Input directory
# cp /path/to/your/capture.pcap Input/
```

---

## Basic Usage Scenarios

### Scenario 1: Single PCAP File Analysis
**Use Case**: Analyze a single network capture file
```bash
# Basic analysis
python -m src.flowlyzer.main -i Input/capture.pcap

# With custom output directory
python -m src.flowlyzer.main -i Input/capture.pcap -o MyResults

# With verbose logging
python -m src.flowlyzer.main -i Input/capture.pcap --log-level DEBUG
```

### Scenario 2: Multiple PCAP Files in Directory
**Use Case**: Analyze all PCAP files in a single directory
```bash
# Process all PCAP files in Input directory
python -m src.flowlyzer.main -i Input/

# Separate Layer 2 and Layer 3 analysis
python -m src.flowlyzer.main -i Input/ --separate-layers

# With performance optimization
python -m src.flowlyzer.main -i Input/ --workers 8 --feature-threads 6
```

### Scenario 3: Multi-Folder Processing (Daily Captures)
**Use Case**: Process multiple days of network captures, each day split into multiple files

**Directory structure:**
```
Captures/
├── Day1/
│   ├── morning_01.pcap
│   ├── morning_02.pcap
│   └── morning_03.pcap
├── Day2/
│   ├── afternoon_01.pcap
│   ├── afternoon_02.pcap
│   └── afternoon_03.pcap
└── Day3/
    ├── evening_01.pcap
    └── evening_02.pcap
```

```bash
# Basic multi-folder processing
python -m src.flowlyzer.main -i Captures/ --multi-folder

# With layer separation
python -m src.flowlyzer.main -i Captures/ --multi-folder --separate-layers

# High-performance multi-folder processing
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --workers 8 --feature-threads 6 --folder-threads 2

# Quiet mode with custom output
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  -o DailyAnalysis --quiet
```

---

## Attack Detection Scenarios

### Scenario 4: IP-Based Attack Detection
**Use Case**: Detect attacks from known malicious IP addresses
```bash
# Single attacker IP
python -m src.flowlyzer.main -i Input/ \
  --label-ip "192.168.1.100=ARP Spoofing"

# Multiple attacker IPs
python -m src.flowlyzer.main -i Input/ \
  --label-ip "192.168.1.100=ARP Spoofing" \
  --label-ip "192.168.1.200=DHCP Starvation"
```

### Scenario 5: MAC-Based Attack Detection
**Use Case**: Detect attacks from specific MAC addresses
```bash
# MAC-based labeling
python -m src.flowlyzer.main -i Input/ \
  --label-mac "aa:bb:cc:dd:ee:ff=CAM Flood" \
  --label-mac "11:22:33:44:55:66=ARP Poisoning"
```

### Scenario 6: Time-Based Attack Detection
**Use Case**: Label network traffic during known attack periods
```bash
# Time-based attack labeling
python -m src.flowlyzer.main -i Input/ \
  --label-time "10:00 AM-11:30 AM=DHCP Starvation" \
  --label-time "2:15 PM-3:45 PM=STP Attack"
```

### Scenario 7: Per-Folder Attack Labeling
**Use Case**: Different attack types for different days/sessions

**Setup per-folder labeling:**
```bash
# Create folder-specific labeling files
echo "mac: aa:bb:cc:dd:ee:ff ARP Spoofing" > Captures/Day1/labeling.txt
echo "10:00 AM - 12:00 PM : DHCP Attack" > Captures/Day2/labeling.txt
# Day3 has no labeling.txt (all flows will be "Benign")

# Run multi-folder analysis
python -m src.flowlyzer.main -i Captures/ --multi-folder
```

### Scenario 8: Configuration File-Based Labeling
**Use Case**: Complex labeling rules defined in configuration files

**Create labeling_config.json:**
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
      "label": "CAM Flood",
      "macs": ["aa:bb:cc:dd:ee:ff"]
    }
  ],
  "time_attacks": [
    {
      "label": "STP Attack",
      "time_ranges": [{"start": "9:00 AM", "end": "10:30 AM"}]
    }
  ]
}
```

```bash
# Use configuration file
python -m src.flowlyzer.main -i Input/ --label-config labeling_config.json
```

---

## Performance Optimization Scenarios

### Scenario 9: High-Performance Processing
**Use Case**: Maximum performance for large datasets
```bash
# Maximum threading with memory optimization
python -m src.flowlyzer.main -i Input/ \
  --workers 12 --feature-threads 8 --max-flows 500000 \
  --queue-size 200000 --batch-size 50

# Multi-folder high performance with batching
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --workers 8 --feature-threads 8 --folder-threads 3 \
  --flow-timeout 600 --batch-size 40
```

### Scenario 10: Memory-Conscious Processing
**Use Case**: Limited memory environments
```bash
# Conservative memory usage with small batches
python -m src.flowlyzer.main -i Input/ \
  --workers 2 --feature-threads 2 --max-flows 50000 \
  --queue-size 25000 --flow-timeout 300 --batch-size 15

# Sequential multi-folder processing with memory optimization
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --folder-threads 1 --workers 4 --feature-threads 4 \
  --batch-size 20 --max-flows 5000

# Ultra-conservative for very limited memory
python -m src.flowlyzer.main -i Input/ \
  --workers 1 --feature-threads 1 --batch-size 10 \
  --max-flows 1000 --queue-size 5000
```

---

## Advanced Scenarios

### Scenario 11: Research and Development
**Use Case**: Detailed analysis for research purposes
```bash
# Full analysis with all features
python -m src.flowlyzer.main -i Input/ \
  --separate-layers --log-level DEBUG \
  --label-config research_labeling.json

# Multi-folder research analysis
python -m src.flowlyzer.main -i ResearchData/ --multi-folder \
  --separate-layers --workers 6 --feature-threads 8 \
  -o ResearchResults
```

### Scenario 12: Production Monitoring
**Use Case**: Automated network monitoring in production
```bash
# Production-ready configuration
python -m src.flowlyzer.main -i /var/log/network/captures/ \
  --multi-folder --quiet --log-level WARNING \
  -o /var/log/network/analysis/ \
  --label-config /etc/flowlyzer/production_labels.json
```

### Scenario 13: Forensic Investigation
**Use Case**: Detailed forensic analysis of security incidents
```bash
# Forensic analysis with time-based labeling
python -m src.flowlyzer.main -i Evidence/Incident_20241201/ \
  --separate-layers \
  --label-time "14:30-15:45=Suspected Breach" \
  --label-time "16:00-16:30=Data Exfiltration" \
  --log-level DEBUG -o Forensic_Analysis_20241201
```

---

### Scenario 14: Memory-Optimized Multi-Folder Processing
**Use Case**: Large multi-folder datasets with memory constraints
```bash
# Balanced performance and memory usage
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --batch-size 30 --workers 4 --feature-threads 4 \
  --max-flows 10000

# Conservative memory with frequent CSV updates
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --batch-size 15 --workers 2 --feature-threads 2 \
  --max-flows 5000 --folder-threads 1

# Maximum memory optimization
python -m src.flowlyzer.main -i Captures/ --multi-folder \
  --batch-size 10 --workers 1 --feature-threads 1 \
  --max-flows 2000 --queue-size 10000
```

### Scenario 15: Disable Batching for Small Datasets
**Use Case**: Small PCAP files where batching overhead isn't worth it
```bash
# Disable batching for small files
python -m src.flowlyzer.main -i Input/small_capture.pcap --disable-batching

# Traditional processing (pre-optimization behavior)
python -m src.flowlyzer.main -i Input/ --disable-batching \
  --separate-layers
```

---

## Troubleshooting Common Issues

### Memory Issues
```bash
# Modern memory optimization (recommended approach):
python -m src.flowlyzer.main -i Input/ \
  --batch-size 15 --workers 2 --max-flows 5000

# If you still encounter memory errors, use ultra-conservative settings:
python -m src.flowlyzer.main -i LargeFile.pcap \
  --batch-size 10 --workers 1 --feature-threads 1 \
  --max-flows 2000 --flow-timeout 300

# Legacy approach (disable optimizations):
python -m src.flowlyzer.main -i Input/ --disable-batching \
  --workers 2 --feature-threads 2 --max-flows 10000

# Monitor memory usage in debug mode:
python -m src.flowlyzer.main -i Input/ --log-level DEBUG
```

### Permission Issues
```bash
# Ensure proper permissions for input files
chmod -R 755 Input/

# Check if running with sufficient privileges for packet analysis
sudo python -m src.flowlyzer.main -i Input/
```

### Performance Issues
```bash
# Check system resources first
python -m src.flowlyzer.main -i Input/ --log-level DEBUG

# Start with minimal threading and increase gradually
python -m src.flowlyzer.main -i Input/ --workers 1 --feature-threads 1
python -m src.flowlyzer.main -i Input/ --workers 2 --feature-threads 2
```

---

## Output Files Explanation

After running any command, you'll find these files in your output directory:

### Basic Output Files
- `features_YYYYMMDD_HHMMSS.csv` - Main feature extraction results
- `log.txt` - Processing log file

### With Layer Separation
- `features_combined_YYYYMMDD_HHMMSS.csv` - All flows
- `features_layer2_YYYYMMDD_HHMMSS.csv` - Layer 2 flows only
- `features_layer3_YYYYMMDD_HHMMSS.csv` - Layer 3 flows only

### Visualization Files
- `protocol_statistics_*.png` - Protocol distribution
- `layer2_analysis_*.png` - Layer 2 traffic analysis
- `flow_statistics_*.png` - Flow duration and packet statistics
- `attack_analysis_*.png` - Attack label distribution
- `feature_correlation_*.png` - Feature correlation heatmap

### Multi-Folder Output Structure
```
Results/
├── Day1/
│   ├── Day1_features_YYYYMMDD_HHMMSS.csv
│   └── [visualization files]
├── Day2/
│   ├── Day2_features_YYYYMMDD_HHMMSS.csv  
│   └── [visualization files]
└── log.txt
```

---

## Next Steps

1. **Analyze Results**: Open CSV files in your preferred data analysis tool (Python pandas, R, Excel)
2. **Machine Learning**: Use the feature vectors for training ML models
3. **Visualization**: Examine the generated plots for insights
4. **Configuration**: Create custom configuration files for repeated analysis
5. **Automation**: Integrate commands into scripts for automated analysis

For detailed technical documentation, see `PROJECT_STRUCTURE.md` and `features_explanation.md`.