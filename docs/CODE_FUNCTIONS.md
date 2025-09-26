# DLL Flowlyzer - Code Functions Reference

## Overview

This document provides detailed descriptions of key functions and methods in DLL Flowlyzer for developers and maintainers.

## Main Entry Point Functions

### `src/flowlyzer/main.py`

#### `main() -> int`
**Purpose**: Main entry point for DLL Flowlyzer application
**Returns**: Exit code (0 for success, 1 for error)
**Key Operations**:
- Initialize configuration manager and parse arguments
- Set up logging system
- Choose between single-folder and multi-folder processing
- Generate automatic visualizations

#### `parse_json_labeling_config(config: dict, flow_labeler) -> None`
**Purpose**: Parse JSON labeling configuration and apply attack rules
**Parameters**:
- `config`: Dictionary containing JSON labeling configuration
- `flow_labeler`: FlowLabeler instance to apply rules to
**Key Features**:
- Handles time-based, protocol-specific, IP-based, and MAC-based attacks
- Supports Layer 2-only attack detection
- Provides detailed logging of applied rules

#### `load_folder_labeling_config(folder_path: str) -> dict`
**Purpose**: Load labeling configuration from folder (JSON or text)
**Parameters**:
- `folder_path`: Path to folder containing labeling config
**Returns**: Dictionary with labeling configuration or None
**Search Priority**: 
1. `labeling.json`
2. `arp_spoof_labels.json` 
3. `attack_config.json`
4. `labeling.txt` (fallback)

#### `process_single_folder_batched(folder_name, pcap_files, processing_config, log_config, global_labeling_config, logger) -> dict`
**Purpose**: Process a single folder with batched CSV export and memory optimization
**Key Features**:
- Real-time CSV batching to prevent data loss
- Memory pressure monitoring and automatic cleanup
- Per-folder labeling configuration support
- Automatic visualization generation

#### `process_multi_folders(config_manager, processing_config, log_config, global_labeling_config, logger) -> int`
**Purpose**: Process multiple folders with independent flow contexts
**Key Features**:
- Per-folder result organization
- Independent flow analysis for each folder
- Automatic visualization generation per folder

## Packet Processing Functions

### `src/flowlyzer/packets/base_packet.py`

#### `BasePacket.__init__(self, packet, timestamp)`
**Purpose**: Initialize base packet with common features
**Parameters**:
- `packet`: Scapy packet object
- `timestamp`: Packet timestamp
**Extracted Features**: MAC addresses, timing, basic network information

#### `_get_vendor_from_oui(self, oui: str) -> str`
**Purpose**: Get vendor name from OUI using comprehensive database
**Parameters**: 
- `oui`: 6-character OUI string (e.g., "00000C")
**Returns**: Vendor name or "Unknown"
**Database**: Uses comprehensive `vendors.py` database with 500+ vendors

#### `_extract_mac_features(self, mac_address: str, prefix: str)`
**Purpose**: Extract comprehensive MAC address features
**Parameters**:
- `mac_address`: MAC address string
- `prefix`: Feature name prefix ("src_mac" or "dst_mac")
**Extracted Features**:
- OUI and vendor information
- Individual/Group (I/G) bit
- Local/Global (L/G) bit
- Device classification

### `src/flowlyzer/packets/layer2_only_packet.py`

#### `_analyze_cdp_packet(self)`
**Purpose**: Analyze CDP (Cisco Discovery Protocol) packets with complete TLV parsing
**Extracted Features**:
- Device ID, software version, platform information
- Capabilities flags (router, switch, bridge, etc.)
- Power management information
- Address and port information

#### `_analyze_stp_packet(self)`
**Purpose**: Analyze STP (Spanning Tree Protocol) packets
**Extracted Features**:
- Root and bridge identifiers with priorities
- Message age, forward delay, hello time
- Topology change flags
- Port identifiers and costs

#### `_analyze_arp_packet(self)`
**Purpose**: Analyze ARP (Address Resolution Protocol) packets
**Extracted Features**:
- Hardware and protocol types
- Operation codes (request/reply)
- Address mappings
- Gratuitous ARP detection

#### `_analyze_dhcp_packet(self)`
**Purpose**: Analyze DHCP packets with BOOTP field parsing
**Extracted Features**:
- BOOTP fields (opcodes, transaction IDs, flags)
- DHCP options parsing
- Message type identification
- Lease time information

## Flow Management Functions

### `src/flowlyzer/flows/flow.py`

#### `Flow.__init__(self, flow_id: str, first_packet: BasePacket)`
**Purpose**: Initialize flow with first packet
**Parameters**:
- `flow_id`: Unique flow identifier
- `first_packet`: First packet in the flow
**Initialization**: Sets up flow identifiers, timing, and feature cache

#### `add_packet(self, packet: BasePacket)`
**Purpose**: Add packet to flow and update flow state
**Operations**:
- Update end time and last activity
- Append packet to flow packet list
- Mark features cache as dirty

#### `get_features(self) -> Dict[str, Any]`
**Purpose**: Extract comprehensive flow features (343+ features)
**Returns**: Dictionary with all flow-level features
**Categories**: Flow IDs, MAC features, frame statistics, protocol-specific features

### `src/flowlyzer/flows/flow_manager.py`

#### `process_packet(self, packet)`
**Purpose**: Process incoming packet and assign to appropriate flow
**Operations**:
- Generate unique flow ID
- Find existing flow or create new one
- Handle flow timeouts and completion
- Manage memory usage

#### `get_batch_completed_flows(self, batch_size: int = 30) -> List[Flow]`
**Purpose**: Get batch of completed flows for processing
**Parameters**:
- `batch_size`: Maximum number of flows to return
**Returns**: List of completed Flow objects
**Memory Management**: Automatically removes flows from memory after return

#### `force_flow_completion(self, max_active_flows: int = 1000)`
**Purpose**: Force completion of oldest flows for memory management
**Parameters**:
- `max_active_flows`: Maximum number of flows to keep active
**Usage**: Called during memory pressure situations

## Feature Extraction Functions

### `src/flowlyzer/features/feature_extractor.py`

#### `extract_features(self, flows: List[Flow], global_protocol_stats: Dict = None) -> pd.DataFrame`
**Purpose**: Extract features from list of flows
**Parameters**:
- `flows`: List of Flow objects
- `global_protocol_stats`: Global protocol statistics for normalization
**Returns**: Pandas DataFrame with 343+ features per flow
**Threading**: Automatically uses parallel processing for large batches

#### `_extract_flow_features(self, flow: Flow, global_protocol_stats: Dict = None) -> Dict`
**Purpose**: Extract all features from single flow
**Returns**: Dictionary with all 343+ features
**Categories**:
- Flow identifiers (3 features)
- MAC address features (14 features)
- Frame statistics (32 features)
- Layer 2 protocol features (294+ features)

#### `_get_feature_columns(self) -> List[str]`
**Purpose**: Get complete list of feature column names
**Returns**: List of all 343+ feature names
**Usage**: Used for DataFrame creation and validation

### `src/flowlyzer/features/csv_exporter.py`

#### `CSVExporter.__init__(self, output_dir: str)`
**Purpose**: Initialize CSV exporter with output directory
**Parameters**:
- `output_dir`: Directory for CSV output files

#### `create_batch_files(self, base_filename: str, separate_layers: bool = False) -> Dict`
**Purpose**: Create CSV files for batched export
**Parameters**:
- `base_filename`: Base name for CSV files
- `separate_layers`: Whether to create separate Layer 2/3 files
**Returns**: Dictionary with file paths for different CSV files

#### `export_batch(self, features_df: pd.DataFrame, batch_files: Dict, append: bool = True)`
**Purpose**: Export batch of features to CSV files with real-time writing
**Parameters**:
- `features_df`: DataFrame with extracted features
- `batch_files`: Dictionary with CSV file paths
- `append`: Whether to append to existing files
**Memory Management**: Automatically cleans up DataFrame after export

### `src/flowlyzer/features/labeling.py`

#### `FlowLabeler.label_flows(self, flows_df: pd.DataFrame) -> pd.DataFrame`
**Purpose**: Apply attack labels to flows DataFrame
**Parameters**:
- `flows_df`: DataFrame with extracted flow features
**Returns**: DataFrame with added 'label' column
**Default**: All flows labeled as "Benign" unless matching attack criteria

#### `add_time_attack(self, label: str, time_ranges: List[Tuple[str, str]], layer_2_only: bool = False)`
**Purpose**: Add time-based attack labeling rule
**Parameters**:
- `label`: Attack label name
- `time_ranges`: List of (start_time, end_time) tuples
- `layer_2_only`: Apply only to Layer 2 flows
**Format**: Time format "HH:MM AM/PM" or "HH:MM"

#### `add_protocol_attack(self, label: str, protocols: List[str], time_ranges: Optional[List] = None)`
**Purpose**: Add protocol-specific attack labeling
**Parameters**:
- `label`: Attack label name
- `protocols`: List of protocols to target (e.g., ["ARP", "STP"])
- `time_ranges`: Optional time windows
**Usage**: Ideal for Layer 2 protocol-specific attacks

## Utility Functions

### `src/flowlyzer/utils/config_manager.py`

#### `ConfigManager.parse_arguments(self) -> argparse.Namespace`
**Purpose**: Parse command-line arguments with comprehensive options
**Returns**: Parsed arguments namespace
**Options**: 20+ command-line options for processing control

#### `get_pcap_folders(self) -> Dict[str, List[str]]`
**Purpose**: Discover and organize PCAP files in multi-folder structure
**Returns**: Dictionary mapping folder names to PCAP file lists
**File Detection**: Handles .pcap, .pcapng, numbered files (.pcap1, .pcap2, etc.)

#### `get_labeling_config(self) -> Dict[str, Any]`
**Purpose**: Build labeling configuration from command-line arguments
**Returns**: Dictionary with IP, MAC, and time-based attack configurations
**Sources**: --label-ip, --label-mac, --label-time arguments

### `src/flowlyzer/utils/memory_monitor.py`

#### `MemoryMonitor.get_memory_stats(self) -> Dict`
**Purpose**: Get current memory usage statistics
**Returns**: Dictionary with memory usage in MB and percentages
**Metrics**: Process memory, system memory, memory pressure indicators

#### `check_memory_pressure(self) -> bool`
**Purpose**: Check if system is under memory pressure
**Returns**: True if memory usage exceeds critical threshold
**Usage**: Triggers automatic flow completion and cleanup

### `src/flowlyzer/utils/plotting.py`

#### `FlowlyzerPlotter.create_all_plots(self, flows_df: pd.DataFrame, stats: Dict) -> List[str]`
**Purpose**: Generate all visualization plots automatically
**Parameters**:
- `flows_df`: DataFrame with flow features and labels
- `stats`: Processing statistics dictionary
**Returns**: List of generated plot file paths
**Generated Charts**:
1. Protocol distribution charts
2. Attack analysis timeline
3. Feature correlation heatmaps
4. Layer 2 protocol breakdown
5. Flow statistics analysis
6. Bidirectional traffic analysis
7. MAC address analysis

#### `_create_attack_analysis_plot(self, flows_df: pd.DataFrame, output_path: str)`
**Purpose**: Create attack distribution and timeline visualization
**Features**:
- Attack type distribution pie chart
- Attack timeline over time
- Attack vs benign comparison
- Statistical summaries

## Error Handling and Logging

### `src/flowlyzer/utils/logger.py`

#### `FlowlyzerLogger.__init__(self, log_file: str, console_output: bool = True)`
**Purpose**: Initialize comprehensive logging system
**Parameters**:
- `log_file`: Path to log file
- `console_output`: Whether to also log to console
**Features**: Structured logging with timestamps, progress tracking

#### `log_flow_statistics(self, stats: Dict)`
**Purpose**: Log comprehensive flow processing statistics
**Parameters**:
- `stats`: Dictionary with processing metrics
**Logged Information**: Active flows, completed flows, protocol distribution, memory usage

## Performance Optimization Functions

### Memory Management

#### `perform_aggressive_cleanup(flow_manager, logger, memory_monitor)`
**Purpose**: Perform aggressive memory cleanup during high usage
**Operations**:
- Force completion of 70% of active flows
- Clear completed flow accumulation
- Trigger garbage collection
- Log memory statistics before/after

### Threading Optimization

#### Multi-threaded packet processing via `PacketQueue`
**Purpose**: Distribute packet processing across multiple worker threads
**Benefits**: 
- Linear performance scaling with CPU cores
- 5,000+ packets/second processing rate
- Configurable worker thread count

### Batch Processing

#### Real-time CSV batching
**Purpose**: Save flows in configurable batches to prevent data loss
**Benefits**:
- Memory efficient processing
- Data integrity protection
- Configurable batch sizes (10-200 flows)
- Automatic cleanup after export

This comprehensive function reference provides developers with detailed understanding of DLL Flowlyzer's internal architecture and key implementation details.