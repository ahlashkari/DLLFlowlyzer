# DLL Flowlyzer Features Documentation

Comprehensive documentation of all 343+ features extracted by DLL Flowlyzer for network flow analysis and machine learning applications.

## Table of Contents
- [Feature Overview](#feature-overview)
- [Flow Identifiers](#flow-identifiers)
- [MAC Address Features](#mac-address-features)
- [Network Layer Features](#network-layer-features)
- [Timing Features](#timing-features)
- [Frame Statistics](#frame-statistics)
- [Layer 2 Protocol Features](#layer-2-protocol-features)
- [Advanced Statistical Features](#advanced-statistical-features)
- [Feature Categories Summary](#feature-categories-summary)

## Feature Overview

DLL Flowlyzer extracts 343+ comprehensive features from network flows, focusing on Layer 2 (DataLink Layer) protocols while maintaining full support for Layer 3 analysis. All features use `-100` as the default value for missing data to ensure consistency in machine learning applications.

### Feature Categories
- **Flow Identifiers** (3): Basic flow identification
- **MAC Address Features** (14): Source/destination MAC analysis with vendor information
- **Network Layer Features** (5): IP addresses, ports, and Ethernet types
- **Timing Features** (1): Flow duration analysis
- **Frame Statistics** (32): Packet size, direction, and quality metrics
- **LLC Features** (15): Logical Link Control protocol analysis
- **STP Features** (19): Spanning Tree Protocol comprehensive analysis
- **Loop Detection Features** (8): Network loop identification
- **DTP Features** (15): Dynamic Trunking Protocol analysis
- **ISL Features** (18): Inter-Switch Link protocol analysis
- **ARP Features** (36): Address Resolution Protocol detailed analysis
- **DHCP Features** (37): DHCP protocol comprehensive features
- **CDP Features** (69): Cisco Discovery Protocol extensive analysis
- **Advanced Statistical Features** (16): Cross-protocol ratios and diversity metrics

## Flow Identifiers

### Basic Flow Information
| Feature | Description | Type | Example |
|---------|-------------|------|---------|
| `connection` | Unique flow identifier combining endpoints | String | "192.168.1.1:80-192.168.1.100:45123" |
| `tcp_stream` | TCP stream identifier (empty for non-TCP) | String | "tcp_stream_1234" |
| `protocol` | Primary protocol detected | String | "TCP", "ARP", "STP" |

## MAC Address Features

### Source MAC Analysis
| Feature | Description | Type | Example |
|---------|-------------|------|---------|
| `src_mac_addr` | Source MAC address | String | "aa:bb:cc:dd:ee:ff" |
| `src_mac_addr_vendor` | Vendor from OUI lookup | String | "Cisco Systems" |
| `src_mac_addr_device` | Device type classification | String | "Router", "Switch" |
| `src_mac_addr_vendor_name` | Full vendor name | String | "Cisco Systems, Inc." |
| `src_mac_addr_vendor_name_known` | Whether vendor is identified | Boolean | True/False |
| `src_mac_ig` | Individual/Group bit | Boolean | True/False |
| `src_mac_lg` | Local/Global bit | Boolean | True/False |
| `src_mac_oui` | Organizationally Unique Identifier | String | "00:00:0c" |

### Destination MAC Analysis
| Feature | Description | Type | Example |
|---------|-------------|------|---------|
| `dst_mac_addr` | Destination MAC address | String | "ff:ff:ff:ff:ff:ff" |
| `dst_mac_addr_vendor` | Vendor from OUI lookup | String | "Broadcast" |
| `dst_mac_addr_device` | Device type classification | String | "Broadcast", "Switch" |
| `dst_mac_addr_vendor_name` | Full vendor name | String | "Broadcast" |
| `dst_mac_addr_vendor_name_known` | Whether vendor is identified | Boolean | True/False |
| `dst_mac_ig` | Individual/Group bit | Boolean | True/False |
| `dst_mac_lg` | Local/Global bit | Boolean | True/False |
| `dst_mac_oui` | Organizationally Unique Identifier | String | "ff:ff:ff" |

## Network Layer Features

| Feature | Description | Type | Example |
|---------|-------------|------|---------|
| `eth_type` | Ethernet type field | Integer | 2048 (IPv4), 2054 (ARP) |
| `dst_ip_addr` | Destination IP address | String | "192.168.1.100" |
| `src_ip_addr` | Source IP address | String | "192.168.1.1" |
| `dst_port` | Destination port number | Integer | 80, 443, 22 |
| `src_port` | Source port number | Integer | 45123, 51234 |

## Timing Features

| Feature | Description | Type | Unit |
|---------|-------------|------|------|
| `time_delta` | Flow duration | Float | Seconds |

## Frame Statistics

### Basic Frame Counts
| Feature | Description | Type |
|---------|-------------|------|
| `num_frame` | Total number of packets in flow | Integer |
| `sum_frame_len` | Total bytes in all packets | Integer |
| `sum_frame_len_div_time` | Data rate (bytes per second) | Float |
| `num_frame_marked` | Number of marked packets | Integer |
| `num_frame_ignored` | Number of ignored packets | Integer |

### Directional Frame Statistics
| Feature | Description | Type |
|---------|-------------|------|
| `sum_frames_dst_src` | Total bytes destination to source | Integer |
| `mean_frames_dst_src` | Average packet size dst→src | Float |
| `max_frames_dst_src` | Maximum packet size dst→src | Integer |
| `min_frames_dst_src` | Minimum packet size dst→src | Integer |
| `median_frames_dst_src` | Median packet size dst→src | Float |
| `std_frames_dst_src` | Standard deviation dst→src | Float |
| `norm_frames_dst_src` | Normalized std deviation dst→src | Float |

| Feature | Description | Type |
|---------|-------------|------|
| `sum_frames_src_dst` | Total bytes source to destination | Integer |
| `mean_frames_src_dst` | Average packet size src→dst | Float |
| `max_frames_src_dst` | Maximum packet size src→dst | Integer |
| `min_frames_src_dst` | Minimum packet size src→dst | Integer |
| `median_frames_src_dst` | Median packet size src→dst | Float |
| `std_frames_src_dst` | Standard deviation src→dst | Float |
| `norm_frames_src_dst` | Normalized std deviation src→dst | Float |

### Overall Frame Statistics
| Feature | Description | Type |
|---------|-------------|------|
| `mean_frame_len` | Average packet size in flow | Float |
| `max_frame_len` | Maximum packet size in flow | Integer |
| `min_frame_len` | Minimum packet size in flow | Integer |
| `median_frame_len` | Median packet size in flow | Float |
| `std_frame_len` | Standard deviation of packet sizes | Float |
| `norm_frame_len` | Normalized std deviation | Float |
| `percent_frame_marked` | Percentage of marked packets | Float |
| `percent_frame_ignored` | Percentage of ignored packets | Float |

## Layer 2 Protocol Features

### LLC (Logical Link Control) Features
| Feature | Description | Type | Range |
|---------|-------------|------|-------|
| `num_llc_frame` | Number of LLC frames | Integer | 0+ |
| `percent_llc_frame` | Percentage of LLC frames | Float | 0-100 |
| `llc_mean_ssap_sap` | Average SSAP value | Float | 0-255 |
| `llc_max_ssap_sap` | Maximum SSAP value | Integer | 0-255 |
| `llc_min_ssap_sap` | Minimum SSAP value | Integer | 0-255 |
| `llc_median_ssap_sap` | Median SSAP value | Float | 0-255 |
| `llc_std_ssap_sap` | SSAP standard deviation | Float | 0+ |
| `llc_norm_ssap_sap` | Normalized SSAP std dev | Float | 0+ |
| `llc_sum_dsap_sap` | Sum of DSAP values | Integer | 0+ |
| `llc_mean_dsap_sap` | Average DSAP value | Float | 0-255 |
| `llc_max_dsap_sap` | Maximum DSAP value | Integer | 0-255 |
| `llc_min_dsap_sap` | Minimum DSAP value | Integer | 0-255 |
| `llc_median_dsap_sap` | Median DSAP value | Float | 0-255 |
| `llc_std_dsap_sap` | DSAP standard deviation | Float | 0+ |
| `llc_norm_dsap_sap` | Normalized DSAP std dev | Float | 0+ |
| `llc_mean_ssap_cr` | Average SSAP C/R bit | Float | 0-1 |
| `llc_mean_dsap_cr` | Average DSAP C/R bit | Float | 0-1 |
| `llc_control_ftype` | Control frame type | Integer | 0-3 |
| `llc_control_u_modifier` | U-frame modifier | Integer | 0+ |
| `llc_dsap_ig` | DSAP Individual/Group bit | Boolean | True/False |

### STP (Spanning Tree Protocol) Features
| Feature | Description | Type | Unit |
|---------|-------------|------|------|
| `num_stp_frame` | Number of STP frames | Integer | Count |
| `percent_stp_frame` | Percentage of STP frames | Float | 0-100% |
| `stp_sum_msg_age` | Sum of message ages | Integer | Seconds |
| `stp_mean_msg_age` | Average message age | Float | Seconds |
| `stp_max_msg_age` | Maximum message age | Integer | Seconds |
| `stp_min_msg_age` | Minimum message age | Integer | Seconds |
| `stp_median_msg_age` | Median message age | Float | Seconds |
| `stp_std_msg_age` | Message age std deviation | Float | Seconds |
| `stp_norm_msg_age` | Normalized message age std | Float | - |
| `stp_sum_forward` | Sum of forward delays | Integer | Seconds |
| `stp_mean_forward` | Average forward delay | Float | Seconds |
| `stp_max_forward` | Maximum forward delay | Integer | Seconds |
| `stp_min_forward` | Minimum forward delay | Integer | Seconds |
| `stp_median_forward` | Median forward delay | Float | Seconds |
| `stp_std_forward` | Forward delay std deviation | Float | Seconds |
| `stp_count_flags_tc_1` | Topology change flag count | Integer | Count |
| `stp_count_flags_tcack_1` | TC acknowledgment count | Integer | Count |
| `stp_percent_flags_tc_1` | Topology change percentage | Float | 0-100% |
| `stp_percent_flags_tcack_1` | TC ack percentage | Float | 0-100% |
| `stp_age_div_max_age` | Age/Max age ratio | Float | 0-1 |
| `stp_version` | STP version | Integer | 0-2 |
| `stp_hello` | Hello time | Integer | Seconds |
| `stp_root_identifier_prio` | Root bridge priority | Integer | 0-65535 |
| `stp_root_identifier_ext` | Root bridge extended ID | Integer | 0-4095 |
| `stp_bridge_identifier_prio` | Bridge priority | Integer | 0-65535 |
| `stp_bridge_identifier_ext` | Bridge extended ID | Integer | 0-4095 |
| `stp_root_cost` | Root path cost | Integer | 0+ |
| `stp_port_id` | Port identifier | Integer | 0-65535 |

### ARP (Address Resolution Protocol) Features
| Feature | Description | Type |
|---------|-------------|------|
| `num_arp_frame` | Number of ARP frames | Integer |
| `percent_arp_frame` | Percentage of ARP frames | Float |
| `arp_type` | ARP type field | Integer |
| `arp_size` | ARP packet size | Integer |
| `arp_dst_hw_mac` | Destination hardware MAC | String |
| `arp_src_hw_mac` | Source hardware MAC | String |
| `arp_proto_size` | Protocol address size | Integer |
| `arp_hw_size` | Hardware address size | Integer |
| `arp_hw_type` | Hardware type | Integer |
| `arp_opcode` | Operation code | Integer |
| `arp_proto_type` | Protocol type | Integer |

#### ARP Statistical Features
| Feature | Description | Type |
|---------|-------------|------|
| `arp_sum_hw_type` | Sum of hardware types | Integer |
| `arp_mean_hw_type` | Average hardware type | Float |
| `arp_max_hw_type` | Maximum hardware type | Integer |
| `arp_min_hw_type` | Minimum hardware type | Integer |
| `arp_sum_proto_type` | Sum of protocol types | Integer |
| `arp_mean_proto_type` | Average protocol type | Float |
| `arp_sum_opcode` | Sum of operation codes | Integer |
| `arp_mean_opcode` | Average operation code | Float |
| `arp_max_opcode` | Maximum operation code | Integer |
| `arp_min_opcode` | Minimum operation code | Integer |
| `arp_sum_size` | Sum of ARP sizes | Integer |
| `arp_mean_size` | Average ARP size | Float |
| `arp_max_size` | Maximum ARP size | Integer |
| `arp_min_size` | Minimum ARP size | Integer |
| `arp_request_count` | Number of ARP requests | Integer |
| `arp_reply_count` | Number of ARP replies | Integer |
| `arp_gratuitous_count` | Number of gratuitous ARPs | Integer |
| `arp_request_ratio` | Request/total ARP ratio | Float |
| `arp_reply_ratio` | Reply/total ARP ratio | Float |

### DHCP Features
| Feature | Description | Type |
|---------|-------------|------|
| `num_dhcp_frame` | Number of DHCP frames | Integer |
| `percent_dhcp_frame` | Percentage of DHCP frames | Float |
| `dhcp_hw_type` | DHCP hardware type | Integer |
| `dhcp_type` | DHCP message type | Integer |
| `dhcp_hw_len` | Hardware address length | Integer |
| `dhcp_hops` | Number of hops | Integer |
| `dhcp_secs` | Seconds elapsed | Integer |
| `dhcp_flags_bc` | Broadcast flag | Boolean |
| `dhcp_flags_reserved` | Reserved flags | Integer |
| `dhcp_cookie` | Magic cookie value | Integer |
| `dhcp_padding` | Padding length | Integer |
| `dhcp_options_count` | Number of DHCP options | Integer |
| `dhcp_options` | DHCP options present | String |
| `dhcp_message_type` | DHCP message type | Integer |
| `dhcp_options_len` | Total options length | Integer |
| `dhcp_option_padding` | Option padding length | Integer |

#### DHCP Statistical Features
| Feature | Description | Type |
|---------|-------------|------|
| `dhcp_sum_opcode` | Sum of opcodes | Integer |
| `dhcp_mean_opcode` | Average opcode | Float |
| `dhcp_sum_transaction_id` | Sum of transaction IDs | Integer |
| `dhcp_mean_transaction_id` | Average transaction ID | Float |
| `dhcp_max_transaction_id` | Maximum transaction ID | Integer |
| `dhcp_min_transaction_id` | Minimum transaction ID | Integer |
| `dhcp_sum_lease_time` | Sum of lease times | Integer |
| `dhcp_mean_lease_time` | Average lease time | Float |
| `dhcp_max_lease_time` | Maximum lease time | Integer |
| `dhcp_min_lease_time` | Minimum lease time | Integer |
| `dhcp_sum_message_type` | Sum of message types | Integer |
| `dhcp_mean_message_type` | Average message type | Float |
| `dhcp_sum_options_count` | Sum of option counts | Integer |
| `dhcp_mean_options_count` | Average option count | Float |
| `dhcp_max_options_count` | Maximum option count | Integer |
| `dhcp_min_options_count` | Minimum option count | Integer |

### CDP (Cisco Discovery Protocol) Features

#### Basic CDP Features
| Feature | Description | Type |
|---------|-------------|------|
| `num_cdp_frame` | Number of CDP frames | Integer |
| `percent_cdp_frame` | Percentage of CDP frames | Float |
| `cdp_version` | CDP version | Integer |
| `cdp_ttl` | Time to live | Integer |
| `cdp_checksum_status` | Checksum status | Boolean |

#### CDP Address Features
| Feature | Description | Type |
|---------|-------------|------|
| `cdp_sum_addresses_count` | Sum of address counts | Integer |
| `cdp_mean_addresses_count` | Average address count | Float |
| `cdp_max_addresses_count` | Maximum address count | Integer |
| `cdp_min_addresses_count` | Minimum address count | Integer |
| `cdp_median_addresses_count` | Median address count | Float |
| `cdp_std_addresses_count` | Address count std deviation | Float |
| `cdp_norm_addresses_count` | Normalized address count std | Float |

#### CDP TLV Features
| Feature | Description | Type |
|---------|-------------|------|
| `cdp_sum_tlvs` | Sum of TLV counts | Integer |
| `cdp_device_id_tlv_len` | Device ID TLV length | Integer |
| `cdp_software_version_tlv_len` | Software version TLV length | Integer |
| `cdp_platform_tlv_len` | Platform TLV length | Integer |
| `cdp_platform` | Platform information | String |
| `cdp_addresses_tlv_len` | Addresses TLV length | Integer |
| `cdp_addresses_sum_len` | Sum of address lengths | Integer |
| `cdp_addresses_sum_protocol_len` | Sum of protocol lengths | Integer |
| `cdp_management_addresses_sum_len` | Management address lengths | Integer |
| `cdp_management_addresses_sum_protocol_len` | Management protocol lengths | Integer |
| `cdp_port_id_tlv_len` | Port ID TLV length | Integer |

#### CDP Capabilities Features
| Feature | Description | Type |
|---------|-------------|------|
| `cdp_capabilities_tlv_len` | Capabilities TLV length | Integer |
| `cdp_sum_capabilities` | Sum of capabilities | Integer |
| `cdp_capabilities_router` | Router capability | Boolean |
| `cdp_capabilities_trans_bridge` | Transparent bridge capability | Boolean |
| `cdp_capabilities_src_bridge` | Source route bridge capability | Boolean |
| `cdp_capabilities_switch` | Switch capability | Boolean |
| `cdp_capabilities_host` | Host capability | Boolean |
| `cdp_capabilities_igmp` | IGMP capability | Boolean |
| `cdp_capabilities_repeater` | Repeater capability | Boolean |
| `cdp_capabilities_voip_phone` | VoIP phone capability | Boolean |
| `cdp_capabilities_remote` | Remote capability | Boolean |
| `cdp_capabilities_cvta` | CVTA capability | Boolean |
| `cdp_capabilities_mac_relay` | MAC relay capability | Boolean |

#### CDP Power Management Features
| Feature | Description | Type |
|---------|-------------|------|
| `cdp_mean_power_sum` | Average power sum | Float |
| `cdp_max_power_sum` | Maximum power sum | Integer |
| `cdp_min_power_sum` | Minimum power sum | Integer |
| `cdp_median_power_sum` | Median power sum | Float |
| `cdp_std_power_sum` | Power sum std deviation | Float |
| `cdp_norm_power_sum` | Normalized power sum std | Float |
| `cdp_power_tlv_len` | Power TLV length | Integer |
| `cdp_power_request_id` | Power request ID | Integer |
| `cdp_power_management_id` | Power management ID | Integer |

#### CDP Additional Features
| Feature | Description | Type |
|---------|-------------|------|
| `cdp_hello_tlv_len` | Hello TLV length | Integer |
| `cdp_hello_oui` | Hello OUI | Integer |
| `cdp_hello_num_unknown` | Number of unknown hello fields | Integer |
| `cdp_hello_management_vlan` | Management VLAN | Integer |
| `cdp_vtp_management_tlv_len` | VTP management TLV length | Integer |
| `cdp_vlan_native_tlv_len` | Native VLAN TLV length | Integer |
| `cdp_vlan_native_native_vlan` | Native VLAN ID | Integer |
| `cdp_duplex_tlv_len` | Duplex TLV length | Integer |
| `cdp_duplex` | Duplex mode | Boolean |
| `cdp_spare_pair_tlv_len` | Spare pair TLV length | Integer |
| `cdp_spare_poe_tlv_poe` | Spare pair PoE | Boolean |
| `cdp_spare_poe_tlv_spare_pair_arch` | Spare pair architecture | Integer |
| `cdp_spare_poe_tlv_req_spare_pair_poe` | Required spare pair PoE | Boolean |
| `cdp_spare_poe_tlv_pse_spare_pair_poe` | PSE spare pair PoE | Boolean |

### DTP (Dynamic Trunking Protocol) Features
| Feature | Description | Type |
|---------|-------------|------|
| `num_dtp_frame` | Number of DTP frames | Integer |
| `percent_dtp_frame` | Percentage of DTP frames | Float |
| `sum_dtp_tlvs` | Sum of DTP TLVs | Integer |
| `dtp_version` | DTP version | Integer |
| `dtp_tlv_len` | TLV length | Integer |
| `dtp_trunk_status_tlv_len` | Trunk status TLV length | Integer |
| `dtp_trunk_type_tlv_len` | Trunk type TLV length | Integer |
| `dtp_sender_tlv_len` | Sender TLV length | Integer |
| `dtp_sender_id` | Sender ID | String |
| `dtp_sum_version` | Sum of versions | Integer |
| `dtp_mean_version` | Average version | Float |
| `dtp_sum_tlv_count` | Sum of TLV counts | Integer |
| `dtp_mean_tlv_count` | Average TLV count | Float |
| `dtp_max_tlv_count` | Maximum TLV count | Integer |
| `dtp_min_tlv_count` | Minimum TLV count | Integer |
| `dtp_sum_domain_length` | Sum of domain lengths | Integer |
| `dtp_mean_domain_length` | Average domain length | Float |
| `dtp_frame_isl_count` | ISL frame count | Integer |
| `dtp_frame_802dot1q_count` | 802.1Q frame count | Integer |
| `dtp_frame_isl_ratio` | ISL frame ratio | Float |

### ISL (Inter-Switch Link) Features
| Feature | Description | Type |
|---------|-------------|------|
| `num_isl_frame` | Number of ISL frames | Integer |
| `percent_isl_frame` | Percentage of ISL frames | Float |
| `isl_mean_bpdu` | Average BPDU value | Float |
| `isl_sum_len` | Sum of ISL lengths | Integer |
| `isl_mean_len` | Average ISL length | Float |
| `isl_max_len` | Maximum ISL length | Integer |
| `isl_min_len` | Minimum ISL length | Integer |
| `isl_median_len` | Median ISL length | Float |
| `isl_std_len` | ISL length std deviation | Float |
| `isl_norm_len` | Normalized ISL length std | Float |
| `isl_reserved` | Reserved field | Integer |
| `isl_index` | ISL index | Integer |
| `isl_vlan_id` | VLAN ID | Integer |
| `isl_hsa` | High bits of SA | Integer |
| `isl_dsap` | DSAP value | Integer |
| `isl_ssap` | SSAP value | Integer |
| `isl_control` | Control field | Integer |
| `isl_dst_type` | Destination type | Integer |
| `isl_dst_user_eth` | Destination user Ethernet | Boolean |

### Loop Detection Features
| Feature | Description | Type |
|---------|-------------|------|
| `sum_loop_skipcount` | Sum of loop skip counts | Integer |
| `num_loop_frame` | Number of loop frames | Integer |
| `percent_loop_frame` | Percentage of loop frames | Float |
| `loop_skipcount` | Loop skip count | Integer |
| `loop_receipt_number` | Loop receipt number | Integer |
| `loop_function` | Loop function code | Integer |
| `loop_relevant_function` | Relevant loop function | Integer |

## Advanced Statistical Features

### Protocol Relationship Ratios
| Feature | Description | Type |
|---------|-------------|------|
| `stp_over_cdp_ratio` | STP/CDP packet ratio | Float |
| `cdp_over_stp_ratio` | CDP/STP packet ratio | Float |
| `arp_over_dhcp_ratio` | ARP/DHCP packet ratio | Float |
| `dhcp_over_arp_ratio` | DHCP/ARP packet ratio | Float |

### Network Diversity Metrics
| Feature | Description | Type |
|---------|-------------|------|
| `l2_protocol_diversity` | Layer 2 protocol diversity index | Float |
| `std_stp_over_std_arp` | STP std dev / ARP std dev ratio | Float |
| `std_frame_len_over_std_stp` | Frame length std / STP std ratio | Float |
| `stp_concentration` | STP packet concentration metric | Float |
| `cdp_concentration` | CDP packet concentration metric | Float |
| `arp_concentration` | ARP packet concentration metric | Float |

### Advanced Flow Metrics
| Feature | Description | Type |
|---------|-------------|------|
| `l2_weighted_activity_score` | Weighted Layer 2 activity score | Float |
| `l2_protocol_imbalance` | Protocol distribution imbalance | Float |
| `inter_arrival_cv` | Inter-arrival time coefficient of variation | Float |
| `burst_ratio` | Packet burst ratio | Float |

### Flow Label
| Feature | Description | Type |
|---------|-------------|------|
| `label` | Flow classification label | String |

## Feature Categories Summary

| Category | Count | Description |
|----------|-------|-------------|
| Flow Identifiers | 3 | Basic flow identification |
| MAC Address Features | 14 | Source/destination MAC analysis |
| Network Layer | 5 | IP addresses, ports, Ethernet types |
| Timing Features | 1 | Flow duration |
| Frame Statistics | 32 | Packet size, direction, quality |
| LLC Features | 15 | Logical Link Control analysis |
| STP Features | 19 | Spanning Tree Protocol |
| Loop Detection | 8 | Network loop identification |
| DTP Features | 15 | Dynamic Trunking Protocol |
| ISL Features | 18 | Inter-Switch Link protocol |
| ARP Features | 36 | Address Resolution Protocol |
| DHCP Features | 37 | DHCP protocol analysis |
| CDP Features | 69 | Cisco Discovery Protocol |
| Advanced Statistical | 16 | Cross-protocol metrics |
| **Total Features** | **343+** | **Comprehensive Layer 2 analysis** |

## Missing Value Handling

All features use `-100` as the default value for missing or unavailable data. This ensures:
- Consistent data format for machine learning applications
- Clear distinction between zero values and missing data
- Compatibility with various ML algorithms that handle missing values

## Feature Usage Guidelines

### For Machine Learning
- Use `-100` missing value handling for consistent preprocessing
- Consider feature normalization for statistical features
- Focus on protocol-specific features for attack detection

### For Network Analysis
- MAC vendor features help identify device types
- Protocol distribution features indicate network behavior
- Timing features reveal traffic patterns

### For Security Analysis
- ARP features detect spoofing attacks
- STP features identify topology manipulation
- CDP features reveal device information leakage
- Statistical ratios highlight anomalous behavior

---

For implementation details and usage examples, see:
- [COMMANDS.md](COMMANDS.md) - Command line usage
- [EXAMPLES.md](EXAMPLES.md) - Practical examples
- [CONFIGURATION.md](CONFIGURATION.md) - Setup and configuration