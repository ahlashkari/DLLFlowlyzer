#!/usr/bin/env python3
"""Update features_explanation.md with new protocol-first naming and PyShark features."""

import re

# Read current features_explanation.md
with open('mdfiles/features_explanation.md', 'r') as f:
    content = f.read()

# Feature renames mapping (same as before)
feature_renames = {
    # LLC features
    'mean_llc_ssap_sap': 'llc_mean_ssap_sap',
    'max_llc_ssap_sap': 'llc_max_ssap_sap',
    'min_llc_ssap_sap': 'llc_min_ssap_sap',
    'median_llc_ssap_sap': 'llc_median_ssap_sap',
    'std_llc_ssap_sap': 'llc_std_ssap_sap',
    'norm_llc_ssap_sap': 'llc_norm_ssap_sap',
    'sum_llc_dsap_sap': 'llc_sum_dsap_sap',
    'mean_llc_dsap_sap': 'llc_mean_dsap_sap',
    'max_llc_dsap_sap': 'llc_max_dsap_sap',
    'min_llc_dsap_sap': 'llc_min_dsap_sap',
    'median_llc_dsap_sap': 'llc_median_dsap_sap',
    'std_llc_dsap_sap': 'llc_std_dsap_sap',
    'norm_llc_dsap_sap': 'llc_norm_dsap_sap',
    'mean_llc_ssap_cr': 'llc_mean_ssap_cr',
    'mean_llc_dsap_cr': 'llc_mean_dsap_cr',
    
    # STP features
    'sum_stp_msg_age': 'stp_sum_msg_age',
    'mean_stp_msg_age': 'stp_mean_msg_age',
    'max_stp_msg_age': 'stp_max_msg_age',
    'min_stp_msg_age': 'stp_min_msg_age',
    'median_stp_msg_age': 'stp_median_msg_age',
    'std_stp_msg_age': 'stp_std_msg_age',
    'norm_stp_msg_age': 'stp_norm_msg_age',
    'sum_stp_forward': 'stp_sum_forward',
    'mean_stp_forward': 'stp_mean_forward',
    'max_stp_forward': 'stp_max_forward',
    'min_stp_forward': 'stp_min_forward',
    'median_stp_forward': 'stp_median_forward',
    'std_stp_forward': 'stp_std_forward',
    'count_stp_flags_tc_1': 'stp_count_flags_tc_1',
    'count_stp_flags_tcack_1': 'stp_count_flags_tcack_1',
    'percent_stp_flags_tc_1': 'stp_percent_flags_tc_1',
    'percent_stp_flags_tcack_1': 'stp_percent_flags_tcack_1',
    
    # ARP features  
    'sum_arp_hw_type': 'arp_sum_hw_type',
    'mean_arp_hw_type': 'arp_mean_hw_type',
    'max_arp_hw_type': 'arp_max_hw_type',
    'min_arp_hw_type': 'arp_min_hw_type',
    'sum_arp_proto_type': 'arp_sum_proto_type',
    'mean_arp_proto_type': 'arp_mean_proto_type',
    'sum_arp_opcode': 'arp_sum_opcode',
    'mean_arp_opcode': 'arp_mean_opcode',
    'max_arp_opcode': 'arp_max_opcode',
    'min_arp_opcode': 'arp_min_opcode',
    'sum_arp_size': 'arp_sum_size',
    'mean_arp_size': 'arp_mean_size',
    'max_arp_size': 'arp_max_size',
    'min_arp_size': 'arp_min_size',
    
    # CDP features
    'sum_cdp_addresses_count': 'cdp_sum_addresses_count',
    'mean_cdp_addresses_count': 'cdp_mean_addresses_count',
    'max_cdp_addresses_count': 'cdp_max_addresses_count',
    'min_cdp_addresses_count': 'cdp_min_addresses_count',
    'median_cdp_addresses_count': 'cdp_median_addresses_count',
    'std_cdp_addresses_count': 'cdp_std_addresses_count',
    'norm_cdp_addresses_count': 'cdp_norm_addresses_count',
    'sum_cdp_tlvs': 'cdp_sum_tlvs',
    'sum_cdp_capabilities': 'cdp_sum_capabilities',
    'mean_cdp_power_sum': 'cdp_mean_power_sum',
    'max_cdp_power_sum': 'cdp_max_power_sum',
    'min_cdp_power_sum': 'cdp_min_power_sum',
    'median_cdp_power_sum': 'cdp_median_power_sum',
    'std_cdp_power_sum': 'cdp_std_power_sum',
    'norm_cdp_power_sum': 'cdp_norm_power_sum',
    
    # DHCP features
    'sum_dhcp_opcode': 'dhcp_sum_opcode',
    'mean_dhcp_opcode': 'dhcp_mean_opcode',
    'sum_dhcp_transaction_id': 'dhcp_sum_transaction_id',
    'mean_dhcp_transaction_id': 'dhcp_mean_transaction_id',
    'max_dhcp_transaction_id': 'dhcp_max_transaction_id',
    'min_dhcp_transaction_id': 'dhcp_min_transaction_id',
    'sum_dhcp_lease_time': 'dhcp_sum_lease_time',
    'mean_dhcp_lease_time': 'dhcp_mean_lease_time',
    'max_dhcp_lease_time': 'dhcp_max_lease_time',
    'min_dhcp_lease_time': 'dhcp_min_lease_time',
    'sum_dhcp_message_type': 'dhcp_sum_message_type',
    'mean_dhcp_message_type': 'dhcp_mean_message_type',
    'sum_dhcp_options_count': 'dhcp_sum_options_count',
    'mean_dhcp_options_count': 'dhcp_mean_options_count',
    'max_dhcp_options_count': 'dhcp_max_options_count',
    'min_dhcp_options_count': 'dhcp_min_options_count',
}

# Apply feature renames to documentation
original_content = content
changes_made = []

for old_name, new_name in feature_renames.items():
    # Replace feature names in headers, code blocks, and descriptions
    patterns = [
        f"### {old_name}",
        f"`{old_name}`",
        f"**{old_name}**",
        f"- {old_name}:",
        f"{old_name} ",
    ]
    
    for pattern in patterns:
        new_pattern = pattern.replace(old_name, new_name)
        if pattern in content:
            content = content.replace(pattern, new_pattern)
            changes_made.append(f"  {pattern} -> {new_pattern}")

# Update the header to reflect new feature count and PyShark integration
content = content.replace(
    "This document provides comprehensive explanations for all 240+ features",
    "This document provides comprehensive explanations for all 282 features"
)

# Add PyShark integration note
pyshark_note = """

## Recent Updates (2025)

### PyShark Integration for Enhanced Protocol Analysis
DLL Flowlyzer now uses PyShark for deep protocol inspection, extracting real protocol features instead of default values:

- **STP Features**: Real message age, bridge IDs, timing values from BPDU parsing
- **CDP Features**: Actual device information, capabilities, power consumption from TLV analysis  
- **ARP Features**: Hardware/protocol types, addresses, operation codes from ARP headers
- **DHCP Features**: Transaction IDs, lease times, options from DHCP/BOOTP parsing
- **DTP Features**: Domain information, frame types, TLV data from DTP analysis

### Protocol-First Naming Convention
All protocol-specific features now use protocol-first naming:
- Old: `mean_arp_hw_type` → New: `arp_mean_hw_type`
- Old: `sum_cdp_addresses_count` → New: `cdp_sum_addresses_count`
- Old: `std_stp_msg_age` → New: `stp_std_msg_age`

### Enhanced Null Handling
- Missing protocol features show as `null` instead of default values (0, '')
- Statistical features return `null` when insufficient data exists
- Global percentage calculations use total Layer 2 packets across all flows

---
"""

# Insert the note after the table of contents
toc_end = content.find("---\n", content.find("## Table of Contents"))
if toc_end != -1:
    content = content[:toc_end + 4] + pyshark_note + content[toc_end + 4:]

# Write updated content
with open('mdfiles/features_explanation.md', 'w') as f:
    f.write(content)

print(f"Updated features_explanation.md")
print(f"Applied {len(changes_made)} feature name changes")
print("Added PyShark integration documentation")
print("Updated feature count from 240+ to 282")
print("Added protocol-first naming convention note")