#!/usr/bin/env python3
"""Apply systematic feature renaming across the codebase."""

import re
import os
from pathlib import Path

# Feature rename mapping
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
    
    # DTP features
    'sum_dtp_version': 'dtp_sum_version',
    'mean_dtp_version': 'dtp_mean_version',
    'sum_dtp_tlv_count': 'dtp_sum_tlv_count',
    'mean_dtp_tlv_count': 'dtp_mean_tlv_count',
    'max_dtp_tlv_count': 'dtp_max_tlv_count',
    'min_dtp_tlv_count': 'dtp_min_tlv_count',
    'sum_dtp_domain_length': 'dtp_sum_domain_length',
    'mean_dtp_domain_length': 'dtp_mean_domain_length',
    
    # ISL features
    'mean_isl_bpdu': 'isl_mean_bpdu',
    'sum_isl_len': 'isl_sum_len',
    'mean_isl_len': 'isl_mean_len',
    'max_isl_len': 'isl_max_len',
    'min_isl_len': 'isl_min_len',
    'median_isl_len': 'isl_median_len',
    'std_isl_len': 'isl_std_len',
    'norm_isl_len': 'isl_norm_len',
    
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
}

def apply_renames_to_file(file_path: str, dry_run: bool = False):
    """Apply feature renames to a single file."""
    print(f"\nProcessing: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    changes_made = []
    
    # Apply each rename
    for old_name, new_name in feature_renames.items():
        # Pattern to match the old feature name in various contexts:
        # - In quotes: 'old_name' or "old_name"
        # - As dictionary keys: ['old_name'] or ["old_name"]
        # - In f-strings and format strings
        patterns = [
            f"'{old_name}'",
            f'"{old_name}"',
            f"['{old_name}']",
            f'["{old_name}"]',
            f"features\\['{old_name}'\\]",
            f'features\\["{old_name}"\\]',
            f"get\\('{old_name}'",
            f'get\\("{old_name}"',
        ]
        
        for pattern in patterns:
            old_pattern = pattern
            new_pattern = pattern.replace(old_name, new_name)
            
            if old_pattern in content:
                content = content.replace(old_pattern, new_pattern)
                changes_made.append(f"  {old_pattern} -> {new_pattern}")
    
    if changes_made:
        print(f"  Made {len(changes_made)} changes")
        if not dry_run:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        for change in changes_made[:5]:  # Show first 5 changes
            print(change)
        if len(changes_made) > 5:
            print(f"  ... and {len(changes_made) - 5} more")
    else:
        print("  No changes needed")

def main():
    # Files to process
    files_to_process = [
        'src/flowlyzer/features/feature_extractor.py',
        'src/flowlyzer/flows/flow.py',
        'debug_null_values.py',
        'debug_flow_aggregation.py',
        'debug_statistical_null.py',
        'debug_global_percentages.py',
    ]
    
    print("Starting feature rename process...")
    print(f"Will rename {len(feature_renames)} features")
    
    dry_run = False  # Set to False to actually apply changes
    if dry_run:
        print("\n*** DRY RUN - NO CHANGES WILL BE MADE ***")
    
    for file_path in files_to_process:
        if os.path.exists(file_path):
            apply_renames_to_file(file_path, dry_run)
        else:
            print(f"\nSkipping (not found): {file_path}")
    
    print(f"\nFeature rename process {'(DRY RUN) ' if dry_run else ''}completed!")

if __name__ == "__main__":
    main()