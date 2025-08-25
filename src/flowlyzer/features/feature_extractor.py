"""
Feature extraction engine for generating comprehensive flow features.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import logging
from ..flows.flow import Flow


class FeatureExtractor:
    """
    Main feature extraction engine that generates all required features from flows.
    """
    
    def __init__(self, num_threads: int = 4):
        self.feature_columns = self._get_feature_columns()
        self.num_threads = num_threads
        self.logger = logging.getLogger(__name__)
    
    def extract_features(self, flows: List[Flow], global_protocol_stats: Dict[str, int] = None) -> pd.DataFrame:
        if not flows:
            return pd.DataFrame(columns=self.feature_columns)
        
        if self.num_threads == 1 or len(flows) < 100:
            return self._extract_features_sequential(flows, global_protocol_stats)
        else:
            return self._extract_features_parallel(flows, global_protocol_stats)
    
    def _extract_features_sequential(self, flows: List[Flow], global_protocol_stats: Dict[str, int] = None) -> pd.DataFrame:
        feature_rows = []
        
        for flow in flows:
            try:
                flow_features = self._extract_flow_features(flow, global_protocol_stats)
                feature_rows.append(flow_features)
            except Exception as e:
                default_features = self._get_default_features()
                default_features['connection'] = flow.flow_id
                feature_rows.append(default_features)
        
        df = pd.DataFrame(feature_rows, columns=self.feature_columns)
        df = self._fill_missing_values(df)
        return df
    
    def _extract_features_parallel(self, flows: List[Flow], global_protocol_stats: Dict[str, int] = None) -> pd.DataFrame:
        self.logger.info(f"Extracting features from {len(flows)} flows using {self.num_threads} threads")
        
        chunk_size = max(1, len(flows) // (self.num_threads * 2))
        flow_chunks = [flows[i:i + chunk_size] for i in range(0, len(flows), chunk_size)]
        
        feature_rows = []
        completed_chunks = 0
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_chunk = {executor.submit(self._process_flow_chunk, chunk, global_protocol_stats): chunk 
                             for chunk in flow_chunks}
            
            for future in as_completed(future_to_chunk):
                try:
                    chunk_features = future.result()
                    feature_rows.extend(chunk_features)
                    completed_chunks += 1
                    
                    if completed_chunks % 5 == 0 or completed_chunks == len(flow_chunks):
                        self.logger.info(f"Completed {completed_chunks}/{len(flow_chunks)} feature extraction chunks")
                        
                except Exception as e:
                    self.logger.error(f"Error in feature extraction chunk: {e}")
                    chunk = future_to_chunk[future]
                    for flow in chunk:
                        default_features = self._get_default_features()
                        default_features['connection'] = flow.flow_id
                        feature_rows.append(default_features)
        
        df = pd.DataFrame(feature_rows, columns=self.feature_columns)
        df = self._fill_missing_values(df)
        return df
    
    def _process_flow_chunk(self, flows: List[Flow], global_protocol_stats: Dict[str, int] = None) -> List[Dict[str, Any]]:
        chunk_features = []
        for flow in flows:
            try:
                flow_features = self._extract_flow_features(flow, global_protocol_stats)
                chunk_features.append(flow_features)
            except Exception as e:
                default_features = self._get_default_features()
                default_features['connection'] = flow.flow_id
                chunk_features.append(default_features)
        return chunk_features
    
    def _extract_flow_features(self, flow: Flow, global_protocol_stats: Dict[str, int] = None) -> Dict[str, Any]:
        """Extract all features for a single flow."""
        features = flow.get_features()
        
        # Update percentage calculations with global context if available
        if global_protocol_stats:
            flow.update_global_percentages(features, global_protocol_stats)
        
        if flow.packets:
            first_packet_features = flow.packets[0].get_features()
            self._add_mac_vendor_features(features, first_packet_features)
        
        self._add_loop_features(features, flow)
        self._add_advanced_protocol_features(features, flow)
        
        for col in self.feature_columns:
            if col not in features:
                features[col] = self._get_default_value_for_column(col)
        
        return features
    
    def _add_mac_vendor_features(self, features: Dict[str, Any], packet_features: Dict[str, Any]):
        """Add MAC vendor information from packet features."""

        features['src_mac_addr_vendor'] = packet_features.get('src_mac_vendor', 'Unknown')
        features['src_mac_addr_device'] = packet_features.get('src_mac_device', 'Unknown')
        features['src_mac_addr_vendor_name'] = packet_features.get('src_mac_vendor_name', 'Unknown')
        features['src_mac_addr_vendor_name_known'] = packet_features.get('src_mac_vendor_name_known', False)
        features['src_mac_ig'] = packet_features.get('src_mac_ig', False)
        features['src_mac_lg'] = packet_features.get('src_mac_lg', False)
        features['src_mac_oui'] = packet_features.get('src_mac_oui', 'Unknown')
        
        features['dst_mac_addr_vendor'] = packet_features.get('dst_mac_vendor', 'Unknown')
        features['dst_mac_addr_device'] = packet_features.get('dst_mac_device', 'Unknown')
        features['dst_mac_addr_vendor_name'] = packet_features.get('dst_mac_vendor_name', 'Unknown')
        features['dst_mac_addr_vendor_name_known'] = packet_features.get('dst_mac_vendor_name_known', False)
        features['dst_mac_ig'] = packet_features.get('dst_mac_ig', False)
        features['dst_mac_lg'] = packet_features.get('dst_mac_lg', False)
        features['dst_mac_oui'] = packet_features.get('dst_mac_oui', 'Unknown')
        
        features['eth_type'] = packet_features.get('eth_type', 0)
    
    def _add_loop_features(self, features: Dict[str, Any], flow: Flow):
        """Add loop-related features (simplified implementation)."""
        try:
            # Count potential loop indicators
            loop_count = 0
            skip_count = 0
            
            for packet in flow.packets:
                packet_features = packet.get_features()
                
                # indicate loops
                if packet_features.get('frame_len', 0) < 64:  
                    loop_count += 1
                

                if packet.is_ignored():
                    skip_count += 1
            
            features['num_loop_frame'] = loop_count
            features['percent_loop_frame'] = (loop_count / len(flow.packets)) * 100 if flow.packets else 0
            features['sum_loop_skipcount'] = skip_count
            
        except Exception:
            features['num_loop_frame'] = 0
            features['percent_loop_frame'] = 0
            features['sum_loop_skipcount'] = 0
    
    def _add_advanced_protocol_features(self, features: Dict[str, Any], flow: Flow):
        """Add advanced protocol-specific features."""
        try:
            # DTP features
            dtp_packets = [p for p in flow.packets if p.get_features().get('is_dtp', False)]
            features['num_dtp_frame'] = len(dtp_packets)
            features['percent_dtp_frame'] = (len(dtp_packets) / len(flow.packets)) * 100 if flow.packets else 0
            if dtp_packets:
                features['sum_dtp_tlvs'] = sum(p.get_features().get('dtp_tlvs', 0) for p in dtp_packets)
            else:
                features['sum_dtp_tlvs'] = 0
            
            # ISL features
            isl_packets = [p for p in flow.packets if p.get_features().get('is_isl', False)]
            features['num_isl_frame'] = len(isl_packets)
            features['percent_isl_frame'] = (len(isl_packets) / len(flow.packets)) * 100 if flow.packets else 0
            
            if isl_packets:
                isl_lengths = [p.get_features().get('isl_len', 0) for p in isl_packets]
                isl_bpdus = [p.get_features().get('isl_bpdu', 0) for p in isl_packets]
                
                features['isl_sum_len'] = sum(isl_lengths)
                features['isl_mean_len'] = np.mean(isl_lengths) if isl_lengths else 0
                features['isl_max_len'] = max(isl_lengths) if isl_lengths else 0
                features['isl_min_len'] = min(isl_lengths) if isl_lengths else 0
                features['isl_median_len'] = np.median(isl_lengths) if isl_lengths else 0
                features['isl_std_len'] = np.std(isl_lengths) if len(isl_lengths) > 1 else 0
                features['isl_norm_len'] = features['isl_std_len'] / features['isl_mean_len'] if features['isl_mean_len'] > 0 else 0
                features['isl_mean_bpdu'] = np.mean(isl_bpdus) if isl_bpdus else 0
                
            else:
                self._set_default_isl_features(features)
                
        except Exception:
            features['num_dtp_frame'] = 0
            features['percent_dtp_frame'] = 0
            features['sum_dtp_tlvs'] = 0
            self._set_default_isl_features(features)
    
    def _set_default_isl_features(self, features: Dict[str, Any]):
        """Set default ISL features."""
        isl_defaults = {
            'num_isl_frame': 0,
            'percent_isl_frame': 0,
            'isl_mean_bpdu': 0,
            'isl_sum_len': 0,
            'isl_mean_len': 0,
            'isl_max_len': 0,
            'isl_min_len': 0,
            'isl_median_len': 0,
            'isl_std_len': 0,
            'isl_norm_len': 0,
        }
        features.update(isl_defaults)
    
    def _get_feature_columns(self) -> List[str]:
        """Get the complete list of feature columns."""
        return [
            # Flow identifiers
            'connection',
            'tcp_stream',
            'protocol',
            
            # MAC address features
            'dst_mac_addr',
            'dst_mac_addr_vendor',
            'dst_mac_addr_device',
            'dst_mac_addr_vendor_name',
            'dst_mac_addr_vendor_name_known',
            'dst_mac_ig',
            'dst_mac_lg',
            'dst_mac_oui',
            'src_mac_addr',
            'src_mac_addr_vendor',
            'src_mac_addr_device',
            'src_mac_addr_vendor_name',
            'src_mac_addr_vendor_name_known',
            'src_mac_ig',
            'src_mac_lg',
            'src_mac_oui',
            
            # Network layer
            'eth_type',
            'dst_ip_addr',
            'src_ip_addr',
            'dst_port',
            'src_port',
            
            # Timing features
            'time_delta',
            
            # Frame statistics
            'num_frame',
            'sum_frame_len',
            'sum_frame_len_div_time',
            'num_frame_marked',
            'num_frame_ignored',
            'sum_frames_dst_src',
            'mean_frames_dst_src',
            'max_frames_dst_src',
            'min_frames_dst_src',
            'median_frames_dst_src',
            'std_frames_dst_src',
            'norm_frames_dst_src',
            'sum_frames_src_dst',
            'mean_frames_src_dst',
            'max_frames_src_dst',
            'min_frames_src_dst',
            'median_frames_src_dst',
            'std_frames_src_dst',
            'norm_frames_src_dst',
            'mean_frame_len',
            'max_frame_len',
            'min_frame_len',
            'median_frame_len',
            'std_frame_len',
            'norm_frame_len',
            'percent_frame_marked',
            'percent_frame_ignored',
            
            # LLC features (enhanced)
            'num_llc_frame',
            'percent_llc_frame',
            'llc_mean_ssap_sap',
            'llc_max_ssap_sap',
            'llc_min_ssap_sap',
            'llc_median_ssap_sap',
            'llc_std_ssap_sap',
            'llc_norm_ssap_sap',
            'llc_sum_dsap_sap',
            'llc_mean_dsap_sap',
            'llc_max_dsap_sap',
            'llc_min_dsap_sap',
            'llc_median_dsap_sap',
            'llc_std_dsap_sap',
            'llc_norm_dsap_sap',
            'llc_mean_ssap_cr',
            'llc_mean_dsap_cr',
            'llc_control_ftype',
            'llc_control_u_modifier',
            'llc_dsap_ig',
            
            # STP features (enhanced)
            'num_stp_frame',
            'percent_stp_frame',
            'stp_sum_msg_age',
            'stp_mean_msg_age',
            'stp_max_msg_age',
            'stp_min_msg_age',
            'stp_median_msg_age',
            'stp_std_msg_age',
            'stp_norm_msg_age',
            'stp_sum_forward',
            'stp_mean_forward',
            'stp_max_forward',
            'stp_min_forward',
            'stp_median_forward',
            'stp_std_forward',
            'stp_count_flags_tc_1',
            'stp_count_flags_tcack_1',
            'stp_percent_flags_tc_1',
            'stp_percent_flags_tcack_1',
            'stp_age_div_max_age',
            'stp_version',
            'stp_hello',
            'stp_root_identifier_prio',
            'stp_root_identifier_ext',
            'stp_bridge_identifier_prio',
            'stp_bridge_identifier_ext',
            'stp_root_cost',
            'stp_port_id',
            
            # Loop features (enhanced)
            'sum_loop_skipcount',
            'num_loop_frame',
            'percent_loop_frame',
            'loop_skipcount',
            'loop_receipt_number',
            'loop_function',
            'loop_relevant_function',
            
            # DTP features (enhanced) - num/percent/sum are dynamically generated
            'dtp_version',
            'dtp_tlv_len',
            'dtp_trunk_status_tlv_len',
            'dtp_trunk_type_tlv_len',
            'dtp_sender_tlv_len',
            'dtp_sender_id',
            
            # DTP aggregated features
            'dtp_sum_version',
            'dtp_mean_version',
            'dtp_sum_tlv_count',
            'dtp_mean_tlv_count',
            'dtp_max_tlv_count',
            'dtp_min_tlv_count',
            'dtp_sum_domain_length',
            'dtp_mean_domain_length',
            'dtp_frame_isl_count',
            'dtp_frame_802dot1q_count',
            'dtp_frame_isl_ratio',
            
            # ISL features (enhanced) - num/percent are dynamically generated
            'isl_mean_bpdu',
            'isl_sum_len',
            'isl_mean_len',
            'isl_max_len',
            'isl_min_len',
            'isl_median_len',
            'isl_std_len',
            'isl_norm_len',
            'isl_reserved',
            'isl_index',
            'isl_vlan_id',
            'isl_hsa',
            'isl_dsap',
            'isl_ssap',
            'isl_control',
            'isl_dst_type',
            'isl_dst_user_eth',
            
            # ARP features (enhanced)
            'num_arp_frame',
            'percent_arp_frame',
            'arp_type',
            'arp_size',
            'arp_dst_hw_mac',
            'arp_src_hw_mac',
            'arp_proto_size',
            'arp_hw_size',
            'arp_hw_type',
            'arp_opcode',
            'arp_proto_type',
            
            # ARP aggregated features
            'arp_sum_hw_type',
            'arp_mean_hw_type',
            'arp_max_hw_type',
            'arp_min_hw_type',
            'arp_sum_proto_type',
            'arp_mean_proto_type',
            'arp_sum_opcode',
            'arp_mean_opcode',
            'arp_max_opcode',
            'arp_min_opcode',
            'arp_sum_size',
            'arp_mean_size',
            'arp_max_size',
            'arp_min_size',
            'arp_request_count',
            'arp_reply_count',
            'arp_gratuitous_count',
            'arp_request_ratio',
            'arp_reply_ratio',
            
            # DHCP features (enhanced)
            'num_dhcp_frame',
            'percent_dhcp_frame',
            'dhcp_hw_type',
            'dhcp_type',
            'dhcp_hw_len',
            'dhcp_hops',
            'dhcp_secs',
            'dhcp_flags_bc',
            'dhcp_flags_reserved',
            'dhcp_cookie',
            'dhcp_padding',
            'dhcp_options_count',
            'dhcp_options',
            'dhcp_message_type',
            'dhcp_options_len',
            'dhcp_option_padding',
            
            # DHCP aggregated features
            'dhcp_sum_opcode',
            'dhcp_mean_opcode',
            'dhcp_sum_transaction_id',
            'dhcp_mean_transaction_id',
            'dhcp_max_transaction_id',
            'dhcp_min_transaction_id',
            'dhcp_sum_lease_time',
            'dhcp_mean_lease_time',
            'dhcp_max_lease_time',
            'dhcp_min_lease_time',
            'dhcp_sum_message_type',
            'dhcp_mean_message_type',
            'dhcp_sum_options_count',
            'dhcp_mean_options_count',
            'dhcp_max_options_count',
            'dhcp_min_options_count',
            
            # CDP features (comprehensive)
            'num_cdp_frame',
            'percent_cdp_frame',
            'cdp_sum_addresses_count',
            'cdp_mean_addresses_count',
            'cdp_max_addresses_count',
            'cdp_min_addresses_count',
            'cdp_median_addresses_count',
            'cdp_std_addresses_count',
            'cdp_norm_addresses_count',
            'cdp_sum_tlvs',
            'cdp_sum_capabilities',
            'cdp_mean_power_sum',
            'cdp_max_power_sum',
            'cdp_min_power_sum',
            'cdp_median_power_sum',
            'cdp_std_power_sum',
            'cdp_norm_power_sum',
            'cdp_version',
            'cdp_ttl',
            'cdp_checksum_status',
            'cdp_device_id_tlv_len',
            'cdp_software_version_tlv_len',
            'cdp_platform_tlv_len',
            'cdp_platform',
            'cdp_addresses_tlv_len',
            'cdp_addresses_sum_len',
            'cdp_addresses_sum_protocol_len',
            'cdp_management_addresses_sum_len',
            'cdp_management_addresses_sum_protocol_len',
            'cdp_port_id_tlv_len',
            'cdp_capabilities_tlv_len',
            'cdp_capabilities_router',
            'cdp_capabilities_trans_bridge',
            'cdp_capabilities_src_bridge',
            'cdp_capabilities_switch',
            'cdp_capabilities_host',
            'cdp_capabilities_igmp',
            'cdp_capabilities_repeater',
            'cdp_capabilities_voip_phone',
            'cdp_capabilities_remote',
            'cdp_capabilities_cvta',
            'cdp_capabilities_mac_relay',
            'cdp_hello_tlv_len',
            'cdp_hello_oui',
            'cdp_hello_num_unknown',
            'cdp_hello_management_vlan',
            'cdp_vtp_management_tlv_len',
            'cdp_vlan_native_tlv_len',
            'cdp_vlan_native_native_vlan',
            'cdp_duplex_tlv_len',
            'cdp_duplex',
            'cdp_power_tlv_len',
            'cdp_power_request_id',
            'cdp_power_management_id',
            'cdp_spare_pair_tlv_len',
            'cdp_spare_poe_tlv_poe',
            'cdp_spare_poe_tlv_spare_pair_arch',
            'cdp_spare_poe_tlv_req_spare_pair_poe',
            'cdp_spare_poe_tlv_pse_spare_pair_poe',
            
            # Extended statistical features (ratios and combinations)
            'stp_over_cdp_ratio',
            'cdp_over_stp_ratio',
            'arp_over_dhcp_ratio',
            'dhcp_over_arp_ratio',
            'l2_protocol_diversity',
            'std_stp_over_std_arp',
            'std_frame_len_over_std_stp',
            'stp_concentration',
            'cdp_concentration',
            'arp_concentration',
            'l2_weighted_activity_score',
            'l2_protocol_imbalance',
            'inter_arrival_cv',
            'burst_ratio',
            
            'label',
        ]
    
    def _get_default_features(self) -> Dict[str, Any]:
        """Get default feature values for all columns."""
        defaults = {}
        
        for col in self.feature_columns:
            defaults[col] = self._get_default_value_for_column(col)
        
        return defaults
    
    def _get_default_value_for_column(self, column: str) -> Any:
        """Get appropriate default value for a specific column."""
        # String columns
        if column in ['connection', 'tcp_stream', 'dst_mac_addr', 'src_mac_addr', 
                     'dst_ip_addr', 'src_ip_addr', 'dst_mac_addr_vendor', 
                     'src_mac_addr_vendor', 'dst_mac_addr_device', 'src_mac_addr_device',
                     'dst_mac_addr_vendor_name', 'src_mac_addr_vendor_name',
                     'dst_mac_oui', 'src_mac_oui', 'label']:
            return 'Unknown' if 'vendor' in column or 'device' in column or 'oui' in column else ''
        
        # Boolean columns
        elif any(keyword in column for keyword in ['known', 'ig', 'lg', 'percent']):
            if 'percent' in column:
                return np.nan  # Use NaN instead of 0.0 for missing percentage data
            else:
                return False
        
        # Numeric columns - use NaN instead of 0 for missing data
        else:
            return np.nan
    
    def _fill_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fill missing values in DataFrame with appropriate defaults."""
        for col in df.columns:
            if df[col].isnull().any():
                default_value = self._get_default_value_for_column(col)
                df[col] = df[col].fillna(default_value)
        
        return df
    
    def separate_layer2_layer3(self, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Separate flows into Layer 2 and Layer 3 DataFrames.
        
        Args:
            df: Complete features DataFrame
            
        Returns:
            Tuple of (layer2_df, layer3_df)
        """
        # Layer 2 flows: no IP addressing
        layer2_mask = (df['src_ip_addr'].isnull() | df['src_ip_addr'].eq('')) | \
                     (df['dst_ip_addr'].isnull() | df['dst_ip_addr'].eq(''))
        
        layer2_df = df[layer2_mask].copy()
        layer3_df = df[~layer2_mask].copy()
        
        return layer2_df, layer3_df
    
    def get_feature_descriptions(self) -> Dict[str, str]:
        """Get descriptions for all features."""
        return {
            'connection': 'Unique flow identifier combining endpoints',
            'tcp_stream': 'TCP stream identifier (empty for non-TCP)',
            'dst_mac_addr': 'Destination MAC address',
            'dst_mac_addr_vendor': 'Destination MAC vendor from OUI',
            'dst_mac_addr_device': 'Destination MAC device type',
            'dst_mac_addr_vendor_name': 'Destination MAC vendor name',
            'dst_mac_addr_vendor_name_known': 'Whether destination MAC vendor is known',
            'dst_mac_ig': 'Destination MAC Individual/Group bit',
            'dst_mac_lg': 'Destination MAC Local/Global bit',
            'dst_mac_oui': 'Destination MAC OUI (first 3 bytes)',
            'src_mac_addr': 'Source MAC address',
            'src_mac_addr_vendor': 'Source MAC vendor from OUI',
            'src_mac_addr_device': 'Source MAC device type',
            'src_mac_addr_vendor_name': 'Source MAC vendor name',
            'src_mac_addr_vendor_name_known': 'Whether source MAC vendor is known',
            'src_mac_ig': 'Source MAC Individual/Group bit',
            'src_mac_lg': 'Source MAC Local/Global bit',
            'src_mac_oui': 'Source MAC OUI (first 3 bytes)',
            'eth_type': 'Ethernet type field',
            'dst_ip_addr': 'Destination IP address',
            'src_ip_addr': 'Source IP address',
            'dst_port': 'Destination port number',
            'src_port': 'Source port number',
            'time_delta': 'Flow duration in seconds',
            'num_frame': 'Total number of packets in flow',
            'sum_frame_len': 'Total bytes in all packets',
            'sum_frame_len_div_time': 'Data rate (bytes per second)',
            'num_frame_marked': 'Number of marked packets',
            'num_frame_ignored': 'Number of ignored packets',
            'sum_frames_dst_src': 'Total bytes destination to source',
            'mean_frames_dst_src': 'Average packet size destination to source',
            'max_frames_dst_src': 'Maximum packet size destination to source',
            'min_frames_dst_src': 'Minimum packet size destination to source',
            'median_frames_dst_src': 'Median packet size destination to source',
            'std_frames_dst_src': 'Standard deviation packet size destination to source',
            'norm_frames_dst_src': 'Normalized standard deviation destination to source',
            'sum_frames_src_dst': 'Total bytes source to destination',
            'mean_frames_src_dst': 'Average packet size source to destination',
            'max_frames_src_dst': 'Maximum packet size source to destination',
            'min_frames_src_dst': 'Minimum packet size source to destination',
            'median_frames_src_dst': 'Median packet size source to destination',
            'std_frames_src_dst': 'Standard deviation packet size source to destination',
            'norm_frames_src_dst': 'Normalized standard deviation source to destination',
            'mean_frame_len': 'Average packet size in flow',
            'max_frame_len': 'Maximum packet size in flow',
            'min_frame_len': 'Minimum packet size in flow',
            'median_frame_len': 'Median packet size in flow',
            'std_frame_len': 'Standard deviation of packet sizes',
            'norm_frame_len': 'Normalized standard deviation of packet sizes',
            'percent_frame_marked': 'Percentage of marked packets',
            'percent_frame_ignored': 'Percentage of ignored packets',
            'label': 'Flow label (attack type or Benign)',
        }
    
    def add_custom_feature(self, feature_name: str, extraction_func: callable):
        """
        Add a custom feature extraction function.
        
        Args:
            feature_name: Name of the new feature
            extraction_func: Function that takes a Flow and returns the feature value
        """
        if feature_name not in self.feature_columns:
            self.feature_columns.append(feature_name)
        
        # Store custom extraction function for later use
        if not hasattr(self, '_custom_extractors'):
            self._custom_extractors = {}
        
        self._custom_extractors[feature_name] = extraction_func