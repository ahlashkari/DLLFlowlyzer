"""
Flow class for grouping related packets and extracting flow-level features.
"""

import time
import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime
from ..packets.base_packet import BasePacket


class Flow:
    """
    Represents a network flow - a collection of related packets.
    Extracts flow-level features and statistics.
    """
    
    def __init__(self, flow_id: str, first_packet: BasePacket):
        """
        Initialize flow with the first packet.
        
        Args:
            flow_id: Unique identifier for this flow
            first_packet: The first packet in this flow
        """
        self.flow_id = flow_id
        self.packets: List[BasePacket] = [first_packet]
        self.start_time = first_packet.timestamp
        self.end_time = first_packet.timestamp
        self.protocol = first_packet.get_protocol_type()
        
        # Flow identifiers from first packet
        features = first_packet.get_features()
        self.src_mac = features.get('src_mac_addr')
        self.dst_mac = features.get('dst_mac_addr')
        self.src_ip = features.get('src_ip_addr')
        self.dst_ip = features.get('dst_ip_addr')
        self.src_port = features.get('src_port')
        self.dst_port = features.get('dst_port')
        
        self.is_active = True
        self.last_activity = first_packet.timestamp
        
        # Feature cache
        self._features_cache = None
        self._features_dirty = True
    
    def add_packet(self, packet: BasePacket):
        """Add a packet to this flow."""
        self.packets.append(packet)
        self.end_time = packet.timestamp
        self.last_activity = packet.timestamp
        self._features_dirty = True
    
    def get_duration(self) -> float:
        """Get flow duration in seconds."""
        return self.end_time - self.start_time
    
    def get_packet_count(self) -> int:
        """Get total number of packets in flow."""
        return len(self.packets)
    
    def is_timeout(self, current_time: float, timeout_seconds: float = 1200) -> bool:
        """Check if flow has timed out."""
        return (current_time - self.last_activity) > timeout_seconds
    
    def close_flow(self):
        """Mark flow as closed/inactive."""
        self.is_active = False
    
    def get_features(self) -> Dict[str, Any]:
        """
        Extract comprehensive flow features.
        Returns cached features if available and not dirty.
        """
        if not self._features_dirty and self._features_cache is not None:
            return self._features_cache.copy()
        
        features = {}
        
        # Basic flow information
        features['connection'] = self.flow_id
        features['tcp_stream'] = self.flow_id if self.protocol == 'TCP' else ''
        features['protocol'] = self.protocol
        features['num_frame'] = len(self.packets)
        features['time_delta'] = self.get_duration()
        
        # Endpoint information
        features['src_mac_addr'] = self.src_mac
        features['dst_mac_addr'] = self.dst_mac
        features['src_ip_addr'] = self.src_ip
        features['dst_ip_addr'] = self.dst_ip
        features['src_port'] = self.src_port
        features['dst_port'] = self.dst_port
        
        # Extract statistical features
        self._extract_frame_statistics(features)
        self._extract_directional_statistics(features)
        self._extract_protocol_statistics(features)
        self._extract_timing_statistics(features)
        
        # Cache the features
        self._features_cache = features.copy()
        self._features_dirty = False
        
        return features
    
    def _extract_frame_statistics(self, features: Dict[str, Any]):
        """Extract frame size and count statistics."""
        try:
            frame_lengths = [p.get_features().get('frame_len', 0) for p in self.packets]
            
            features['sum_frame_len'] = sum(frame_lengths)
            features['mean_frame_len'] = np.mean(frame_lengths) if frame_lengths else -100
            features['max_frame_len'] = max(frame_lengths) if frame_lengths else -100
            features['min_frame_len'] = min(frame_lengths) if frame_lengths else -100
            features['median_frame_len'] = np.median(frame_lengths) if frame_lengths else -100
            features['std_frame_len'] = np.std(frame_lengths) if len(frame_lengths) > 1 else -100
            features['norm_frame_len'] = features['std_frame_len'] / features['mean_frame_len'] if features['mean_frame_len'] > 0 else -100
            
            # Frame rate
            duration = self.get_duration()
            features['sum_frame_len_div_time'] = features['sum_frame_len'] / duration if duration > 0 else -100
            
            # Marked and ignored frames
            marked_count = sum(1 for p in self.packets if p.is_marked())
            ignored_count = sum(1 for p in self.packets if p.is_ignored())
            
            features['num_frame_marked'] = marked_count
            features['num_frame_ignored'] = ignored_count
            features['percent_frame_marked'] = (marked_count / len(self.packets)) * 100 if self.packets else -100
            features['percent_frame_ignored'] = (ignored_count / len(self.packets)) * 100 if self.packets else -100
            
        except Exception:
            self._set_default_frame_statistics(features)
    
    def _extract_directional_statistics(self, features: Dict[str, Any]):
        """Extract directional flow statistics (src->dst vs dst->src)."""
        try:
            src_to_dst = []
            dst_to_src = []
            
            for packet in self.packets:
                packet_features = packet.get_features()
                packet_src_mac = packet_features.get('src_mac_addr')
                packet_dst_mac = packet_features.get('dst_mac_addr')
                frame_len = packet_features.get('frame_len', 0)
                
                if packet_src_mac == self.src_mac and packet_dst_mac == self.dst_mac:
                    src_to_dst.append(frame_len)
                elif packet_src_mac == self.dst_mac and packet_dst_mac == self.src_mac:
                    dst_to_src.append(frame_len)
            
            # Source to destination statistics
            if src_to_dst:
                features['sum_frames_src_dst'] = sum(src_to_dst)
                features['mean_frames_src_dst'] = np.mean(src_to_dst)
                features['max_frames_src_dst'] = max(src_to_dst)
                features['min_frames_src_dst'] = min(src_to_dst)
                features['median_frames_src_dst'] = np.median(src_to_dst)
                features['std_frames_src_dst'] = np.std(src_to_dst) if len(src_to_dst) > 1 else -100
                features['norm_frames_src_dst'] = features['std_frames_src_dst'] / features['mean_frames_src_dst'] if features['mean_frames_src_dst'] > 0 else -100
            else:
                self._set_default_directional_features(features, 'src_dst')
            
            # Destination to source statistics
            if dst_to_src:
                features['sum_frames_dst_src'] = sum(dst_to_src)
                features['mean_frames_dst_src'] = np.mean(dst_to_src)
                features['max_frames_dst_src'] = max(dst_to_src)
                features['min_frames_dst_src'] = min(dst_to_src)
                features['median_frames_dst_src'] = np.median(dst_to_src)
                features['std_frames_dst_src'] = np.std(dst_to_src) if len(dst_to_src) > 1 else -100
                features['norm_frames_dst_src'] = features['std_frames_dst_src'] / features['mean_frames_dst_src'] if features['mean_frames_dst_src'] > 0 else -100
            else:
                self._set_default_directional_features(features, 'dst_src')
                
        except Exception:
            self._set_default_directional_features(features, 'src_dst')
            self._set_default_directional_features(features, 'dst_src')
    
    def _extract_protocol_statistics(self, features: Dict[str, Any]):
        """Extract protocol-specific statistics."""
        try:
            # Count packets by protocol type
            protocol_counts = {}
            llc_count = 0
            stp_count = 0
            arp_count = 0
            dhcp_count = 0
            cdp_count = 0
            
            for packet in self.packets:
                packet_features = packet.get_features()
                
                # LLC frames
                if packet_features.get('is_llc', False):
                    llc_count += 1
                
                # Protocol-specific counts
                if packet.get_protocol_type() == 'ARP':
                    arp_count += 1
                elif packet_features.get('is_dhcp', False):
                    dhcp_count += 1
                
                # STP detection - check for STP protocol type or any STP feature
                if (packet.get_protocol_type() == 'STP' or 
                    packet_features.get('stp_version', -100) != -100 or
                    packet_features.get('stp_proto_id') is not None):
                    stp_count += 1
                
                # CDP detection - check for CDP protocol type or any CDP feature
                if (packet.get_protocol_type() == 'CDP' or 
                    packet_features.get('cdp_tlvs', 0) > 0 or
                    packet_features.get('cdp_version', -100) != -100):
                    cdp_count += 1
            
            # LLC statistics
            features['num_llc_frame'] = llc_count
            features['percent_llc_frame'] = (llc_count / len(self.packets)) * 100 if self.packets else -100
            
            # STP statistics
            features['num_stp_frame'] = stp_count
            features['percent_stp_frame'] = (stp_count / len(self.packets)) * 100 if self.packets else -100
            
            # ARP statistics
            features['num_arp_frame'] = arp_count
            features['percent_arp_frame'] = (arp_count / len(self.packets)) * 100 if self.packets else -100
            
            # DHCP statistics
            features['num_dhcp_frame'] = dhcp_count
            features['percent_dhcp_frame'] = (dhcp_count / len(self.packets)) * 100 if self.packets else -100
            
            # CDP statistics
            features['num_cdp_frame'] = cdp_count
            features['percent_cdp_frame'] = (cdp_count / len(self.packets)) * 100 if self.packets else -100
            
            # Extended statistical features combining protocols
            self._extract_combined_statistical_features(features, {
                'stp_count': stp_count,
                'cdp_count': cdp_count,
                'arp_count': arp_count,
                'dhcp_count': dhcp_count,
                'llc_count': llc_count
            })
            
            # Extract protocol-specific aggregated features
            self._extract_stp_aggregated_features(features)
            self._extract_cdp_aggregated_features(features)
            self._extract_llc_aggregated_features(features)
            self._extract_arp_aggregated_features(features)
            self._extract_dhcp_aggregated_features(features)
            self._extract_dtp_aggregated_features(features)
            self._extract_isl_aggregated_features(features)
            
        except Exception:
            self._set_default_protocol_statistics(features)
    
    def _extract_stp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated STP features across all STP packets in flow."""
        try:
            # Improved STP packet detection
            stp_packets = []
            for p in self.packets:
                packet_features = p.get_features()
                if (p.get_protocol_type() == 'STP' or 
                    packet_features.get('stp_version', -100) != -100 or
                    packet_features.get('stp_proto_id') is not None):
                    stp_packets.append(p)
            
            if stp_packets:
                msg_ages = [p.get_features().get('stp_msg_age', 0) for p in stp_packets if p.get_features().get('stp_msg_age', -100) != -100]
                forward_delays = [p.get_features().get('stp_forward_delay', 0) for p in stp_packets if p.get_features().get('stp_forward_delay', -100) != -100]
                tc_flags = [p.get_features().get('stp_flags_tc', False) for p in stp_packets if p.get_features().get('stp_flags_tc', -100) != -100]
                tcack_flags = [p.get_features().get('stp_flags_tcack', False) for p in stp_packets if p.get_features().get('stp_flags_tcack', -100) != -100]
                
                features['stp_sum_msg_age'] = sum(msg_ages)
                features['stp_mean_msg_age'] = np.mean(msg_ages) if msg_ages else -100
                features['stp_max_msg_age'] = max(msg_ages) if msg_ages else -100
                features['stp_min_msg_age'] = min(msg_ages) if msg_ages else -100
                features['stp_median_msg_age'] = np.median(msg_ages) if msg_ages else -100
                features['stp_std_msg_age'] = np.std(msg_ages) if len(msg_ages) > 1 else -100
                features['stp_norm_msg_age'] = features['stp_std_msg_age'] / features['stp_mean_msg_age'] if features['stp_mean_msg_age'] > 0 else -100
                
                features['stp_sum_forward'] = sum(forward_delays)
                features['stp_mean_forward'] = np.mean(forward_delays) if forward_delays else -100
                features['stp_max_forward'] = max(forward_delays) if forward_delays else -100
                features['stp_min_forward'] = min(forward_delays) if forward_delays else -100
                features['stp_median_forward'] = np.median(forward_delays) if forward_delays else -100
                features['stp_std_forward'] = np.std(forward_delays) if len(forward_delays) > 1 else -100
                
                # Flag counts
                features['stp_count_flags_tc_1'] = sum(tc_flags)
                features['stp_count_flags_tcack_1'] = sum(tcack_flags)
                features['stp_percent_flags_tc_1'] = (sum(tc_flags) / len(stp_packets)) * 100
                features['stp_percent_flags_tcack_1'] = (sum(tcack_flags) / len(stp_packets)) * 100
                
            else:
                self._set_default_stp_aggregated_features(features)
                
        except Exception:
            self._set_default_stp_aggregated_features(features)
    
    def _extract_cdp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated CDP features."""
        try:
            # Improved CDP packet detection
            cdp_packets = []
            for p in self.packets:
                packet_features = p.get_features()
                if (p.get_protocol_type() == 'CDP' or 
                    packet_features.get('cdp_tlvs', 0) > 0 or
                    packet_features.get('cdp_version', -100) != -100):
                    cdp_packets.append(p)
            
            if cdp_packets:
                addresses_counts = [p.get_features().get('cdp_addresses_count', 0) for p in cdp_packets if p.get_features().get('cdp_addresses_count', -100) != -100]
                tlv_counts = [p.get_features().get('cdp_tlvs', 0) for p in cdp_packets if p.get_features().get('cdp_tlvs', -100) > 0]
                capabilities = [p.get_features().get('cdp_capabilities', 0) for p in cdp_packets if p.get_features().get('cdp_capabilities', -100) != -100]
                # Note: power_sum may not exist in fixed parser, use defaults
                power_sums = [p.get_features().get('cdp_power_sum', 0) for p in cdp_packets if p.get_features().get('cdp_power_sum', -100) != -100]
                
                features['cdp_sum_addresses_count'] = sum(addresses_counts)
                features['cdp_mean_addresses_count'] = np.mean(addresses_counts) if addresses_counts else -100
                features['cdp_max_addresses_count'] = max(addresses_counts) if addresses_counts else -100
                features['cdp_min_addresses_count'] = min(addresses_counts) if addresses_counts else -100
                features['cdp_median_addresses_count'] = np.median(addresses_counts) if addresses_counts else -100
                features['cdp_std_addresses_count'] = np.std(addresses_counts) if len(addresses_counts) > 1 else -100
                features['cdp_norm_addresses_count'] = features['cdp_std_addresses_count'] / features['cdp_mean_addresses_count'] if features['cdp_mean_addresses_count'] > 0 else -100
                
                features['cdp_sum_tlvs'] = sum(tlv_counts)
                features['cdp_sum_capabilities'] = sum(capabilities)
                
                features['cdp_mean_power_sum'] = np.mean(power_sums) if power_sums else -100
                features['cdp_max_power_sum'] = max(power_sums) if power_sums else -100
                features['cdp_min_power_sum'] = min(power_sums) if power_sums else -100
                features['cdp_median_power_sum'] = np.median(power_sums) if power_sums else -100
                features['cdp_std_power_sum'] = np.std(power_sums) if len(power_sums) > 1 else -100
                features['cdp_norm_power_sum'] = features['cdp_std_power_sum'] / features['cdp_mean_power_sum'] if features['cdp_mean_power_sum'] > 0 else -100
                
            else:
                self._set_default_cdp_aggregated_features(features)
                
        except Exception:
            self._set_default_cdp_aggregated_features(features)
    
    def _extract_llc_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated LLC features."""
        try:
            llc_packets = [p for p in self.packets if p.get_features().get('is_llc', False)]
            
            if llc_packets:
                ssap_saps = [p.get_features().get('llc_ssap_sap', 0) for p in llc_packets]
                dsap_saps = [p.get_features().get('llc_dsap_sap', 0) for p in llc_packets]
                ssap_crs = [p.get_features().get('llc_ssap_cr', False) for p in llc_packets]
                dsap_crs = [p.get_features().get('llc_dsap_cr', False) for p in llc_packets]
                
                # SSAP SAP statistics
                features['llc_mean_ssap_sap'] = np.mean(ssap_saps) if ssap_saps else -100
                features['llc_max_ssap_sap'] = max(ssap_saps) if ssap_saps else -100
                features['llc_min_ssap_sap'] = min(ssap_saps) if ssap_saps else -100
                features['llc_median_ssap_sap'] = np.median(ssap_saps) if ssap_saps else -100
                features['llc_std_ssap_sap'] = np.std(ssap_saps) if len(ssap_saps) > 1 else -100
                features['llc_norm_ssap_sap'] = features['llc_std_ssap_sap'] / features['llc_mean_ssap_sap'] if features['llc_mean_ssap_sap'] > 0 else -100
                
                # DSAP SAP statistics
                features['llc_sum_dsap_sap'] = sum(dsap_saps)
                features['llc_mean_dsap_sap'] = np.mean(dsap_saps) if dsap_saps else -100
                features['llc_max_dsap_sap'] = max(dsap_saps) if dsap_saps else -100
                features['llc_min_dsap_sap'] = min(dsap_saps) if dsap_saps else -100
                features['llc_median_dsap_sap'] = np.median(dsap_saps) if dsap_saps else -100
                features['llc_std_dsap_sap'] = np.std(dsap_saps) if len(dsap_saps) > 1 else -100
                features['llc_norm_dsap_sap'] = features['llc_std_dsap_sap'] / features['llc_mean_dsap_sap'] if features['llc_mean_dsap_sap'] > 0 else -100
                
                # Command/Response bit averages
                features['llc_mean_ssap_cr'] = np.mean([1 if cr else 0 for cr in ssap_crs]) if ssap_crs else -100
                features['llc_mean_dsap_cr'] = np.mean([1 if cr else 0 for cr in dsap_crs]) if dsap_crs else -100
                
            else:
                self._set_default_llc_aggregated_features(features)
                
        except Exception:
            self._set_default_llc_aggregated_features(features)
    
    def _extract_arp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated ARP features across all ARP packets in flow."""
        try:
            # Improved ARP packet detection
            arp_packets = []
            for p in self.packets:
                packet_features = p.get_features()
                if (p.get_protocol_type() == 'ARP' or 
                    packet_features.get('arp_opcode', -100) != -100):
                    arp_packets.append(p)
            
            if arp_packets:
                # Extract ARP-specific features for aggregation using fixed feature names
                hw_types = [p.get_features().get('arp_hw_type', 0) for p in arp_packets if p.get_features().get('arp_hw_type', -100) != -100]
                proto_types = [p.get_features().get('arp_proto_type', 0) for p in arp_packets if p.get_features().get('arp_proto_type', -100) != -100]
                opcodes = [p.get_features().get('arp_opcode', 0) for p in arp_packets if p.get_features().get('arp_opcode', -100) != -100]
                # Calculate packet size from frame length since arp_packet_size may not exist
                packet_sizes = [p.get_features().get('frame_len', 0) for p in arp_packets if p.get_features().get('frame_len', 0) > 0]
                
                # Hardware type statistics (use -100 if no data)
                features['arp_sum_hw_type'] = sum(hw_types) if hw_types else -100
                features['arp_mean_hw_type'] = float(np.mean(hw_types)) if hw_types else -100
                features['arp_max_hw_type'] = max(hw_types) if hw_types else -100
                features['arp_min_hw_type'] = min(hw_types) if hw_types else -100
                
                # Protocol type statistics  
                features['arp_sum_proto_type'] = sum(proto_types) if proto_types else -100
                features['arp_mean_proto_type'] = float(np.mean(proto_types)) if proto_types else -100
                
                # Opcode statistics
                features['arp_sum_opcode'] = sum(opcodes) if opcodes else -100
                features['arp_mean_opcode'] = float(np.mean(opcodes)) if opcodes else -100
                features['arp_max_opcode'] = max(opcodes) if opcodes else -100
                features['arp_min_opcode'] = min(opcodes) if opcodes else -100
                
                # Size statistics
                features['arp_sum_size'] = sum(packet_sizes) if packet_sizes else -100
                features['arp_mean_size'] = float(np.mean(packet_sizes)) if packet_sizes else -100
                features['arp_max_size'] = max(packet_sizes) if packet_sizes else -100
                features['arp_min_size'] = min(packet_sizes) if packet_sizes else -100
                
                # Protocol-specific counts (only count packets that have the feature)
                request_count = sum(1 for p in arp_packets if p.get_features().get('arp_is_request') is True)
                reply_count = sum(1 for p in arp_packets if p.get_features().get('arp_is_reply') is True)
                gratuitous_count = sum(1 for p in arp_packets if p.get_features().get('arp_is_gratuitous') is True)
                
                features['arp_request_count'] = request_count
                features['arp_reply_count'] = reply_count
                features['arp_gratuitous_count'] = gratuitous_count
                features['arp_request_ratio'] = (request_count / len(arp_packets)) * 100 if arp_packets else -100
                features['arp_reply_ratio'] = (reply_count / len(arp_packets)) * 100 if arp_packets else -100
                
            else:
                self._set_default_arp_aggregated_features(features)
                
        except Exception:
            self._set_default_arp_aggregated_features(features)
    
    def _extract_dhcp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated DHCP features across all DHCP packets in flow."""
        try:
            # Improved DHCP packet detection
            dhcp_packets = []
            for p in self.packets:
                packet_features = p.get_features()
                if (p.get_features().get('is_dhcp', False) or
                    packet_features.get('dhcp_op', -100) != -100):
                    dhcp_packets.append(p)
            
            if dhcp_packets:
                # Extract DHCP-specific features for aggregation using fixed feature names
                opcodes = [p.get_features().get('dhcp_op', 0) for p in dhcp_packets if p.get_features().get('dhcp_op', -100) != -100]
                transaction_ids = [p.get_features().get('dhcp_xid', 0) for p in dhcp_packets if p.get_features().get('dhcp_xid', -100) != -100]
                # Note: lease_time may not be available in fixed parser
                lease_times = []  # Not commonly available in packet headers
                # Use dhcp_options for message type info
                options_counts = [p.get_features().get('dhcp_options', 0) for p in dhcp_packets if p.get_features().get('dhcp_options', -100) != -100]
                
                # DHCP opcode statistics (use -100 if no data)
                features['dhcp_sum_opcode'] = sum(opcodes) if opcodes else -100
                features['dhcp_mean_opcode'] = float(np.mean(opcodes)) if opcodes else -100
                
                # Transaction ID statistics
                features['dhcp_sum_transaction_id'] = sum(transaction_ids) if transaction_ids else -100
                features['dhcp_mean_transaction_id'] = float(np.mean(transaction_ids)) if transaction_ids else -100
                features['dhcp_max_transaction_id'] = max(transaction_ids) if transaction_ids else -100
                features['dhcp_min_transaction_id'] = min(transaction_ids) if transaction_ids else -100
                
                # Lease time statistics
                features['dhcp_sum_lease_time'] = sum(lease_times) if lease_times else -100
                features['dhcp_mean_lease_time'] = float(np.mean(lease_times)) if lease_times else -100
                features['dhcp_max_lease_time'] = max(lease_times) if lease_times else -100
                features['dhcp_min_lease_time'] = min(lease_times) if lease_times else -100
                
                # Message type statistics - not available in fixed parser
                features['dhcp_sum_message_type'] = -100  # Not extracted by fixed parser
                features['dhcp_mean_message_type'] = -100  # Not extracted by fixed parser
                
                # Options count statistics
                features['dhcp_sum_options_count'] = sum(options_counts) if options_counts else -100
                features['dhcp_mean_options_count'] = float(np.mean(options_counts)) if options_counts else -100
                features['dhcp_max_options_count'] = max(options_counts) if options_counts else -100
                features['dhcp_min_options_count'] = min(options_counts) if options_counts else -100
                
            else:
                self._set_default_dhcp_aggregated_features(features)
                
        except Exception:
            self._set_default_dhcp_aggregated_features(features)
    
    def _extract_dtp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated DTP features across all DTP packets in flow."""
        try:
            dtp_packets = [p for p in self.packets if p.get_features().get('dtp_tlv_count', 0) > 0]
            
            if dtp_packets:
                # Extract DTP-specific features for aggregation - only use values that exist
                versions = [p.get_features()['dtp_version'] for p in dtp_packets if 'dtp_version' in p.get_features()]
                tlv_counts = [p.get_features()['dtp_tlv_count'] for p in dtp_packets if 'dtp_tlv_count' in p.get_features()]
                domain_lengths = [p.get_features()['dtp_domain_length'] for p in dtp_packets if 'dtp_domain_length' in p.get_features()]
                
                # DTP version statistics (use null if no data)
                features['dtp_sum_version'] = sum(versions) if versions else None
                features['dtp_mean_version'] = float(np.mean(versions)) if versions else None
                
                # TLV count statistics
                features['dtp_sum_tlv_count'] = sum(tlv_counts) if tlv_counts else None
                features['dtp_mean_tlv_count'] = float(np.mean(tlv_counts)) if tlv_counts else None
                features['dtp_max_tlv_count'] = max(tlv_counts) if tlv_counts else None
                features['dtp_min_tlv_count'] = min(tlv_counts) if tlv_counts else None
                
                # Domain length statistics
                features['dtp_sum_domain_length'] = sum(domain_lengths) if domain_lengths else None
                features['dtp_mean_domain_length'] = float(np.mean(domain_lengths)) if domain_lengths else None
                
                # Frame type counts (count features should be 0, not null when no data)
                isl_count = sum(1 for p in dtp_packets if p.get_features().get('dtp_frame_isl') is True)
                dot1q_count = sum(1 for p in dtp_packets if p.get_features().get('dtp_frame_802dot1q') is True)
                
                features['dtp_frame_isl_count'] = isl_count
                features['dtp_frame_802dot1q_count'] = dot1q_count
                features['dtp_frame_isl_ratio'] = (isl_count / len(dtp_packets)) * 100 if dtp_packets else None
                
            else:
                self._set_default_dtp_aggregated_features(features)
                
        except Exception:
            self._set_default_dtp_aggregated_features(features)
    
    def _extract_isl_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated ISL features across all ISL packets in flow."""
        try:
            # Improved ISL packet detection
            isl_packets = []
            for p in self.packets:
                packet_features = p.get_features()
                if (p.get_protocol_type() == 'ISL' or 
                    packet_features.get('isl_frame_type', -100) != -100 or
                    packet_features.get('isl_src_vlan_id', -100) != -100):
                    isl_packets.append(p)
            
            if isl_packets:
                frame_types = [p.get_features().get('isl_frame_type', 0) for p in isl_packets if p.get_features().get('isl_frame_type', -100) != -100]
                user_bits = [p.get_features().get('isl_user_bits', 0) for p in isl_packets if p.get_features().get('isl_user_bits', -100) != -100]
                vlan_ids = [p.get_features().get('isl_src_vlan_id', 0) for p in isl_packets if p.get_features().get('isl_src_vlan_id', -100) != -100]
                bpdu_flags = [p.get_features().get('isl_bpdu', False) for p in isl_packets if p.get_features().get('isl_bpdu', -100) != -100]
                indexes = [p.get_features().get('isl_index', 0) for p in isl_packets if p.get_features().get('isl_index', -100) != -100]
                
                # Frame type statistics
                features['isl_sum_frame_type'] = sum(frame_types)
                features['isl_mean_frame_type'] = np.mean(frame_types) if frame_types else -100
                features['isl_max_frame_type'] = max(frame_types) if frame_types else -100
                features['isl_min_frame_type'] = min(frame_types) if frame_types else -100
                
                # User bits statistics
                features['isl_sum_user_bits'] = sum(user_bits)
                features['isl_mean_user_bits'] = np.mean(user_bits) if user_bits else -100
                
                # VLAN ID statistics
                features['isl_sum_vlan_id'] = sum(vlan_ids)
                features['isl_mean_vlan_id'] = np.mean(vlan_ids) if vlan_ids else -100
                features['isl_max_vlan_id'] = max(vlan_ids) if vlan_ids else -100
                features['isl_min_vlan_id'] = min(vlan_ids) if vlan_ids else -100
                features['isl_std_vlan_id'] = np.std(vlan_ids) if len(vlan_ids) > 1 else -100
                
                # BPDU flag statistics
                bpdu_count = sum(1 for flag in bpdu_flags if flag is True)
                features['isl_bpdu_count'] = bpdu_count
                features['isl_bpdu_ratio'] = (bpdu_count / len(isl_packets)) * 100 if isl_packets else -100
                
                # Index statistics
                features['isl_sum_index'] = sum(indexes)
                features['isl_mean_index'] = np.mean(indexes) if indexes else -100
                
                # ISL-specific flow features
                features['isl_unique_vlans'] = len(set(vlan_ids)) if vlan_ids else 0
                features['isl_unique_frame_types'] = len(set(frame_types)) if frame_types else 0
                
            else:
                self._set_default_isl_aggregated_features(features)
                
        except Exception:
            self._set_default_isl_aggregated_features(features)

    def _extract_timing_statistics(self, features: Dict[str, Any]):
        """Extract timing-related features."""
        try:
            if len(self.packets) > 1:
                # Inter-arrival times
                timestamps = [p.timestamp for p in self.packets]
                inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                features['mean_inter_arrival_time'] = np.mean(inter_arrival_times) if inter_arrival_times else -100
                features['std_inter_arrival_time'] = np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else -100
                features['max_inter_arrival_time'] = max(inter_arrival_times) if inter_arrival_times else -100
                features['min_inter_arrival_time'] = min(inter_arrival_times) if inter_arrival_times else -100
                
            else:
                features['mean_inter_arrival_time'] = -100
                features['std_inter_arrival_time'] = -100
                features['max_inter_arrival_time'] = -100
                features['min_inter_arrival_time'] = -100
                
        except Exception:
            features['mean_inter_arrival_time'] = -100
            features['std_inter_arrival_time'] = -100
            features['max_inter_arrival_time'] = -100
            features['min_inter_arrival_time'] = -100
    
    def _set_default_frame_statistics(self, features: Dict[str, Any]):
        """Set default frame statistics."""
        frame_defaults = {
            'sum_frame_len': 0,
            'mean_frame_len': -100,
            'max_frame_len': -100,
            'min_frame_len': -100,
            'median_frame_len': -100,
            'std_frame_len': -100,
            'norm_frame_len': -100,
            'sum_frame_len_div_time': -100,
            'num_frame_marked': 0,
            'num_frame_ignored': 0,
            'percent_frame_marked': -100,
            'percent_frame_ignored': -100,
        }
        features.update(frame_defaults)
    
    def _set_default_directional_features(self, features: Dict[str, Any], direction: str):
        """Set default directional features."""
        directional_defaults = {
            f'sum_frames_{direction}': 0,
            f'mean_frames_{direction}': -100,
            f'max_frames_{direction}': -100,
            f'min_frames_{direction}': -100,
            f'median_frames_{direction}': -100,
            f'std_frames_{direction}': -100,
            f'norm_frames_{direction}': -100,
        }
        features.update(directional_defaults)
    
    def _set_default_protocol_statistics(self, features: Dict[str, Any]):
        """Set default protocol statistics."""
        protocol_defaults = {
            'num_llc_frame': 0,
            'percent_llc_frame': -100,
            'num_stp_frame': 0,
            'percent_stp_frame': -100,
            'num_arp_frame': 0,
            'percent_arp_frame': -100,
            'num_dhcp_frame': 0,
            'percent_dhcp_frame': -100,
            'num_cdp_frame': 0,
            'percent_cdp_frame': -100,
            'num_isl_frame': 0,
            'percent_isl_frame': -100,
        }
        features.update(protocol_defaults)
        self._set_default_stp_aggregated_features(features)
        self._set_default_cdp_aggregated_features(features)
        self._set_default_llc_aggregated_features(features)
        self._set_default_arp_aggregated_features(features)
        self._set_default_dhcp_aggregated_features(features)
        self._set_default_dtp_aggregated_features(features)
        self._set_default_isl_aggregated_features(features)
    
    def _set_default_stp_aggregated_features(self, features: Dict[str, Any]):
        """Set default STP aggregated features."""
        stp_defaults = {
            'stp_sum_msg_age': -100,
            'stp_mean_msg_age': -100,
            'stp_max_msg_age': -100,
            'stp_min_msg_age': -100,
            'stp_median_msg_age': -100,
            'stp_std_msg_age': -100,
            'stp_norm_msg_age': -100,
            'stp_sum_forward': -100,
            'stp_mean_forward': -100,
            'stp_max_forward': -100,
            'stp_min_forward': -100,
            'stp_median_forward': -100,
            'stp_std_forward': -100,
            'stp_count_flags_tc_1': -100,
            'stp_count_flags_tcack_1': -100,
            'stp_percent_flags_tc_1': -100,
            'stp_percent_flags_tcack_1': -100,
        }
        features.update(stp_defaults)
    
    def _set_default_cdp_aggregated_features(self, features: Dict[str, Any]):
        """Set default CDP aggregated features."""
        cdp_defaults = {
            'cdp_sum_addresses_count': -100,
            'cdp_mean_addresses_count': -100,
            'cdp_max_addresses_count': -100,
            'cdp_min_addresses_count': -100,
            'cdp_median_addresses_count': -100,
            'cdp_std_addresses_count': -100,
            'cdp_norm_addresses_count': -100,
            'cdp_sum_tlvs': -100,
            'cdp_sum_capabilities': -100,
            'cdp_mean_power_sum': -100,
            'cdp_max_power_sum': -100,
            'cdp_min_power_sum': -100,
            'cdp_median_power_sum': -100,
            'cdp_std_power_sum': -100,
            'cdp_norm_power_sum': -100,
        }
        features.update(cdp_defaults)
    
    def _set_default_llc_aggregated_features(self, features: Dict[str, Any]):
        """Set default LLC aggregated features."""
        llc_defaults = {
            'llc_mean_ssap_sap': -100,
            'llc_max_ssap_sap': -100,
            'llc_min_ssap_sap': -100,
            'llc_median_ssap_sap': -100,
            'llc_std_ssap_sap': -100,
            'llc_norm_ssap_sap': -100,
            'llc_sum_dsap_sap': -100,
            'llc_mean_dsap_sap': -100,
            'llc_max_dsap_sap': -100,
            'llc_min_dsap_sap': -100,
            'llc_median_dsap_sap': -100,
            'llc_std_dsap_sap': -100,
            'llc_norm_dsap_sap': -100,
            'llc_mean_ssap_cr': -100,
            'llc_mean_dsap_cr': -100,
        }
        features.update(llc_defaults)
    
    def _set_default_arp_aggregated_features(self, features: Dict[str, Any]):
        """Set default ARP aggregated features when no ARP packets exist."""
        arp_defaults = {
            'arp_sum_hw_type': -100,
            'arp_mean_hw_type': -100,
            'arp_max_hw_type': -100,
            'arp_min_hw_type': -100,
            'arp_sum_proto_type': -100,
            'arp_mean_proto_type': -100,
            'arp_sum_opcode': -100,
            'arp_mean_opcode': -100,
            'arp_max_opcode': -100,
            'arp_min_opcode': -100,
            'arp_sum_size': -100,
            'arp_mean_size': -100,
            'arp_max_size': -100,
            'arp_min_size': -100,
            'arp_request_count': -100,
            'arp_reply_count': -100,
            'arp_gratuitous_count': -100,
            'arp_request_ratio': -100,
            'arp_reply_ratio': -100,
        }
        features.update(arp_defaults)
    
    def _set_default_dhcp_aggregated_features(self, features: Dict[str, Any]):
        """Set default DHCP aggregated features when no DHCP packets exist."""
        dhcp_defaults = {
            'dhcp_sum_opcode': -100,
            'dhcp_mean_opcode': -100,
            'dhcp_sum_transaction_id': -100,
            'dhcp_mean_transaction_id': -100,
            'dhcp_max_transaction_id': -100,
            'dhcp_min_transaction_id': -100,
            'dhcp_sum_lease_time': -100,
            'dhcp_mean_lease_time': -100,
            'dhcp_max_lease_time': -100,
            'dhcp_min_lease_time': -100,
            'dhcp_sum_message_type': -100,
            'dhcp_mean_message_type': -100,
            'dhcp_sum_options_count': -100,
            'dhcp_mean_options_count': -100,
            'dhcp_max_options_count': -100,
            'dhcp_min_options_count': -100,
        }
        features.update(dhcp_defaults)
    
    def _set_default_dtp_aggregated_features(self, features: Dict[str, Any]):
        """Set default DTP aggregated features when no DTP packets exist."""
        dtp_defaults = {
            'dtp_sum_version': -100,
            'dtp_mean_version': -100,
            'dtp_sum_tlv_count': -100,
            'dtp_mean_tlv_count': -100,
            'dtp_max_tlv_count': -100,
            'dtp_min_tlv_count': -100,
            'dtp_sum_domain_length': -100,
            'dtp_mean_domain_length': -100,
            'dtp_frame_isl_count': -100,
            'dtp_frame_802dot1q_count': -100,
            'dtp_frame_isl_ratio': -100,
        }
        features.update(dtp_defaults)
    
    def _set_default_isl_aggregated_features(self, features: Dict[str, Any]):
        """Set default ISL aggregated features when no ISL packets exist."""
        isl_defaults = {
            'isl_sum_frame_type': -100,
            'isl_mean_frame_type': -100,
            'isl_max_frame_type': -100,
            'isl_min_frame_type': -100,
            'isl_sum_user_bits': -100,
            'isl_mean_user_bits': -100,
            'isl_sum_vlan_id': -100,
            'isl_mean_vlan_id': -100,
            'isl_max_vlan_id': -100,
            'isl_min_vlan_id': -100,
            'isl_std_vlan_id': -100,
            'isl_bpdu_count': -100,
            'isl_bpdu_ratio': -100,
            'isl_sum_index': -100,
            'isl_mean_index': -100,
            'isl_unique_vlans': -100,
            'isl_unique_frame_types': -100,
        }
        features.update(isl_defaults)

    def _extract_combined_statistical_features(self, features: Dict[str, Any], protocol_counts: Dict[str, int]):
        """Extract advanced statistical features combining multiple protocols."""
        total_packets = len(self.packets)
        if total_packets == 0:
            return
        
        # Protocol ratio features
        stp_count = protocol_counts.get('stp_count', 0)
        cdp_count = protocol_counts.get('cdp_count', 0)
        arp_count = protocol_counts.get('arp_count', 0)
        dhcp_count = protocol_counts.get('dhcp_count', 0)
        llc_count = protocol_counts.get('llc_count', 0)
        
        # STP over CDP ratio
        features['stp_over_cdp_ratio'] = stp_count / (cdp_count + 1e-8)
        features['cdp_over_stp_ratio'] = cdp_count / (stp_count + 1e-8)
        
        # ARP over DHCP ratio
        features['arp_over_dhcp_ratio'] = arp_count / (dhcp_count + 1e-8)
        features['dhcp_over_arp_ratio'] = dhcp_count / (arp_count + 1e-8)
        
        # Layer 2 protocol diversity (entropy-like measure)
        l2_counts = [stp_count, cdp_count, arp_count, dhcp_count, llc_count]
        l2_total = sum(l2_counts)
        if l2_total > 0:
            l2_probs = [count / l2_total for count in l2_counts if count > 0]
            features['l2_protocol_diversity'] = -sum(p * np.log2(p) for p in l2_probs if p > 0)
        else:
            features['l2_protocol_diversity'] = 0
        
        # Protocol count ratios (replacing std ratios)
        try:
            # Recent protocol activity ratios using actual counts
            features['stp_over_arp_count_ratio'] = stp_count / (arp_count + 1e-8)
            features['arp_over_stp_count_ratio'] = arp_count / (stp_count + 1e-8)
            
            # CDP vs ARP activity ratio
            features['cdp_over_arp_count_ratio'] = cdp_count / (arp_count + 1e-8)
            features['arp_over_cdp_count_ratio'] = arp_count / (cdp_count + 1e-8)
            
            # STP vs DHCP activity ratio
            features['stp_over_dhcp_count_ratio'] = stp_count / (dhcp_count + 1e-8)
            features['dhcp_over_stp_count_ratio'] = dhcp_count / (stp_count + 1e-8)
            
        except Exception:
            features['stp_over_arp_count_ratio'] = 0
            features['arp_over_stp_count_ratio'] = 0
            features['cdp_over_arp_count_ratio'] = 0
            features['arp_over_cdp_count_ratio'] = 0
            features['stp_over_dhcp_count_ratio'] = 0
            features['dhcp_over_stp_count_ratio'] = 0
        
        # Protocol concentration metrics
        features['stp_concentration'] = (stp_count / total_packets) ** 2 if total_packets > 0 else 0
        features['cdp_concentration'] = (cdp_count / total_packets) ** 2 if total_packets > 0 else 0
        features['arp_concentration'] = (arp_count / total_packets) ** 2 if total_packets > 0 else 0
        
        # Combined protocol activity score
        l2_activity_scores = {
            'stp': stp_count * 1.0,  # Weight by importance
            'cdp': cdp_count * 1.2,  # CDP slightly more important
            'arp': arp_count * 0.8,
            'dhcp': dhcp_count * 1.1,
            'llc': llc_count * 0.5
        }
        features['l2_weighted_activity_score'] = sum(l2_activity_scores.values())
        
        # Protocol imbalance measure (Gini-like coefficient)
        if l2_total > 0:
            sorted_counts = sorted(l2_counts, reverse=True)
            n = len([c for c in sorted_counts if c > 0])
            if n > 1:
                cumulative = np.cumsum(sorted_counts)
                features['l2_protocol_imbalance'] = (n + 1 - 2 * sum((n + 1 - i) * count for i, count in enumerate(sorted_counts, 1)) / cumulative[-1]) / n
            else:
                features['l2_protocol_imbalance'] = 1.0  # Perfect imbalance (only one protocol)
        else:
            features['l2_protocol_imbalance'] = 0
        
        # Temporal clustering features (if packets have timing)
        try:
            if len(self.packets) > 2:
                timestamps = [packet.timestamp for packet in self.packets]
                inter_arrival_times = np.diff(timestamps)
                
                # Coefficient of variation for inter-arrival times
                if len(inter_arrival_times) > 1 and np.mean(inter_arrival_times) > 0:
                    features['inter_arrival_cv'] = np.std(inter_arrival_times) / np.mean(inter_arrival_times)
                else:
                    features['inter_arrival_cv'] = 0
                
                # Burst detection - ratio of fast vs slow packets
                median_time = np.median(inter_arrival_times)
                fast_packets = sum(1 for t in inter_arrival_times if t < median_time / 2)
                features['burst_ratio'] = fast_packets / len(inter_arrival_times) if inter_arrival_times else 0
            else:
                features['inter_arrival_cv'] = 0
                features['burst_ratio'] = 0
        except Exception:
            features['inter_arrival_cv'] = 0
            features['burst_ratio'] = 0
    
    def update_global_percentages(self, features: Dict[str, Any], global_protocol_stats: Dict[str, int]):
        """
        Update percentage calculations to use global Layer 2 packet counts instead of per-flow counts.
        
        Args:
            features: Flow features dictionary to update
            global_protocol_stats: Global protocol statistics from FlowManager
        """
        # Calculate total Layer 2 packets (excluding IP-based protocols)
        layer2_protocols = {'STP', 'ARP', 'CDP', 'DHCP', 'DTP', 'LLC', 'Unknown'}
        total_layer2_packets = sum(
            count for protocol, count in global_protocol_stats.items() 
            if protocol in layer2_protocols
        )
        
        if total_layer2_packets > 0:
            # Get flow-specific counts
            stp_count = features.get('num_stp_frame', 0)
            arp_count = features.get('num_arp_frame', 0)  
            cdp_count = features.get('num_cdp_frame', 0)
            dhcp_count = features.get('num_dhcp_frame', 0)
            llc_count = features.get('num_llc_frame', 0)
            isl_count = features.get('num_isl_frame', 0)
            
            # Update percentage calculations based on global Layer 2 totals
            features['percent_stp_frame'] = (stp_count / total_layer2_packets) * 100
            features['percent_arp_frame'] = (arp_count / total_layer2_packets) * 100
            features['percent_cdp_frame'] = (cdp_count / total_layer2_packets) * 100
            features['percent_dhcp_frame'] = (dhcp_count / total_layer2_packets) * 100
            features['percent_llc_frame'] = (llc_count / total_layer2_packets) * 100
            features['percent_isl_frame'] = (isl_count / total_layer2_packets) * 100
        else:
            # If no Layer 2 packets globally, set all percentages to 0
            features['percent_stp_frame'] = 0.0
            features['percent_arp_frame'] = 0.0
            features['percent_cdp_frame'] = 0.0
            features['percent_dhcp_frame'] = 0.0
            features['percent_llc_frame'] = 0.0

    def is_layer2_flow(self) -> bool:
        """Check if this is a Layer 2 flow (no IP addressing)."""
        return self.src_ip is None or self.dst_ip is None
    
    def __str__(self) -> str:
        """String representation of flow."""
        return f"Flow {self.flow_id}: {self.protocol} {len(self.packets)} packets, {self.get_duration():.2f}s"