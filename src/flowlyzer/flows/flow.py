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
            features['mean_frame_len'] = np.mean(frame_lengths) if frame_lengths else np.nan
            features['max_frame_len'] = max(frame_lengths) if frame_lengths else np.nan
            features['min_frame_len'] = min(frame_lengths) if frame_lengths else np.nan
            features['median_frame_len'] = np.median(frame_lengths) if frame_lengths else np.nan
            features['std_frame_len'] = np.std(frame_lengths) if len(frame_lengths) > 1 else np.nan
            features['norm_frame_len'] = features['std_frame_len'] / features['mean_frame_len'] if features['mean_frame_len'] > 0 else np.nan
            
            # Frame rate
            duration = self.get_duration()
            features['sum_frame_len_div_time'] = features['sum_frame_len'] / duration if duration > 0 else np.nan
            
            # Marked and ignored frames
            marked_count = sum(1 for p in self.packets if p.is_marked())
            ignored_count = sum(1 for p in self.packets if p.is_ignored())
            
            features['num_frame_marked'] = marked_count
            features['num_frame_ignored'] = ignored_count
            features['percent_frame_marked'] = (marked_count / len(self.packets)) * 100 if self.packets else np.nan
            features['percent_frame_ignored'] = (ignored_count / len(self.packets)) * 100 if self.packets else np.nan
            
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
                features['std_frames_src_dst'] = np.std(src_to_dst) if len(src_to_dst) > 1 else np.nan
                features['norm_frames_src_dst'] = features['std_frames_src_dst'] / features['mean_frames_src_dst'] if features['mean_frames_src_dst'] > 0 else np.nan
            else:
                self._set_default_directional_features(features, 'src_dst')
            
            # Destination to source statistics
            if dst_to_src:
                features['sum_frames_dst_src'] = sum(dst_to_src)
                features['mean_frames_dst_src'] = np.mean(dst_to_src)
                features['max_frames_dst_src'] = max(dst_to_src)
                features['min_frames_dst_src'] = min(dst_to_src)
                features['median_frames_dst_src'] = np.median(dst_to_src)
                features['std_frames_dst_src'] = np.std(dst_to_src) if len(dst_to_src) > 1 else np.nan
                features['norm_frames_dst_src'] = features['std_frames_dst_src'] / features['mean_frames_dst_src'] if features['mean_frames_dst_src'] > 0 else np.nan
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
                
                # STP detection
                if packet_features.get('stp_proto_id') is not None:
                    stp_count += 1
                
                # CDP detection
                if packet_features.get('cdp_tlvs', 0) > 0:
                    cdp_count += 1
            
            # LLC statistics
            features['num_llc_frame'] = llc_count
            features['percent_llc_frame'] = (llc_count / len(self.packets)) * 100 if self.packets else np.nan
            
            # STP statistics
            features['num_stp_frame'] = stp_count
            features['percent_stp_frame'] = (stp_count / len(self.packets)) * 100 if self.packets else np.nan
            
            # ARP statistics
            features['num_arp_frame'] = arp_count
            features['percent_arp_frame'] = (arp_count / len(self.packets)) * 100 if self.packets else np.nan
            
            # DHCP statistics
            features['num_dhcp_frame'] = dhcp_count
            features['percent_dhcp_frame'] = (dhcp_count / len(self.packets)) * 100 if self.packets else np.nan
            
            # CDP statistics
            features['num_cdp_frame'] = cdp_count
            features['percent_cdp_frame'] = (cdp_count / len(self.packets)) * 100 if self.packets else np.nan
            
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
            
        except Exception:
            self._set_default_protocol_statistics(features)
    
    def _extract_stp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated STP features across all STP packets in flow."""
        try:
            stp_packets = [p for p in self.packets if p.get_features().get('stp_proto_id') is not None]
            
            if stp_packets:
                msg_ages = [p.get_features().get('stp_msg_age', 0) for p in stp_packets]
                forward_delays = [p.get_features().get('stp_forward_delay', 0) for p in stp_packets]
                tc_flags = [p.get_features().get('stp_flags_tc', False) for p in stp_packets]
                tcack_flags = [p.get_features().get('stp_flags_tcack', False) for p in stp_packets]
                
                features['sum_stp_msg_age'] = sum(msg_ages)
                features['mean_stp_msg_age'] = np.mean(msg_ages) if msg_ages else np.nan
                features['max_stp_msg_age'] = max(msg_ages) if msg_ages else np.nan
                features['min_stp_msg_age'] = min(msg_ages) if msg_ages else np.nan
                features['median_stp_msg_age'] = np.median(msg_ages) if msg_ages else np.nan
                features['std_stp_msg_age'] = np.std(msg_ages) if len(msg_ages) > 1 else np.nan
                features['norm_stp_msg_age'] = features['std_stp_msg_age'] / features['mean_stp_msg_age'] if features['mean_stp_msg_age'] > 0 else np.nan
                
                features['sum_stp_forward'] = sum(forward_delays)
                features['mean_stp_forward'] = np.mean(forward_delays) if forward_delays else np.nan
                features['max_stp_forward'] = max(forward_delays) if forward_delays else np.nan
                features['min_stp_forward'] = min(forward_delays) if forward_delays else np.nan
                features['median_stp_forward'] = np.median(forward_delays) if forward_delays else np.nan
                features['std_stp_forward'] = np.std(forward_delays) if len(forward_delays) > 1 else np.nan
                
                # Flag counts
                features['count_stp_flags_tc_1'] = sum(tc_flags)
                features['count_stp_flags_tcack_1'] = sum(tcack_flags)
                features['percent_stp_flags_tc_1'] = (sum(tc_flags) / len(stp_packets)) * 100
                features['percent_stp_flags_tcack_1'] = (sum(tcack_flags) / len(stp_packets)) * 100
                
            else:
                self._set_default_stp_aggregated_features(features)
                
        except Exception:
            self._set_default_stp_aggregated_features(features)
    
    def _extract_cdp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated CDP features."""
        try:
            cdp_packets = [p for p in self.packets if p.get_features().get('cdp_tlvs', 0) > 0]
            
            if cdp_packets:
                addresses_counts = [p.get_features().get('cdp_addresses_count', 0) for p in cdp_packets]
                tlv_counts = [p.get_features().get('cdp_tlvs', 0) for p in cdp_packets]
                capabilities = [p.get_features().get('cdp_capabilities', 0) for p in cdp_packets]
                power_sums = [p.get_features().get('cdp_power_sum', 0) for p in cdp_packets]
                
                features['sum_cdp_addresses_count'] = sum(addresses_counts)
                features['mean_cdp_addresses_count'] = np.mean(addresses_counts) if addresses_counts else np.nan
                features['max_cdp_addresses_count'] = max(addresses_counts) if addresses_counts else np.nan
                features['min_cdp_addresses_count'] = min(addresses_counts) if addresses_counts else np.nan
                features['median_cdp_addresses_count'] = np.median(addresses_counts) if addresses_counts else np.nan
                features['std_cdp_addresses_count'] = np.std(addresses_counts) if len(addresses_counts) > 1 else np.nan
                features['norm_cdp_addresses_count'] = features['std_cdp_addresses_count'] / features['mean_cdp_addresses_count'] if features['mean_cdp_addresses_count'] > 0 else np.nan
                
                features['sum_cdp_tlvs'] = sum(tlv_counts)
                features['sum_cdp_capabilities'] = sum(capabilities)
                
                features['mean_cdp_power_sum'] = np.mean(power_sums) if power_sums else np.nan
                features['max_cdp_power_sum'] = max(power_sums) if power_sums else np.nan
                features['min_cdp_power_sum'] = min(power_sums) if power_sums else np.nan
                features['median_cdp_power_sum'] = np.median(power_sums) if power_sums else np.nan
                features['std_cdp_power_sum'] = np.std(power_sums) if len(power_sums) > 1 else np.nan
                features['norm_cdp_power_sum'] = features['std_cdp_power_sum'] / features['mean_cdp_power_sum'] if features['mean_cdp_power_sum'] > 0 else np.nan
                
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
                features['mean_llc_ssap_sap'] = np.mean(ssap_saps) if ssap_saps else np.nan
                features['max_llc_ssap_sap'] = max(ssap_saps) if ssap_saps else np.nan
                features['min_llc_ssap_sap'] = min(ssap_saps) if ssap_saps else np.nan
                features['median_llc_ssap_sap'] = np.median(ssap_saps) if ssap_saps else np.nan
                features['std_llc_ssap_sap'] = np.std(ssap_saps) if len(ssap_saps) > 1 else np.nan
                features['norm_llc_ssap_sap'] = features['std_llc_ssap_sap'] / features['mean_llc_ssap_sap'] if features['mean_llc_ssap_sap'] > 0 else np.nan
                
                # DSAP SAP statistics
                features['sum_llc_dsap_sap'] = sum(dsap_saps)
                features['mean_llc_dsap_sap'] = np.mean(dsap_saps) if dsap_saps else np.nan
                features['max_llc_dsap_sap'] = max(dsap_saps) if dsap_saps else np.nan
                features['min_llc_dsap_sap'] = min(dsap_saps) if dsap_saps else np.nan
                features['median_llc_dsap_sap'] = np.median(dsap_saps) if dsap_saps else np.nan
                features['std_llc_dsap_sap'] = np.std(dsap_saps) if len(dsap_saps) > 1 else np.nan
                features['norm_llc_dsap_sap'] = features['std_llc_dsap_sap'] / features['mean_llc_dsap_sap'] if features['mean_llc_dsap_sap'] > 0 else np.nan
                
                # Command/Response bit averages
                features['mean_llc_ssap_cr'] = np.mean([1 if cr else 0 for cr in ssap_crs]) if ssap_crs else np.nan
                features['mean_llc_dsap_cr'] = np.mean([1 if cr else 0 for cr in dsap_crs]) if dsap_crs else np.nan
                
            else:
                self._set_default_llc_aggregated_features(features)
                
        except Exception:
            self._set_default_llc_aggregated_features(features)
    
    def _extract_timing_statistics(self, features: Dict[str, Any]):
        """Extract timing-related features."""
        try:
            if len(self.packets) > 1:
                # Inter-arrival times
                timestamps = [p.timestamp for p in self.packets]
                inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                features['mean_inter_arrival_time'] = np.mean(inter_arrival_times) if inter_arrival_times else np.nan
                features['std_inter_arrival_time'] = np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else np.nan
                features['max_inter_arrival_time'] = max(inter_arrival_times) if inter_arrival_times else np.nan
                features['min_inter_arrival_time'] = min(inter_arrival_times) if inter_arrival_times else np.nan
                
            else:
                features['mean_inter_arrival_time'] = np.nan
                features['std_inter_arrival_time'] = np.nan
                features['max_inter_arrival_time'] = np.nan
                features['min_inter_arrival_time'] = np.nan
                
        except Exception:
            features['mean_inter_arrival_time'] = np.nan
            features['std_inter_arrival_time'] = np.nan
            features['max_inter_arrival_time'] = np.nan
            features['min_inter_arrival_time'] = np.nan
    
    def _set_default_frame_statistics(self, features: Dict[str, Any]):
        """Set default frame statistics."""
        frame_defaults = {
            'sum_frame_len': 0,
            'mean_frame_len': np.nan,
            'max_frame_len': np.nan,
            'min_frame_len': np.nan,
            'median_frame_len': np.nan,
            'std_frame_len': np.nan,
            'norm_frame_len': np.nan,
            'sum_frame_len_div_time': np.nan,
            'num_frame_marked': 0,
            'num_frame_ignored': 0,
            'percent_frame_marked': np.nan,
            'percent_frame_ignored': np.nan,
        }
        features.update(frame_defaults)
    
    def _set_default_directional_features(self, features: Dict[str, Any], direction: str):
        """Set default directional features."""
        directional_defaults = {
            f'sum_frames_{direction}': 0,
            f'mean_frames_{direction}': np.nan,
            f'max_frames_{direction}': np.nan,
            f'min_frames_{direction}': np.nan,
            f'median_frames_{direction}': np.nan,
            f'std_frames_{direction}': np.nan,
            f'norm_frames_{direction}': np.nan,
        }
        features.update(directional_defaults)
    
    def _set_default_protocol_statistics(self, features: Dict[str, Any]):
        """Set default protocol statistics."""
        protocol_defaults = {
            'num_llc_frame': 0,
            'percent_llc_frame': np.nan,
            'num_stp_frame': 0,
            'percent_stp_frame': np.nan,
            'num_arp_frame': 0,
            'percent_arp_frame': np.nan,
            'num_dhcp_frame': 0,
            'percent_dhcp_frame': np.nan,
            'num_cdp_frame': 0,
            'percent_cdp_frame': np.nan,
        }
        features.update(protocol_defaults)
        self._set_default_stp_aggregated_features(features)
        self._set_default_cdp_aggregated_features(features)
        self._set_default_llc_aggregated_features(features)
    
    def _set_default_stp_aggregated_features(self, features: Dict[str, Any]):
        """Set default STP aggregated features."""
        stp_defaults = {
            'sum_stp_msg_age': 0,
            'mean_stp_msg_age': 0,
            'max_stp_msg_age': 0,
            'min_stp_msg_age': 0,
            'median_stp_msg_age': 0,
            'std_stp_msg_age': 0,
            'norm_stp_msg_age': 0,
            'sum_stp_forward': 0,
            'mean_stp_forward': 0,
            'max_stp_forward': 0,
            'min_stp_forward': 0,
            'median_stp_forward': 0,
            'std_stp_forward': 0,
            'count_stp_flags_tc_1': 0,
            'count_stp_flags_tcack_1': 0,
            'percent_stp_flags_tc_1': 0,
            'percent_stp_flags_tcack_1': 0,
        }
        features.update(stp_defaults)
    
    def _set_default_cdp_aggregated_features(self, features: Dict[str, Any]):
        """Set default CDP aggregated features."""
        cdp_defaults = {
            'sum_cdp_addresses_count': 0,
            'mean_cdp_addresses_count': 0,
            'max_cdp_addresses_count': 0,
            'min_cdp_addresses_count': 0,
            'median_cdp_addresses_count': 0,
            'std_cdp_addresses_count': 0,
            'norm_cdp_addresses_count': 0,
            'sum_cdp_tlvs': 0,
            'sum_cdp_capabilities': 0,
            'mean_cdp_power_sum': 0,
            'max_cdp_power_sum': 0,
            'min_cdp_power_sum': 0,
            'median_cdp_power_sum': 0,
            'std_cdp_power_sum': 0,
            'norm_cdp_power_sum': 0,
        }
        features.update(cdp_defaults)
    
    def _set_default_llc_aggregated_features(self, features: Dict[str, Any]):
        """Set default LLC aggregated features."""
        llc_defaults = {
            'mean_llc_ssap_sap': 0,
            'max_llc_ssap_sap': 0,
            'min_llc_ssap_sap': 0,
            'median_llc_ssap_sap': 0,
            'std_llc_ssap_sap': 0,
            'norm_llc_ssap_sap': 0,
            'sum_llc_dsap_sap': 0,
            'mean_llc_dsap_sap': 0,
            'max_llc_dsap_sap': 0,
            'min_llc_dsap_sap': 0,
            'median_llc_dsap_sap': 0,
            'std_llc_dsap_sap': 0,
            'norm_llc_dsap_sap': 0,
            'mean_llc_ssap_cr': 0,
            'mean_llc_dsap_cr': 0,
        }
        features.update(llc_defaults)
    
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
        
        # Statistical variance ratios
        try:
            # Collect various feature values for standard deviation calculations
            frame_lens = [packet.get_features().get('frame_len', 0) for packet in self.packets]
            stp_ages = [packet.get_features().get('stp_msg_age', 0) for packet in self.packets if packet.get_features().get('stp_msg_age', 0) > 0]
            arp_opcodes = [packet.get_features().get('arp_opcode', 0) for packet in self.packets if packet.get_features().get('arp_opcode', 0) > 0]
            
            std_frame_len = np.std(frame_lens) if frame_lens else 0
            std_stp_ages = np.std(stp_ages) if len(stp_ages) > 1 else 0
            std_arp_opcodes = np.std(arp_opcodes) if len(arp_opcodes) > 1 else 0
            
            # STD ratios
            features['std_stp_over_std_arp'] = std_stp_ages / (std_arp_opcodes + 1e-8)
            features['std_frame_len_over_std_stp'] = std_frame_len / (std_stp_ages + 1e-8)
            
        except Exception:
            features['std_stp_over_std_arp'] = 0
            features['std_frame_len_over_std_stp'] = 0
        
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
    
    def is_layer2_flow(self) -> bool:
        """Check if this is a Layer 2 flow (no IP addressing)."""
        return self.src_ip is None or self.dst_ip is None
    
    def __str__(self) -> str:
        """String representation of flow."""
        return f"Flow {self.flow_id}: {self.protocol} {len(self.packets)} packets, {self.get_duration():.2f}s"