"""
Layer 2-only flow class for --justlayertwo mode.
Focuses exclusively on Layer 2 features and MAC-based flow identification.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
from ..packets.simple_layer2_packet import SimpleLayer2Packet
from ..packets.fixed_layer2_packet import MISSING_VALUE
import logging


class Layer2OnlyFlow:
    """Flow class that extracts only Layer 2 features."""
    
    def __init__(self, flow_key: str, first_packet: SimpleLayer2Packet):
        self.flow_key = flow_key
        self.packets: List[SimpleLayer2Packet] = [first_packet]
        self.start_time = first_packet.timestamp
        self.end_time = first_packet.timestamp
        self.last_activity = first_packet.timestamp
        self.logger = logging.getLogger(__name__)
        
        # MAC-based flow identification (since we're Layer 2 only)
        self.src_mac = first_packet.features.get('src_mac', str(MISSING_VALUE))
        self.dst_mac = first_packet.features.get('dst_mac', str(MISSING_VALUE))
    
    def add_packet(self, packet: SimpleLayer2Packet):
        """Add a packet to the flow."""
        self.packets.append(packet)
        self.end_time = max(self.end_time, packet.timestamp)
        self.last_activity = packet.timestamp
    
    def get_features(self) -> Dict[str, Any]:
        """Extract Layer 2 flow features."""
        try:
            features = {}
            
            # Basic flow information
            self._extract_basic_flow_features(features)
            
            # MAC address flow features
            self._extract_mac_flow_features(features)
            
            # Layer 2 protocol statistics
            self._extract_layer2_protocol_statistics(features)
            
            # Layer 2 protocol aggregated features (CRITICAL - was missing!)
            self._extract_stp_aggregated_features(features)
            self._extract_cdp_aggregated_features(features)
            self._extract_arp_aggregated_features(features)
            self._extract_dhcp_aggregated_features(features)
            self._extract_llc_aggregated_features(features)
            self._extract_isl_aggregated_features(features)
            self._extract_dtp_aggregated_features(features)
            
            # Frame size and timing analysis
            self._extract_frame_statistics(features)
            
            # Layer 2 quality metrics
            self._extract_layer2_quality_features(features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting Layer 2 flow features: {e}")
            return self._get_default_features()
    
    def _extract_basic_flow_features(self, features: Dict[str, Any]):
        """Extract basic flow information."""
        try:
            features['flow_key'] = self.flow_key
            features['src_mac'] = self.src_mac
            features['dst_mac'] = self.dst_mac
            features['num_packets'] = len(self.packets)
            features['start_time'] = self.start_time
            features['end_time'] = self.end_time
            features['flow_duration'] = self.end_time - self.start_time if len(self.packets) > 1 else 0
            
            # Get primary protocol type
            protocol_counts = {}
            for packet in self.packets:
                proto = packet.get_protocol_type()
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            if protocol_counts:
                try:
                    max_protocol_item = max(protocol_counts.items(), key=lambda x: x[1])
                    features['primary_protocol'] = max_protocol_item[0]
                except (ValueError, IndexError, TypeError):
                    features['primary_protocol'] = 'Layer2'
            else:
                features['primary_protocol'] = 'Layer2'
                
        except Exception as e:
            self.logger.debug(f"Error extracting basic flow features: {e}")
            features.update({
                'flow_key': self.flow_key,
                'src_mac': str(MISSING_VALUE),
                'dst_mac': str(MISSING_VALUE),
                'num_packets': 0,
                'start_time': MISSING_VALUE,
                'end_time': MISSING_VALUE,
                'flow_duration': MISSING_VALUE,
                'primary_protocol': str(MISSING_VALUE)
            })
    
    def _extract_mac_flow_features(self, features: Dict[str, Any]):
        """Extract MAC address-based flow features."""
        try:
            # MAC vendor analysis
            src_vendors = [p.features.get('src_mac_vendor', 'Unknown') for p in self.packets 
                          if p.features.get('src_mac_vendor') != str(MISSING_VALUE)]
            dst_vendors = [p.features.get('dst_mac_vendor', 'Unknown') for p in self.packets
                          if p.features.get('dst_mac_vendor') != str(MISSING_VALUE)]
            
            features['src_mac_vendor'] = src_vendors[0] if src_vendors else str(MISSING_VALUE)
            features['dst_mac_vendor'] = dst_vendors[0] if dst_vendors else str(MISSING_VALUE)
            features['mac_vendor_diversity'] = len(set(src_vendors + dst_vendors)) if (src_vendors or dst_vendors) else 0
            
            # MAC characteristics
            multicast_count = sum(1 for p in self.packets if p.features.get('dst_mac_is_multicast', False))
            broadcast_count = sum(1 for p in self.packets if p.features.get('dst_mac_is_broadcast', False))
            
            features['multicast_packet_count'] = multicast_count
            features['broadcast_packet_count'] = broadcast_count
            features['unicast_packet_count'] = len(self.packets) - multicast_count - broadcast_count
            
            # MAC address patterns
            unique_src_macs = len(set(p.features.get('src_mac', '') for p in self.packets 
                                    if p.features.get('src_mac') != str(MISSING_VALUE)))
            unique_dst_macs = len(set(p.features.get('dst_mac', '') for p in self.packets
                                    if p.features.get('dst_mac') != str(MISSING_VALUE)))
            
            features['unique_src_mac_count'] = unique_src_macs
            features['unique_dst_mac_count'] = unique_dst_macs
            features['mac_address_diversity'] = unique_src_macs + unique_dst_macs
            
        except Exception as e:
            self.logger.debug(f"Error extracting MAC flow features: {e}")
            features.update({
                'src_mac_vendor': str(MISSING_VALUE),
                'dst_mac_vendor': str(MISSING_VALUE),
                'mac_vendor_diversity': MISSING_VALUE,
                'multicast_packet_count': MISSING_VALUE,
                'broadcast_packet_count': MISSING_VALUE,
                'unicast_packet_count': MISSING_VALUE,
                'unique_src_mac_count': MISSING_VALUE,
                'unique_dst_mac_count': MISSING_VALUE,
                'mac_address_diversity': MISSING_VALUE
            })
    
    def _extract_layer2_protocol_statistics(self, features: Dict[str, Any]):
        """Extract Layer 2 protocol statistics."""
        try:
            # Protocol counters
            protocol_counts = {
                'arp_count': sum(1 for p in self.packets if p.features.get('is_arp', False)),
                'stp_count': sum(1 for p in self.packets if p.features.get('is_stp', False)),
                'cdp_count': sum(1 for p in self.packets if p.features.get('is_cdp', False)),
                'dhcp_count': sum(1 for p in self.packets if p.features.get('is_dhcp', False)),
                'llc_count': sum(1 for p in self.packets if p.features.get('is_llc', False)),
                'isl_count': sum(1 for p in self.packets if p.features.get('is_isl', False)),
                'lldp_count': sum(1 for p in self.packets if p.features.get('is_lldp', False)),
                'dtp_count': sum(1 for p in self.packets if p.features.get('is_dtp', False))
            }
            
            features.update(protocol_counts)
            
            # Protocol percentages
            total_packets = len(self.packets)
            if total_packets > 0:
                for protocol, count in protocol_counts.items():
                    percentage_key = protocol.replace('_count', '_percentage')
                    features[percentage_key] = (count / total_packets) * 100
            else:
                for protocol in protocol_counts.keys():
                    percentage_key = protocol.replace('_count', '_percentage')
                    features[percentage_key] = MISSING_VALUE
            
            # Protocol diversity metrics
            active_protocols = sum(1 for count in protocol_counts.values() if count > 0)
            features['active_protocol_count'] = active_protocols
            features['protocol_diversity_ratio'] = active_protocols / 8 if active_protocols > 0 else 0  # Updated to 8 protocols
            
            # Dominant protocol analysis
            if protocol_counts:
                try:
                    dominant_protocol = max(protocol_counts.items(), key=lambda x: x[1])
                    features['dominant_l2_protocol'] = dominant_protocol[0].replace('_count', '')
                    features['dominant_protocol_percentage'] = (dominant_protocol[1] / total_packets) * 100 if total_packets > 0 else 0
                except (ValueError, IndexError, TypeError):
                    features['dominant_l2_protocol'] = str(MISSING_VALUE)
                    features['dominant_protocol_percentage'] = MISSING_VALUE
            else:
                features['dominant_l2_protocol'] = str(MISSING_VALUE)
                features['dominant_protocol_percentage'] = MISSING_VALUE
            
        except Exception as e:
            self.logger.debug(f"Error extracting Layer 2 protocol statistics: {e}")
            self._set_default_protocol_features(features)
    
    def _extract_frame_statistics(self, features: Dict[str, Any]):
        """Extract frame size and timing statistics."""
        try:
            if not self.packets:
                self._set_default_frame_features(features)
                return
            
            # Frame size statistics
            frame_sizes = [p.features.get('frame_len', 0) for p in self.packets if p.features.get('frame_len', 0) > 0]
            
            if frame_sizes:
                features['total_bytes'] = sum(frame_sizes)
                features['mean_frame_size'] = np.mean(frame_sizes)
                features['min_frame_size'] = min(frame_sizes)
                features['max_frame_size'] = max(frame_sizes)
                features['std_frame_size'] = np.std(frame_sizes) if len(frame_sizes) > 1 else 0
                features['median_frame_size'] = np.median(frame_sizes)
            else:
                features.update({
                    'total_bytes': MISSING_VALUE,
                    'mean_frame_size': MISSING_VALUE,
                    'min_frame_size': MISSING_VALUE,
                    'max_frame_size': MISSING_VALUE,
                    'std_frame_size': MISSING_VALUE,
                    'median_frame_size': MISSING_VALUE
                })
            
            # Frame size categories
            jumbo_count = sum(1 for p in self.packets if p.features.get('is_jumbo_frame', False))
            small_count = sum(1 for p in self.packets if p.features.get('is_small_frame', False))
            
            features['jumbo_frame_count'] = jumbo_count
            features['small_frame_count'] = small_count
            features['normal_frame_count'] = len(self.packets) - jumbo_count - small_count
            
            # Timing statistics
            if len(self.packets) > 1:
                timestamps = [p.timestamp for p in self.packets]
                inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                if inter_arrival_times:
                    features['mean_inter_arrival_time'] = np.mean(inter_arrival_times)
                    features['std_inter_arrival_time'] = np.std(inter_arrival_times)
                    features['min_inter_arrival_time'] = min(inter_arrival_times)
                    features['max_inter_arrival_time'] = max(inter_arrival_times)
                else:
                    features.update({
                        'mean_inter_arrival_time': MISSING_VALUE,
                        'std_inter_arrival_time': MISSING_VALUE,
                        'min_inter_arrival_time': MISSING_VALUE,
                        'max_inter_arrival_time': MISSING_VALUE
                    })
            else:
                features.update({
                    'mean_inter_arrival_time': MISSING_VALUE,
                    'std_inter_arrival_time': MISSING_VALUE,
                    'min_inter_arrival_time': MISSING_VALUE,
                    'max_inter_arrival_time': MISSING_VALUE
                })
            
        except Exception as e:
            self.logger.debug(f"Error extracting frame statistics: {e}")
            self._set_default_frame_features(features)
    
    def _extract_layer2_quality_features(self, features: Dict[str, Any]):
        """Extract Layer 2-specific quality and analysis features."""
        try:
            # VLAN analysis
            vlan_packets = [p for p in self.packets if p.features.get('has_vlan', False)]
            if vlan_packets:
                vlan_ids = [p.features.get('vlan_id') for p in vlan_packets 
                           if p.features.get('vlan_id', MISSING_VALUE) != MISSING_VALUE]
                features['vlan_packet_count'] = len(vlan_packets)
                features['unique_vlan_count'] = len(set(vlan_ids)) if vlan_ids else 0
                features['has_vlan_traffic'] = True
            else:
                features['vlan_packet_count'] = 0
                features['unique_vlan_count'] = 0
                features['has_vlan_traffic'] = False
            
            # Protocol co-occurrence analysis
            protocol_pairs = []
            for packet in self.packets:
                active_protocols = []
                if packet.features.get('is_arp', False): active_protocols.append('ARP')
                if packet.features.get('is_stp', False): active_protocols.append('STP')
                if packet.features.get('is_cdp', False): active_protocols.append('CDP')
                if packet.features.get('is_dhcp', False): active_protocols.append('DHCP')
                
                if len(active_protocols) > 1:
                    protocol_pairs.extend(active_protocols)
            
            features['multi_protocol_packets'] = len(set(protocol_pairs)) // 2 if protocol_pairs else 0
            
            # Network behavior indicators
            features['is_layer2_only_flow'] = True  # Always true for this flow type
            features['has_broadcast_activity'] = features.get('broadcast_packet_count', 0) > 0
            features['has_multicast_activity'] = features.get('multicast_packet_count', 0) > 0
            
            # Attack indicators (Layer 2 specific)
            features['suspicious_mac_changes'] = features.get('unique_src_mac_count', 0) > 1
            features['excessive_broadcast_ratio'] = (features.get('broadcast_packet_count', 0) / len(self.packets)) > 0.5 if self.packets else False
            
        except Exception as e:
            self.logger.debug(f"Error extracting Layer 2 quality features: {e}")
            self._set_default_quality_features(features)
    
    def _set_default_protocol_features(self, features: Dict[str, Any]):
        """Set default protocol features."""
        protocol_defaults = {
            'arp_count': MISSING_VALUE, 'arp_percentage': MISSING_VALUE,
            'stp_count': MISSING_VALUE, 'stp_percentage': MISSING_VALUE,
            'cdp_count': MISSING_VALUE, 'cdp_percentage': MISSING_VALUE,
            'dhcp_count': MISSING_VALUE, 'dhcp_percentage': MISSING_VALUE,
            'llc_count': MISSING_VALUE, 'llc_percentage': MISSING_VALUE,
            'isl_count': MISSING_VALUE, 'isl_percentage': MISSING_VALUE,
            'lldp_count': MISSING_VALUE, 'lldp_percentage': MISSING_VALUE,
            'dtp_count': MISSING_VALUE, 'dtp_percentage': MISSING_VALUE,
            'active_protocol_count': MISSING_VALUE,
            'protocol_diversity_ratio': MISSING_VALUE,
            'dominant_l2_protocol': str(MISSING_VALUE),
            'dominant_protocol_percentage': MISSING_VALUE
        }
        features.update(protocol_defaults)
    
    def _set_default_frame_features(self, features: Dict[str, Any]):
        """Set default frame features."""
        frame_defaults = {
            'total_bytes': MISSING_VALUE,
            'mean_frame_size': MISSING_VALUE,
            'min_frame_size': MISSING_VALUE,
            'max_frame_size': MISSING_VALUE,
            'std_frame_size': MISSING_VALUE,
            'median_frame_size': MISSING_VALUE,
            'jumbo_frame_count': MISSING_VALUE,
            'small_frame_count': MISSING_VALUE,
            'normal_frame_count': MISSING_VALUE,
            'mean_inter_arrival_time': MISSING_VALUE,
            'std_inter_arrival_time': MISSING_VALUE,
            'min_inter_arrival_time': MISSING_VALUE,
            'max_inter_arrival_time': MISSING_VALUE
        }
        features.update(frame_defaults)
    
    # CRITICAL LAYER 2 AGGREGATED FEATURES - These were completely missing!
    def _extract_stp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated STP features."""
        try:
            stp_packets = [p for p in self.packets if p.features.get('is_stp', False)]
            
            if stp_packets:
                msg_ages = [p.features.get('stp_msg_age', 0) for p in stp_packets if p.features.get('stp_msg_age', MISSING_VALUE) != MISSING_VALUE]
                forward_delays = [p.features.get('stp_forward_delay', 0) for p in stp_packets if p.features.get('stp_forward_delay', MISSING_VALUE) != MISSING_VALUE]
                tc_flags = [p.features.get('stp_flags_tc', False) for p in stp_packets if p.features.get('stp_flags_tc', MISSING_VALUE) != MISSING_VALUE]
                tcack_flags = [p.features.get('stp_flags_tcack', False) for p in stp_packets if p.features.get('stp_flags_tcack', MISSING_VALUE) != MISSING_VALUE]
                
                features['stp_sum_msg_age'] = sum(msg_ages)
                features['stp_mean_msg_age'] = np.mean(msg_ages) if msg_ages else MISSING_VALUE
                features['stp_max_msg_age'] = max(msg_ages) if msg_ages else MISSING_VALUE
                features['stp_min_msg_age'] = min(msg_ages) if msg_ages else MISSING_VALUE
                features['stp_median_msg_age'] = np.median(msg_ages) if msg_ages else MISSING_VALUE
                features['stp_std_msg_age'] = np.std(msg_ages) if len(msg_ages) > 1 else MISSING_VALUE
                features['stp_norm_msg_age'] = features['stp_std_msg_age'] / features['stp_mean_msg_age'] if features['stp_mean_msg_age'] > 0 else MISSING_VALUE
                
                features['stp_sum_forward'] = sum(forward_delays)
                features['stp_mean_forward'] = np.mean(forward_delays) if forward_delays else MISSING_VALUE
                features['stp_max_forward'] = max(forward_delays) if forward_delays else MISSING_VALUE
                features['stp_min_forward'] = min(forward_delays) if forward_delays else MISSING_VALUE
                features['stp_median_forward'] = np.median(forward_delays) if forward_delays else MISSING_VALUE
                features['stp_std_forward'] = np.std(forward_delays) if len(forward_delays) > 1 else MISSING_VALUE
                
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
            cdp_packets = [p for p in self.packets if p.features.get('is_cdp', False)]
            
            if cdp_packets:
                addresses_counts = [p.features.get('cdp_addresses_count', 0) for p in cdp_packets if p.features.get('cdp_addresses_count', MISSING_VALUE) != MISSING_VALUE]
                tlv_counts = [p.features.get('cdp_tlvs', 0) for p in cdp_packets if p.features.get('cdp_tlvs', MISSING_VALUE) > 0]
                capabilities = [p.features.get('cdp_capabilities', 0) for p in cdp_packets if p.features.get('cdp_capabilities', MISSING_VALUE) != MISSING_VALUE]
                power_sums = [p.features.get('cdp_power_sum', 0) for p in cdp_packets if p.features.get('cdp_power_sum', MISSING_VALUE) != MISSING_VALUE]
                
                features['cdp_sum_addresses_count'] = sum(addresses_counts)
                features['cdp_mean_addresses_count'] = np.mean(addresses_counts) if addresses_counts else MISSING_VALUE
                features['cdp_max_addresses_count'] = max(addresses_counts) if addresses_counts else MISSING_VALUE
                features['cdp_min_addresses_count'] = min(addresses_counts) if addresses_counts else MISSING_VALUE
                features['cdp_median_addresses_count'] = np.median(addresses_counts) if addresses_counts else MISSING_VALUE
                features['cdp_std_addresses_count'] = np.std(addresses_counts) if len(addresses_counts) > 1 else MISSING_VALUE
                features['cdp_norm_addresses_count'] = features['cdp_std_addresses_count'] / features['cdp_mean_addresses_count'] if features['cdp_mean_addresses_count'] > 0 else MISSING_VALUE
                
                features['cdp_sum_tlvs'] = sum(tlv_counts)
                features['cdp_sum_capabilities'] = sum(capabilities)
                
                features['cdp_mean_power_sum'] = np.mean(power_sums) if power_sums else MISSING_VALUE
                features['cdp_max_power_sum'] = max(power_sums) if power_sums else MISSING_VALUE
                features['cdp_min_power_sum'] = min(power_sums) if power_sums else MISSING_VALUE
                features['cdp_median_power_sum'] = np.median(power_sums) if power_sums else MISSING_VALUE
                features['cdp_std_power_sum'] = np.std(power_sums) if len(power_sums) > 1 else MISSING_VALUE
                features['cdp_norm_power_sum'] = features['cdp_std_power_sum'] / features['cdp_mean_power_sum'] if features['cdp_mean_power_sum'] > 0 else MISSING_VALUE
                
            else:
                self._set_default_cdp_aggregated_features(features)
        except Exception:
            self._set_default_cdp_aggregated_features(features)
    
    def _extract_arp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated ARP features."""
        try:
            arp_packets = [p for p in self.packets if p.features.get('is_arp', False)]
            
            if arp_packets:
                hw_types = [p.features.get('arp_hw_type', 0) for p in arp_packets if p.features.get('arp_hw_type', MISSING_VALUE) != MISSING_VALUE]
                proto_types = [p.features.get('arp_proto_type', 0) for p in arp_packets if p.features.get('arp_proto_type', MISSING_VALUE) != MISSING_VALUE]
                opcodes = [p.features.get('arp_opcode', 0) for p in arp_packets if p.features.get('arp_opcode', MISSING_VALUE) != MISSING_VALUE]
                packet_sizes = [p.features.get('frame_len', 0) for p in arp_packets if p.features.get('frame_len', 0) > 0]
                
                features['arp_sum_hw_type'] = sum(hw_types) if hw_types else MISSING_VALUE
                features['arp_mean_hw_type'] = float(np.mean(hw_types)) if hw_types else MISSING_VALUE
                features['arp_max_hw_type'] = max(hw_types) if hw_types else MISSING_VALUE
                features['arp_min_hw_type'] = min(hw_types) if hw_types else MISSING_VALUE
                
                features['arp_sum_proto_type'] = sum(proto_types) if proto_types else MISSING_VALUE
                features['arp_mean_proto_type'] = float(np.mean(proto_types)) if proto_types else MISSING_VALUE
                
                features['arp_sum_opcode'] = sum(opcodes) if opcodes else MISSING_VALUE
                features['arp_mean_opcode'] = float(np.mean(opcodes)) if opcodes else MISSING_VALUE
                features['arp_max_opcode'] = max(opcodes) if opcodes else MISSING_VALUE
                features['arp_min_opcode'] = min(opcodes) if opcodes else MISSING_VALUE
                
                features['arp_sum_size'] = sum(packet_sizes) if packet_sizes else MISSING_VALUE
                features['arp_mean_size'] = float(np.mean(packet_sizes)) if packet_sizes else MISSING_VALUE
                features['arp_max_size'] = max(packet_sizes) if packet_sizes else MISSING_VALUE
                features['arp_min_size'] = min(packet_sizes) if packet_sizes else MISSING_VALUE
                
                # Protocol-specific counts
                request_count = sum(1 for p in arp_packets if p.features.get('arp_is_request') is True)
                reply_count = sum(1 for p in arp_packets if p.features.get('arp_is_reply') is True)
                gratuitous_count = sum(1 for p in arp_packets if p.features.get('arp_is_gratuitous') is True)
                
                features['arp_request_count'] = request_count
                features['arp_reply_count'] = reply_count
                features['arp_gratuitous_count'] = gratuitous_count
                features['arp_request_ratio'] = (request_count / len(arp_packets)) * 100 if arp_packets else MISSING_VALUE
                features['arp_reply_ratio'] = (reply_count / len(arp_packets)) * 100 if arp_packets else MISSING_VALUE
                
            else:
                self._set_default_arp_aggregated_features(features)
        except Exception:
            self._set_default_arp_aggregated_features(features)
    
    def _extract_dhcp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated DHCP features."""
        try:
            dhcp_packets = [p for p in self.packets if p.features.get('is_dhcp', False)]
            
            if dhcp_packets:
                opcodes = [p.features.get('dhcp_op', 0) for p in dhcp_packets if p.features.get('dhcp_op', MISSING_VALUE) != MISSING_VALUE]
                transaction_ids = [p.features.get('dhcp_xid', 0) for p in dhcp_packets if p.features.get('dhcp_xid', MISSING_VALUE) != MISSING_VALUE]
                lease_times = []  # Not commonly available in packet headers
                options_counts = [p.features.get('dhcp_options', 0) for p in dhcp_packets if p.features.get('dhcp_options', MISSING_VALUE) != MISSING_VALUE]
                
                features['dhcp_sum_opcode'] = sum(opcodes) if opcodes else MISSING_VALUE
                features['dhcp_mean_opcode'] = float(np.mean(opcodes)) if opcodes else MISSING_VALUE
                
                features['dhcp_sum_transaction_id'] = sum(transaction_ids) if transaction_ids else MISSING_VALUE
                features['dhcp_mean_transaction_id'] = float(np.mean(transaction_ids)) if transaction_ids else MISSING_VALUE
                features['dhcp_max_transaction_id'] = max(transaction_ids) if transaction_ids else MISSING_VALUE
                features['dhcp_min_transaction_id'] = min(transaction_ids) if transaction_ids else MISSING_VALUE
                
                features['dhcp_sum_lease_time'] = sum(lease_times) if lease_times else MISSING_VALUE
                features['dhcp_mean_lease_time'] = float(np.mean(lease_times)) if lease_times else MISSING_VALUE
                features['dhcp_max_lease_time'] = max(lease_times) if lease_times else MISSING_VALUE
                features['dhcp_min_lease_time'] = min(lease_times) if lease_times else MISSING_VALUE
                
                features['dhcp_sum_message_type'] = MISSING_VALUE  # Not extracted by fixed parser
                features['dhcp_mean_message_type'] = MISSING_VALUE  # Not extracted by fixed parser
                
                features['dhcp_sum_options_count'] = sum(options_counts) if options_counts else MISSING_VALUE
                features['dhcp_mean_options_count'] = float(np.mean(options_counts)) if options_counts else MISSING_VALUE
                features['dhcp_max_options_count'] = max(options_counts) if options_counts else MISSING_VALUE
                features['dhcp_min_options_count'] = min(options_counts) if options_counts else MISSING_VALUE
                
            else:
                self._set_default_dhcp_aggregated_features(features)
        except Exception:
            self._set_default_dhcp_aggregated_features(features)
    
    def _extract_llc_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated LLC features."""
        try:
            llc_packets = [p for p in self.packets if p.features.get('is_llc', False)]
            
            if llc_packets:
                ssap_saps = [p.features.get('llc_ssap', 0) for p in llc_packets if p.features.get('llc_ssap', MISSING_VALUE) != MISSING_VALUE]
                dsap_saps = [p.features.get('llc_dsap', 0) for p in llc_packets if p.features.get('llc_dsap', MISSING_VALUE) != MISSING_VALUE]
                ctrl_vals = [p.features.get('llc_ctrl', 0) for p in llc_packets if p.features.get('llc_ctrl', MISSING_VALUE) != MISSING_VALUE]
                
                # SSAP statistics
                features['llc_mean_ssap_sap'] = np.mean(ssap_saps) if ssap_saps else MISSING_VALUE
                features['llc_max_ssap_sap'] = max(ssap_saps) if ssap_saps else MISSING_VALUE
                features['llc_min_ssap_sap'] = min(ssap_saps) if ssap_saps else MISSING_VALUE
                features['llc_median_ssap_sap'] = np.median(ssap_saps) if ssap_saps else MISSING_VALUE
                features['llc_std_ssap_sap'] = np.std(ssap_saps) if len(ssap_saps) > 1 else MISSING_VALUE
                features['llc_norm_ssap_sap'] = features['llc_std_ssap_sap'] / features['llc_mean_ssap_sap'] if features['llc_mean_ssap_sap'] > 0 else MISSING_VALUE
                
                # DSAP statistics
                features['llc_sum_dsap_sap'] = sum(dsap_saps)
                features['llc_mean_dsap_sap'] = np.mean(dsap_saps) if dsap_saps else MISSING_VALUE
                features['llc_max_dsap_sap'] = max(dsap_saps) if dsap_saps else MISSING_VALUE
                features['llc_min_dsap_sap'] = min(dsap_saps) if dsap_saps else MISSING_VALUE
                features['llc_median_dsap_sap'] = np.median(dsap_saps) if dsap_saps else MISSING_VALUE
                features['llc_std_dsap_sap'] = np.std(dsap_saps) if len(dsap_saps) > 1 else MISSING_VALUE
                features['llc_norm_dsap_sap'] = features['llc_std_dsap_sap'] / features['llc_mean_dsap_sap'] if features['llc_mean_dsap_sap'] > 0 else MISSING_VALUE
                
                # Control field statistics
                features['llc_mean_ctrl'] = np.mean(ctrl_vals) if ctrl_vals else MISSING_VALUE
                features['llc_max_ctrl'] = max(ctrl_vals) if ctrl_vals else MISSING_VALUE
                
            else:
                self._set_default_llc_aggregated_features(features)
        except Exception:
            self._set_default_llc_aggregated_features(features)
    
    def _extract_isl_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated ISL features."""
        try:
            isl_packets = [p for p in self.packets if p.features.get('is_isl', False)]
            
            if isl_packets:
                frame_types = [p.features.get('isl_frame_type', 0) for p in isl_packets if p.features.get('isl_frame_type', MISSING_VALUE) != MISSING_VALUE]
                user_bits = [p.features.get('isl_user_bits', 0) for p in isl_packets if p.features.get('isl_user_bits', MISSING_VALUE) != MISSING_VALUE]
                vlan_ids = [p.features.get('isl_src_vlan_id', 0) for p in isl_packets if p.features.get('isl_src_vlan_id', MISSING_VALUE) != MISSING_VALUE]
                bpdu_flags = [p.features.get('isl_bpdu', False) for p in isl_packets if p.features.get('isl_bpdu', MISSING_VALUE) != MISSING_VALUE]
                indexes = [p.features.get('isl_index', 0) for p in isl_packets if p.features.get('isl_index', MISSING_VALUE) != MISSING_VALUE]
                
                features['isl_sum_frame_type'] = sum(frame_types)
                features['isl_mean_frame_type'] = np.mean(frame_types) if frame_types else MISSING_VALUE
                features['isl_max_frame_type'] = max(frame_types) if frame_types else MISSING_VALUE
                features['isl_min_frame_type'] = min(frame_types) if frame_types else MISSING_VALUE
                
                features['isl_sum_user_bits'] = sum(user_bits)
                features['isl_mean_user_bits'] = np.mean(user_bits) if user_bits else MISSING_VALUE
                
                features['isl_sum_vlan_id'] = sum(vlan_ids)
                features['isl_mean_vlan_id'] = np.mean(vlan_ids) if vlan_ids else MISSING_VALUE
                features['isl_max_vlan_id'] = max(vlan_ids) if vlan_ids else MISSING_VALUE
                features['isl_min_vlan_id'] = min(vlan_ids) if vlan_ids else MISSING_VALUE
                features['isl_std_vlan_id'] = np.std(vlan_ids) if len(vlan_ids) > 1 else MISSING_VALUE
                
                bpdu_count = sum(1 for flag in bpdu_flags if flag is True)
                features['isl_bpdu_count'] = bpdu_count
                features['isl_bpdu_ratio'] = (bpdu_count / len(isl_packets)) * 100 if isl_packets else MISSING_VALUE
                
                features['isl_sum_index'] = sum(indexes)
                features['isl_mean_index'] = np.mean(indexes) if indexes else MISSING_VALUE
                
                features['isl_unique_vlans'] = len(set(vlan_ids)) if vlan_ids else 0
                features['isl_unique_frame_types'] = len(set(frame_types)) if frame_types else 0
                
            else:
                self._set_default_isl_aggregated_features(features)
        except Exception:
            self._set_default_isl_aggregated_features(features)
    
    def _extract_dtp_aggregated_features(self, features: Dict[str, Any]):
        """Extract aggregated DTP features."""
        try:
            dtp_packets = [p for p in self.packets if p.features.get('dtp_tlv_count', 0) > 0]
            
            if dtp_packets:
                versions = [p.features.get('dtp_version', 0) for p in dtp_packets if p.features.get('dtp_version', MISSING_VALUE) != MISSING_VALUE]
                tlv_counts = [p.features.get('dtp_tlv_count', 0) for p in dtp_packets if p.features.get('dtp_tlv_count', MISSING_VALUE) != MISSING_VALUE]
                domain_lengths = [p.features.get('dtp_domain_length', 0) for p in dtp_packets if p.features.get('dtp_domain_length', MISSING_VALUE) != MISSING_VALUE]
                
                features['dtp_sum_version'] = sum(versions) if versions else MISSING_VALUE
                features['dtp_mean_version'] = float(np.mean(versions)) if versions else MISSING_VALUE
                
                features['dtp_sum_tlv_count'] = sum(tlv_counts) if tlv_counts else MISSING_VALUE
                features['dtp_mean_tlv_count'] = float(np.mean(tlv_counts)) if tlv_counts else MISSING_VALUE
                features['dtp_max_tlv_count'] = max(tlv_counts) if tlv_counts else MISSING_VALUE
                features['dtp_min_tlv_count'] = min(tlv_counts) if tlv_counts else MISSING_VALUE
                
                features['dtp_sum_domain_length'] = sum(domain_lengths) if domain_lengths else MISSING_VALUE
                features['dtp_mean_domain_length'] = float(np.mean(domain_lengths)) if domain_lengths else MISSING_VALUE
                
                isl_count = sum(1 for p in dtp_packets if p.features.get('dtp_frame_isl') is True)
                dot1q_count = sum(1 for p in dtp_packets if p.features.get('dtp_frame_802dot1q') is True)
                
                features['dtp_frame_isl_count'] = isl_count
                features['dtp_frame_802dot1q_count'] = dot1q_count
                features['dtp_frame_isl_ratio'] = (isl_count / len(dtp_packets)) * 100 if dtp_packets else MISSING_VALUE
                
            else:
                self._set_default_dtp_aggregated_features(features)
        except Exception:
            self._set_default_dtp_aggregated_features(features)
    
    # Default setters for all aggregated features
    def _set_default_stp_aggregated_features(self, features: Dict[str, Any]):
        """Set default STP aggregated features."""
        stp_defaults = {
            'stp_sum_msg_age': MISSING_VALUE, 'stp_mean_msg_age': MISSING_VALUE, 'stp_max_msg_age': MISSING_VALUE,
            'stp_min_msg_age': MISSING_VALUE, 'stp_median_msg_age': MISSING_VALUE, 'stp_std_msg_age': MISSING_VALUE,
            'stp_norm_msg_age': MISSING_VALUE, 'stp_sum_forward': MISSING_VALUE, 'stp_mean_forward': MISSING_VALUE,
            'stp_max_forward': MISSING_VALUE, 'stp_min_forward': MISSING_VALUE, 'stp_median_forward': MISSING_VALUE,
            'stp_std_forward': MISSING_VALUE, 'stp_count_flags_tc_1': MISSING_VALUE, 'stp_count_flags_tcack_1': MISSING_VALUE,
            'stp_percent_flags_tc_1': MISSING_VALUE, 'stp_percent_flags_tcack_1': MISSING_VALUE
        }
        features.update(stp_defaults)
    
    def _set_default_cdp_aggregated_features(self, features: Dict[str, Any]):
        """Set default CDP aggregated features."""
        cdp_defaults = {
            'cdp_sum_addresses_count': MISSING_VALUE, 'cdp_mean_addresses_count': MISSING_VALUE,
            'cdp_max_addresses_count': MISSING_VALUE, 'cdp_min_addresses_count': MISSING_VALUE,
            'cdp_median_addresses_count': MISSING_VALUE, 'cdp_std_addresses_count': MISSING_VALUE,
            'cdp_norm_addresses_count': MISSING_VALUE, 'cdp_sum_tlvs': MISSING_VALUE, 'cdp_sum_capabilities': MISSING_VALUE,
            'cdp_mean_power_sum': MISSING_VALUE, 'cdp_max_power_sum': MISSING_VALUE, 'cdp_min_power_sum': MISSING_VALUE,
            'cdp_median_power_sum': MISSING_VALUE, 'cdp_std_power_sum': MISSING_VALUE, 'cdp_norm_power_sum': MISSING_VALUE
        }
        features.update(cdp_defaults)
    
    def _set_default_arp_aggregated_features(self, features: Dict[str, Any]):
        """Set default ARP aggregated features."""
        arp_defaults = {
            'arp_sum_hw_type': MISSING_VALUE, 'arp_mean_hw_type': MISSING_VALUE, 'arp_max_hw_type': MISSING_VALUE,
            'arp_min_hw_type': MISSING_VALUE, 'arp_sum_proto_type': MISSING_VALUE, 'arp_mean_proto_type': MISSING_VALUE,
            'arp_sum_opcode': MISSING_VALUE, 'arp_mean_opcode': MISSING_VALUE, 'arp_max_opcode': MISSING_VALUE,
            'arp_min_opcode': MISSING_VALUE, 'arp_sum_size': MISSING_VALUE, 'arp_mean_size': MISSING_VALUE,
            'arp_max_size': MISSING_VALUE, 'arp_min_size': MISSING_VALUE, 'arp_request_count': MISSING_VALUE,
            'arp_reply_count': MISSING_VALUE, 'arp_gratuitous_count': MISSING_VALUE, 'arp_request_ratio': MISSING_VALUE,
            'arp_reply_ratio': MISSING_VALUE
        }
        features.update(arp_defaults)
    
    def _set_default_dhcp_aggregated_features(self, features: Dict[str, Any]):
        """Set default DHCP aggregated features."""
        dhcp_defaults = {
            'dhcp_sum_opcode': MISSING_VALUE, 'dhcp_mean_opcode': MISSING_VALUE, 'dhcp_sum_transaction_id': MISSING_VALUE,
            'dhcp_mean_transaction_id': MISSING_VALUE, 'dhcp_max_transaction_id': MISSING_VALUE, 'dhcp_min_transaction_id': MISSING_VALUE,
            'dhcp_sum_lease_time': MISSING_VALUE, 'dhcp_mean_lease_time': MISSING_VALUE, 'dhcp_max_lease_time': MISSING_VALUE,
            'dhcp_min_lease_time': MISSING_VALUE, 'dhcp_sum_message_type': MISSING_VALUE, 'dhcp_mean_message_type': MISSING_VALUE,
            'dhcp_sum_options_count': MISSING_VALUE, 'dhcp_mean_options_count': MISSING_VALUE, 'dhcp_max_options_count': MISSING_VALUE,
            'dhcp_min_options_count': MISSING_VALUE
        }
        features.update(dhcp_defaults)
    
    def _set_default_llc_aggregated_features(self, features: Dict[str, Any]):
        """Set default LLC aggregated features."""
        llc_defaults = {
            'llc_mean_ssap_sap': MISSING_VALUE, 'llc_max_ssap_sap': MISSING_VALUE, 'llc_min_ssap_sap': MISSING_VALUE,
            'llc_median_ssap_sap': MISSING_VALUE, 'llc_std_ssap_sap': MISSING_VALUE, 'llc_norm_ssap_sap': MISSING_VALUE,
            'llc_sum_dsap_sap': MISSING_VALUE, 'llc_mean_dsap_sap': MISSING_VALUE, 'llc_max_dsap_sap': MISSING_VALUE,
            'llc_min_dsap_sap': MISSING_VALUE, 'llc_median_dsap_sap': MISSING_VALUE, 'llc_std_dsap_sap': MISSING_VALUE,
            'llc_norm_dsap_sap': MISSING_VALUE, 'llc_mean_ctrl': MISSING_VALUE, 'llc_max_ctrl': MISSING_VALUE
        }
        features.update(llc_defaults)
    
    def _set_default_isl_aggregated_features(self, features: Dict[str, Any]):
        """Set default ISL aggregated features."""
        isl_defaults = {
            'isl_sum_frame_type': MISSING_VALUE, 'isl_mean_frame_type': MISSING_VALUE, 'isl_max_frame_type': MISSING_VALUE,
            'isl_min_frame_type': MISSING_VALUE, 'isl_sum_user_bits': MISSING_VALUE, 'isl_mean_user_bits': MISSING_VALUE,
            'isl_sum_vlan_id': MISSING_VALUE, 'isl_mean_vlan_id': MISSING_VALUE, 'isl_max_vlan_id': MISSING_VALUE,
            'isl_min_vlan_id': MISSING_VALUE, 'isl_std_vlan_id': MISSING_VALUE, 'isl_bpdu_count': MISSING_VALUE,
            'isl_bpdu_ratio': MISSING_VALUE, 'isl_sum_index': MISSING_VALUE, 'isl_mean_index': MISSING_VALUE,
            'isl_unique_vlans': MISSING_VALUE, 'isl_unique_frame_types': MISSING_VALUE
        }
        features.update(isl_defaults)
    
    def _set_default_dtp_aggregated_features(self, features: Dict[str, Any]):
        """Set default DTP aggregated features."""
        dtp_defaults = {
            'dtp_sum_version': MISSING_VALUE, 'dtp_mean_version': MISSING_VALUE, 'dtp_sum_tlv_count': MISSING_VALUE,
            'dtp_mean_tlv_count': MISSING_VALUE, 'dtp_max_tlv_count': MISSING_VALUE, 'dtp_min_tlv_count': MISSING_VALUE,
            'dtp_sum_domain_length': MISSING_VALUE, 'dtp_mean_domain_length': MISSING_VALUE, 'dtp_frame_isl_count': MISSING_VALUE,
            'dtp_frame_802dot1q_count': MISSING_VALUE, 'dtp_frame_isl_ratio': MISSING_VALUE
        }
        features.update(dtp_defaults)
    
    def _set_default_quality_features(self, features: Dict[str, Any]):
        """Set default quality features."""
        quality_defaults = {
            'vlan_packet_count': MISSING_VALUE,
            'unique_vlan_count': MISSING_VALUE,
            'has_vlan_traffic': MISSING_VALUE,
            'multi_protocol_packets': MISSING_VALUE,
            'is_layer2_only_flow': True,
            'has_broadcast_activity': MISSING_VALUE,
            'has_multicast_activity': MISSING_VALUE,
            'suspicious_mac_changes': MISSING_VALUE,
            'excessive_broadcast_ratio': MISSING_VALUE
        }
        features.update(quality_defaults)
    
    def _get_default_features(self) -> Dict[str, Any]:
        """Return default features when extraction fails."""
        defaults = {
            'flow_key': self.flow_key,
            'src_mac': str(MISSING_VALUE),
            'dst_mac': str(MISSING_VALUE),
            'num_packets': MISSING_VALUE,
            'start_time': MISSING_VALUE,
            'end_time': MISSING_VALUE,
            'flow_duration': MISSING_VALUE,
            'primary_protocol': str(MISSING_VALUE),
            'is_layer2_only_flow': True
        }
        
        self._set_default_protocol_features(defaults)
        self._set_default_frame_features(defaults)
        self._set_default_quality_features(defaults)
        
        # Set all aggregated feature defaults
        self._set_default_stp_aggregated_features(defaults)
        self._set_default_cdp_aggregated_features(defaults)
        self._set_default_arp_aggregated_features(defaults)
        self._set_default_dhcp_aggregated_features(defaults)
        self._set_default_llc_aggregated_features(defaults)
        self._set_default_isl_aggregated_features(defaults)
        self._set_default_dtp_aggregated_features(defaults)
        
        return defaults
    
    def should_timeout(self, current_time: float, timeout: float) -> bool:
        """Check if flow should timeout."""
        return (current_time - self.last_activity) > timeout
    
    def clear_packets(self):
        """Clear packet data to free memory."""
        self.packets.clear()
    
    def __str__(self) -> str:
        return f"Layer2Flow({self.flow_key}, packets={len(self.packets)}, duration={self.end_time - self.start_time:.2f}s)"