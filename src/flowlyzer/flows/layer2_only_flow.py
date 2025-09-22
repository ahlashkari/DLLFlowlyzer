"""
Layer 2-only flow class for --justlayertwo mode.
Focuses exclusively on Layer 2 features and MAC-based flow identification.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
from ..packets.layer2_only_packet import Layer2OnlyPacket, MISSING_VALUE
import logging


class Layer2OnlyFlow:
    """Flow class that extracts only Layer 2 features."""
    
    def __init__(self, flow_key: str, first_packet: Layer2OnlyPacket):
        self.flow_key = flow_key
        self.packets: List[Layer2OnlyPacket] = [first_packet]
        self.start_time = first_packet.timestamp
        self.end_time = first_packet.timestamp
        self.last_activity = first_packet.timestamp
        self.logger = logging.getLogger(__name__)
        
        # MAC-based flow identification (since we're Layer 2 only)
        self.src_mac = first_packet.features.get('src_mac', str(MISSING_VALUE))
        self.dst_mac = first_packet.features.get('dst_mac', str(MISSING_VALUE))
    
    def add_packet(self, packet: Layer2OnlyPacket):
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
                features['primary_protocol'] = max(protocol_counts.items(), key=lambda x: x[1])[0]
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
                'lldp_count': sum(1 for p in self.packets if p.features.get('is_lldp', False))
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
            features['protocol_diversity_ratio'] = active_protocols / 7 if active_protocols > 0 else 0
            
            # Dominant protocol analysis
            if protocol_counts:
                dominant_protocol = max(protocol_counts.items(), key=lambda x: x[1])
                features['dominant_l2_protocol'] = dominant_protocol[0].replace('_count', '')
                features['dominant_protocol_percentage'] = (dominant_protocol[1] / total_packets) * 100 if total_packets > 0 else 0
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
        
        return defaults
    
    def should_timeout(self, current_time: float, timeout: float) -> bool:
        """Check if flow should timeout."""
        return (current_time - self.last_activity) > timeout
    
    def clear_packets(self):
        """Clear packet data to free memory."""
        self.packets.clear()
    
    def __str__(self) -> str:
        return f"Layer2Flow({self.flow_key}, packets={len(self.packets)}, duration={self.end_time - self.start_time:.2f}s)"