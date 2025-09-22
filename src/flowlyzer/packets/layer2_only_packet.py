"""
Layer 2-Only packet analysis class for extracting only Layer 2 features from all packets.
This includes MAC addresses, Layer 2 protocols, frame information, etc.
"""

from .base_packet import BasePacket
from .fixed_layer2_packet import (parse_cdp_packet, parse_dhcp_packet, parse_stp_packet, 
                                  parse_arp_packet, parse_isl_packet, MISSING_VALUE)
from scapy.all import Packet
from typing import Dict, Any
import struct
import logging


class Layer2OnlyPacket(BasePacket):
    """Extract only Layer 2 features from any packet type."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self.logger = logging.getLogger(__name__)
        self._extract_layer2_only_features()
    
    def _extract_layer2_only_features(self):
        """Extract only Layer 2 relevant features from the packet."""
        try:
            # Basic frame information (always Layer 2)
            self.features['frame_len'] = len(self.packet)
            self.features['frame_number'] = self.frame_number
            self.features['timestamp'] = float(self.packet.time) if hasattr(self.packet, 'time') else self.timestamp
            
            # Extract MAC addresses from Ethernet layer
            if self.packet.haslayer('Ether'):
                eth_layer = self.packet['Ether']
                self.features['src_mac'] = str(eth_layer.src)
                self.features['dst_mac'] = str(eth_layer.dst)
                self.features['eth_type'] = int(eth_layer.type)
                
                # MAC address analysis
                self._analyze_mac_addresses()
            else:
                self.features['src_mac'] = str(MISSING_VALUE)
                self.features['dst_mac'] = str(MISSING_VALUE) 
                self.features['eth_type'] = MISSING_VALUE
                self._set_default_mac_features()
            
            # VLAN information (802.1Q) - Layer 2 feature
            if self.packet.haslayer('Dot1Q'):
                dot1q_layer = self.packet['Dot1Q']
                self.features['vlan_id'] = int(dot1q_layer.vlan) if hasattr(dot1q_layer, 'vlan') else MISSING_VALUE
                self.features['vlan_priority'] = int(dot1q_layer.prio) if hasattr(dot1q_layer, 'prio') else MISSING_VALUE
                self.features['has_vlan'] = True
            else:
                self.features['vlan_id'] = MISSING_VALUE
                self.features['vlan_priority'] = MISSING_VALUE
                self.features['has_vlan'] = False
            
            # Layer 2 protocol detection and extraction
            self._extract_layer2_protocols()
            
            # Layer 2 quality metrics
            self._extract_layer2_quality_metrics()
            
        except Exception as e:
            self.logger.debug(f"Error extracting Layer 2 features: {e}")
            self._set_layer2_defaults()
    
    def _analyze_mac_addresses(self):
        """Analyze MAC addresses for vendor info and characteristics."""
        try:
            src_mac = self.features.get('src_mac', '')
            dst_mac = self.features.get('dst_mac', '')
            
            # MAC vendor analysis (OUI - first 3 octets)
            if src_mac and src_mac != str(MISSING_VALUE):
                self.features['src_mac_oui'] = src_mac[:8]  # First 3 octets (XX:XX:XX)
                self.features['src_mac_vendor'] = self._get_mac_vendor(src_mac)
                self.features['src_mac_is_multicast'] = self._is_multicast_mac(src_mac)
                self.features['src_mac_is_broadcast'] = (src_mac.lower() == 'ff:ff:ff:ff:ff:ff')
                self.features['src_mac_is_local'] = self._is_local_mac(src_mac)
            else:
                self.features['src_mac_oui'] = str(MISSING_VALUE)
                self.features['src_mac_vendor'] = str(MISSING_VALUE)
                self.features['src_mac_is_multicast'] = MISSING_VALUE
                self.features['src_mac_is_broadcast'] = MISSING_VALUE
                self.features['src_mac_is_local'] = MISSING_VALUE
            
            if dst_mac and dst_mac != str(MISSING_VALUE):
                self.features['dst_mac_oui'] = dst_mac[:8]
                self.features['dst_mac_vendor'] = self._get_mac_vendor(dst_mac)
                self.features['dst_mac_is_multicast'] = self._is_multicast_mac(dst_mac)
                self.features['dst_mac_is_broadcast'] = (dst_mac.lower() == 'ff:ff:ff:ff:ff:ff')
                self.features['dst_mac_is_local'] = self._is_local_mac(dst_mac)
            else:
                self.features['dst_mac_oui'] = str(MISSING_VALUE)
                self.features['dst_mac_vendor'] = str(MISSING_VALUE)
                self.features['dst_mac_is_multicast'] = MISSING_VALUE
                self.features['dst_mac_is_broadcast'] = MISSING_VALUE
                self.features['dst_mac_is_local'] = MISSING_VALUE
                
        except Exception as e:
            self.logger.debug(f"Error analyzing MAC addresses: {e}")
            self._set_default_mac_features()
    
    def _extract_layer2_protocols(self):
        """Extract Layer 2 protocol features."""
        try:
            # Initialize all protocol flags
            self.features['is_arp'] = False
            self.features['is_stp'] = False
            self.features['is_cdp'] = False
            self.features['is_dhcp'] = False
            self.features['is_llc'] = False
            self.features['is_isl'] = False
            self.features['is_lldp'] = False
            self.features['is_dtp'] = False
            
            # ARP Protocol
            if self.packet.haslayer('ARP'):
                self.features['is_arp'] = True
                arp_features = parse_arp_packet(self.packet)
                self.features.update(arp_features)
            else:
                self._set_default_arp_features()
            
            # STP Protocol
            if self.packet.haslayer('STP'):
                self.features['is_stp'] = True
                stp_features = parse_stp_packet(self.packet)
                self.features.update(stp_features)
            else:
                self._set_default_stp_features()
            
            # DHCP Protocol (check both UDP ports and protocol layers)
            if self.packet.haslayer('UDP'):
                udp_layer = self.packet['UDP']
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                
                if ((src_port in [67, 68] or dst_port in [67, 68]) and 
                    (self.packet.haslayer('DHCP') or self.packet.haslayer('BOOTP'))):
                    self.features['is_dhcp'] = True
                    dhcp_features = parse_dhcp_packet(self.packet)
                    self.features.update(dhcp_features)
                else:
                    self._set_default_dhcp_features()
            else:
                self._set_default_dhcp_features()
            
            # CDP Protocol (enhanced detection)
            if self._is_cdp_packet():
                self.features['is_cdp'] = True
                raw_data = bytes(self.packet)
                cdp_features = parse_cdp_packet(raw_data)
                self.features.update(cdp_features)
            else:
                self._set_default_cdp_features()
            
            # LLC Protocol
            if self.packet.haslayer('LLC'):
                self.features['is_llc'] = True
                self._extract_llc_features()
            else:
                self._set_default_llc_features()
            
            # ISL Protocol
            if self._is_isl_packet():
                self.features['is_isl'] = True
                raw_data = bytes(self.packet)
                isl_features = parse_isl_packet(raw_data)
                self.features.update(isl_features)
            else:
                self._set_default_isl_features()
            
            # LLDP Protocol
            if self._is_lldp_packet():
                self.features['is_lldp'] = True
                self._extract_lldp_features()
            else:
                self._set_default_lldp_features()
            
            # DTP Protocol (Dynamic Trunking Protocol)
            if self._is_dtp_packet():
                self.features['is_dtp'] = True
                self._extract_dtp_features()
            else:
                self._set_default_dtp_features()
                
        except Exception as e:
            self.logger.debug(f"Error extracting Layer 2 protocols: {e}")
            self._set_all_protocol_defaults()
    
    def _extract_layer2_quality_metrics(self):
        """Extract Layer 2 quality and analysis metrics."""
        try:
            # Frame quality indicators
            self.features['frame_is_broadcast'] = self.features.get('dst_mac_is_broadcast', False)
            self.features['frame_is_multicast'] = self.features.get('dst_mac_is_multicast', False)
            self.features['frame_is_unicast'] = not (self.features.get('frame_is_broadcast', False) or 
                                                    self.features.get('frame_is_multicast', False))
            
            # Protocol diversity (how many Layer 2 protocols are active)
            active_protocols = sum([
                self.features.get('is_arp', False),
                self.features.get('is_stp', False), 
                self.features.get('is_cdp', False),
                self.features.get('is_dhcp', False),
                self.features.get('is_llc', False),
                self.features.get('is_isl', False),
                self.features.get('is_lldp', False),
                self.features.get('is_dtp', False)
            ])
            self.features['layer2_protocol_count'] = active_protocols
            
            # Frame size analysis
            frame_size = self.features.get('frame_len', 0)
            if frame_size > 0:
                self.features['is_jumbo_frame'] = (frame_size > 1500)
                self.features['is_small_frame'] = (frame_size < 64)
                
                # Frame size category
                if frame_size < 64:
                    self.features['frame_size_category'] = 'runt'
                elif frame_size <= 1500:
                    self.features['frame_size_category'] = 'normal'  
                elif frame_size <= 9000:
                    self.features['frame_size_category'] = 'jumbo'
                else:
                    self.features['frame_size_category'] = 'super_jumbo'
            else:
                self.features['is_jumbo_frame'] = MISSING_VALUE
                self.features['is_small_frame'] = MISSING_VALUE
                self.features['frame_size_category'] = str(MISSING_VALUE)
                
        except Exception as e:
            self.logger.debug(f"Error extracting Layer 2 quality metrics: {e}")
            self._set_default_quality_metrics()
    
    # Helper methods for protocol detection
    def _is_cdp_packet(self) -> bool:
        """Enhanced CDP packet detection."""
        try:
            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
            
            # Method 1: LLC/SNAP CDP detection
            if self.packet.haslayer('LLC'):
                llc_layer = self.packet['LLC']
                if hasattr(llc_layer, 'dsap') and hasattr(llc_layer, 'ssap'):
                    if llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa:
                        llc_payload = bytes(llc_layer.payload) if llc_layer.payload else b''
                        if len(llc_payload) >= 5:
                            if llc_payload[0:3] == b'\x00\x00\x0c' and llc_payload[3:5] == b'\x20\x00':
                                return True
            
            # Method 2: Search for CDP SNAP signature in payload
            for i in range(len(raw_payload) - 7):
                if (raw_payload[i:i+3] == b'\x00\x00\x0c' and 
                    raw_payload[i+3:i+5] == b'\x20\x00'):
                    return True
            
            return False
        except Exception:
            return False
    
    def _is_isl_packet(self) -> bool:
        """ISL packet detection."""
        try:
            if self.packet.haslayer('Ether'):
                if len(self.packet) > 30:
                    raw_data = bytes(self.packet)
                    if len(raw_data) >= 26 and raw_data[0:4] == b'\x01\x00\x0c\x00':
                        return True
            return False
        except Exception:
            return False
    
    def _is_lldp_packet(self) -> bool:
        """LLDP packet detection."""
        try:
            # Check for LLDP multicast MAC address
            dst_mac = self.features.get('dst_mac', '').lower()
            if dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                return True
            
            # Check Ethernet type for LLDP
            eth_type = self.features.get('eth_type', 0)
            if eth_type == 0x88cc:  # LLDP Ethernet type
                return True
            
            return False
        except Exception:
            return False
    
    def _is_dtp_packet(self) -> bool:
        """DTP packet detection using SNAP OUI/PID analysis."""
        try:
            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
            
            # Method 1: LLC/SNAP DTP detection
            if self.packet.haslayer('LLC'):
                llc_layer = self.packet['LLC']
                if hasattr(llc_layer, 'dsap') and hasattr(llc_layer, 'ssap'):
                    if llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa:
                        llc_payload = bytes(llc_layer.payload) if llc_layer.payload else b''
                        if len(llc_payload) >= 5:
                            # Check for DTP SNAP OUI (00:00:0c) and PID (0x2004)
                            if llc_payload[0:3] == b'\x00\x00\x0c' and llc_payload[3:5] == b'\x20\x04':
                                return True
            
            # Method 2: Search for DTP SNAP signature in payload
            for i in range(len(raw_payload) - 7):
                if (raw_payload[i:i+3] == b'\x00\x00\x0c' and 
                    raw_payload[i+3:i+5] == b'\x20\x04'):
                    return True
            
            return False
        except Exception:
            return False
    
    # MAC address analysis helpers
    def _get_mac_vendor(self, mac_address: str) -> str:
        """Get vendor information from MAC OUI."""
        try:
            oui = mac_address.replace(':', '').replace('-', '')[:6].upper()
            
            # Common vendor OUIs
            vendor_map = {
                '000C29': 'VMware',
                '005056': 'VMware', 
                '0050F2': 'Microsoft',
                '00E04C': 'Realtek',
                '001B21': 'Intel',
                '00D0C9': 'Intel',
                '00AA00': 'Intel',
                '0002B3': 'Intel',
                '000394': 'Cisco',
                '00000C': 'Cisco',
                '001F26': 'Cisco',
                '0025B3': 'Apple',
                '001CB3': 'Apple',
                '7CF05F': 'Apple',
                '001FF3': 'Apple'
            }
            
            return vendor_map.get(oui, 'Unknown')
        except Exception:
            return 'Unknown'
    
    def _is_multicast_mac(self, mac_address: str) -> bool:
        """Check if MAC address is multicast."""
        try:
            first_octet = int(mac_address.split(':')[0], 16)
            return bool(first_octet & 0x01)
        except Exception:
            return False
    
    def _is_local_mac(self, mac_address: str) -> bool:
        """Check if MAC address is locally administered."""
        try:
            first_octet = int(mac_address.split(':')[0], 16)
            return bool(first_octet & 0x02)
        except Exception:
            return False
    
    # Protocol feature extraction methods
    def _extract_llc_features(self):
        """Extract LLC protocol features."""
        try:
            if self.packet.haslayer('LLC'):
                llc_layer = self.packet['LLC']
                self.features['llc_dsap'] = int(llc_layer.dsap) if hasattr(llc_layer, 'dsap') else MISSING_VALUE
                self.features['llc_ssap'] = int(llc_layer.ssap) if hasattr(llc_layer, 'ssap') else MISSING_VALUE
                self.features['llc_ctrl'] = int(llc_layer.ctrl) if hasattr(llc_layer, 'ctrl') else MISSING_VALUE
            else:
                self._set_default_llc_features()
        except Exception:
            self._set_default_llc_features()
    
    def _extract_lldp_features(self):
        """Extract LLDP protocol features."""
        try:
            # Basic LLDP detection - actual TLV parsing would be more complex
            self.features['lldp_detected'] = True
            self.features['lldp_chassis_id_type'] = MISSING_VALUE  # Would need TLV parsing
            self.features['lldp_port_id_type'] = MISSING_VALUE
            self.features['lldp_ttl'] = MISSING_VALUE
        except Exception:
            self._set_default_lldp_features()
    
    def _extract_dtp_features(self):
        """Extract DTP protocol features."""
        try:
            # Basic DTP analysis
            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
            
            # Try to extract basic DTP fields
            self.features['dtp_version'] = 1  # Default DTP version
            self.features['dtp_tlv_count'] = 1  # Mark as having DTP data
            self.features['dtp_domain_length'] = 0  # Would need proper parsing
            
            # DTP frame type detection (simplified)
            self.features['dtp_frame_isl'] = False
            self.features['dtp_frame_802dot1q'] = True  # Most common
            
        except Exception:
            self._set_default_dtp_features()
    
    # Default feature setters
    def _set_default_mac_features(self):
        """Set default MAC address features."""
        mac_defaults = {
            'src_mac_oui': str(MISSING_VALUE),
            'src_mac_vendor': str(MISSING_VALUE),
            'src_mac_is_multicast': MISSING_VALUE,
            'src_mac_is_broadcast': MISSING_VALUE,
            'src_mac_is_local': MISSING_VALUE,
            'dst_mac_oui': str(MISSING_VALUE),
            'dst_mac_vendor': str(MISSING_VALUE),
            'dst_mac_is_multicast': MISSING_VALUE,
            'dst_mac_is_broadcast': MISSING_VALUE,
            'dst_mac_is_local': MISSING_VALUE
        }
        self.features.update(mac_defaults)
    
    def _set_default_arp_features(self):
        """Set default ARP features."""
        arp_defaults = {
            'arp_hw_type': MISSING_VALUE,
            'arp_proto_type': MISSING_VALUE,
            'arp_hw_len': MISSING_VALUE,
            'arp_proto_len': MISSING_VALUE,
            'arp_opcode': MISSING_VALUE,
            'arp_src_hw_addr': str(MISSING_VALUE),
            'arp_dst_hw_addr': str(MISSING_VALUE),
            'arp_src_proto_addr': str(MISSING_VALUE),
            'arp_dst_proto_addr': str(MISSING_VALUE)
        }
        self.features.update(arp_defaults)
    
    def _set_default_stp_features(self):
        """Set default STP features."""
        stp_defaults = {
            'stp_version': MISSING_VALUE,
            'stp_bpdu_type': MISSING_VALUE,
            'stp_flags': MISSING_VALUE,
            'stp_flags_tc': MISSING_VALUE,
            'stp_flags_tcack': MISSING_VALUE,
            'stp_msg_age': MISSING_VALUE,
            'stp_max_age': MISSING_VALUE,
            'stp_hello_time': MISSING_VALUE,
            'stp_forward_delay': MISSING_VALUE,
            'stp_root_cost': MISSING_VALUE,
            'stp_port_id': MISSING_VALUE,
            'stp_proto_id': MISSING_VALUE
        }
        self.features.update(stp_defaults)
    
    def _set_default_dhcp_features(self):
        """Set default DHCP features."""
        dhcp_defaults = {
            'dhcp_op': MISSING_VALUE,
            'dhcp_hw_type': MISSING_VALUE,
            'dhcp_hw_len': MISSING_VALUE,
            'dhcp_hops': MISSING_VALUE,
            'dhcp_xid': MISSING_VALUE,
            'dhcp_secs': MISSING_VALUE,
            'dhcp_flags': MISSING_VALUE,
            'dhcp_flags_bc': MISSING_VALUE,
            'dhcp_flags_reserved': MISSING_VALUE,
            'dhcp_cookie': MISSING_VALUE,
            'dhcp_options': MISSING_VALUE,
            'dhcp_options_len': MISSING_VALUE
        }
        self.features.update(dhcp_defaults)
    
    def _set_default_cdp_features(self):
        """Set default CDP features."""
        cdp_defaults = {
            'cdp_version': MISSING_VALUE,
            'cdp_ttl': MISSING_VALUE,
            'cdp_checksum': MISSING_VALUE,
            'cdp_tlv_count': MISSING_VALUE,
            'cdp_device_id_tlv_len': MISSING_VALUE,
            'cdp_software_version_tlv_len': MISSING_VALUE,
            'cdp_platform_tlv_len': MISSING_VALUE,
            'cdp_addresses_count': MISSING_VALUE,
            'cdp_capabilities': MISSING_VALUE,
            'cdp_capabilities_router': MISSING_VALUE,
            'cdp_capabilities_trans_bridge': MISSING_VALUE,
            'cdp_capabilities_switch': MISSING_VALUE,
            'cdp_capabilities_host': MISSING_VALUE,
            'cdp_tlvs': MISSING_VALUE
        }
        self.features.update(cdp_defaults)
    
    def _set_default_llc_features(self):
        """Set default LLC features."""
        llc_defaults = {
            'llc_dsap': MISSING_VALUE,
            'llc_ssap': MISSING_VALUE,
            'llc_ctrl': MISSING_VALUE
        }
        self.features.update(llc_defaults)
    
    def _set_default_isl_features(self):
        """Set default ISL features."""
        isl_defaults = {
            'isl_frame_type': MISSING_VALUE,
            'isl_user_bits': MISSING_VALUE,
            'isl_src_vlan_id': MISSING_VALUE,
            'isl_bpdu': MISSING_VALUE,
            'isl_index': MISSING_VALUE,
            'isl_reserved': MISSING_VALUE
        }
        self.features.update(isl_defaults)
    
    def _set_default_lldp_features(self):
        """Set default LLDP features."""
        lldp_defaults = {
            'lldp_detected': False,
            'lldp_chassis_id_type': MISSING_VALUE,
            'lldp_port_id_type': MISSING_VALUE,
            'lldp_ttl': MISSING_VALUE
        }
        self.features.update(lldp_defaults)
    
    def _set_default_dtp_features(self):
        """Set default DTP features."""
        dtp_defaults = {
            'dtp_version': MISSING_VALUE,
            'dtp_tlv_count': MISSING_VALUE,
            'dtp_domain_length': MISSING_VALUE,
            'dtp_frame_isl': MISSING_VALUE,
            'dtp_frame_802dot1q': MISSING_VALUE
        }
        self.features.update(dtp_defaults)
    
    def _set_default_quality_metrics(self):
        """Set default quality metrics."""
        quality_defaults = {
            'frame_is_broadcast': MISSING_VALUE,
            'frame_is_multicast': MISSING_VALUE,
            'frame_is_unicast': MISSING_VALUE,
            'layer2_protocol_count': MISSING_VALUE,
            'is_jumbo_frame': MISSING_VALUE,
            'is_small_frame': MISSING_VALUE,
            'frame_size_category': str(MISSING_VALUE)
        }
        self.features.update(quality_defaults)
    
    def _set_all_protocol_defaults(self):
        """Set all protocol default features."""
        self._set_default_arp_features()
        self._set_default_stp_features()
        self._set_default_dhcp_features()
        self._set_default_cdp_features()
        self._set_default_llc_features()
        self._set_default_isl_features()
        self._set_default_lldp_features()
        self._set_default_dtp_features()
    
    def _set_layer2_defaults(self):
        """Set all Layer 2 default features when extraction fails."""
        self._set_default_mac_features()
        self._set_all_protocol_defaults()
        self._set_default_quality_metrics()
    
    def get_protocol_type(self) -> str:
        """Return the primary Layer 2 protocol type."""
        if self.features.get('is_arp', False):
            return 'ARP'
        elif self.features.get('is_stp', False):
            return 'STP'
        elif self.features.get('is_cdp', False):
            return 'CDP'
        elif self.features.get('is_dhcp', False):
            return 'DHCP'
        elif self.features.get('is_llc', False):
            return 'LLC'
        elif self.features.get('is_isl', False):
            return 'ISL'
        elif self.features.get('is_lldp', False):
            return 'LLDP'
        elif self.features.get('is_dtp', False):
            return 'DTP'
        else:
            return 'Layer2'