"""
Base packet class for extracting general packet features.
This class serves as the foundation for all protocol-specific packet classes.
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional
from scapy.all import Packet
import numpy as np


class BasePacket:
    """
    Base class for packet analysis and feature extraction.
    Contains common features that apply to all network packets.
    """
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        """
        Initialize base packet with scapy packet data.
        
        Args:
            scapy_packet: The scapy packet object
            frame_number: Sequential frame number in the capture
        """
        self.packet = scapy_packet
        self.frame_number = frame_number
        self.timestamp = float(scapy_packet.time) if hasattr(scapy_packet, 'time') else time.time()
        self.features = {}
        self._extract_base_features()
    
    def _extract_base_features(self):
        """Extract basic features common to all packets."""
        try:
            # Frame-level features
            self.features['num_frame'] = self.frame_number
            self.features['frame_len'] = len(self.packet)
            self.features['timestamp'] = self.timestamp
            
            # Ethernet layer features
            if self.packet.haslayer('Ether'):
                eth_layer = self.packet['Ether']
                self.features['dst_mac_addr'] = str(eth_layer.dst)
                self.features['src_mac_addr'] = str(eth_layer.src)
                self.features['eth_type'] = int(eth_layer.type)
                
                # MAC address analysis
                self._extract_mac_features('dst_mac', eth_layer.dst)
                self._extract_mac_features('src_mac', eth_layer.src)
            else:
                self._set_default_mac_features()
            
            # IP layer features
            if self.packet.haslayer('IP'):
                ip_layer = self.packet['IP']
                self.features['dst_ip_addr'] = str(ip_layer.dst)
                self.features['src_ip_addr'] = str(ip_layer.src)
            elif self.packet.haslayer('IPv6'):
                ipv6_layer = self.packet['IPv6']
                self.features['dst_ip_addr'] = str(ipv6_layer.dst)
                self.features['src_ip_addr'] = str(ipv6_layer.src)
            else:
                self.features['dst_ip_addr'] = None
                self.features['src_ip_addr'] = None
            
            # Port features
            self._extract_port_features()
            
        except Exception as e:
            self._set_default_features()
    
    def _extract_mac_features(self, prefix: str, mac_addr: str):
        """Extract MAC address specific features."""
        try:
            # Clean MAC address
            mac_clean = mac_addr.replace(':', '').replace('-', '').upper()
            
            # OUI (first 3 bytes)
            oui = mac_clean[:6]
            self.features[f'{prefix}_oui'] = oui
            
            # Individual/Group bit (bit 0 of first byte)
            first_byte = int(mac_clean[:2], 16)
            self.features[f'{prefix}_ig'] = (first_byte & 0x01) == 1
            
            # Local/Global bit (bit 1 of first byte)
            self.features[f'{prefix}_lg'] = (first_byte & 0x02) == 2
            
            # Vendor information (simplified - would need OUI database for full implementation)
            self.features[f'{prefix}_vendor'] = self._get_vendor_from_oui(oui)
            self.features[f'{prefix}_vendor_known'] = self.features[f'{prefix}_vendor'] != 'Unknown'
            self.features[f'{prefix}_device'] = 'Unknown'
            self.features[f'{prefix}_vendor_name'] = self.features[f'{prefix}_vendor']
            self.features[f'{prefix}_vendor_name_known'] = self.features[f'{prefix}_vendor_known']
            
        except Exception:
            self.features[f'{prefix}_oui'] = 'Unknown'
            self.features[f'{prefix}_ig'] = False
            self.features[f'{prefix}_lg'] = False
            self.features[f'{prefix}_vendor'] = 'Unknown'
            self.features[f'{prefix}_vendor_known'] = False
            self.features[f'{prefix}_device'] = 'Unknown'
            self.features[f'{prefix}_vendor_name'] = 'Unknown'
            self.features[f'{prefix}_vendor_name_known'] = False
    
    def _get_vendor_from_oui(self, oui: str) -> str:
        """Get vendor name from OUI (simplified implementation)."""
        # This would typically use an OUI database
        common_ouis = {
            '000C29': 'VMware',
            '0050F2': 'Microsoft',
            '00E04C': 'Realtek',
            '001B21': 'Intel',
            '00D0C9': 'Intel',
            '001125': 'Apple',
            '3C0754': 'Apple',
        }
        return common_ouis.get(oui, 'Unknown')
    
    def _extract_port_features(self):
        """Extract port information from transport layer."""
        try:
            if self.packet.haslayer('TCP'):
                tcp_layer = self.packet['TCP']
                self.features['dst_port'] = int(tcp_layer.dport)
                self.features['src_port'] = int(tcp_layer.sport)
            elif self.packet.haslayer('UDP'):
                udp_layer = self.packet['UDP']
                self.features['dst_port'] = int(udp_layer.dport)
                self.features['src_port'] = int(udp_layer.sport)
            else:
                self.features['dst_port'] = None
                self.features['src_port'] = None
        except Exception:
            self.features['dst_port'] = None
            self.features['src_port'] = None
    
    def _set_default_mac_features(self):
        """Set default values for MAC features when Ethernet layer is not present."""
        for prefix in ['dst_mac', 'src_mac']:
            self.features[f'{prefix}_addr'] = None
            self.features[f'{prefix}_oui'] = 'Unknown'
            self.features[f'{prefix}_ig'] = False
            self.features[f'{prefix}_lg'] = False
            self.features[f'{prefix}_vendor'] = 'Unknown'
            self.features[f'{prefix}_vendor_known'] = False
            self.features[f'{prefix}_device'] = 'Unknown'
            self.features[f'{prefix}_vendor_name'] = 'Unknown'
            self.features[f'{prefix}_vendor_name_known'] = False
    
    def _set_default_features(self):
        """Set default values for all features in case of extraction errors."""
        default_features = {
            'num_frame': self.frame_number,
            'frame_len': 0,
            'timestamp': self.timestamp,
            'dst_mac_addr': None,
            'src_mac_addr': None,
            'eth_type': 0,
            'dst_ip_addr': None,
            'src_ip_addr': None,
            'dst_port': None,
            'src_port': None,
        }
        self.features.update(default_features)
        self._set_default_mac_features()
    
    def get_features(self) -> Dict[str, Any]:
        """Return extracted features as dictionary."""
        return self.features.copy()
    
    def get_protocol_type(self) -> str:
        """Return the main protocol type of this packet."""
        try:
            # Check Layer 3/4 protocols first
            if self.packet.haslayer('TCP'):
                return 'TCP'
            elif self.packet.haslayer('UDP'):
                return 'UDP'
            elif self.packet.haslayer('ICMP'):
                return 'ICMP'
            elif self.packet.haslayer('ARP'):
                return 'ARP'
            
            # Check Layer 2 protocols
            elif self.packet.haslayer('STP'):
                return 'STP'
            elif self.packet.haslayer('LLC'):
                # Try to identify LLC sub-protocols
                if self.packet.haslayer('Ether'):
                    dst_mac = str(self.packet['Ether'].dst).lower()
                    if dst_mac == '01:00:0c:cc:cc:cc':
                        return 'CDP'
                    elif dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                        return 'LLDP'
                return 'LLC'
            
            # Check other Layer 2 protocols by EtherType
            elif self.packet.haslayer('Ether'):
                eth_type = self.packet['Ether'].type
                if eth_type == 0x8100:  # 802.1Q VLAN
                    return '802.1Q'
                elif eth_type == 0x88cc:  # LLDP
                    return 'LLDP'
                elif eth_type == 0x809b:  # AppleTalk
                    return 'AppleTalk'
                elif eth_type == 0x8038:  # DEC LAT
                    return 'DEC_LAT'
                elif eth_type == 0x86dd:  # IPv6
                    return 'IPv6'
                elif eth_type == 0x0800:  # IPv4 (might be missed)
                    return 'IPv4'
                else:
                    return f'ETH_0x{eth_type:04x}'
            
            # Final fallback with packet analysis
            else:
                # Try to get more specific info from packet layers
                layers = [layer.name for layer in self.packet.layers()]
                if 'Raw' in layers:
                    return 'RAW'
                elif 'Padding' in layers:
                    return 'PADDING'
                elif len(layers) > 1:
                    return f'{layers[-1]}_LAYER'
                else:
                    return 'OTHER'
                    
        except Exception:
            return 'OTHER'
    
    def get_flow_key(self) -> str:
        """
        Generate a unique flow identifier.
        Combines source/destination MAC, IP, and port information.
        """
        try:
            src_mac = self.features.get('src_mac_addr', 'unknown')
            dst_mac = self.features.get('dst_mac_addr', 'unknown')
            src_ip = self.features.get('src_ip_addr', 'unknown')
            dst_ip = self.features.get('dst_ip_addr', 'unknown')
            src_port = self.features.get('src_port', 0)
            dst_port = self.features.get('dst_port', 0)
            protocol = self.get_protocol_type()
            
            # Create bidirectional flow key (normalize by sorting endpoints)
            endpoints = sorted([
                f"{src_mac}:{src_ip}:{src_port}",
                f"{dst_mac}:{dst_ip}:{dst_port}"
            ])
            
            return f"{protocol}:{endpoints[0]}:{endpoints[1]}"
            
        except Exception:
            return f"unknown:{self.frame_number}"
    
    def is_marked(self) -> bool:
        """Check if packet is marked (has special flags or conditions)."""
        try:
            # Check for specific protocol flags or conditions that mark a packet as special
            if self.packet.haslayer('TCP'):
                tcp_layer = self.packet['TCP']
                # Mark packets with special TCP flags
                return bool(tcp_layer.flags & 0x3F)  # Any control flags
            return False
        except Exception:
            return False
    
    def is_ignored(self) -> bool:
        """Check if packet should be ignored in analysis."""
        try:
            # Ignore malformed or corrupted packets
            return len(self.packet) < 14  # Minimum Ethernet frame size
        except Exception:
            return True