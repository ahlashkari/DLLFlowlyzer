"""
UDP packet analysis class for extracting UDP-specific features.
"""

from .base_packet import BasePacket
from scapy.all import Packet
from typing import Dict, Any


class UDPPacket(BasePacket):
    """UDP packet analyzer with UDP-specific feature extraction."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_udp_features()
    
    def _extract_udp_features(self):
        """Extract UDP-specific features."""
        try:
            if not self.packet.haslayer('UDP'):
                return
            
            udp_layer = self.packet['UDP']
            
            # UDP header fields
            self.features['udp_len'] = int(udp_layer.len)
            self.features['udp_checksum'] = int(udp_layer.chksum)
            
            # UDP payload length
            self.features['udp_payload_len'] = len(udp_layer.payload) if udp_layer.payload else 0
            
            # Check for DNS
            if self.features.get('src_port') == 53 or self.features.get('dst_port') == 53:
                self.features['is_dns'] = True
                self._extract_dns_features()
            else:
                self.features['is_dns'] = False
            
            # Check for DHCP
            if self.features.get('src_port') in [67, 68] or self.features.get('dst_port') in [67, 68]:
                self.features['is_dhcp'] = True
                self._extract_dhcp_features()
            else:
                self.features['is_dhcp'] = False
                
        except Exception:
            self._set_default_udp_features()
    
    def _extract_dns_features(self):
        """Extract DNS-specific features from UDP payload."""
        try:
            if self.packet.haslayer('DNS'):
                dns_layer = self.packet['DNS']
                self.features['dns_id'] = int(dns_layer.id)
                self.features['dns_qr'] = bool(dns_layer.qr)
                self.features['dns_opcode'] = int(dns_layer.opcode)
                self.features['dns_rcode'] = int(dns_layer.rcode)
                self.features['dns_qdcount'] = int(dns_layer.qdcount)
                self.features['dns_ancount'] = int(dns_layer.ancount)
                self.features['dns_nscount'] = int(dns_layer.nscount)
                self.features['dns_arcount'] = int(dns_layer.arcount)
            else:
                self._set_default_dns_features()
        except Exception:
            self._set_default_dns_features()
    
    def _extract_dhcp_features(self):
        """Extract comprehensive DHCP-specific features from UDP payload."""
        try:
            if self.packet.haslayer('DHCP') or self.packet.haslayer('BOOTP'):
                # Use BOOTP layer for DHCP (DHCP is built on BOOTP)
                if self.packet.haslayer('BOOTP'):
                    bootp_layer = self.packet['BOOTP']
                    
                    # Basic DHCP/BOOTP fields based on example
                    self.features['dhcp_op'] = int(bootp_layer.op) if hasattr(bootp_layer, 'op') else 1
                    self.features['dhcp_hw_type'] = int(bootp_layer.htype) if hasattr(bootp_layer, 'htype') else 1
                    self.features['dhcp_type'] = self.features['dhcp_hw_type']  # Alias
                    self.features['dhcp_hw_len'] = int(bootp_layer.hlen) if hasattr(bootp_layer, 'hlen') else 6
                    self.features['dhcp_hops'] = int(bootp_layer.hops) if hasattr(bootp_layer, 'hops') else 0
                    self.features['dhcp_secs'] = int(bootp_layer.secs) if hasattr(bootp_layer, 'secs') else 0
                    
                    # DHCP flags
                    if hasattr(bootp_layer, 'flags'):
                        flags = int(bootp_layer.flags)
                        self.features['dhcp_flags_bc'] = bool(flags & 0x8000)  # Broadcast flag
                        self.features['dhcp_flags_reserved'] = flags & 0x7FFF  # Reserved bits
                    else:
                        self.features['dhcp_flags_bc'] = False
                        self.features['dhcp_flags_reserved'] = 0
                    
                    # Magic cookie
                    self.features['dhcp_cookie'] = int(bootp_layer.options) if hasattr(bootp_layer, 'options') and isinstance(bootp_layer.options, int) else 0
                    
                    # Hardware address padding (simplified)
                    if hasattr(bootp_layer, 'chaddr'):
                        chaddr_len = len(bootp_layer.chaddr) if bootp_layer.chaddr else 0
                        self.features['dhcp_padding'] = max(0, 16 - chaddr_len)  # DHCP chaddr is 16 bytes
                    else:
                        self.features['dhcp_padding'] = 0
                
                # DHCP options analysis
                if self.packet.haslayer('DHCP'):
                    dhcp_layer = self.packet['DHCP']
                    dhcp_options = dhcp_layer.options if hasattr(dhcp_layer, 'options') else []
                    
                    self.features['dhcp_options_count'] = len(dhcp_options)
                    self.features['dhcp_options'] = len(dhcp_options)  # Alias
                    
                    # Calculate total options length
                    options_len = 0
                    message_type = 0
                    padding_found = False
                    
                    for option in dhcp_options:
                        if isinstance(option, tuple) and len(option) >= 2:
                            option_type, option_value = option[0], option[1]
                            
                            if option_type == 'message-type':
                                message_type = option_value if isinstance(option_value, int) else 0
                            elif option_type == 'pad':
                                padding_found = True
                            elif isinstance(option_value, (bytes, str)):
                                options_len += len(option_value) + 2  # Type + Length + Value
                            else:
                                options_len += 3  # Minimum option size
                    
                    self.features['dhcp_message_type'] = message_type
                    self.features['dhcp_options_len'] = options_len
                    self.features['dhcp_option_padding'] = 1 if padding_found else 0
                    
                else:
                    self.features['dhcp_options_count'] = 0
                    self.features['dhcp_options'] = 0
                    self.features['dhcp_message_type'] = 0
                    self.features['dhcp_options_len'] = 0
                    self.features['dhcp_option_padding'] = 0
                
            else:
                # This is a DHCP packet but we couldn't find BOOTP/DHCP layers
                # Set reasonable defaults for DHCP identification
                self.features['dhcp_op'] = 1  # Assume BOOTREQUEST
                self.features['dhcp_hw_type'] = 1  # Ethernet
                self.features['dhcp_type'] = 1
                self.features['dhcp_hw_len'] = 6  # MAC address length
                self.features['dhcp_hops'] = 0
                self.features['dhcp_secs'] = 0
                self.features['dhcp_flags_bc'] = False
                self.features['dhcp_flags_reserved'] = 0
                self.features['dhcp_cookie'] = 0x63825363  # Standard DHCP magic cookie
                self.features['dhcp_padding'] = 0
                self.features['dhcp_options_count'] = 0
                self.features['dhcp_options'] = 0
                self.features['dhcp_message_type'] = 1  # DHCP Discover
                self.features['dhcp_options_len'] = 0
                self.features['dhcp_option_padding'] = 0
        except Exception:
            # Final fallback with DHCP-like defaults
            self.features['dhcp_op'] = 1
            self.features['dhcp_hw_type'] = 1
            self.features['dhcp_type'] = 1
            self.features['dhcp_hw_len'] = 6
            self.features['dhcp_hops'] = 0
            self.features['dhcp_secs'] = 0
            self.features['dhcp_flags_bc'] = False
            self.features['dhcp_flags_reserved'] = 0
            self.features['dhcp_cookie'] = 0x63825363
            self.features['dhcp_padding'] = 0
            self.features['dhcp_options_count'] = 0
            self.features['dhcp_options'] = 0
            self.features['dhcp_message_type'] = 1
            self.features['dhcp_options_len'] = 0
            self.features['dhcp_option_padding'] = 0
    
    def _set_default_udp_features(self):
        """Set default UDP features when extraction fails."""
        udp_defaults = {
            'udp_len': 0,
            'udp_checksum': 0,
            'udp_payload_len': 0,
            'is_dns': False,
            'is_dhcp': False,
        }
        self.features.update(udp_defaults)
        self._set_default_dns_features()
        self._set_default_dhcp_features()
    
    def _set_default_dns_features(self):
        """Set default DNS features."""
        dns_defaults = {
            'dns_id': 0,
            'dns_qr': False,
            'dns_opcode': 0,
            'dns_rcode': 0,
            'dns_qdcount': 0,
            'dns_ancount': 0,
            'dns_nscount': 0,
            'dns_arcount': 0,
        }
        self.features.update(dns_defaults)
    
    def _set_default_dhcp_features(self):
        """Set default DHCP features."""
        dhcp_defaults = {
            'dhcp_op': 1,  # BOOTREQUEST by default
            'dhcp_hw_type': 1,  # Ethernet
            'dhcp_type': 1,
            'dhcp_hw_len': 6,  # MAC address length
            'dhcp_hops': 0,
            'dhcp_secs': 0,
            'dhcp_flags_bc': False,
            'dhcp_flags_reserved': 0,
            'dhcp_cookie': 0x63825363,  # Standard DHCP magic cookie
            'dhcp_padding': 0,
            'dhcp_options_count': 0,
            'dhcp_options': 0,
            'dhcp_message_type': 1,  # DHCP Discover
            'dhcp_options_len': 0,
            'dhcp_option_padding': 0,
        }
        self.features.update(dhcp_defaults)