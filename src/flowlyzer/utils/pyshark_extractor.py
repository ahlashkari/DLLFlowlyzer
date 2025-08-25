"""
PyShark-based protocol feature extractor for enhanced Layer 2 analysis.
Provides deep inspection of STP, CDP, ARP, DHCP, and DTP protocols.
"""

import logging
from typing import Dict, Any, Optional
import pyshark

logger = logging.getLogger(__name__)


class PySharkProtocolExtractor:
    """Enhanced protocol feature extraction using PyShark."""
    
    def __init__(self):
        self.logger = logger
    
    def extract_packet_features(self, packet_data: bytes, protocol_type: str) -> Dict[str, Any]:
        """
        Extract detailed protocol features using PyShark.
        
        Args:
            packet_data: Raw packet bytes
            protocol_type: Expected protocol type (STP, CDP, ARP, DHCP, DTP)
            
        Returns:
            Dictionary of extracted features with protocol prefix
        """
        try:
            # Create a temporary file-like object from bytes
            import io
            from scapy.all import wrpcap, rdpcap
            
            # Create packet from bytes using scapy first
            from scapy.packet import Raw
            temp_packet = Raw(packet_data)
            
            # Use pyshark for detailed analysis
            features = {}
            
            if protocol_type == 'STP':
                features.update(self._extract_stp_features_pyshark(packet_data))
            elif protocol_type == 'CDP':
                features.update(self._extract_cdp_features_pyshark(packet_data))
            elif protocol_type == 'ARP':
                features.update(self._extract_arp_features_pyshark(packet_data))
            elif protocol_type == 'DHCP':
                features.update(self._extract_dhcp_features_pyshark(packet_data))
            elif protocol_type == 'DTP':
                features.update(self._extract_dtp_features_pyshark(packet_data))
            
            return features
            
        except Exception as e:
            self.logger.warning(f"PyShark extraction failed for {protocol_type}: {e}")
            return {}
    
    def _extract_stp_features_pyshark(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract STP features using PyShark for accurate parsing."""
        features = {
            'stp_msg_age': 0,
            'stp_max_age': 0,
            'stp_hello_time': 0,
            'stp_forward_delay': 0,
            'stp_bridge_id': '',
            'stp_root_id': '',
            'stp_port_id': 0,
            'stp_cost': 0,
            'stp_bridge_priority': 0,
            'stp_root_priority': 0,
            'stp_flags_tc': False,
            'stp_flags_tcack': False,
            'stp_flags_agreement': False,
            'stp_flags_learning': False,
            'stp_flags_forwarding': False,
            'stp_proto_id': 0,
            'stp_version': 0,
            'stp_type': 0
        }
        
        try:
            # Try to parse STP using raw bytes analysis since PyShark needs file
            if len(packet_data) >= 35:  # Minimum STP BPDU size
                # Look for STP in the packet
                # IEEE 802.1D STP BPDU structure
                offset = 0
                
                # Find STP marker (Protocol ID = 0x0000)
                for i in range(len(packet_data) - 10):
                    if packet_data[i:i+2] == b'\x00\x00':  # Protocol ID
                        offset = i
                        break
                
                if offset + 35 <= len(packet_data):
                    # Extract STP BPDU fields
                    features['stp_proto_id'] = int.from_bytes(packet_data[offset:offset+2], 'big')
                    features['stp_version'] = packet_data[offset+2]
                    features['stp_type'] = packet_data[offset+3]
                    
                    # Flags
                    flags = packet_data[offset+4]
                    features['stp_flags_tc'] = bool(flags & 0x01)
                    features['stp_flags_tcack'] = bool(flags & 0x80)
                    features['stp_flags_agreement'] = bool(flags & 0x40)
                    features['stp_flags_learning'] = bool(flags & 0x20)
                    features['stp_flags_forwarding'] = bool(flags & 0x10)
                    
                    # Root ID (8 bytes: priority + MAC)
                    root_priority = int.from_bytes(packet_data[offset+5:offset+7], 'big')
                    root_mac = packet_data[offset+7:offset+13].hex(':')
                    features['stp_root_priority'] = root_priority
                    features['stp_root_id'] = f"{root_priority}:{root_mac}"
                    
                    # Cost (4 bytes)
                    features['stp_cost'] = int.from_bytes(packet_data[offset+13:offset+17], 'big')
                    
                    # Bridge ID (8 bytes: priority + MAC)
                    bridge_priority = int.from_bytes(packet_data[offset+17:offset+19], 'big')
                    bridge_mac = packet_data[offset+19:offset+25].hex(':')
                    features['stp_bridge_priority'] = bridge_priority
                    features['stp_bridge_id'] = f"{bridge_priority}:{bridge_mac}"
                    
                    # Port ID (2 bytes)
                    features['stp_port_id'] = int.from_bytes(packet_data[offset+25:offset+27], 'big')
                    
                    # Message Age (2 bytes, in 1/256 seconds)
                    msg_age_raw = int.from_bytes(packet_data[offset+27:offset+29], 'big')
                    features['stp_msg_age'] = msg_age_raw / 256.0
                    
                    # Max Age (2 bytes, in 1/256 seconds)
                    max_age_raw = int.from_bytes(packet_data[offset+29:offset+31], 'big')
                    features['stp_max_age'] = max_age_raw / 256.0
                    
                    # Hello Time (2 bytes, in 1/256 seconds)
                    hello_time_raw = int.from_bytes(packet_data[offset+31:offset+33], 'big')
                    features['stp_hello_time'] = hello_time_raw / 256.0
                    
                    # Forward Delay (2 bytes, in 1/256 seconds)
                    forward_delay_raw = int.from_bytes(packet_data[offset+33:offset+35], 'big')
                    features['stp_forward_delay'] = forward_delay_raw / 256.0
                    
        except Exception as e:
            self.logger.debug(f"STP parsing error: {e}")
        
        return features
    
    def _extract_cdp_features_pyshark(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract CDP features using enhanced parsing."""
        features = {
            'cdp_version': 0,
            'cdp_ttl': 0,
            'cdp_checksum': 0,
            'cdp_device_id': '',
            'cdp_device_id_len': 0,
            'cdp_addresses_count': 0,
            'cdp_port_id': '',
            'cdp_port_id_len': 0,
            'cdp_capabilities_flags': 0,
            'cdp_capabilities_router': False,
            'cdp_capabilities_bridge': False,
            'cdp_capabilities_switch': False,
            'cdp_capabilities_host': False,
            'cdp_platform': '',
            'cdp_platform_len': 0,
            'cdp_software_version': '',
            'cdp_software_version_len': 0,
            'cdp_tlv_count': 0,
            'cdp_tlvs': 0,
            'cdp_power_consumption': 0,
            'cdp_power_request': 0,
            'cdp_power_available': 0,
            'cdp_duplex': '',
            'cdp_vlan_id': 0
        }
        
        try:
            # Look for CDP header (version, TTL, checksum)
            if len(packet_data) >= 8:
                # Find CDP header - usually after LLC/SNAP
                offset = self._find_cdp_start(packet_data)
                
                if offset >= 0 and offset + 4 <= len(packet_data):
                    features['cdp_version'] = packet_data[offset]
                    features['cdp_ttl'] = packet_data[offset+1]
                    features['cdp_checksum'] = int.from_bytes(packet_data[offset+2:offset+4], 'big')
                    
                    # Parse TLVs starting after header
                    tlv_offset = offset + 4
                    tlv_count = 0
                    
                    while tlv_offset + 4 <= len(packet_data):
                        tlv_type = int.from_bytes(packet_data[tlv_offset:tlv_offset+2], 'big')
                        tlv_length = int.from_bytes(packet_data[tlv_offset+2:tlv_offset+4], 'big')
                        
                        if tlv_length < 4 or tlv_offset + tlv_length > len(packet_data):
                            break
                            
                        tlv_count += 1
                        tlv_data = packet_data[tlv_offset+4:tlv_offset+tlv_length]
                        
                        # Parse specific TLV types
                        if tlv_type == 0x0001 and tlv_data:  # Device ID
                            features['cdp_device_id'] = tlv_data.decode('utf-8', errors='ignore')[:50]
                            features['cdp_device_id_len'] = len(tlv_data)
                        elif tlv_type == 0x0002:  # Addresses
                            features['cdp_addresses_count'] = self._parse_cdp_addresses(tlv_data)
                        elif tlv_type == 0x0003 and tlv_data:  # Port ID
                            features['cdp_port_id'] = tlv_data.decode('utf-8', errors='ignore')[:50]
                            features['cdp_port_id_len'] = len(tlv_data)
                        elif tlv_type == 0x0004 and len(tlv_data) >= 4:  # Capabilities
                            caps = int.from_bytes(tlv_data[:4], 'big')
                            features['cdp_capabilities_flags'] = caps
                            features['cdp_capabilities_router'] = bool(caps & 0x01)
                            features['cdp_capabilities_bridge'] = bool(caps & 0x02)
                            features['cdp_capabilities_switch'] = bool(caps & 0x04)
                            features['cdp_capabilities_host'] = bool(caps & 0x08)
                        elif tlv_type == 0x0005 and tlv_data:  # Software Version
                            features['cdp_software_version'] = tlv_data.decode('utf-8', errors='ignore')[:100]
                            features['cdp_software_version_len'] = len(tlv_data)
                        elif tlv_type == 0x0006 and tlv_data:  # Platform
                            features['cdp_platform'] = tlv_data.decode('utf-8', errors='ignore')[:50]
                            features['cdp_platform_len'] = len(tlv_data)
                        elif tlv_type == 0x0016 and len(tlv_data) >= 4:  # Power Consumption
                            features['cdp_power_consumption'] = int.from_bytes(tlv_data[:4], 'big')
                        elif tlv_type == 0x000E and len(tlv_data) >= 2:  # Native VLAN
                            features['cdp_vlan_id'] = int.from_bytes(tlv_data[:2], 'big')
                        elif tlv_type == 0x000B and len(tlv_data) >= 1:  # Duplex
                            duplex_val = tlv_data[0]
                            features['cdp_duplex'] = 'full' if duplex_val == 1 else 'half'
                        
                        tlv_offset += tlv_length
                    
                    features['cdp_tlv_count'] = tlv_count
                    features['cdp_tlvs'] = max(1, tlv_count)  # Used for flow detection
                    
        except Exception as e:
            self.logger.debug(f"CDP parsing error: {e}")
        
        return features
    
    def _extract_arp_features_pyshark(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract ARP features using enhanced parsing."""
        features = {
            'arp_hardware_type': 1,
            'arp_protocol_type': 0x0800,
            'arp_hardware_size': 6,
            'arp_protocol_size': 4,
            'arp_opcode': 1,
            'arp_sender_hw_addr': '',
            'arp_sender_proto_addr': '',
            'arp_target_hw_addr': '',
            'arp_target_proto_addr': '',
            'arp_is_request': True,
            'arp_is_reply': False,
            'arp_is_gratuitous': False,
            'arp_packet_size': 0
        }
        
        try:
            # Find ARP in packet - look for ARP header
            arp_offset = self._find_arp_start(packet_data)
            
            if arp_offset >= 0 and arp_offset + 28 <= len(packet_data):
                # Parse ARP header (28 bytes minimum)
                features['arp_hardware_type'] = int.from_bytes(packet_data[arp_offset:arp_offset+2], 'big')
                features['arp_protocol_type'] = int.from_bytes(packet_data[arp_offset+2:arp_offset+4], 'big')
                features['arp_hardware_size'] = packet_data[arp_offset+4]
                features['arp_protocol_size'] = packet_data[arp_offset+5]
                features['arp_opcode'] = int.from_bytes(packet_data[arp_offset+6:arp_offset+8], 'big')
                
                # Hardware and protocol addresses
                hw_size = features['arp_hardware_size']
                proto_size = features['arp_protocol_size']
                
                if arp_offset + 8 + 2*hw_size + 2*proto_size <= len(packet_data):
                    # Sender hardware address
                    sender_hw = packet_data[arp_offset+8:arp_offset+8+hw_size]
                    features['arp_sender_hw_addr'] = sender_hw.hex(':')
                    
                    # Sender protocol address
                    sender_proto = packet_data[arp_offset+8+hw_size:arp_offset+8+hw_size+proto_size]
                    if proto_size == 4:  # IPv4
                        features['arp_sender_proto_addr'] = '.'.join(str(b) for b in sender_proto)
                    
                    # Target hardware address
                    target_hw = packet_data[arp_offset+8+hw_size+proto_size:arp_offset+8+2*hw_size+proto_size]
                    features['arp_target_hw_addr'] = target_hw.hex(':')
                    
                    # Target protocol address
                    target_proto = packet_data[arp_offset+8+2*hw_size+proto_size:arp_offset+8+2*hw_size+2*proto_size]
                    if proto_size == 4:  # IPv4
                        features['arp_target_proto_addr'] = '.'.join(str(b) for b in target_proto)
                    
                    # Determine ARP type
                    opcode = features['arp_opcode']
                    features['arp_is_request'] = (opcode == 1)
                    features['arp_is_reply'] = (opcode == 2)
                    
                    # Check for gratuitous ARP
                    if features['arp_sender_proto_addr'] == features['arp_target_proto_addr']:
                        features['arp_is_gratuitous'] = True
                
                features['arp_packet_size'] = len(packet_data)
                
        except Exception as e:
            self.logger.debug(f"ARP parsing error: {e}")
        
        return features
    
    def _extract_dhcp_features_pyshark(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract DHCP features using enhanced parsing."""
        features = {
            'dhcp_opcode': 1,
            'dhcp_hardware_type': 1,
            'dhcp_hardware_addr_len': 6,
            'dhcp_hops': 0,
            'dhcp_transaction_id': 0,
            'dhcp_seconds_elapsed': 0,
            'dhcp_flags': 0,
            'dhcp_client_ip': '',
            'dhcp_your_ip': '',
            'dhcp_server_ip': '',
            'dhcp_gateway_ip': '',
            'dhcp_client_mac': '',
            'dhcp_magic_cookie': 0,
            'dhcp_message_type': 1,
            'dhcp_requested_ip': '',
            'dhcp_server_identifier': '',
            'dhcp_lease_time': 0,
            'dhcp_options_count': 0,
            'dhcp_vendor_class': '',
            'dhcp_hostname': '',
            'dhcp_domain_name': '',
            'is_dhcp': False
        }
        
        try:
            # Find DHCP/BOOTP in packet
            dhcp_offset = self._find_dhcp_start(packet_data)
            
            if dhcp_offset >= 0 and dhcp_offset + 240 <= len(packet_data):
                # Parse BOOTP/DHCP header (240 bytes)
                features['dhcp_opcode'] = packet_data[dhcp_offset]
                features['dhcp_hardware_type'] = packet_data[dhcp_offset+1]
                features['dhcp_hardware_addr_len'] = packet_data[dhcp_offset+2]
                features['dhcp_hops'] = packet_data[dhcp_offset+3]
                
                features['dhcp_transaction_id'] = int.from_bytes(packet_data[dhcp_offset+4:dhcp_offset+8], 'big')
                features['dhcp_seconds_elapsed'] = int.from_bytes(packet_data[dhcp_offset+8:dhcp_offset+10], 'big')
                features['dhcp_flags'] = int.from_bytes(packet_data[dhcp_offset+10:dhcp_offset+12], 'big')
                
                # IP addresses
                client_ip = packet_data[dhcp_offset+12:dhcp_offset+16]
                features['dhcp_client_ip'] = '.'.join(str(b) for b in client_ip)
                
                your_ip = packet_data[dhcp_offset+16:dhcp_offset+20]
                features['dhcp_your_ip'] = '.'.join(str(b) for b in your_ip)
                
                server_ip = packet_data[dhcp_offset+20:dhcp_offset+24]
                features['dhcp_server_ip'] = '.'.join(str(b) for b in server_ip)
                
                gateway_ip = packet_data[dhcp_offset+24:dhcp_offset+28]
                features['dhcp_gateway_ip'] = '.'.join(str(b) for b in gateway_ip)
                
                # Client hardware address (16 bytes, but usually 6 for MAC)
                client_mac = packet_data[dhcp_offset+28:dhcp_offset+34]
                features['dhcp_client_mac'] = client_mac.hex(':')
                
                # Magic cookie at offset 236
                if dhcp_offset + 240 <= len(packet_data):
                    magic_cookie = int.from_bytes(packet_data[dhcp_offset+236:dhcp_offset+240], 'big')
                    features['dhcp_magic_cookie'] = magic_cookie
                    
                    # Parse options if magic cookie is correct (0x63825363)
                    if magic_cookie == 0x63825363 and dhcp_offset + 240 < len(packet_data):
                        options_data = packet_data[dhcp_offset+240:]
                        features.update(self._parse_dhcp_options(options_data))
                        features['is_dhcp'] = True  # Mark as DHCP if magic cookie is valid
                
        except Exception as e:
            self.logger.debug(f"DHCP parsing error: {e}")
        
        return features
    
    def _extract_dtp_features_pyshark(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract DTP (Dynamic Trunking Protocol) features."""
        features = {
            'dtp_version': 0,
            'dtp_domain_length': 0,
            'dtp_domain_name': '',
            'dtp_status': 0,
            'dtp_type': 0,
            'dtp_neighbor_length': 0,
            'dtp_neighbor_info': '',
            'dtp_frame_isl': False,
            'dtp_frame_802dot1q': False,
            'dtp_tlv_count': 0
        }
        
        try:
            # Find DTP in packet - look for DTP TLVs
            offset = self._find_dtp_start(packet_data)
            
            if offset >= 0:
                tlv_count = 0
                
                while offset + 4 <= len(packet_data):
                    tlv_type = int.from_bytes(packet_data[offset:offset+2], 'big')
                    tlv_length = int.from_bytes(packet_data[offset+2:offset+4], 'big')
                    
                    if tlv_length < 4 or offset + tlv_length > len(packet_data):
                        break
                    
                    tlv_count += 1
                    tlv_data = packet_data[offset+4:offset+tlv_length]
                    
                    if tlv_type == 0x0001 and tlv_data:  # Domain
                        features['dtp_domain_name'] = tlv_data.decode('utf-8', errors='ignore')[:50]
                        features['dtp_domain_length'] = len(tlv_data)
                    elif tlv_type == 0x0002 and len(tlv_data) >= 1:  # Status
                        features['dtp_status'] = tlv_data[0]
                    elif tlv_type == 0x0003 and len(tlv_data) >= 1:  # Type
                        features['dtp_type'] = tlv_data[0]
                        # Check for ISL vs 802.1Q
                        if tlv_data[0] & 0x01:
                            features['dtp_frame_isl'] = True
                        if tlv_data[0] & 0x02:
                            features['dtp_frame_802dot1q'] = True
                    elif tlv_type == 0x0004 and tlv_data:  # Neighbor
                        features['dtp_neighbor_info'] = tlv_data.hex()[:50]
                        features['dtp_neighbor_length'] = len(tlv_data)
                    
                    offset += tlv_length
                
                features['dtp_tlv_count'] = tlv_count
                
        except Exception as e:
            self.logger.debug(f"DTP parsing error: {e}")
        
        return features
    
    # Helper methods
    def _find_cdp_start(self, packet_data: bytes) -> int:
        """Find CDP header start in packet data."""
        # Look for CDP after LLC/SNAP (OUI 00:00:0c, PID 0x2000)
        for i in range(len(packet_data) - 10):
            if (packet_data[i:i+3] == b'\x00\x00\x0c' and 
                packet_data[i+3:i+5] == b'\x20\x00'):
                return i + 5  # Skip SNAP header
        return -1
    
    def _find_arp_start(self, packet_data: bytes) -> int:
        """Find ARP header start in packet data."""
        # Look for ARP EtherType (0x0806) or after Ethernet header
        for i in range(len(packet_data) - 2):
            if packet_data[i:i+2] == b'\x08\x06':
                return i + 2
        # Try after standard Ethernet header (14 bytes)
        if len(packet_data) > 14:
            return 14
        return -1
    
    def _find_dhcp_start(self, packet_data: bytes) -> int:
        """Find DHCP/BOOTP header start in packet data."""
        # Look after UDP header (usually at IP + UDP headers)
        # DHCP uses UDP ports 67/68
        for i in range(len(packet_data) - 8):
            # Look for UDP header with ports 67 or 68
            if (i + 8 <= len(packet_data) and 
                (packet_data[i:i+2] == b'\x00\x43' or  # Port 67
                 packet_data[i:i+2] == b'\x00\x44' or  # Port 68
                 packet_data[i+2:i+4] == b'\x00\x43' or  # Dest port 67
                 packet_data[i+2:i+4] == b'\x00\x44')):  # Dest port 68
                return i + 8  # Skip UDP header
        return -1
    
    def _find_dtp_start(self, packet_data: bytes) -> int:
        """Find DTP header start in packet data."""
        # Look for DTP after LLC/SNAP (OUI 00:00:0c, PID 0x2004)
        for i in range(len(packet_data) - 10):
            if (packet_data[i:i+3] == b'\x00\x00\x0c' and 
                packet_data[i+3:i+5] == b'\x20\x04'):
                return i + 5  # Skip SNAP header
        return -1
    
    def _parse_cdp_addresses(self, tlv_data: bytes) -> int:
        """Parse CDP addresses TLV and return count."""
        try:
            if len(tlv_data) >= 4:
                return int.from_bytes(tlv_data[:4], 'big')
        except:
            pass
        return 0
    
    def _parse_dhcp_options(self, options_data: bytes) -> Dict[str, Any]:
        """Parse DHCP options and extract key information."""
        options = {
            'dhcp_options_count': 0,
            'dhcp_message_type': 0,
            'dhcp_requested_ip': '',
            'dhcp_server_identifier': '',
            'dhcp_lease_time': 0,
            'dhcp_vendor_class': '',
            'dhcp_hostname': '',
            'dhcp_domain_name': ''
        }
        
        try:
            offset = 0
            count = 0
            
            while offset < len(options_data):
                if offset >= len(options_data):
                    break
                    
                option_code = options_data[offset]
                if option_code == 0:  # Pad
                    offset += 1
                    continue
                elif option_code == 255:  # End
                    break
                    
                if offset + 1 >= len(options_data):
                    break
                    
                option_len = options_data[offset + 1]
                if offset + 2 + option_len > len(options_data):
                    break
                    
                option_data = options_data[offset + 2:offset + 2 + option_len]
                count += 1
                
                if option_code == 53 and len(option_data) >= 1:  # Message Type
                    options['dhcp_message_type'] = option_data[0]
                elif option_code == 50 and len(option_data) >= 4:  # Requested IP
                    options['dhcp_requested_ip'] = '.'.join(str(b) for b in option_data[:4])
                elif option_code == 54 and len(option_data) >= 4:  # Server Identifier
                    options['dhcp_server_identifier'] = '.'.join(str(b) for b in option_data[:4])
                elif option_code == 51 and len(option_data) >= 4:  # Lease Time
                    options['dhcp_lease_time'] = int.from_bytes(option_data[:4], 'big')
                elif option_code == 60 and option_data:  # Vendor Class
                    options['dhcp_vendor_class'] = option_data.decode('utf-8', errors='ignore')[:50]
                elif option_code == 12 and option_data:  # Hostname
                    options['dhcp_hostname'] = option_data.decode('utf-8', errors='ignore')[:50]
                elif option_code == 15 and option_data:  # Domain Name
                    options['dhcp_domain_name'] = option_data.decode('utf-8', errors='ignore')[:50]
                
                offset += 2 + option_len
            
            options['dhcp_options_count'] = count
            
        except Exception as e:
            logger.debug(f"DHCP options parsing error: {e}")
        
        return options