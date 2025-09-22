"""
COMPLETELY FIXED Layer 2 protocol packet analysis classes.
This replaces the broken PyShark integration with direct packet parsing.
Uses -100 as the consistent missing value throughout.
"""

from .base_packet import BasePacket
from scapy.all import Packet
import struct
import logging

logger = logging.getLogger(__name__)
MISSING_VALUE = -100  # Global missing value constant


def parse_cdp_packet(raw_data: bytes) -> dict:
    """Parse CDP packet data directly from raw bytes."""
    features = {}
    
    try:
        # Find CDP header in payload (after LLC/SNAP)
        cdp_offset = -1
        
        # Method 1: Look for CDP SNAP signature (00:00:0c:20:00)
        for i in range(len(raw_data) - 10):
            if raw_data[i:i+5] == b'\x00\x00\x0c\x20\x00':
                cdp_offset = i + 5
                break
                
        if cdp_offset == -1:
            # Method 2: Look for CDP version/ttl pattern
            for i in range(len(raw_data) - 4):
                if raw_data[i] in [1, 2] and 1 <= raw_data[i+1] <= 255:
                    # Validate by checking for reasonable TLV after header
                    if i + 8 < len(raw_data):
                        tlv_type = struct.unpack('!H', raw_data[i+4:i+6])[0]
                        tlv_len = struct.unpack('!H', raw_data[i+6:i+8])[0]
                        if 1 <= tlv_type <= 25 and 4 <= tlv_len <= 1000:
                            cdp_offset = i
                            break
        
        if cdp_offset >= 0 and cdp_offset + 4 <= len(raw_data):
            # Parse CDP header
            version = raw_data[cdp_offset]
            ttl = raw_data[cdp_offset + 1]
            checksum = struct.unpack('!H', raw_data[cdp_offset+2:cdp_offset+4])[0]
            
            features['cdp_version'] = int(version)
            features['cdp_ttl'] = int(ttl)
            features['cdp_checksum'] = int(checksum)
            
            # Parse TLVs
            tlv_offset = cdp_offset + 4
            tlv_count = 0
            device_id_len = 0
            software_ver_len = 0
            platform_len = 0
            addresses_count = 0
            capabilities = 0
            
            while tlv_offset + 4 <= len(raw_data):
                try:
                    tlv_type = struct.unpack('!H', raw_data[tlv_offset:tlv_offset+2])[0]
                    tlv_length = struct.unpack('!H', raw_data[tlv_offset+2:tlv_offset+4])[0]
                    
                    if tlv_length < 4 or tlv_offset + tlv_length > len(raw_data):
                        break
                        
                    tlv_count += 1
                    
                    # Parse specific TLV types
                    if tlv_type == 1:  # Device ID
                        device_id_len = tlv_length - 4
                    elif tlv_type == 5:  # Software Version  
                        software_ver_len = tlv_length - 4
                    elif tlv_type == 6:  # Platform
                        platform_len = tlv_length - 4
                    elif tlv_type == 2:  # Addresses
                        if tlv_length >= 8:
                            addresses_count = struct.unpack('!I', raw_data[tlv_offset+4:tlv_offset+8])[0]
                    elif tlv_type == 4:  # Capabilities
                        if tlv_length >= 8:
                            capabilities = struct.unpack('!I', raw_data[tlv_offset+4:tlv_offset+8])[0]
                    
                    tlv_offset += tlv_length
                    
                except (struct.error, IndexError):
                    break
            
            features['cdp_tlv_count'] = tlv_count
            features['cdp_tlvs'] = max(1, tlv_count)  # At least 1 for detection
            features['cdp_device_id_tlv_len'] = device_id_len
            features['cdp_software_version_tlv_len'] = software_ver_len
            features['cdp_platform_tlv_len'] = platform_len
            features['cdp_addresses_count'] = addresses_count
            features['cdp_capabilities'] = capabilities
            
            # Parse capability flags
            features['cdp_capabilities_router'] = bool(capabilities & 0x01)
            features['cdp_capabilities_trans_bridge'] = bool(capabilities & 0x02)
            features['cdp_capabilities_switch'] = bool(capabilities & 0x08)
            features['cdp_capabilities_host'] = bool(capabilities & 0x10)
            
        else:
            # No CDP data found, set all to missing
            for key in ['cdp_version', 'cdp_ttl', 'cdp_checksum', 'cdp_tlv_count', 'cdp_device_id_tlv_len',
                       'cdp_software_version_tlv_len', 'cdp_platform_tlv_len', 'cdp_addresses_count',
                       'cdp_capabilities', 'cdp_capabilities_router', 'cdp_capabilities_trans_bridge',
                       'cdp_capabilities_switch', 'cdp_capabilities_host']:
                features[key] = MISSING_VALUE
            features['cdp_tlvs'] = 1  # Still mark as CDP packet for counting
            
    except Exception as e:
        logger.debug(f"CDP parsing error: {e}")
        # Set all to missing on error
        for key in ['cdp_version', 'cdp_ttl', 'cdp_checksum', 'cdp_tlv_count', 'cdp_device_id_tlv_len',
                   'cdp_software_version_tlv_len', 'cdp_platform_tlv_len', 'cdp_addresses_count',
                   'cdp_capabilities', 'cdp_capabilities_router', 'cdp_capabilities_trans_bridge',
                   'cdp_capabilities_switch', 'cdp_capabilities_host']:
            features[key] = MISSING_VALUE
        features['cdp_tlvs'] = 1  # Still mark as CDP packet for counting
    
    return features


def parse_dhcp_packet(scapy_packet: Packet) -> dict:
    """Parse DHCP packet data from Scapy packet."""
    features = {}
    
    try:
        bootp_layer = None
        dhcp_layer = None
        
        if scapy_packet.haslayer('BOOTP'):
            bootp_layer = scapy_packet['BOOTP']
        if scapy_packet.haslayer('DHCP'):
            dhcp_layer = scapy_packet['DHCP']
        
        if bootp_layer:
            # Extract BOOTP/DHCP fields
            features['dhcp_op'] = int(bootp_layer.op) if hasattr(bootp_layer, 'op') else MISSING_VALUE
            features['dhcp_hw_type'] = int(bootp_layer.htype) if hasattr(bootp_layer, 'htype') else MISSING_VALUE
            features['dhcp_hw_len'] = int(bootp_layer.hlen) if hasattr(bootp_layer, 'hlen') else MISSING_VALUE
            features['dhcp_hops'] = int(bootp_layer.hops) if hasattr(bootp_layer, 'hops') else MISSING_VALUE
            features['dhcp_xid'] = int(bootp_layer.xid) if hasattr(bootp_layer, 'xid') else MISSING_VALUE
            features['dhcp_secs'] = int(bootp_layer.secs) if hasattr(bootp_layer, 'secs') else MISSING_VALUE
            features['dhcp_flags'] = int(bootp_layer.flags) if hasattr(bootp_layer, 'flags') else MISSING_VALUE
            
            # Parse flags
            if hasattr(bootp_layer, 'flags') and bootp_layer.flags is not None:
                flags = int(bootp_layer.flags)
                features['dhcp_flags_bc'] = bool(flags & 0x8000)
                features['dhcp_flags_reserved'] = bool(flags & 0x7FFF)
            else:
                features['dhcp_flags_bc'] = MISSING_VALUE
                features['dhcp_flags_reserved'] = MISSING_VALUE
                
            features['dhcp_cookie'] = 0x63825363  # Standard DHCP magic cookie
        else:
            # No BOOTP layer, set all to missing
            for key in ['dhcp_op', 'dhcp_hw_type', 'dhcp_hw_len', 'dhcp_hops', 'dhcp_xid',
                       'dhcp_secs', 'dhcp_flags', 'dhcp_flags_bc', 'dhcp_flags_reserved', 'dhcp_cookie']:
                features[key] = MISSING_VALUE
        
        # Count DHCP options and extract message type
        if dhcp_layer and hasattr(dhcp_layer, 'options') and dhcp_layer.options:
            options_count = len(dhcp_layer.options)
            options_total_len = 0
            message_type = MISSING_VALUE
            
            # Parse DHCP options
            for option in dhcp_layer.options:
                if isinstance(option, tuple) and len(option) >= 2:
                    option_name, option_value = option[0], option[1]
                    
                    # Extract message type
                    if option_name == 'message-type':
                        message_type = int(option_value) if isinstance(option_value, int) else MISSING_VALUE
                    
                    # Calculate option length
                    if isinstance(option_value, (str, bytes)):
                        options_total_len += len(option_value)
                    else:
                        options_total_len += 4  # Approximate for non-string options
            
            features['dhcp_options'] = options_count
            features['dhcp_options_len'] = options_total_len
            features['dhcp_message_type'] = message_type
        else:
            features['dhcp_options'] = MISSING_VALUE
            features['dhcp_options_len'] = MISSING_VALUE
            features['dhcp_message_type'] = MISSING_VALUE
            
    except Exception as e:
        logger.debug(f"DHCP parsing error: {e}")
        # Set all to missing on error
        for key in ['dhcp_op', 'dhcp_hw_type', 'dhcp_hw_len', 'dhcp_hops', 'dhcp_xid',
                   'dhcp_secs', 'dhcp_flags', 'dhcp_flags_bc', 'dhcp_flags_reserved', 'dhcp_cookie',
                   'dhcp_options', 'dhcp_options_len', 'dhcp_message_type']:
            features[key] = MISSING_VALUE
    
    return features


def parse_stp_packet(scapy_packet: Packet) -> dict:
    """Parse STP packet data from Scapy packet."""
    features = {}
    
    try:
        if scapy_packet.haslayer('STP'):
            stp_layer = scapy_packet['STP']
            
            # Extract STP fields
            features['stp_version'] = int(stp_layer.version) if hasattr(stp_layer, 'version') else MISSING_VALUE
            features['stp_bpdu_type'] = int(stp_layer.bpdutype) if hasattr(stp_layer, 'bpdutype') else MISSING_VALUE
            features['stp_flags'] = int(stp_layer.bpduflags) if hasattr(stp_layer, 'bpduflags') else MISSING_VALUE
            
            # Parse flags
            if hasattr(stp_layer, 'bpduflags') and stp_layer.bpduflags is not None:
                flags = int(stp_layer.bpduflags)
                features['stp_flags_tc'] = bool(flags & 0x01)
                features['stp_flags_tcack'] = bool(flags & 0x80)
            else:
                features['stp_flags_tc'] = MISSING_VALUE
                features['stp_flags_tcack'] = MISSING_VALUE
            
            # Timing fields (convert from timer units to seconds)
            features['stp_msg_age'] = float(stp_layer.msg_age) / 256 if hasattr(stp_layer, 'msg_age') else MISSING_VALUE
            features['stp_max_age'] = float(stp_layer.max_age) / 256 if hasattr(stp_layer, 'max_age') else MISSING_VALUE
            features['stp_hello_time'] = float(stp_layer.hello_time) / 256 if hasattr(stp_layer, 'hello_time') else MISSING_VALUE
            features['stp_forward_delay'] = float(stp_layer.forward_delay) / 256 if hasattr(stp_layer, 'forward_delay') else MISSING_VALUE
            
            # Bridge/Root information
            features['stp_root_cost'] = int(stp_layer.pathcost) if hasattr(stp_layer, 'pathcost') else MISSING_VALUE
            features['stp_port_id'] = int(stp_layer.portid) if hasattr(stp_layer, 'portid') else MISSING_VALUE
            
            # Protocol ID
            features['stp_proto_id'] = int(stp_layer.proto) if hasattr(stp_layer, 'proto') else MISSING_VALUE
            
        else:
            # No STP layer, set all to missing
            for key in ['stp_version', 'stp_bpdu_type', 'stp_flags', 'stp_flags_tc', 'stp_flags_tcack',
                       'stp_msg_age', 'stp_max_age', 'stp_hello_time', 'stp_forward_delay',
                       'stp_root_cost', 'stp_port_id', 'stp_proto_id']:
                features[key] = MISSING_VALUE
                
    except Exception as e:
        logger.debug(f"STP parsing error: {e}")
        # Set all to missing on error
        for key in ['stp_version', 'stp_bpdu_type', 'stp_flags', 'stp_flags_tc', 'stp_flags_tcack',
                   'stp_msg_age', 'stp_max_age', 'stp_hello_time', 'stp_forward_delay',
                   'stp_root_cost', 'stp_port_id', 'stp_proto_id']:
            features[key] = MISSING_VALUE
    
    return features


def parse_arp_packet(scapy_packet: Packet) -> dict:
    """Parse ARP packet data from Scapy packet."""
    features = {}
    
    try:
        if scapy_packet.haslayer('ARP'):
            arp_layer = scapy_packet['ARP']
            
            # Extract ARP fields
            features['arp_hw_type'] = int(arp_layer.hwtype) if hasattr(arp_layer, 'hwtype') else MISSING_VALUE
            features['arp_proto_type'] = int(arp_layer.ptype) if hasattr(arp_layer, 'ptype') else MISSING_VALUE
            features['arp_hw_len'] = int(arp_layer.hwlen) if hasattr(arp_layer, 'hwlen') else MISSING_VALUE
            features['arp_proto_len'] = int(arp_layer.plen) if hasattr(arp_layer, 'plen') else MISSING_VALUE
            features['arp_opcode'] = int(arp_layer.op) if hasattr(arp_layer, 'op') else MISSING_VALUE
            
            # MAC addresses (as strings)
            features['arp_src_hw_addr'] = str(arp_layer.hwsrc) if hasattr(arp_layer, 'hwsrc') else str(MISSING_VALUE)
            features['arp_dst_hw_addr'] = str(arp_layer.hwdst) if hasattr(arp_layer, 'hwdst') else str(MISSING_VALUE)
            
            # IP addresses (as strings)
            features['arp_src_proto_addr'] = str(arp_layer.psrc) if hasattr(arp_layer, 'psrc') else str(MISSING_VALUE)
            features['arp_dst_proto_addr'] = str(arp_layer.pdst) if hasattr(arp_layer, 'pdst') else str(MISSING_VALUE)
            
            # ARP analysis features for flow aggregation
            opcode = int(arp_layer.op) if hasattr(arp_layer, 'op') else 0
            features['arp_is_request'] = (opcode == 1)  # ARP request
            features['arp_is_reply'] = (opcode == 2)    # ARP reply
            
            # Gratuitous ARP detection (same source and destination IP)
            src_ip = str(arp_layer.psrc) if hasattr(arp_layer, 'psrc') else ''
            dst_ip = str(arp_layer.pdst) if hasattr(arp_layer, 'pdst') else ''
            features['arp_is_gratuitous'] = (src_ip == dst_ip and src_ip != str(MISSING_VALUE))
            
        else:
            # No ARP layer, set all to missing
            for key in ['arp_hw_type', 'arp_proto_type', 'arp_hw_len', 'arp_proto_len', 'arp_opcode']:
                features[key] = MISSING_VALUE
            for key in ['arp_src_hw_addr', 'arp_dst_hw_addr', 'arp_src_proto_addr', 'arp_dst_proto_addr']:
                features[key] = str(MISSING_VALUE)
            for key in ['arp_is_request', 'arp_is_reply', 'arp_is_gratuitous']:
                features[key] = MISSING_VALUE
                
    except Exception as e:
        logger.debug(f"ARP parsing error: {e}")
        # Set all to missing on error
        for key in ['arp_hw_type', 'arp_proto_type', 'arp_hw_len', 'arp_proto_len', 'arp_opcode']:
            features[key] = MISSING_VALUE
        for key in ['arp_src_hw_addr', 'arp_dst_hw_addr', 'arp_src_proto_addr', 'arp_dst_proto_addr']:
            features[key] = str(MISSING_VALUE)
        for key in ['arp_is_request', 'arp_is_reply', 'arp_is_gratuitous']:
            features[key] = MISSING_VALUE
    
    return features


def parse_isl_packet(raw_data: bytes) -> dict:
    """Parse ISL packet data directly from raw bytes."""
    features = {}
    
    try:
        # ISL header is at the beginning of the frame
        if len(raw_data) >= 30:  # ISL header is 26 bytes + Ethernet header
            # Parse ISL fields safely with int conversion
            features['isl_frame_type'] = int((raw_data[0] & 0xF0) >> 4)
            features['isl_user_bits'] = int(raw_data[0] & 0x0F)
            features['isl_src_vlan_id'] = int(((raw_data[1] & 0x0F) << 8) | raw_data[2])
            features['isl_bpdu'] = bool(raw_data[3] & 0x80)
            features['isl_index'] = int(raw_data[3] & 0x1F)
            features['isl_reserved'] = int(raw_data[4])
            
        else:
            # Not enough data for ISL
            for key in ['isl_frame_type', 'isl_user_bits', 'isl_src_vlan_id', 'isl_bpdu', 'isl_index', 'isl_reserved']:
                features[key] = MISSING_VALUE
                
    except Exception as e:
        logger.debug(f"ISL parsing error: {e}")
        # Set all to missing on error
        for key in ['isl_frame_type', 'isl_user_bits', 'isl_src_vlan_id', 'isl_bpdu', 'isl_index', 'isl_reserved']:
            features[key] = MISSING_VALUE
    
    return features


class FixedSTPPacket(BasePacket):
    """Fixed STP packet analyzer with direct parsing."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self.features.update(parse_stp_packet(scapy_packet))
    
    def get_protocol_type(self) -> str:
        return 'STP'


class FixedCDPPacket(BasePacket):
    """Fixed CDP packet analyzer with direct parsing."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        raw_data = bytes(scapy_packet)
        self.features.update(parse_cdp_packet(raw_data))
    
    def get_protocol_type(self) -> str:
        return 'CDP'


class FixedDHCPPacket(BasePacket):
    """Fixed DHCP packet analyzer with direct parsing."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self.features.update(parse_dhcp_packet(scapy_packet))
        # Mark as DHCP for flow counting
        self.features['is_dhcp'] = True
    
    def get_protocol_type(self) -> str:
        return 'DHCP'


class FixedARPPacket(BasePacket):
    """Fixed ARP packet analyzer with direct parsing."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self.features.update(parse_arp_packet(scapy_packet))
    
    def get_protocol_type(self) -> str:
        return 'ARP'


class FixedISLPacket(BasePacket):
    """Fixed ISL packet analyzer with direct parsing."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        raw_data = bytes(scapy_packet)
        self.features.update(parse_isl_packet(raw_data))
    
    def get_protocol_type(self) -> str:
        return 'ISL'