"""
Layer 2 protocol packet analysis classes (STP, CDP, LLDP, etc.).
"""

from .base_packet import BasePacket
from scapy.all import Packet
from typing import Dict, Any


class STPPacket(BasePacket):
    """Spanning Tree Protocol packet analyzer."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_stp_features()
    
    def get_protocol_type(self) -> str:
        """Override to ensure STP packets are correctly identified."""
        return 'STP'
    
    def _extract_stp_features(self):
        """Extract comprehensive STP-specific features."""
        try:
            if self.packet.haslayer('STP'):
                stp_layer = self.packet['STP']
                
                self.features['stp_proto_id'] = int(stp_layer.proto) if hasattr(stp_layer, 'proto') else 0
                self.features['stp_version'] = int(stp_layer.version) if hasattr(stp_layer, 'version') else 0
                self.features['stp_bpdu_type'] = int(stp_layer.bpdutype) if hasattr(stp_layer, 'bpdutype') else 0
                
                if hasattr(stp_layer, 'bpduflags'):
                    flags = int(stp_layer.bpduflags)
                    self.features['stp_flags'] = flags
                    self.features['stp_flags_tc'] = bool(flags & 0x01)
                    self.features['stp_flags_tcack'] = bool(flags & 0x80)
                else:
                    self.features['stp_flags'] = 0
                    self.features['stp_flags_tc'] = False
                    self.features['stp_flags_tcack'] = False
                
                self.features['stp_msg_age'] = int(stp_layer.msg_age) if hasattr(stp_layer, 'msg_age') else 0
                self.features['stp_max_age'] = int(stp_layer.max_age) if hasattr(stp_layer, 'max_age') else 0
                self.features['stp_hello_time'] = int(stp_layer.hello_time) if hasattr(stp_layer, 'hello_time') else 0
                self.features['stp_forward_delay'] = int(stp_layer.forward_delay) if hasattr(stp_layer, 'forward_delay') else 0
                self.features['stp_hello'] = self.features['stp_hello_time']
                self.features['stp_forward'] = self.features['stp_forward_delay']
                
                max_age = self.features['stp_max_age']
                if max_age > 0:
                    self.features['stp_age_div_max_age'] = self.features['stp_msg_age'] / max_age
                else:
                    self.features['stp_age_div_max_age'] = 0
                
                if hasattr(stp_layer, 'rootid'):
                    root_id = int(stp_layer.rootid) if isinstance(stp_layer.rootid, (int, str)) else 0
                    self.features['stp_root_id'] = str(stp_layer.rootid)
                    self.features['stp_root_identifier_prio'] = (root_id >> 48) & 0xFFFF
                    self.features['stp_root_identifier_ext'] = (root_id >> 32) & 0xFFFF
                    self.features['stp_root_cost'] = int(stp_layer.pathcost) if hasattr(stp_layer, 'pathcost') else 0
                else:
                    self.features['stp_root_id'] = ''
                    self.features['stp_root_identifier_prio'] = 0
                    self.features['stp_root_identifier_ext'] = 0
                    self.features['stp_root_cost'] = 0
                
                if hasattr(stp_layer, 'bridgeid'):
                    bridge_id = int(stp_layer.bridgeid) if isinstance(stp_layer.bridgeid, (int, str)) else 0
                    self.features['stp_bridge_id'] = str(stp_layer.bridgeid)
                    self.features['stp_bridge_identifier_prio'] = (bridge_id >> 48) & 0xFFFF
                    self.features['stp_bridge_identifier_ext'] = (bridge_id >> 32) & 0xFFFF
                else:
                    self.features['stp_bridge_id'] = ''
                    self.features['stp_bridge_identifier_prio'] = 0
                    self.features['stp_bridge_identifier_ext'] = 0
                
                self.features['stp_port_id'] = int(stp_layer.portid) if hasattr(stp_layer, 'portid') else 0
                
            else:
                self._set_default_stp_features()
                
        except Exception:
            self._set_default_stp_features()
    
    def _set_default_stp_features(self):
        """Set default STP features."""
        stp_defaults = {
            'stp_proto_id': 0,
            'stp_version': 0,
            'stp_bpdu_type': 0,
            'stp_flags': 0,
            'stp_flags_tc': False,
            'stp_flags_tcack': False,
            'stp_msg_age': 0,
            'stp_max_age': 0,
            'stp_hello_time': 0,
            'stp_forward_delay': 0,
            'stp_hello': 0,
            'stp_forward': 0,
            'stp_age_div_max_age': 0,
            'stp_root_id': '',
            'stp_bridge_id': '',
            'stp_root_identifier_prio': 0,
            'stp_root_identifier_ext': 0,
            'stp_root_cost': 0,
            'stp_bridge_identifier_prio': 0,
            'stp_bridge_identifier_ext': 0,
            'stp_port_id': 0,
        }
        self.features.update(stp_defaults)


class CDPPacket(BasePacket):
    """Cisco Discovery Protocol packet analyzer."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_cdp_features()
    
    def get_protocol_type(self) -> str:
        """Override to ensure CDP packets are correctly identified."""
        return 'CDP'
    
    def _extract_cdp_features(self):
        """Extract comprehensive CDP-specific features using payload-based detection."""
        try:
            # This class is only created for confirmed CDP packets, so extract directly
            if self._try_pyshark_cdp_extraction():
                return
            
            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
            
            if self._validate_cdp_structure(raw_payload):
                cdp_offset = self._find_cdp_header_offset(raw_payload)
                
                if cdp_offset >= 0 and len(raw_payload) >= cdp_offset + 4:
                    self.features['cdp_version'] = raw_payload[cdp_offset] if cdp_offset < len(raw_payload) else 0
                    self.features['cdp_ttl'] = raw_payload[cdp_offset + 1] if cdp_offset + 1 < len(raw_payload) else 0
                    if cdp_offset + 4 <= len(raw_payload):
                        self.features['cdp_checksum_status'] = int.from_bytes(raw_payload[cdp_offset + 2:cdp_offset + 4], 'big')
                    else:
                        self.features['cdp_checksum_status'] = 0
                else:
                    self.features['cdp_version'] = 0
                    self.features['cdp_ttl'] = 0
                    self.features['cdp_checksum_status'] = 0
            else:
                self.features['cdp_version'] = 0
                self.features['cdp_ttl'] = 0
                self.features['cdp_checksum_status'] = 0
            
            tlv_data = self._parse_cdp_tlvs(raw_payload[cdp_offset + 4:] if cdp_offset >= 0 else raw_payload)
            
            self.features['cdp_tlvs'] = tlv_data['tlv_count']
            self.features['cdp_addresses_count'] = tlv_data['addresses_count']
            
            # Device information TLVs
            self.features['cdp_device_id_tlv_len'] = tlv_data.get('device_id_len', 0)
            self.features['cdp_software_version_tlv_len'] = tlv_data.get('software_version_len', 0)
            self.features['cdp_platform_tlv_len'] = tlv_data.get('platform_len', 0)
            self.features['cdp_platform'] = tlv_data.get('platform', '')
            
            # Address TLVs
            self.features['cdp_addresses_tlv_len'] = tlv_data.get('addresses_tlv_len', 0)
            self.features['cdp_addresses_sum_len'] = tlv_data.get('addresses_sum_len', 0)
            self.features['cdp_addresses_sum_protocol_len'] = tlv_data.get('addresses_sum_protocol_len', 0)
            self.features['cdp_management_addresses_sum_len'] = tlv_data.get('mgmt_addresses_sum_len', 0)
            self.features['cdp_management_addresses_sum_protocol_len'] = tlv_data.get('mgmt_addresses_sum_protocol_len', 0)
            
            # Port and capabilities
            self.features['cdp_port_id_tlv_len'] = tlv_data.get('port_id_len', 0)
            self.features['cdp_capabilities_tlv_len'] = tlv_data.get('capabilities_len', 0)
            
            # Capability flags
            capabilities = tlv_data.get('capabilities_flags', 0)
            self.features['cdp_capabilities'] = capabilities
            self.features['cdp_capabilities_router'] = bool(capabilities & 0x01)
            self.features['cdp_capabilities_trans_bridge'] = bool(capabilities & 0x02)
            self.features['cdp_capabilities_src_bridge'] = bool(capabilities & 0x04)
            self.features['cdp_capabilities_switch'] = bool(capabilities & 0x08)
            self.features['cdp_capabilities_host'] = bool(capabilities & 0x10)
            self.features['cdp_capabilities_igmp'] = bool(capabilities & 0x20)
            self.features['cdp_capabilities_repeater'] = bool(capabilities & 0x40)
            self.features['cdp_capabilities_voip_phone'] = bool(capabilities & 0x80)
            self.features['cdp_capabilities_remote'] = bool(capabilities & 0x100)
            self.features['cdp_capabilities_cvta'] = bool(capabilities & 0x200)
            self.features['cdp_capabilities_mac_relay'] = bool(capabilities & 0x400)
            
            # Protocol hello and VTP
            self.features['cdp_hello_tlv_len'] = tlv_data.get('hello_tlv_len', 0)
            self.features['cdp_hello_oui'] = tlv_data.get('hello_oui', 0)
            self.features['cdp_hello_num_unknown'] = tlv_data.get('hello_num_unknown', 0)
            self.features['cdp_hello_management_vlan'] = tlv_data.get('hello_management_vlan', 0)
            self.features['cdp_vtp_management_tlv_len'] = tlv_data.get('vtp_management_len', 0)
            
            # Native VLAN
            self.features['cdp_vlan_native_tlv_len'] = tlv_data.get('native_vlan_len', 0)
            self.features['cdp_vlan_native_native_vlan'] = tlv_data.get('native_vlan_id', 0)
            
            # Duplex
            self.features['cdp_duplex_tlv_len'] = tlv_data.get('duplex_len', 0)
            self.features['cdp_duplex'] = tlv_data.get('duplex_value', 0)
            
            # Power features
            self.features['cdp_power_tlv_len'] = tlv_data.get('power_len', 0)
            self.features['cdp_power_request_id'] = tlv_data.get('power_request_id', 0)
            self.features['cdp_power_management_id'] = tlv_data.get('power_management_id', 0)
            self.features['cdp_power_sum'] = tlv_data.get('power_sum', 0)
            
            # Spare pair PoE
            self.features['cdp_spare_pair_tlv_len'] = tlv_data.get('spare_pair_len', 0)
            self.features['cdp_spare_poe_tlv_poe'] = tlv_data.get('spare_poe_poe', 0)
            self.features['cdp_spare_poe_tlv_spare_pair_arch'] = tlv_data.get('spare_pair_arch', 0)
            self.features['cdp_spare_poe_tlv_req_spare_pair_poe'] = tlv_data.get('req_spare_pair_poe', 0)
            self.features['cdp_spare_poe_tlv_pse_spare_pair_poe'] = tlv_data.get('pse_spare_pair_poe', 0)
                
        except Exception as e:
            self._set_default_cdp_features()
    
    def _parse_cdp_tlvs(self, payload: bytes) -> dict:
        """Parse CDP TLVs and extract detailed information."""
        tlv_data = {
            'tlv_count': 0,
            'addresses_count': 0,
            'device_id_len': 0,
            'software_version_len': 0,
            'platform_len': 0,
            'platform': '',
            'addresses_tlv_len': 0,
            'addresses_sum_len': 0,
            'addresses_sum_protocol_len': 0,
            'mgmt_addresses_sum_len': 0,
            'mgmt_addresses_sum_protocol_len': 0,
            'port_id_len': 0,
            'capabilities_len': 0,
            'capabilities_flags': 0,
            'hello_tlv_len': 0,
            'hello_oui': 0,
            'hello_num_unknown': 0,
            'hello_management_vlan': 0,
            'vtp_management_len': 0,
            'native_vlan_len': 0,
            'native_vlan_id': 0,
            'duplex_len': 0,
            'duplex_value': 0,
            'power_len': 0,
            'power_request_id': 0,
            'power_management_id': 0,
            'power_sum': 0,
            'spare_pair_len': 0,
            'spare_poe_poe': 0,
            'spare_pair_arch': 0,
            'req_spare_pair_poe': 0,
            'pse_spare_pair_poe': 0,
        }
        
        try:
            offset = 4  # Skip CDP header
            while offset < len(payload) - 4:
                if offset + 4 > len(payload):
                    break
                
                tlv_type = int.from_bytes(payload[offset:offset+2], 'big')
                tlv_length = int.from_bytes(payload[offset+2:offset+4], 'big')
                
                if tlv_length < 4 or offset + tlv_length > len(payload):
                    break
                
                tlv_data['tlv_count'] += 1
                
                # Extract TLV-specific data based on type
                tlv_value = payload[offset+4:offset+tlv_length]
                
                if tlv_type == 0x0001:  # Device ID
                    tlv_data['device_id_len'] = tlv_length
                elif tlv_type == 0x0005:  # Software Version
                    tlv_data['software_version_len'] = tlv_length
                elif tlv_type == 0x0006:  # Platform
                    tlv_data['platform_len'] = tlv_length
                    tlv_data['platform'] = tlv_value.decode('utf-8', errors='ignore')[:50]
                elif tlv_type == 0x0002:  # Addresses
                    tlv_data['addresses_tlv_len'] = tlv_length
                    tlv_data['addresses_count'] = self._extract_address_count(tlv_value)
                elif tlv_type == 0x0003:  # Port ID
                    tlv_data['port_id_len'] = tlv_length
                elif tlv_type == 0x0004:  # Capabilities
                    tlv_data['capabilities_len'] = tlv_length
                    if len(tlv_value) >= 4:
                        tlv_data['capabilities_flags'] = int.from_bytes(tlv_value[:4], 'big')
                elif tlv_type == 0x0008:  # Protocol Hello
                    tlv_data['hello_tlv_len'] = tlv_length
                elif tlv_type == 0x0009:  # VTP Management Domain
                    tlv_data['vtp_management_len'] = tlv_length
                elif tlv_type == 0x000A:  # Native VLAN
                    tlv_data['native_vlan_len'] = tlv_length
                    if len(tlv_value) >= 2:
                        tlv_data['native_vlan_id'] = int.from_bytes(tlv_value[:2], 'big')
                elif tlv_type == 0x000B:  # Duplex
                    tlv_data['duplex_len'] = tlv_length
                    if len(tlv_value) >= 1:
                        tlv_data['duplex_value'] = tlv_value[0]
                elif tlv_type == 0x0010:  # Power Available
                    tlv_data['power_len'] = tlv_length
                    if len(tlv_value) >= 4:
                        tlv_data['power_sum'] = int.from_bytes(tlv_value[:4], 'big')
                
                offset += tlv_length
                
        except Exception:
            pass
        
        return tlv_data
    
    def _validate_cdp_structure(self, payload: bytes) -> bool:
        """Validate that payload has proper CDP structure."""
        try:
            if len(payload) < 4:  # Minimum CDP header
                return False
            
            # Look for CDP in different positions (LLC, direct ethernet payload, etc.)
            cdp_offset = self._find_cdp_header_offset(payload)
            if cdp_offset < 0:
                return False
            
            if len(payload) < cdp_offset + 4:
                return False
            
            # Check CDP header fields
            version = payload[cdp_offset]
            ttl = payload[cdp_offset + 1]
            
            # CDP version should be 1 or 2, TTL should be reasonable
            if version not in [1, 2] or ttl == 0 or ttl > 255:
                return False
            
            return True
        except Exception:
            return False
    
    def _find_cdp_header_offset(self, payload: bytes) -> int:
        """Find the offset of CDP header in payload."""
        try:
            # Case 1: Direct CDP (no LLC/SNAP)
            if len(payload) >= 4:
                version = payload[0]
                ttl = payload[1]
                if version in [1, 2] and 1 <= ttl <= 255:
                    return 0
            
            # Case 2: CDP after LLC/SNAP header
            # Look for SNAP OUI/PID pattern: 00:00:0c:20:00
            for i in range(len(payload) - 8):
                if (payload[i:i+5] == b'\x00\x00\x0c\x20\x00' and 
                    i + 5 < len(payload)):
                    # CDP header should follow immediately
                    cdp_start = i + 5
                    if cdp_start + 2 < len(payload):
                        version = payload[cdp_start]
                        ttl = payload[cdp_start + 1]
                        if version in [1, 2] and 1 <= ttl <= 255:
                            return cdp_start
            
            # Case 3: Look for CDP version/TTL pattern anywhere
            for i in range(len(payload) - 4):
                version = payload[i]
                ttl = payload[i + 1]
                if version in [1, 2] and 1 <= ttl <= 255:
                    # Additional validation - check if this looks like a CDP header
                    if i + 4 <= len(payload):
                        # CDP checksum follows version/TTL
                        return i
            
            return -1
        except Exception:
            return -1
    
    def _extract_address_count(self, tlv_value: bytes) -> int:
        """Extract address count from addresses TLV."""
        try:
            if len(tlv_value) >= 4:
                return int.from_bytes(tlv_value[:4], 'big')
            return 0
        except Exception:
            return 0
    
    def _set_default_cdp_features(self):
        """Set default CDP features."""
        cdp_defaults = {
            'cdp_version': 0,
            'cdp_ttl': 0,
            'cdp_checksum_status': 0,
            'cdp_tlvs': 0,
            'cdp_addresses_count': 0,
            'cdp_device_id_tlv_len': 0,
            'cdp_software_version_tlv_len': 0,
            'cdp_platform_tlv_len': 0,
            'cdp_platform': '',
            'cdp_addresses_tlv_len': 0,
            'cdp_addresses_sum_len': 0,
            'cdp_addresses_sum_protocol_len': 0,
            'cdp_management_addresses_sum_len': 0,
            'cdp_management_addresses_sum_protocol_len': 0,
            'cdp_port_id_tlv_len': 0,
            'cdp_capabilities_tlv_len': 0,
            'cdp_capabilities': 0,
            'cdp_capabilities_router': False,
            'cdp_capabilities_trans_bridge': False,
            'cdp_capabilities_src_bridge': False,
            'cdp_capabilities_switch': False,
            'cdp_capabilities_host': False,
            'cdp_capabilities_igmp': False,
            'cdp_capabilities_repeater': False,
            'cdp_capabilities_voip_phone': False,
            'cdp_capabilities_remote': False,
            'cdp_capabilities_cvta': False,
            'cdp_capabilities_mac_relay': False,
            'cdp_hello_tlv_len': 0,
            'cdp_hello_oui': 0,
            'cdp_hello_num_unknown': 0,
            'cdp_hello_management_vlan': 0,
            'cdp_vtp_management_tlv_len': 0,
            'cdp_vlan_native_tlv_len': 0,
            'cdp_vlan_native_native_vlan': 0,
            'cdp_duplex_tlv_len': 0,
            'cdp_duplex': 0,
            'cdp_power_tlv_len': 0,
            'cdp_power_request_id': 0,
            'cdp_power_management_id': 0,
            'cdp_power_sum': 0,
            'cdp_spare_pair_tlv_len': 0,
            'cdp_spare_poe_tlv_poe': 0,
            'cdp_spare_poe_tlv_spare_pair_arch': 0,
            'cdp_spare_poe_tlv_req_spare_pair_poe': 0,
            'cdp_spare_poe_tlv_pse_spare_pair_poe': 0,
        }
        self.features.update(cdp_defaults)
    
    def _try_pyshark_cdp_extraction(self) -> bool:
        """
        Try to extract CDP features using pyshark for enhanced analysis.
        Returns True if successful, False otherwise.
        """
        try:
            import pyshark
            import io
            import tempfile
            import os
            from scapy.all import wrpcap
            
            # Create a temporary pcap file with this single packet
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
                tmp_path = tmp_file.name
                wrpcap(tmp_path, self.packet)
            
            try:
                # Use pyshark to analyze the packet
                cap = pyshark.FileCapture(tmp_path, display_filter='cdp')
                
                for pkt in cap:
                    if hasattr(pkt, 'cdp'):
                        cdp_layer = pkt.cdp
                        
                        # Extract enhanced CDP features using pyshark
                        # Basic CDP header
                        if hasattr(cdp_layer, 'version'):
                            self.features['cdp_version'] = int(cdp_layer.version)
                        if hasattr(cdp_layer, 'ttl'):
                            self.features['cdp_ttl'] = int(cdp_layer.ttl)
                        if hasattr(cdp_layer, 'checksum'):
                            self.features['cdp_checksum_status'] = int(cdp_layer.checksum, 16) if isinstance(cdp_layer.checksum, str) else int(cdp_layer.checksum)
                        
                        # Device ID
                        if hasattr(cdp_layer, 'deviceid'):
                            device_id = str(cdp_layer.deviceid)
                            self.features['cdp_device_id_tlv_len'] = len(device_id)
                        
                        # Platform
                        if hasattr(cdp_layer, 'platform'):
                            platform = str(cdp_layer.platform)
                            self.features['cdp_platform_tlv_len'] = len(platform)
                            self.features['cdp_platform'] = platform
                        
                        # Software version
                        if hasattr(cdp_layer, 'software'):
                            software = str(cdp_layer.software)
                            self.features['cdp_software_version_tlv_len'] = len(software)
                        
                        # Port ID
                        if hasattr(cdp_layer, 'portid'):
                            port_id = str(cdp_layer.portid)
                            self.features['cdp_port_id_tlv_len'] = len(port_id)
                        
                        # Capabilities
                        if hasattr(cdp_layer, 'capabilities_router'):
                            self.features['cdp_capabilities_router'] = cdp_layer.capabilities_router == '1'
                        if hasattr(cdp_layer, 'capabilities_trans_bridge'):
                            self.features['cdp_capabilities_trans_bridge'] = cdp_layer.capabilities_trans_bridge == '1'
                        if hasattr(cdp_layer, 'capabilities_src_bridge'):
                            self.features['cdp_capabilities_src_bridge'] = cdp_layer.capabilities_src_bridge == '1'
                        if hasattr(cdp_layer, 'capabilities_switch'):
                            self.features['cdp_capabilities_switch'] = cdp_layer.capabilities_switch == '1'
                        if hasattr(cdp_layer, 'capabilities_host'):
                            self.features['cdp_capabilities_host'] = cdp_layer.capabilities_host == '1'
                        if hasattr(cdp_layer, 'capabilities_igmp'):
                            self.features['cdp_capabilities_igmp'] = cdp_layer.capabilities_igmp == '1'
                        if hasattr(cdp_layer, 'capabilities_repeater'):
                            self.features['cdp_capabilities_repeater'] = cdp_layer.capabilities_repeater == '1'
                        if hasattr(cdp_layer, 'capabilities_voip_phone'):
                            self.features['cdp_capabilities_voip_phone'] = cdp_layer.capabilities_voip_phone == '1'
                        
                        # VLAN information
                        if hasattr(cdp_layer, 'nativevlan'):
                            self.features['cdp_vlan_native_native_vlan'] = int(cdp_layer.nativevlan)
                            self.features['cdp_vlan_native_tlv_len'] = 4  # Native VLAN TLV is typically 4 bytes
                        
                        # Duplex
                        if hasattr(cdp_layer, 'duplex'):
                            self.features['cdp_duplex'] = 1 if 'full' in str(cdp_layer.duplex).lower() else 0
                            self.features['cdp_duplex_tlv_len'] = 1
                        
                        # Management address
                        if hasattr(cdp_layer, 'mgmtaddr'):
                            addr_str = str(cdp_layer.mgmtaddr)
                            self.features['cdp_management_addresses_sum_len'] = len(addr_str)
                            self.features['cdp_addresses_count'] = 1
                        
                        # Power information
                        if hasattr(cdp_layer, 'power'):
                            try:
                                power_val = int(cdp_layer.power)
                                self.features['cdp_power_sum'] = power_val
                                self.features['cdp_power_tlv_len'] = 4
                            except ValueError:
                                pass
                        
                        # Count TLVs by checking available CDP attributes
                        tlv_count = 0
                        for attr in dir(cdp_layer):
                            if not attr.startswith('_') and hasattr(cdp_layer, attr):
                                tlv_count += 1
                        self.features['cdp_tlvs'] = tlv_count
                        
                        cap.close()
                        return True
                        
                cap.close()
                return False
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            
        except ImportError:
            # pyshark not available, fall back to native extraction
            return False
        except Exception as e:
            # Any error in pyshark processing, fall back to native extraction
            return False


class LLDPPacket(BasePacket):
    """Link Layer Discovery Protocol packet analyzer."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_lldp_features()
    
    def get_protocol_type(self) -> str:
        """Override to ensure LLDP packets are correctly identified."""
        return 'LLDP'
    
    def _extract_lldp_features(self):
        """Extract comprehensive LLDP-specific features with enhanced validation."""
        try:
            # Enhanced LLDP detection with both MAC and payload validation
            dst_mac = self.features.get('dst_mac_addr', '').lower()
            if dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                
                # Enhanced LLDP TLV analysis
                raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
                
                # Validate LLDP structure
                if self._validate_lldp_structure(raw_payload):
                    self.features['is_lldp'] = True
                    
                    # Extract LLDP features
                    tlv_data = self._parse_lldp_tlvs(raw_payload)
                    self.features['lldp_tlvs'] = tlv_data['tlv_count']
                    self.features['lldp_chassis_id_type'] = tlv_data.get('chassis_id_type', 0)
                    self.features['lldp_chassis_id_len'] = tlv_data.get('chassis_id_len', 0)
                    self.features['lldp_port_id_type'] = tlv_data.get('port_id_type', 0)
                    self.features['lldp_port_id_len'] = tlv_data.get('port_id_len', 0)
                    self.features['lldp_ttl'] = tlv_data.get('ttl', 0)
                    self.features['lldp_system_name_len'] = tlv_data.get('system_name_len', 0)
                    self.features['lldp_system_desc_len'] = tlv_data.get('system_desc_len', 0)
                    self.features['lldp_port_desc_len'] = tlv_data.get('port_desc_len', 0)
                    self.features['lldp_capabilities'] = tlv_data.get('capabilities', 0)
                    self.features['lldp_mgmt_addr_count'] = tlv_data.get('mgmt_addr_count', 0)
                    
                    # Legacy compatibility
                    self.features['lldp_chassis_id'] = tlv_data.get('chassis_id', 'unknown')
                    self.features['lldp_port_id'] = tlv_data.get('port_id', 'unknown')
                    
                else:
                    # MAC matches but payload doesn't look like LLDP, assume it's LLDP anyway
                    self.features['is_lldp'] = True
                    self._set_default_lldp_features()
                    
            else:
                self.features['is_lldp'] = False
                self._set_default_lldp_features()
                
        except Exception as e:
            # On error, still mark as LLDP if MAC matches, for compatibility
            dst_mac = self.features.get('dst_mac_addr', '').lower()
            self.features['is_lldp'] = dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']
            self._set_default_lldp_features()
    
    def _validate_lldp_structure(self, payload: bytes) -> bool:
        """Validate that payload has proper LLDP structure."""
        try:
            if len(payload) < 6:  # Minimum LLDP: Chassis ID (2+) + Port ID (2+) + TTL (2+) + End (2)
                return False
            
            # Check first TLV (should be Chassis ID = type 1)
            first_tlv = int.from_bytes(payload[0:2], 'big')
            first_type = (first_tlv >> 9) & 0x7F
            first_length = first_tlv & 0x1FF
            
            # First TLV should be Chassis ID (1) and have reasonable length
            if first_type != 1 or first_length == 0 or first_length > 255:
                return False
            
            # Check second TLV (should be Port ID = type 2)
            if len(payload) < 4 + first_length:
                return False
            
            second_offset = 2 + first_length
            if second_offset + 2 > len(payload):
                return False
                
            second_tlv = int.from_bytes(payload[second_offset:second_offset+2], 'big')
            second_type = (second_tlv >> 9) & 0x7F
            second_length = second_tlv & 0x1FF
            
            # Second TLV should be Port ID (2) and have reasonable length
            if second_type != 2 or second_length == 0 or second_length > 255:
                return False
                
            return True
        except Exception:
            return False
    
    def _parse_lldp_tlvs(self, payload: bytes) -> dict:
        """Parse LLDP TLVs and extract detailed information."""
        tlv_data = {
            'tlv_count': 0,
            'chassis_id_type': 0,
            'chassis_id_len': 0,
            'chassis_id': 'unknown',
            'port_id_type': 0,
            'port_id_len': 0,
            'port_id': 'unknown',
            'ttl': 0,
            'system_name_len': 0,
            'system_desc_len': 0,
            'port_desc_len': 0,
            'capabilities': 0,
            'mgmt_addr_count': 0
        }
        
        try:
            offset = 0
            while offset < len(payload) - 2:
                if offset + 2 > len(payload):
                    break
                
                # LLDP TLV format: Type(7 bits) + Length(9 bits) + Value(variable)
                tlv_header = int.from_bytes(payload[offset:offset+2], 'big')
                tlv_type = (tlv_header >> 9) & 0x7F
                tlv_length = tlv_header & 0x1FF
                
                if tlv_type == 0:  # End of LLDPDU
                    break
                
                if offset + 2 + tlv_length > len(payload):
                    break
                
                tlv_value = payload[offset+2:offset+2+tlv_length] if tlv_length > 0 else b''
                
                # Parse specific TLV types
                if tlv_type == 1:  # Chassis ID
                    if len(tlv_value) >= 1:
                        tlv_data['chassis_id_type'] = tlv_value[0]
                        tlv_data['chassis_id_len'] = tlv_length
                        if len(tlv_value) > 1:
                            tlv_data['chassis_id'] = tlv_value[1:].decode('utf-8', errors='ignore')[:50]
                elif tlv_type == 2:  # Port ID
                    if len(tlv_value) >= 1:
                        tlv_data['port_id_type'] = tlv_value[0]
                        tlv_data['port_id_len'] = tlv_length
                        if len(tlv_value) > 1:
                            tlv_data['port_id'] = tlv_value[1:].decode('utf-8', errors='ignore')[:50]
                elif tlv_type == 3:  # TTL
                    if len(tlv_value) >= 2:
                        tlv_data['ttl'] = int.from_bytes(tlv_value[:2], 'big')
                elif tlv_type == 4:  # Port Description
                    tlv_data['port_desc_len'] = tlv_length
                elif tlv_type == 5:  # System Name
                    tlv_data['system_name_len'] = tlv_length
                elif tlv_type == 6:  # System Description
                    tlv_data['system_desc_len'] = tlv_length
                elif tlv_type == 7:  # System Capabilities
                    if len(tlv_value) >= 4:
                        tlv_data['capabilities'] = int.from_bytes(tlv_value[:4], 'big')
                elif tlv_type == 8:  # Management Address
                    tlv_data['mgmt_addr_count'] += 1
                
                tlv_data['tlv_count'] += 1
                offset += 2 + tlv_length
                
        except Exception:
            pass
        
        return tlv_data
    
    
    def _set_default_lldp_features(self):
        """Set default LLDP features."""
        lldp_defaults = {
            'lldp_tlvs': 0,
            'lldp_chassis_id': 'unknown',
            'lldp_port_id': 'unknown',
            'lldp_chassis_id_type': 0,
            'lldp_chassis_id_len': 0,
            'lldp_port_id_type': 0,
            'lldp_port_id_len': 0,
            'lldp_ttl': 0,
            'lldp_system_name_len': 0,
            'lldp_system_desc_len': 0,
            'lldp_port_desc_len': 0,
            'lldp_capabilities': 0,
            'lldp_mgmt_addr_count': 0,
        }
        self.features.update(lldp_defaults)


class ARPPacket(BasePacket):
    """ARP packet analyzer."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_arp_features()
    
    def get_protocol_type(self) -> str:
        """Override to ensure ARP packets are correctly identified."""
        return 'ARP'
    
    def _extract_arp_features(self):
        """Extract comprehensive ARP-specific features."""
        try:
            if self.packet.haslayer('ARP'):
                arp_layer = self.packet['ARP']
                
                # Basic ARP fields
                self.features['arp_opcode'] = int(arp_layer.op)
                self.features['arp_op'] = self.features['arp_opcode']  # Alias
                self.features['arp_hwsrc'] = str(arp_layer.hwsrc)
                self.features['arp_hwdst'] = str(arp_layer.hwdst)
                self.features['arp_psrc'] = str(arp_layer.psrc)
                self.features['arp_pdst'] = str(arp_layer.pdst)
                self.features['is_arp_request'] = (arp_layer.op == 1)
                self.features['is_arp_reply'] = (arp_layer.op == 2)
                
                # Enhanced ARP features based on example
                self.features['arp_type'] = int(arp_layer.op)
                self.features['arp_size'] = len(self.packet)
                self.features['arp_dst_hw_mac'] = str(arp_layer.hwdst)
                self.features['arp_src_hw_mac'] = str(arp_layer.hwsrc)
                self.features['arp_proto_size'] = int(arp_layer.plen) if hasattr(arp_layer, 'plen') else 4
                self.features['arp_hw_size'] = int(arp_layer.hwlen) if hasattr(arp_layer, 'hwlen') else 6
                self.features['arp_hw_type'] = int(arp_layer.hwtype) if hasattr(arp_layer, 'hwtype') else 1
                
                # Protocol type
                self.features['arp_proto_type'] = int(arp_layer.ptype) if hasattr(arp_layer, 'ptype') else 0x0800
                
            else:
                self._set_default_arp_features()
                
        except Exception:
            self._set_default_arp_features()
    
    def _set_default_arp_features(self):
        """Set default ARP features."""
        arp_defaults = {
            'arp_opcode': 0,
            'arp_op': 0,
            'arp_hwsrc': '',
            'arp_hwdst': '',
            'arp_psrc': '',
            'arp_pdst': '',
            'is_arp_request': False,
            'is_arp_reply': False,
            'arp_type': 0,
            'arp_size': 0,
            'arp_dst_hw_mac': '',
            'arp_src_hw_mac': '',
            'arp_proto_size': 4,
            'arp_hw_size': 6,
            'arp_hw_type': 1,
            'arp_proto_type': 0x0800,
        }
        self.features.update(arp_defaults)