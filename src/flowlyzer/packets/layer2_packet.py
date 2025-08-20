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
                
                # STP basic fields
                self.features['stp_proto_id'] = int(stp_layer.proto) if hasattr(stp_layer, 'proto') else 0
                self.features['stp_version'] = int(stp_layer.version) if hasattr(stp_layer, 'version') else 0
                self.features['stp_bpdu_type'] = int(stp_layer.bpdutype) if hasattr(stp_layer, 'bpdutype') else 0
                
                # STP flags
                if hasattr(stp_layer, 'bpduflags'):
                    flags = int(stp_layer.bpduflags)
                    self.features['stp_flags'] = flags
                    self.features['stp_flags_tc'] = bool(flags & 0x01)
                    self.features['stp_flags_tcack'] = bool(flags & 0x80)
                else:
                    self.features['stp_flags'] = 0
                    self.features['stp_flags_tc'] = False
                    self.features['stp_flags_tcack'] = False
                
                # STP timing fields
                self.features['stp_msg_age'] = int(stp_layer.msg_age) if hasattr(stp_layer, 'msg_age') else 0
                self.features['stp_max_age'] = int(stp_layer.max_age) if hasattr(stp_layer, 'max_age') else 0
                self.features['stp_hello_time'] = int(stp_layer.hello_time) if hasattr(stp_layer, 'hello_time') else 0
                self.features['stp_forward_delay'] = int(stp_layer.forward_delay) if hasattr(stp_layer, 'forward_delay') else 0
                self.features['stp_hello'] = self.features['stp_hello_time']  # Alias for compatibility
                self.features['stp_forward'] = self.features['stp_forward_delay']  # Alias for compatibility
                
                # Calculate age ratio
                max_age = self.features['stp_max_age']
                if max_age > 0:
                    self.features['stp_age_div_max_age'] = self.features['stp_msg_age'] / max_age
                else:
                    self.features['stp_age_div_max_age'] = 0
                
                # Root identifier details
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
                
                # Bridge identifier details
                if hasattr(stp_layer, 'bridgeid'):
                    bridge_id = int(stp_layer.bridgeid) if isinstance(stp_layer.bridgeid, (int, str)) else 0
                    self.features['stp_bridge_id'] = str(stp_layer.bridgeid)
                    self.features['stp_bridge_identifier_prio'] = (bridge_id >> 48) & 0xFFFF
                    self.features['stp_bridge_identifier_ext'] = (bridge_id >> 32) & 0xFFFF
                else:
                    self.features['stp_bridge_id'] = ''
                    self.features['stp_bridge_identifier_prio'] = 0
                    self.features['stp_bridge_identifier_ext'] = 0
                
                # Port identifier
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
        """Extract comprehensive CDP-specific features."""
        try:
            # CDP detection by destination MAC or LLC header
            if (self.features.get('dst_mac_addr') == '01:00:0c:cc:cc:cc' or 
                self.packet.haslayer('LLC')):
                
                # Basic CDP header features
                raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
                if len(raw_payload) >= 8:
                    self.features['cdp_version'] = raw_payload[0] if len(raw_payload) > 0 else 0
                    self.features['cdp_ttl'] = raw_payload[1] if len(raw_payload) > 1 else 0
                    self.features['cdp_checksum_status'] = int.from_bytes(raw_payload[2:4], 'big') if len(raw_payload) >= 4 else 0
                else:
                    self.features['cdp_version'] = 0
                    self.features['cdp_ttl'] = 0
                    self.features['cdp_checksum_status'] = 0
                
                # Enhanced CDP TLV analysis
                tlv_data = self._parse_cdp_tlvs(raw_payload)
                
                # Basic TLV counts
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
                
            else:
                self._set_default_cdp_features()
                
        except Exception:
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


class LLDPPacket(BasePacket):
    """Link Layer Discovery Protocol packet analyzer."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_lldp_features()
    
    def get_protocol_type(self) -> str:
        """Override to ensure LLDP packets are correctly identified."""
        return 'LLDP'
    
    def _extract_lldp_features(self):
        """Extract LLDP-specific features."""
        try:
            # LLDP detection by destination MAC (01:80:c2:00:00:0e)
            if self.features.get('dst_mac_addr') in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                self.features['is_lldp'] = True
                
                # LLDP TLV analysis (simplified)
                raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
                self.features['lldp_tlvs'] = self._count_lldp_tlvs(raw_payload)
                self.features['lldp_chassis_id'] = self._extract_lldp_chassis_id(raw_payload)
                self.features['lldp_port_id'] = self._extract_lldp_port_id(raw_payload)
                
            else:
                self.features['is_lldp'] = False
                self._set_default_lldp_features()
                
        except Exception:
            self.features['is_lldp'] = False
            self._set_default_lldp_features()
    
    def _count_lldp_tlvs(self, payload: bytes) -> int:
        """Count LLDP TLV entries."""
        try:
            tlv_count = 0
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
                
                tlv_count += 1
                offset += 2 + tlv_length
                
            return tlv_count
        except Exception:
            return 0
    
    def _extract_lldp_chassis_id(self, payload: bytes) -> str:
        """Extract LLDP chassis ID."""
        # Simplified implementation
        return 'unknown'
    
    def _extract_lldp_port_id(self, payload: bytes) -> str:
        """Extract LLDP port ID."""
        # Simplified implementation
        return 'unknown'
    
    def _set_default_lldp_features(self):
        """Set default LLDP features."""
        lldp_defaults = {
            'lldp_tlvs': 0,
            'lldp_chassis_id': 'unknown',
            'lldp_port_id': 'unknown',
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