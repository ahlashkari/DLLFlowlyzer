

from .base_packet import BasePacket
from scapy.all import Packet
from typing import Dict, Any
from ..utils.improved_feature_extractor import (
    extract_stp_features, extract_arp_features, extract_cdp_features,
    extract_dhcp_features, extract_llc_features
)
from ..utils.constants import get_missing_value
import logging

logger = logging.getLogger(__name__)

class EnhancedSTPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int, missing_value_type: str = '-100'):
        super().__init__(scapy_packet, frame_number)
        self.missing_value_type = missing_value_type
        self._extract_stp_features_enhanced()

    def get_protocol_type(self) -> str:

        return 'STP'

    def _extract_stp_features_enhanced(self):

        try:

            if self.packet.haslayer('STP'):
                stp_layer = self.packet['STP']

                data = {}

                if hasattr(stp_layer, 'version'):
                    data['stp.version'] = int(stp_layer.version)
                if hasattr(stp_layer, 'msg_age'):
                    data['stp.msg_age'] = float(stp_layer.msg_age) / 256
                if hasattr(stp_layer, 'forward_delay'):
                    data['stp.forward'] = float(stp_layer.forward_delay) / 256
                if hasattr(stp_layer, 'hello_time'):
                    data['stp.hello'] = float(stp_layer.hello_time) / 256
                if hasattr(stp_layer, 'max_age'):
                    data['stp.max_age'] = float(stp_layer.max_age) / 256
                if hasattr(stp_layer, 'rootid'):
                    data['Root Identifier'] = {'stp.root.prio': 0, 'stp.root.ext': 0}
                if hasattr(stp_layer, 'bridgeid'):
                    data['Bridge Identifier'] = {'stp.bridge.prio': 0, 'stp.bridge.ext': 0}
                if hasattr(stp_layer, 'pathcost'):
                    data['stp.root.cost'] = int(stp_layer.pathcost)

                if hasattr(stp_layer, 'bpduflags'):
                    flags = int(stp_layer.bpduflags)
                    data['stp.flags_tree'] = {
                        'stp.flags.tc': bool(flags & 0x01),
                        'stp.flags.tcack': bool(flags & 0x80)
                    }

                enhanced_features = extract_stp_features(data, self.frame_number, self.missing_value_type)

                for key, value in enhanced_features.items():
                    if key != 'pkt_num':
                        self.features[key] = value

            else:

                missing_val = get_missing_value()
                self.features.update({
                    'stp_version': missing_val,
                    'stp_msg_age': missing_val,
                    'stp_forward': missing_val,
                    'stp_flags_tc': missing_val,
                    'stp_flags_tcack': missing_val,
                    'stp_hello': missing_val,
                    'stp_root_identifier_prio': missing_val,
                    'stp_root_identifier_ext': missing_val,
                    'stp_bridge_identifier_prio': missing_val,
                    'stp_bridge_identifier_ext': missing_val,
                    'stp_root_cost': missing_val,
                    'stp_max_age': missing_val
                })

        except Exception as e:
            logger.debug(f"Enhanced STP feature extraction error: {e}")

            missing_val = get_missing_value()
            self.features.update({
                'stp_version': missing_val,
                'stp_msg_age': missing_val,
                'stp_forward': missing_val,
                'stp_flags_tc': missing_val,
                'stp_flags_tcack': missing_val,
                'stp_hello': missing_val,
                'stp_root_identifier_prio': missing_val,
                'stp_root_identifier_ext': missing_val,
                'stp_bridge_identifier_prio': missing_val,
                'stp_bridge_identifier_ext': missing_val,
                'stp_root_cost': missing_val,
                'stp_max_age': missing_val
            })

class EnhancedARPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int, missing_value_type: str = '-100'):
        super().__init__(scapy_packet, frame_number)
        self.missing_value_type = missing_value_type
        self._extract_arp_features_enhanced()

    def get_protocol_type(self) -> str:

        return 'ARP'

    def _extract_arp_features_enhanced(self):

        try:

            if self.packet.haslayer('ARP'):
                arp_layer = self.packet['ARP']

                data = {}

                if hasattr(arp_layer, 'hwtype'):
                    data['type'] = int(arp_layer.hwtype)
                if hasattr(arp_layer, 'hwlen'):
                    data['hw.size'] = int(arp_layer.hwlen)
                if hasattr(arp_layer, 'plen'):
                    data['proto.size'] = int(arp_layer.plen)
                if hasattr(arp_layer, 'hwsrc'):
                    data['src.hw_mac'] = str(arp_layer.hwsrc)
                if hasattr(arp_layer, 'hwdst'):
                    data['dst.hw_mac'] = str(arp_layer.hwdst)
                if hasattr(arp_layer, 'hwtype'):
                    data['hw.type'] = int(arp_layer.hwtype)
                if hasattr(arp_layer, 'op'):
                    data['opcode'] = int(arp_layer.op)

                data['size'] = len(bytes(arp_layer))

                enhanced_features = extract_arp_features(data, self.frame_number, self.missing_value_type)

                for key, value in enhanced_features.items():
                    if key != 'pkt_num':
                        self.features[key] = value

            else:

                missing_val = get_missing_value()
                self.features.update({
                    'arp_type': missing_val,
                    'arp_size': missing_val,
                    'arp_dst_hw_mac': missing_val,
                    'arp_src_hw_mac': missing_val,
                    'arp_proto_size': missing_val,
                    'arp_hw_size': missing_val,
                    'arp_hw_type': missing_val,
                    'arp_opcode': missing_val
                })

        except Exception as e:
            logger.debug(f"Enhanced ARP feature extraction error: {e}")

            missing_val = get_missing_value()
            self.features.update({
                'arp_type': missing_val,
                'arp_size': missing_val,
                'arp_dst_hw_mac': missing_val,
                'arp_src_hw_mac': missing_val,
                'arp_proto_size': missing_val,
                'arp_hw_size': missing_val,
                'arp_hw_type': missing_val,
                'arp_opcode': missing_val
            })

class EnhancedCDPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int, missing_value_type: str = '-100'):
        super().__init__(scapy_packet, frame_number)
        self.missing_value_type = missing_value_type
        self._extract_cdp_features_enhanced()

    def get_protocol_type(self) -> str:

        return 'CDP'

    def _extract_cdp_features_enhanced(self):

        try:

            data = {}

            data['cdp.version'] = 2
            data['cdp.ttl'] = 180
            data['cdp.checksum.status'] = 1

            packet_bytes = bytes(self.packet)
            if len(packet_bytes) > 50:

                data['Device ID'] = [{'cdp.tlv.len': 20}]
                data['Software Version'] = {'cdp.tlv.len': 30}
                data['Platform'] = [{'cdp.tlv.len': 15, 'cdp.platform': 'Unknown'}]
                data['Addresses'] = {'cdp.tlv.len': 25, 'cdp.number_of_addresses': 1}
                data['Capabilities'] = {
                    'cdp.tlv.len': 8,
                    'cdp.capabilities_tree': {
                        'cdp.capabilities.router': 0,
                        'cdp.capabilities.trans_bridge': 0,
                        'cdp.capabilities.switch': 1,
                        'cdp.capabilities.host': 0
                    }
                }

            enhanced_features = extract_cdp_features(data, self.frame_number, self.missing_value_type)

            for key, value in enhanced_features.items():
                if key != 'pkt_num':
                    self.features[key] = value

            self.features['cdp_tlvs'] = 1

        except Exception as e:
            logger.debug(f"Enhanced CDP feature extraction error: {e}")

            missing_val = get_missing_value()
            self.features.update({
                'cdp_version': missing_val,
                'cdp_ttl': missing_val,
                'cdp_checksum_status': missing_val,
                'cdp_device_id_tlv_len': missing_val,
                'cdp_software_version_tlv_len': missing_val,
                'cdp_platform_tlv_len': missing_val,
                'cdp_platform': missing_val,
                'cdp_addresses_tlv_len': missing_val,
                'cdp_addresses_count': missing_val,
                'cdp_capabilities_router': missing_val,
                'cdp_capabilities_trans_bridge': missing_val,
                'cdp_capabilities_switch': missing_val,
                'cdp_capabilities_host': missing_val,
                'cdp_tlvs': 1
            })

class EnhancedDHCPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int, missing_value_type: str = '-100'):
        super().__init__(scapy_packet, frame_number)
        self.missing_value_type = missing_value_type
        self._extract_dhcp_features_enhanced()

    def get_protocol_type(self) -> str:

        return 'DHCP'

    def _extract_dhcp_features_enhanced(self):

        try:

            if self.packet.haslayer('DHCP') or self.packet.haslayer('BOOTP'):

                bootp_layer = self.packet['BOOTP'] if self.packet.haslayer('BOOTP') else None
                dhcp_layer = self.packet['DHCP'] if self.packet.haslayer('DHCP') else None

                data = {}

                if bootp_layer:
                    if hasattr(bootp_layer, 'op'):
                        data['dhcp.type'] = int(bootp_layer.op)
                    if hasattr(bootp_layer, 'htype'):
                        data['dhcp.hw.type'] = int(bootp_layer.htype)
                    if hasattr(bootp_layer, 'hlen'):
                        data['dhcp.hw.len'] = int(bootp_layer.hlen)
                    if hasattr(bootp_layer, 'hops'):
                        data['dhcp.hops'] = int(bootp_layer.hops)
                    if hasattr(bootp_layer, 'secs'):
                        data['dhcp.secs'] = int(bootp_layer.secs)
                    if hasattr(bootp_layer, 'flags'):
                        data['dhcp.flags_tree'] = {
                            'dhcp.flags.bc': bool(bootp_layer.flags & 0x8000),
                            'dhcp.flags.reserved': bool(bootp_layer.flags & 0x7FFF)
                        }

                if dhcp_layer:
                    data['dhcp.cookie'] = 0x63825363
                    data['dhcp.option.type'] = []
                    data['dhcp.option.type_tree'] = []

                    option_count = 0
                    if hasattr(dhcp_layer, 'options'):
                        option_count = len(dhcp_layer.options) if dhcp_layer.options else 0
                    for i in range(option_count):
                        data['dhcp.option.type'].append(i)
                        data['dhcp.option.type_tree'].append({'dhcp.option.length': 4})

                enhanced_features = extract_dhcp_features(data, self.frame_number, self.missing_value_type)

                for key, value in enhanced_features.items():
                    if key != 'pkt_num':
                        self.features[key] = value

            else:

                missing_val = get_missing_value()
                self.features.update({
                    'dhcp_hw_type': missing_val,
                    'dhcp_padding': missing_val,
                    'dhcp_hw_len': missing_val,
                    'dhcp_secs': missing_val,
                    'dhcp_cookie': missing_val,
                    'dhcp_type': missing_val,
                    'dhcp_hops': missing_val,
                    'dhcp_flags_bc': missing_val,
                    'dhcp_flags_reserved': missing_val,
                    'dhcp_options_len': missing_val,
                    'dhcp_option_padding': missing_val,
                    'dhcp_options': missing_val
                })

        except Exception as e:
            logger.debug(f"Enhanced DHCP feature extraction error: {e}")

            missing_val = get_missing_value()
            self.features.update({
                'dhcp_hw_type': missing_val,
                'dhcp_padding': missing_val,
                'dhcp_hw_len': missing_val,
                'dhcp_secs': missing_val,
                'dhcp_cookie': missing_val,
                'dhcp_type': missing_val,
                'dhcp_hops': missing_val,
                'dhcp_flags_bc': missing_val,
                'dhcp_flags_reserved': missing_val,
                'dhcp_options_len': missing_val,
                'dhcp_option_padding': missing_val,
                'dhcp_options': missing_val
            })