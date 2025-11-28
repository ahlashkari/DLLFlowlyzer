

import time
from datetime import datetime
from typing import Dict, Any, Optional
from scapy.all import Packet
import numpy as np

MISSING_VALUE = -100

class BasePacket:

    def __init__(self, scapy_packet: Packet, frame_number: int):

        self.packet = scapy_packet
        self.frame_number = frame_number
        self.timestamp = float(scapy_packet.time) if hasattr(scapy_packet, 'time') else time.time()
        self.features = {}
        self._extract_base_features()

    def _extract_base_features(self):

        try:
            self.features['num_frame'] = self.frame_number
            self.features['frame_len'] = len(self.packet)
            self.features['timestamp'] = self.timestamp

            if self.packet.haslayer('Ether'):
                eth_layer = self.packet['Ether']
                self.features['dst_mac_addr'] = str(eth_layer.dst)
                self.features['src_mac_addr'] = str(eth_layer.src)
                self.features['eth_type'] = int(eth_layer.type)

                self._extract_mac_features('dst_mac', eth_layer.dst)
                self._extract_mac_features('src_mac', eth_layer.src)
            else:
                self._set_default_mac_features()

            if self.packet.haslayer('IP'):
                ip_layer = self.packet['IP']
                self.features['dst_ip_addr'] = str(ip_layer.dst)
                self.features['src_ip_addr'] = str(ip_layer.src)
            elif self.packet.haslayer('IPv6'):
                ipv6_layer = self.packet['IPv6']
                self.features['dst_ip_addr'] = str(ipv6_layer.dst)
                self.features['src_ip_addr'] = str(ipv6_layer.src)
            else:
                self.features['dst_ip_addr'] = str(MISSING_VALUE)
                self.features['src_ip_addr'] = str(MISSING_VALUE)

            self._extract_port_features()

        except Exception as e:
            self._set_default_features()

    def _extract_mac_features(self, prefix: str, mac_addr: str):

        try:
            mac_clean = mac_addr.replace(':', '').replace('-', '').upper()

            oui = mac_clean[:6]
            self.features[f'{prefix}_oui'] = oui

            first_byte = int(mac_clean[:2], 16)
            self.features[f'{prefix}_ig'] = (first_byte & 0x01) == 1

            self.features[f'{prefix}_lg'] = (first_byte & 0x02) == 2

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

        try:
            import sys
            from pathlib import Path

            project_root = Path(__file__).parent.parent.parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))

            from vendors import get_vendor_from_mac

            if len(oui) >= 6:
                formatted_mac = f"{oui[0:2].lower()}:{oui[2:4].lower()}:{oui[4:6].lower()}:00:00:00"
                return get_vendor_from_mac(formatted_mac)
            else:
                return 'Unknown'
        except Exception as e:
            common_ouis = {
                '000C29': 'VMware',
                '0050F2': 'Microsoft',
                '00E04C': 'Realtek',
                '001B21': 'Intel',
                '00D0C9': 'Intel',
                '001125': 'Apple',
                '3C0754': 'Apple',
                '00000C': 'Cisco Systems',
                '000142': 'Cisco Systems',
                '001B17': 'Palo Alto Networks',
            }
            return common_ouis.get(oui, 'Unknown')

    def _extract_port_features(self):

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
                self.features['dst_port'] = MISSING_VALUE
                self.features['src_port'] = MISSING_VALUE
        except Exception:
            self.features['dst_port'] = MISSING_VALUE
            self.features['src_port'] = MISSING_VALUE

    def _set_default_mac_features(self):

        for prefix in ['dst_mac', 'src_mac']:
            self.features[f'{prefix}_addr'] = str(MISSING_VALUE)
            self.features[f'{prefix}_oui'] = 'Unknown'
            self.features[f'{prefix}_ig'] = False
            self.features[f'{prefix}_lg'] = False
            self.features[f'{prefix}_vendor'] = 'Unknown'
            self.features[f'{prefix}_vendor_known'] = False
            self.features[f'{prefix}_device'] = 'Unknown'
            self.features[f'{prefix}_vendor_name'] = 'Unknown'
            self.features[f'{prefix}_vendor_name_known'] = False

    def _set_default_features(self):

        default_features = {
            'num_frame': self.frame_number,
            'frame_len': 0,
            'timestamp': self.timestamp,
            'dst_mac_addr': str(MISSING_VALUE),
            'src_mac_addr': str(MISSING_VALUE),
            'eth_type': MISSING_VALUE,
            'dst_ip_addr': str(MISSING_VALUE),
            'src_ip_addr': str(MISSING_VALUE),
            'dst_port': MISSING_VALUE,
            'src_port': MISSING_VALUE,
        }
        self.features.update(default_features)
        self._set_default_mac_features()

    def get_features(self) -> Dict[str, Any]:

        return self.features.copy()

    def get_protocol_type(self) -> str:

        try:
            if self.packet.haslayer('TCP'):
                return 'TCP'
            elif self.packet.haslayer('UDP'):
                return 'UDP'
            elif self.packet.haslayer('ICMP'):
                return 'ICMP'
            elif self.packet.haslayer('ARP'):
                return 'ARP'

            elif self.packet.haslayer('STP'):
                return 'STP'
            elif self.packet.haslayer('LLC'):
                if self.packet.haslayer('Ether'):
                    dst_mac = str(self.packet['Ether'].dst).lower()
                    if dst_mac == '01:00:0c:cc:cc:cc':
                        return 'CDP'
                    elif dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                        return 'LLDP'
                return 'LLC'

            elif self.packet.haslayer('Ether'):
                eth_type = self.packet['Ether'].type
                if eth_type == 0x8100:
                    return '802.1Q'
                elif eth_type == 0x88cc:
                    return 'LLDP'
                elif eth_type == 0x809b:
                    return 'AppleTalk'
                elif eth_type == 0x8038:
                    return 'DEC_LAT'
                elif eth_type == 0x86dd:
                    return 'IPv6'
                elif eth_type == 0x0800:
                    return 'IPv4'
                else:
                    return f'ETH_0x{eth_type:04x}'

            else:
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

        try:
            src_mac = self.features.get('src_mac_addr', 'unknown')
            dst_mac = self.features.get('dst_mac_addr', 'unknown')
            src_ip = self.features.get('src_ip_addr', 'unknown')
            dst_ip = self.features.get('dst_ip_addr', 'unknown')
            src_port = self.features.get('src_port', 0)
            dst_port = self.features.get('dst_port', 0)
            protocol = self.get_protocol_type()

            endpoints = sorted([
                f"{src_mac}:{src_ip}:{src_port}",
                f"{dst_mac}:{dst_ip}:{dst_port}"
            ])

            return f"{protocol}:{endpoints[0]}:{endpoints[1]}"

        except Exception:
            return f"unknown:{self.frame_number}"

    def is_marked(self) -> bool:

        try:
            if self.packet.haslayer('TCP'):
                tcp_layer = self.packet['TCP']
                return bool(tcp_layer.flags & 0x3F)
            return False
        except Exception:
            return False

    def is_ignored(self) -> bool:

        try:
            return len(self.packet) < 14
        except Exception:
            return True