"""
TCP packet analysis class for extracting TCP-specific features.
"""

from .base_packet import BasePacket
from scapy.all import Packet
from typing import Dict, Any


class TCPPacket(BasePacket):
    """TCP packet analyzer with TCP-specific feature extraction."""
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_tcp_features()
    
    def _extract_tcp_features(self):
        """Extract TCP-specific features."""
        try:
            if not self.packet.haslayer('TCP'):
                return
            
            tcp_layer = self.packet['TCP']
            
            # TCP flags
            self.features['tcp_flags'] = int(tcp_layer.flags)
            self.features['tcp_syn'] = bool(tcp_layer.flags & 0x02)
            self.features['tcp_ack'] = bool(tcp_layer.flags & 0x10)
            self.features['tcp_fin'] = bool(tcp_layer.flags & 0x01)
            self.features['tcp_rst'] = bool(tcp_layer.flags & 0x04)
            self.features['tcp_psh'] = bool(tcp_layer.flags & 0x08)
            self.features['tcp_urg'] = bool(tcp_layer.flags & 0x20)
            
            # TCP sequence and acknowledgment numbers
            self.features['tcp_seq'] = int(tcp_layer.seq)
            self.features['tcp_ack_seq'] = int(tcp_layer.ack)
            
            # TCP window size
            self.features['tcp_window'] = int(tcp_layer.window)
            
            # TCP payload length
            self.features['tcp_payload_len'] = len(tcp_layer.payload) if tcp_layer.payload else 0
            
            # TCP options length
            tcp_options_len = (tcp_layer.dataofs * 4) - 20  # TCP header size - standard 20 bytes
            self.features['tcp_options_len'] = max(0, tcp_options_len)
            
        except Exception:
            self._set_default_tcp_features()
    
    def _set_default_tcp_features(self):
        """Set default TCP features when extraction fails."""
        tcp_defaults = {
            'tcp_flags': 0,
            'tcp_syn': False,
            'tcp_ack': False,
            'tcp_fin': False,
            'tcp_rst': False,
            'tcp_psh': False,
            'tcp_urg': False,
            'tcp_seq': 0,
            'tcp_ack_seq': 0,
            'tcp_window': 0,
            'tcp_payload_len': 0,
            'tcp_options_len': 0,
        }
        self.features.update(tcp_defaults)
    
    def is_connection_start(self) -> bool:
        """Check if this packet starts a TCP connection (SYN flag)."""
        return self.features.get('tcp_syn', False) and not self.features.get('tcp_ack', False)
    
    def is_connection_end(self) -> bool:
        """Check if this packet ends a TCP connection (FIN or RST flag)."""
        return self.features.get('tcp_fin', False) or self.features.get('tcp_rst', False)
    
    def get_tcp_stream_key(self) -> str:
        """Generate TCP stream identifier for flow grouping."""
        try:
            src_ip = self.features.get('src_ip_addr', 'unknown')
            dst_ip = self.features.get('dst_ip_addr', 'unknown')
            src_port = self.features.get('src_port', 0)
            dst_port = self.features.get('dst_port', 0)
            
            # Create bidirectional stream key
            endpoints = sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])
            return f"TCP:{endpoints[0]}:{endpoints[1]}"
            
        except Exception:
            return super().get_flow_key()