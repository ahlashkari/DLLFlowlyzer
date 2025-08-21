"""
Flow manager for tracking and managing network flows.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

from .flow import Flow
from ..packets.base_packet import BasePacket
from ..packets.tcp_packet import TCPPacket
from ..packets.udp_packet import UDPPacket
from ..packets.layer2_packet import STPPacket, CDPPacket, LLDPPacket, ARPPacket
from ..packets.llc_packet import LLCPacket, VTPPacket, DTPPacket, ISLPacket, LoopPacket


class FlowManager:
    """
    Manages network flows, handles flow detection, timeouts, and statistics.
    """
    
    def __init__(self, flow_timeout: float = 1200.0, max_flows: int = 100000):
        """
        Initialize flow manager.
        
        Args:
            flow_timeout: Flow timeout in seconds (default 20 minutes)
            max_flows: Maximum number of concurrent flows
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        
        # Active flows storage
        self.active_flows: Dict[str, Flow] = {}
        self.completed_flows: List[Flow] = []
        
        # Statistics
        self.total_packets_processed = 0
        self.protocol_stats = defaultdict(int)
        self.flow_stats = defaultdict(int)
        
        self.logger = logging.getLogger(__name__)
    
    def process_packet(self, scapy_packet, frame_number: int) -> Optional[Flow]:
        """
        Process a single packet and assign it to appropriate flow.
        
        Args:
            scapy_packet: Scapy packet object
            frame_number: Sequential frame number
            
        Returns:
            Flow object if packet was assigned to a flow, None otherwise
        """
        try:
            # Create appropriate packet object based on protocol
            packet = self._create_packet_object(scapy_packet, frame_number)
            
            self.total_packets_processed += 1
            protocol = packet.get_protocol_type()
            self.protocol_stats[protocol] += 1
            
            # Get flow key for this packet
            flow_key = packet.get_flow_key()
            
            # Check if flow already exists
            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                flow.add_packet(packet)
                
                # Check if TCP flow should be closed
                if isinstance(packet, TCPPacket) and packet.is_connection_end():
                    self._close_flow(flow_key)
                    
            else:
                # Create new flow
                if len(self.active_flows) >= self.max_flows:
                    self._cleanup_old_flows()
                
                flow = Flow(flow_key, packet)
                self.active_flows[flow_key] = flow
                self.flow_stats['created'] += 1
            
            # Periodic cleanup of timed-out flows
            if self.total_packets_processed % 10000 == 0:
                self._cleanup_timed_out_flows()
            
            return self.active_flows.get(flow_key)
            
        except Exception as e:
            self.logger.error(f"Error processing packet {frame_number}: {e}")
            return None
    
    def _create_packet_object(self, scapy_packet, frame_number: int) -> BasePacket:
        """Create appropriate packet object based on protocol."""
        try:
            # Check for TCP
            if scapy_packet.haslayer('TCP'):
                return TCPPacket(scapy_packet, frame_number)
            
            # Check for UDP (and its sub-protocols)
            elif scapy_packet.haslayer('UDP'):
                return UDPPacket(scapy_packet, frame_number)
            
            # Check for Layer 2 protocols
            elif scapy_packet.haslayer('STP'):
                return STPPacket(scapy_packet, frame_number)
            
            elif scapy_packet.haslayer('ARP'):
                return ARPPacket(scapy_packet, frame_number)
            
            # Check for LLC frames
            elif scapy_packet.haslayer('LLC'):
                # Check for specific LLC-based protocols
                if self._is_cdp_packet(scapy_packet):
                    self.logger.debug(f"CDP packet detected at frame {frame_number}")
                    return CDPPacket(scapy_packet, frame_number)
                elif self._is_lldp_packet(scapy_packet):
                    self.logger.debug(f"LLDP packet detected at frame {frame_number}")
                    return LLDPPacket(scapy_packet, frame_number)
                elif self._is_dtp_packet(scapy_packet):
                    self.logger.debug(f"DTP packet detected at frame {frame_number}")
                    return DTPPacket(scapy_packet, frame_number)
                elif self._is_vtp_packet(scapy_packet):
                    self.logger.debug(f"VTP packet detected at frame {frame_number}")
                    return VTPPacket(scapy_packet, frame_number)
                elif self._is_isl_packet(scapy_packet):
                    self.logger.debug(f"ISL packet detected at frame {frame_number}")
                    return ISLPacket(scapy_packet, frame_number)
                else:
                    return LLCPacket(scapy_packet, frame_number)
            
            # Check for LLDP by MAC address and payload (more specific detection)
            elif self._is_lldp_packet(scapy_packet):
                self.logger.debug(f"LLDP packet detected by enhanced analysis at frame {frame_number}")
                return LLDPPacket(scapy_packet, frame_number)
            
            # Check for CDP by MAC address and payload (enhanced detection)
            elif self._is_cdp_packet(scapy_packet):
                self.logger.debug(f"CDP packet detected by enhanced analysis at frame {frame_number}")
                return CDPPacket(scapy_packet, frame_number)
            
            # Check for ISL by characteristics
            elif self._is_isl_packet(scapy_packet):
                return ISLPacket(scapy_packet, frame_number)
            
            # Check for DTP by MAC
            elif self._is_dtp_packet(scapy_packet):
                return DTPPacket(scapy_packet, frame_number)
            
            # Default to base packet
            else:
                return BasePacket(scapy_packet, frame_number)
                
        except Exception as e:
            self.logger.warning(f"Error creating packet object for frame {frame_number}: {e}")
            return BasePacket(scapy_packet, frame_number)
    
    def _is_cdp_packet(self, scapy_packet) -> bool:
        """Check if packet is CDP with enhanced payload analysis."""
        try:
            if scapy_packet.haslayer('Ether'):
                dst_mac = str(scapy_packet['Ether'].dst).lower()
                if dst_mac == '01:00:0c:cc:cc:cc':
                    # CDP uses the same MAC as DTP, need precise payload analysis
                    raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
                    
                    if scapy_packet.haslayer('LLC'):
                        llc_layer = scapy_packet['LLC']
                        # CDP typically has DSAP/SSAP = 0xAA (SNAP)
                        if hasattr(llc_layer, 'dsap') and hasattr(llc_layer, 'ssap'):
                            if llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa:
                                # Check if it's CDP by looking at SNAP OUI and PID
                                # CDP has OUI 00:00:0c and PID 0x2000
                                if len(raw_payload) >= 8:
                                    # Look for CDP SNAP signature in LLC payload
                                    return raw_payload[3:6] == b'\x00\x00\x0c' and raw_payload[6:8] == b'\x20\x00'
                                elif len(raw_payload) >= 5:
                                    # Alternative check: look for CDP SNAP at start of LLC payload
                                    return raw_payload[0:3] == b'\x00\x00\x0c' and raw_payload[3:5] == b'\x20\x00'
                    else:
                        # If no LLC layer, check for CDP directly in ethernet payload
                        if len(raw_payload) >= 8:
                            # Check for CDP version field (should be 1 or 2) and reasonable TTL
                            if len(raw_payload) >= 2:
                                version = raw_payload[0]
                                ttl = raw_payload[1]
                                # CDP version is typically 1 or 2, TTL is reasonable (1-255)
                                if version in [1, 2] and 1 <= ttl <= 255:
                                    return True
                        # If MAC matches but no clear structure, assume it's CDP for compatibility
                        return True
            return False
        except Exception as e:
            self.logger.debug(f"Error in CDP detection: {e}")
            return False
    
    def _is_lldp_packet(self, scapy_packet) -> bool:
        """Check if packet is LLDP with enhanced payload analysis."""
        try:
            if scapy_packet.haslayer('Ether'):
                dst_mac = str(scapy_packet['Ether'].dst).lower()
                # Check for standard LLDP MAC addresses
                if dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                    # Additional payload validation for LLDP
                    raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
                    if len(raw_payload) >= 4:
                        # Check for LLDP TLV structure
                        # First TLV should be Chassis ID (type 1) or Port ID (type 2)
                        first_tlv = int.from_bytes(raw_payload[0:2], 'big') if len(raw_payload) >= 2 else 0
                        tlv_type = (first_tlv >> 9) & 0x7F
                        tlv_length = first_tlv & 0x1FF
                        
                        # Valid LLDP should start with Chassis ID (1), Port ID (2), or TTL (3)
                        if tlv_type in [1, 2, 3] and 0 < tlv_length <= 255:
                            return True
                    # If MAC matches but payload doesn't look like LLDP, still consider it LLDP
                    return True
            return False
        except Exception as e:
            self.logger.debug(f"Error in LLDP detection: {e}")
            return False
    
    def _is_dtp_packet(self, scapy_packet) -> bool:
        """Check if packet is DTP."""
        try:
            if scapy_packet.haslayer('Ether'):
                dst_mac = str(scapy_packet['Ether'].dst).lower()
                if dst_mac == '01:00:0c:cc:cc:cc' and scapy_packet.haslayer('LLC'):
                    # Check if this is DTP and not CDP
                    raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
                    if len(raw_payload) >= 8:
                        # DTP has different SNAP PID than CDP
                        # CDP: OUI 00:00:0c, PID 0x2000
                        # DTP: OUI 00:00:0c, PID 0x2004
                        return (raw_payload[3:6] == b'\x00\x00\x0c' and 
                               raw_payload[6:8] == b'\x20\x04')
                    return False
            return False
        except Exception as e:
            self.logger.debug(f"Error in DTP detection: {e}")
            return False
    
    def _is_vtp_packet(self, scapy_packet) -> bool:
        """Check if packet is VTP."""
        try:
            if scapy_packet.haslayer('LLC'):
                llc_layer = scapy_packet['LLC']
                return llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa
            return False
        except Exception:
            return False
    
    def _is_isl_packet(self, scapy_packet) -> bool:
        """Check if packet is ISL."""
        try:
            if scapy_packet.haslayer('Ether'):
                # ISL packets typically have specific characteristics
                if len(scapy_packet) > 30:  # ISL adds overhead
                    raw_data = bytes(scapy_packet)
                    # Check for ISL header pattern (simplified)
                    if len(raw_data) >= 26 and raw_data[0:4] == b'\x01\x00\x0c\x00':
                        return True
            return False
        except Exception:
            return False
    
    def _close_flow(self, flow_key: str):
        """Close a flow and move it to completed flows."""
        if flow_key in self.active_flows:
            flow = self.active_flows.pop(flow_key)
            flow.close_flow()
            self.completed_flows.append(flow)
            self.flow_stats['completed'] += 1
    
    def _cleanup_timed_out_flows(self):
        """Clean up flows that have timed out."""
        current_time = time.time()
        timed_out_flows = []
        
        # Create a copy of the items to avoid "dictionary changed size during iteration"
        for flow_key, flow in list(self.active_flows.items()):
            if flow.is_timeout(current_time, self.flow_timeout):
                timed_out_flows.append(flow_key)
        
        for flow_key in timed_out_flows:
            self._close_flow(flow_key)
            self.flow_stats['timed_out'] += 1
    
    def _cleanup_old_flows(self):
        """Clean up oldest flows when max_flows limit is reached."""
        if len(self.active_flows) >= self.max_flows:
            # Sort flows by last activity time and close oldest ones
            sorted_flows = sorted(
                self.active_flows.items(),
                key=lambda x: x[1].last_activity
            )
            
            # Close oldest 10% of flows
            flows_to_close = len(sorted_flows) // 10
            for i in range(flows_to_close):
                flow_key = sorted_flows[i][0]
                self._close_flow(flow_key)
                self.flow_stats['force_closed'] += 1
    
    def finalize_all_flows(self):
        """Close all remaining active flows."""
        # Create a copy of the keys to avoid "dictionary changed size during iteration"
        active_flow_keys = list(self.active_flows.keys())
        for flow_key in active_flow_keys:
            self._close_flow(flow_key)
    
    def get_all_flows(self) -> List[Flow]:
        """Get all flows (active and completed)."""
        return list(self.active_flows.values()) + self.completed_flows
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            'total_packets': self.total_packets_processed,
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'total_flows': len(self.active_flows) + len(self.completed_flows),
            'protocol_stats': dict(self.protocol_stats),
            'flow_stats': dict(self.flow_stats),
        }
    
    def get_batch_completed_flows(self, batch_size: int = 30) -> List[Flow]:
        """
        Get a batch of completed flows and remove them from memory.
        
        Args:
            batch_size: Number of flows to return in batch
            
        Returns:
            List of completed flows (up to batch_size)
        """
        if len(self.completed_flows) >= batch_size:
            batch_flows = self.completed_flows[:batch_size]
            self.completed_flows = self.completed_flows[batch_size:]
            self.logger.info(f"Retrieved batch of {len(batch_flows)} flows, {len(self.completed_flows)} remaining")
            return batch_flows
        elif self.completed_flows:
            # Return all remaining flows if less than batch_size
            batch_flows = self.completed_flows.copy()
            self.completed_flows.clear()
            self.logger.info(f"Retrieved final batch of {len(batch_flows)} flows")
            return batch_flows
        else:
            return []
    
    def clear_packet_data(self, flows: List[Flow]):
        """
        Clear packet data from flows to free memory while keeping flow features.
        
        Args:
            flows: List of flows to clear packet data from
        """
        for flow in flows:
            if hasattr(flow, 'packets') and flow.packets:
                # Ensure features are cached before clearing packets
                flow.get_features()  # This caches the features
                # Clear packet data to free memory
                flow.packets.clear()
        
        self.logger.debug(f"Cleared packet data from {len(flows)} flows")
    
    def force_flow_completion(self, max_active_flows: int = 100):
        """
        Force completion of oldest active flows when we need to free memory.
        
        Args:
            max_active_flows: Maximum number of active flows to keep
        """
        if len(self.active_flows) > max_active_flows:
            # Sort by last activity and force completion of oldest flows
            sorted_flows = sorted(
                self.active_flows.items(),
                key=lambda x: x[1].last_activity
            )
            
            flows_to_complete = len(self.active_flows) - max_active_flows
            for i in range(flows_to_complete):
                flow_key = sorted_flows[i][0]
                self._close_flow(flow_key)
                self.flow_stats['force_completed_for_memory'] += 1
            
            self.logger.info(f"Force completed {flows_to_complete} flows to manage memory")
    
    def get_memory_usage_estimate(self) -> dict:
        """
        Get estimated memory usage of flows.
        
        Returns:
            Dictionary with memory usage estimates
        """
        active_flows_mem = len(self.active_flows) * 1024  # Rough estimate
        completed_flows_mem = len(self.completed_flows) * 1024
        
        # More detailed estimation based on packets
        total_packets = sum(len(flow.packets) for flow in self.active_flows.values())
        total_packets += sum(len(flow.packets) for flow in self.completed_flows)
        packet_mem = total_packets * 500  # Rough estimate per packet
        
        return {
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'total_packets_in_memory': total_packets,
            'estimated_memory_mb': (active_flows_mem + completed_flows_mem + packet_mem) / 1024 / 1024
        }

    def log_progress(self):
        """Log current processing progress with detailed protocol breakdown."""
        stats = self.get_statistics()
        
        # Create detailed protocol summary
        protocol_items = []
        for proto, count in sorted(stats['protocol_stats'].items()):
            if count > 0:
                protocol_items.append(f"{count} {proto}")
        
        protocol_summary = ', '.join(protocol_items) if protocol_items else 'no packets processed'
        
        # Special logging for CDP to debug detection
        cdp_count = stats['protocol_stats'].get('CDP', 0)
        if cdp_count > 0:
            self.logger.info(f"CDP Detection: Found {cdp_count} CDP packets")
        
        self.logger.info(
            f"Processed {stats['total_packets']} packets: {protocol_summary} "
            f"with {stats['total_flows']} flows ({stats['active_flows']} active, "
            f"{stats['completed_flows']} completed)"
        )