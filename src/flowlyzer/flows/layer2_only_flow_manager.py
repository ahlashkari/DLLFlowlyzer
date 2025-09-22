"""
Layer 2-only flow manager for --justlayertwo mode.
Uses MAC addresses for flow identification instead of IP addresses.
"""

from typing import Dict, List, Optional, Any
from scapy.all import Packet
from .layer2_only_flow import Layer2OnlyFlow
from ..packets.simple_layer2_packet import SimpleLayer2Packet
import time
import logging


class Layer2OnlyFlowManager:
    """Manages flows based on MAC addresses for Layer 2-only analysis."""
    
    def __init__(self, flow_timeout: int = 300, max_flows: int = 50000):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.active_flows: Dict[str, Layer2OnlyFlow] = {}
        self.completed_flows: List[Layer2OnlyFlow] = []
        
        # Statistics
        self.total_packets_processed = 0
        self.flow_stats = {
            'created': 0,
            'completed': 0,
            'timed_out': 0
        }
        self.protocol_stats: Dict[str, int] = {}
        
        self.logger = logging.getLogger(__name__)
        self.start_time = time.time()
    
    def process_packet(self, scapy_packet: Packet, frame_number: int) -> Optional[Layer2OnlyFlow]:
        """Process a packet and return associated flow."""
        try:
            self.total_packets_processed += 1
            
            # Create simple Layer 2-only packet
            packet = SimpleLayer2Packet(scapy_packet, frame_number)
            
            # Update protocol statistics
            protocol = packet.get_protocol_type()
            self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
            
            # Create flow key based on MAC addresses (bidirectional)
            flow_key = self._create_mac_flow_key(packet)
            
            # Find or create flow
            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                flow.add_packet(packet)
            else:
                # Check flow limits
                if len(self.active_flows) >= self.max_flows:
                    self._cleanup_old_flows()
                
                # Create new flow
                flow = Layer2OnlyFlow(flow_key, packet)
                self.active_flows[flow_key] = flow
                self.flow_stats['created'] += 1
            
            # Periodic cleanup
            if self.total_packets_processed % 10000 == 0:
                self._cleanup_timed_out_flows()
            
            return flow
            
        except Exception as e:
            self.logger.error(f"Error processing packet {frame_number}: {e}")
            return None
    
    def _create_mac_flow_key(self, packet: SimpleLayer2Packet) -> str:
        """Create flow key based on MAC addresses."""
        src_mac = packet.features.get('src_mac', 'unknown')
        dst_mac = packet.features.get('dst_mac', 'unknown')
        
        # Create bidirectional key (smaller MAC first for consistency)
        if src_mac < dst_mac:
            return f"{src_mac}_{dst_mac}"
        else:
            return f"{dst_mac}_{src_mac}"
    
    def _cleanup_old_flows(self):
        """Force completion of old flows to free memory."""
        if not self.active_flows:
            return
        
        # Sort by last activity and complete oldest 25%
        flows_to_complete = len(self.active_flows) // 4
        if flows_to_complete < 100:
            flows_to_complete = min(100, len(self.active_flows) // 2)
        
        sorted_flows = sorted(
            list(self.active_flows.items()),
            key=lambda x: x[1].last_activity
        )
        
        for i in range(flows_to_complete):
            flow_key, flow = sorted_flows[i]
            self._complete_flow(flow_key, 'forced_cleanup')
    
    def _cleanup_timed_out_flows(self):
        """Remove flows that have timed out."""
        current_time = time.time()
        timed_out_keys = []
        
        for flow_key, flow in list(self.active_flows.items()):
            if flow.should_timeout(current_time, self.flow_timeout):
                timed_out_keys.append(flow_key)
        
        for flow_key in timed_out_keys:
            self._complete_flow(flow_key, 'timeout')
    
    def _complete_flow(self, flow_key: str, reason: str):
        """Complete a flow and move to completed list."""
        if flow_key in self.active_flows:
            flow = self.active_flows.pop(flow_key)
            self.completed_flows.append(flow)
            
            if reason == 'timeout':
                self.flow_stats['timed_out'] += 1
            else:
                self.flow_stats['completed'] += 1
    
    def force_flow_completion(self, max_active_flows: int = None):
        """Force completion of flows to manage memory."""
        if max_active_flows is None:
            max_active_flows = self.max_flows // 2
        
        flows_to_complete = max(0, len(self.active_flows) - max_active_flows)
        if flows_to_complete > 0:
            # Complete oldest flows first
            sorted_flows = sorted(
                list(self.active_flows.items()),
                key=lambda x: x[1].last_activity
            )
            
            for i in range(flows_to_complete):
                flow_key, flow = sorted_flows[i]
                self._complete_flow(flow_key, 'forced_memory_cleanup')
            
            self.logger.info(f"Force completed {flows_to_complete} flows for memory management")
    
    def get_batch_completed_flows(self, batch_size: int) -> List[Layer2OnlyFlow]:
        """Get a batch of completed flows and remove them from memory."""
        if len(self.completed_flows) < batch_size:
            return []
        
        batch = self.completed_flows[:batch_size]
        self.completed_flows = self.completed_flows[batch_size:]
        
        return batch
    
    def get_all_completed_flows(self) -> List[Layer2OnlyFlow]:
        """Get all completed flows."""
        flows = self.completed_flows.copy()
        self.completed_flows.clear()
        return flows
    
    def complete_all_active_flows(self):
        """Complete all active flows (called at end of processing)."""
        for flow_key in list(self.active_flows.keys()):
            self._complete_flow(flow_key, 'end_of_processing')
        
        self.logger.info(f"Completed all {len(list(self.active_flows.keys()))} remaining active flows")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        
        return {
            'total_packets': self.total_packets_processed,
            'total_flows': len(self.active_flows) + len(self.completed_flows),
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'flow_stats': self.flow_stats.copy(),
            'protocol_stats': self.protocol_stats.copy(),
            'processing_time': elapsed_time,
            'packets_per_second': self.total_packets_processed / elapsed_time if elapsed_time > 0 else 0,
            'flows_per_second': self.flow_stats['created'] / elapsed_time if elapsed_time > 0 else 0
        }
    
    def clear_completed_flows(self):
        """Clear completed flows from memory."""
        count = len(self.completed_flows)
        self.completed_flows.clear()
        if count > 0:
            self.logger.debug(f"Cleared {count} completed flows from memory")
    
    def print_statistics(self):
        """Print current statistics."""
        stats = self.get_statistics()
        
        self.logger.info("=== Layer 2-Only Flow Manager Statistics ===")
        self.logger.info(f"Total packets processed: {stats['total_packets']:,}")
        self.logger.info(f"Active flows: {stats['active_flows']:,}")
        self.logger.info(f"Completed flows: {stats['completed_flows']:,}")
        self.logger.info(f"Processing rate: {stats['packets_per_second']:.1f} packets/sec")
        self.logger.info(f"Flow creation rate: {stats['flows_per_second']:.1f} flows/sec")
        
        self.logger.info("Flow Statistics:")
        for stat_name, count in stats['flow_stats'].items():
            self.logger.info(f"  {stat_name}: {count:,}")
        
        self.logger.info("Layer 2 Protocol Distribution:")
        total_protocols = sum(stats['protocol_stats'].values())
        for protocol, count in sorted(stats['protocol_stats'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_protocols) * 100 if total_protocols > 0 else 0
            self.logger.info(f"  {protocol}: {count:,} ({percentage:.1f}%)")
    
    def get_memory_usage_estimate(self) -> int:
        """Estimate memory usage in bytes."""
        try:
            # Estimate memory per flow (rough calculation)
            bytes_per_flow = 2048  # Rough estimate for Layer 2-only flows
            
            active_memory = len(self.active_flows) * bytes_per_flow
            completed_memory = len(self.completed_flows) * bytes_per_flow
            
            # Add overhead for statistics and manager itself
            overhead = 1024 * 1024  # 1MB overhead
            
            return active_memory + completed_memory + overhead
        except Exception as e:
            self.logger.debug(f"Error estimating memory usage: {e}")
            return 0
    
    def get_all_flows(self) -> list:
        """Get all flows (active + completed)."""
        try:
            all_flows = list(self.active_flows.values()) + self.completed_flows
            return all_flows
        except Exception as e:
            self.logger.error(f"Error getting all flows: {e}")
            return []
    
    def finalize_all_flows(self) -> list:
        """Finalize all flows and return them."""
        try:
            # Complete all active flows first
            self.complete_all_active_flows()
            
            # Return all completed flows
            all_flows = self.completed_flows.copy()
            
            # Clear flows from memory
            self.completed_flows.clear()
            
            return all_flows
        except Exception as e:
            self.logger.error(f"Error finalizing all flows: {e}")
            return []

    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.active_flows.clear()
            self.completed_flows.clear()
        except:
            pass