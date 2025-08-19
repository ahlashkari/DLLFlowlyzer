"""
Packet queue system for optimized packet processing.
"""

import queue
import threading
import logging
from typing import Callable, Optional, Any, Dict
from scapy.all import Packet


class PacketQueue:
    """
    Thread-safe packet queue for optimized packet processing.
    Implements producer-consumer pattern for efficient packet handling.
    """
    
    def __init__(self, maxsize: int = 100000, num_workers: int = 4):
        """
        Initialize packet queue.
        
        Args:
            maxsize: Maximum queue size
            num_workers: Number of worker threads for processing
        """
        self.queue = queue.Queue(maxsize=maxsize)
        self.num_workers = num_workers
        self.workers = []
        self.running = False
        self.packet_processor: Optional[Callable] = None
        
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.packets_queued = 0
        self.packets_processed = 0
        self.packets_dropped = 0
    
    def set_packet_processor(self, processor: Callable[[Packet, int], Any]):
        """
        Set the packet processing function.
        
        Args:
            processor: Function that takes (scapy_packet, frame_number) and processes it
        """
        self.packet_processor = processor
    
    def start(self):
        """Start the packet processing workers."""
        if self.running:
            return
        
        if self.packet_processor is None:
            raise ValueError("Packet processor must be set before starting queue")
        
        self.running = True
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"PacketWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        self.logger.info(f"Started packet queue with {self.num_workers} workers")
    
    def stop(self, timeout: float = 30.0):
        """
        Stop the packet processing workers.
        
        Args:
            timeout: Maximum time to wait for workers to finish
        """
        if not self.running:
            return
        
        self.running = False
        
        # Add poison pills to stop workers
        for _ in range(self.num_workers):
            try:
                self.queue.put((None, None), timeout=1.0)
            except queue.Full:
                pass
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=timeout/self.num_workers)
        
        self.workers.clear()
        self.logger.info("Stopped packet queue workers")
    
    def put_packet(self, scapy_packet: Packet, frame_number: int, timeout: float = 1.0) -> bool:
        """
        Add a packet to the processing queue.
        
        Args:
            scapy_packet: Scapy packet object
            frame_number: Sequential frame number
            timeout: Maximum time to wait if queue is full
            
        Returns:
            True if packet was queued, False if queue was full
        """
        try:
            self.queue.put((scapy_packet, frame_number), timeout=timeout)
            self.packets_queued += 1
            return True
        except queue.Full:
            self.packets_dropped += 1
            self.logger.warning(f"Dropped packet {frame_number} - queue full")
            return False
    
    def _worker_loop(self):
        """Main worker loop for processing packets."""
        while self.running:
            try:
                # Get packet from queue
                item = self.queue.get(timeout=1.0)
                
                if item == (None, None):  # Poison pill
                    break
                
                scapy_packet, frame_number = item
                
                # Process packet
                if self.packet_processor:
                    self.packet_processor(scapy_packet, frame_number)
                
                self.packets_processed += 1
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in worker loop: {e}")
                continue
    
    def wait_for_completion(self, timeout: Optional[float] = None):
        """
        Wait for all queued packets to be processed.
        
        Args:
            timeout: Maximum time to wait (None for no timeout)
        """
        try:
            if timeout:
                self.queue.join()
            else:
                # Wait with timeout to allow for interrupt
                while not self.queue.empty():
                    self.queue.join()
        except KeyboardInterrupt:
            self.logger.info("Queue processing interrupted by user")
    
    def get_statistics(self) -> Dict[str, int]:
        """Get queue processing statistics."""
        return {
            'packets_queued': self.packets_queued,
            'packets_processed': self.packets_processed,
            'packets_dropped': self.packets_dropped,
            'queue_size': self.queue.qsize(),
            'workers_active': len([w for w in self.workers if w.is_alive()]),
        }
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self.queue.empty()
    
    def qsize(self) -> int:
        """Get current queue size."""
        return self.queue.qsize()