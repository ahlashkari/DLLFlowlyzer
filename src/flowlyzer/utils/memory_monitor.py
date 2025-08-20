"""
Memory monitoring and management utilities for DLL Flowlyzer.
"""

import psutil
import gc
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class MemoryStats:
    """Container for memory usage statistics."""
    total_mb: float
    available_mb: float
    used_mb: float
    percent_used: float
    process_mb: float
    process_percent: float


class MemoryMonitor:
    """
    Monitor and manage memory usage during PCAP processing.
    """
    
    def __init__(self, warning_threshold_mb: float = 1024, critical_threshold_mb: float = 2048):
        """
        Initialize memory monitor.
        
        Args:
            warning_threshold_mb: Memory usage threshold to trigger warnings
            critical_threshold_mb: Memory usage threshold to trigger aggressive cleanup
        """
        self.warning_threshold = warning_threshold_mb
        self.critical_threshold = critical_threshold_mb
        self.logger = logging.getLogger(__name__)
        
        # Track memory usage over time
        self.peak_memory_mb = 0.0
        self.cleanup_count = 0
        self.warning_count = 0
        
        try:
            self.process = psutil.Process()
            self.memory_monitoring_available = True
        except Exception as e:
            self.logger.warning(f"Memory monitoring not available: {e}")
            self.memory_monitoring_available = False
    
    def get_memory_stats(self) -> MemoryStats:
        """Get current memory usage statistics."""
        if not self.memory_monitoring_available:
            return MemoryStats(0, 0, 0, 0, 0, 0)
        
        try:
            # System memory
            system_memory = psutil.virtual_memory()
            total_mb = system_memory.total / 1024 / 1024
            available_mb = system_memory.available / 1024 / 1024
            used_mb = system_memory.used / 1024 / 1024
            percent_used = system_memory.percent
            
            # Process memory
            process_memory = self.process.memory_info()
            process_mb = process_memory.rss / 1024 / 1024
            process_percent = (process_mb / total_mb) * 100
            
            # Update peak memory tracking
            if process_mb > self.peak_memory_mb:
                self.peak_memory_mb = process_mb
            
            return MemoryStats(
                total_mb=total_mb,
                available_mb=available_mb,
                used_mb=used_mb,
                percent_used=percent_used,
                process_mb=process_mb,
                process_percent=process_percent
            )
            
        except Exception as e:
            self.logger.error(f"Error getting memory stats: {e}")
            return MemoryStats(0, 0, 0, 0, 0, 0)
    
    def check_memory_pressure(self) -> tuple[bool, bool]:
        """
        Check if memory usage is approaching limits.
        
        Returns:
            Tuple of (warning_triggered, critical_triggered)
        """
        stats = self.get_memory_stats()
        
        warning_triggered = stats.process_mb > self.warning_threshold
        critical_triggered = stats.process_mb > self.critical_threshold
        
        if warning_triggered:
            self.warning_count += 1
            
        if critical_triggered:
            self.logger.critical(f"Critical memory usage: {stats.process_mb:.1f} MB "
                               f"({stats.process_percent:.1f}% of system)")
        elif warning_triggered:
            self.logger.warning(f"High memory usage: {stats.process_mb:.1f} MB "
                              f"({stats.process_percent:.1f}% of system)")
        
        return warning_triggered, critical_triggered
    
    def force_garbage_collection(self) -> int:
        """
        Force garbage collection and return number of objects collected.
        
        Returns:
            Number of objects collected
        """
        collected = 0
        try:
            for generation in range(3):  # Python has 3 generations
                collected += gc.collect(generation)
            
            self.cleanup_count += 1
            self.logger.debug(f"Garbage collection completed: {collected} objects collected")
            return collected
            
        except Exception as e:
            self.logger.error(f"Error in garbage collection: {e}")
            return 0
    
    def get_monitoring_summary(self) -> Dict[str, Any]:
        """Get summary of monitoring session."""
        stats = self.get_memory_stats()
        
        return {
            'current_memory_mb': stats.process_mb,
            'peak_memory_mb': self.peak_memory_mb,
            'system_memory_percent': stats.percent_used,
            'warning_count': self.warning_count,
            'cleanup_count': self.cleanup_count,
            'memory_monitoring_available': self.memory_monitoring_available,
            'warning_threshold_mb': self.warning_threshold,
            'critical_threshold_mb': self.critical_threshold,
        }
    
    def log_memory_summary(self):
        """Log a summary of memory usage during processing."""
        summary = self.get_monitoring_summary()
        
        self.logger.info("Memory Usage Summary:")
        self.logger.info(f"  Current: {summary['current_memory_mb']:.1f} MB")
        self.logger.info(f"  Peak: {summary['peak_memory_mb']:.1f} MB")
        self.logger.info(f"  System Memory Used: {summary['system_memory_percent']:.1f}%")
        self.logger.info(f"  Memory Warnings: {summary['warning_count']}")
        self.logger.info(f"  Cleanup Operations: {summary['cleanup_count']}")
    
    def suggest_memory_optimization(self) -> list[str]:
        """Suggest memory optimization strategies based on usage patterns."""
        suggestions = []
        stats = self.get_memory_stats()
        
        if stats.process_mb > 1024:  # > 1GB
            suggestions.append("Consider reducing --max-flows parameter")
            suggestions.append("Use smaller --batch-size for more frequent CSV exports")
            suggestions.append("Reduce --queue-size to limit buffered packets")
        
        if stats.process_mb > 2048:  # > 2GB
            suggestions.append("Consider processing smaller PCAP files")
            suggestions.append("Use --workers 2 to reduce thread overhead")
            suggestions.append("Enable --disable-batching only for small datasets")
        
        if self.warning_count > 10:
            suggestions.append("Frequent memory warnings detected - consider increasing system RAM")
            suggestions.append("Process folders sequentially (--folder-threads 1)")
        
        return suggestions


def format_memory_size(bytes_value: float) -> str:
    """Format byte value as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"