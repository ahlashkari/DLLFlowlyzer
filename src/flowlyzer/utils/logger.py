"""
Comprehensive logging system for DLL Flowlyzer.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class FlowlyzerLogger:
    """
    Custom logger for DLL Flowlyzer with progress tracking and structured output.
    """
    
    def __init__(self, log_file: str = "Results/log.txt", 
                 log_level: str = "INFO", 
                 quiet: bool = False):
        """
        Initialize flowlyzer logger.
        
        Args:
            log_file: Path to log file
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
            quiet: Whether to suppress console output
        """
        self.log_file = Path(log_file)
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.quiet = quiet
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(exist_ok=True)
        
        # Set up logging
        self._setup_logging()
        
        # Progress tracking
        self.progress_stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'flows_completed': 0,
            'protocol_counts': {},
            'start_time': None,
        }
    
    def _setup_logging(self):
        """Set up logging configuration."""
        # Clear any existing handlers
        logging.getLogger().handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(formatter)
        
        # Console handler (unless quiet)
        handlers = [file_handler]
        if not self.quiet:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(formatter)
            handlers.append(console_handler)
        
        # Configure root logger
        logging.basicConfig(
            level=self.log_level,
            handlers=handlers,
            force=True
        )
        
        self.logger = logging.getLogger('DLLFlowlyzer')
    
    def log_start(self, input_files: list, config: dict):
        """Log analysis start with configuration."""
        import time
        self.progress_stats['start_time'] = time.time()
        
        self.logger.info("=" * 60)
        self.logger.info("DLL Flowlyzer Analysis Started")
        self.logger.info("=" * 60)
        self.logger.info(f"Input files: {len(input_files)} PCAP file(s)")
        self.logger.info(f"Output directory: {config.get('output_dir', 'Results')}")
        self.logger.info(f"Flow timeout: {config.get('flow_timeout', 1200)}s")
        self.logger.info(f"Separate L2/L3: {config.get('separate_l2_l3', False)}")
        self.logger.info(f"Queue size: {config.get('queue_size', 100000)}")
        
        # Log input files
        for i, file_path in enumerate(input_files[:10], 1):  # Show first 10
            self.logger.info(f"  {i}. {Path(file_path).name}")
        if len(input_files) > 10:
            self.logger.info(f"  ... and {len(input_files) - 10} more files")
        
        self.logger.info("-" * 60)
    
    def log_progress(self, packets_processed: int, protocol_stats: dict, flow_stats: dict):
        """Log processing progress."""
        self.progress_stats['packets_processed'] = packets_processed
        self.progress_stats['protocol_counts'] = protocol_stats.copy()
        self.progress_stats['flows_created'] = flow_stats.get('created', 0)
        self.progress_stats['flows_completed'] = flow_stats.get('completed', 0)
        
        # Create protocol summary
        protocol_summary = ', '.join([f"{count} {proto}" for proto, count in protocol_stats.items()])
        
        # Calculate rate
        elapsed_time = self._get_elapsed_time()
        rate = packets_processed / elapsed_time if elapsed_time > 0 else 0
        
        self.logger.info(
            f"Progress: {packets_processed:,} packets processed | "
            f"{protocol_summary} | "
            f"{flow_stats.get('created', 0)} flows ({flow_stats.get('completed', 0)} completed) | "
            f"{rate:.0f} pkt/s"
        )
    
    def log_file_progress(self, file_index: int, total_files: int, filename: str, packets_in_file: int):
        """Log progress for individual file processing."""
        self.logger.info(
            f"File {file_index}/{total_files}: {Path(filename).name} "
            f"({packets_in_file:,} packets)"
        )
    
    def log_flow_statistics(self, flow_stats: dict):
        """Log detailed flow statistics."""
        self.logger.info("-" * 40)
        self.logger.info("Flow Statistics:")
        self.logger.info(f"  Total flows: {flow_stats.get('total_flows', 0)}")
        self.logger.info(f"  Active flows: {flow_stats.get('active_flows', 0)}")
        self.logger.info(f"  Completed flows: {flow_stats.get('completed_flows', 0)}")
        self.logger.info(f"  Timed out flows: {flow_stats.get('timed_out', 0)}")
        self.logger.info(f"  Force closed flows: {flow_stats.get('force_closed', 0)}")
        
        if 'protocol_stats' in flow_stats:
            self.logger.info("  Protocol distribution:")
            for protocol, count in flow_stats['protocol_stats'].items():
                self.logger.info(f"    {protocol}: {count}")
    
    def log_feature_extraction(self, total_flows: int, feature_count: int):
        """Log feature extraction progress."""
        self.logger.info("-" * 40)
        self.logger.info("Feature Extraction:")
        self.logger.info(f"  Processing {total_flows} flows")
        self.logger.info(f"  Extracting {feature_count} features per flow")
    
    def log_labeling_results(self, label_stats: dict):
        """Log labeling results."""
        self.logger.info("-" * 40)
        self.logger.info("Flow Labeling Results:")
        total_flows = sum(label_stats.values())
        
        for label, count in label_stats.items():
            percentage = (count / total_flows) * 100 if total_flows > 0 else 0
            self.logger.info(f"  {label}: {count} ({percentage:.1f}%)")
    
    def log_export_results(self, export_info: dict):
        """Log CSV export results."""
        self.logger.info("-" * 40)
        self.logger.info("Export Results:")
        self.logger.info(f"  Total flows exported: {export_info.get('total_flows', 0)}")
        
        if export_info.get('combined_file'):
            self.logger.info(f"  Combined file: {Path(export_info['combined_file']).name}")
        
        if export_info.get('layer2_file'):
            self.logger.info(f"  Layer 2 file: {Path(export_info['layer2_file']).name}")
        
        if export_info.get('layer3_file'):
            self.logger.info(f"  Layer 3 file: {Path(export_info['layer3_file']).name}")
        
        if export_info.get('metadata_file'):
            self.logger.info(f"  Metadata file: {Path(export_info['metadata_file']).name}")
    
    def log_completion(self, total_time: float, final_stats: dict):
        """Log analysis completion summary."""
        self.logger.info("=" * 60)
        self.logger.info("DLL Flowlyzer Analysis Completed")
        self.logger.info("=" * 60)
        
        # Processing summary
        total_packets = final_stats.get('total_packets', 0)
        total_flows = final_stats.get('total_flows', 0)
        avg_rate = total_packets / total_time if total_time > 0 else 0
        
        self.logger.info(f"Total time: {total_time:.2f} seconds")
        self.logger.info(f"Total packets: {total_packets:,}")
        self.logger.info(f"Total flows: {total_flows:,}")
        self.logger.info(f"Average rate: {avg_rate:.0f} packets/second")
        
        # Protocol distribution
        if 'protocol_stats' in final_stats:
            self.logger.info("\nProtocol Distribution:")
            for protocol, count in final_stats['protocol_stats'].items():
                percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                self.logger.info(f"  {protocol}: {count:,} ({percentage:.1f}%)")
        
        self.logger.info("=" * 60)
    
    def log_error(self, error_msg: str, exception: Optional[Exception] = None):
        """Log error with optional exception details."""
        self.logger.error(error_msg)
        if exception:
            self.logger.error(f"Exception details: {str(exception)}")
    
    def log_warning(self, warning_msg: str):
        """Log warning message."""
        self.logger.warning(warning_msg)
    
    def _get_elapsed_time(self) -> float:
        """Get elapsed time since analysis start."""
        import time
        start_time = self.progress_stats.get('start_time')
        if start_time:
            return time.time() - start_time
        return 0.0
    
    def get_log_summary(self) -> dict:
        """Get summary of logged information."""
        return {
            'log_file': str(self.log_file),
            'log_level': logging.getLevelName(self.log_level),
            'quiet_mode': self.quiet,
            'packets_processed': self.progress_stats['packets_processed'],
            'flows_created': self.progress_stats['flows_created'],
            'elapsed_time': self._get_elapsed_time(),
        }