

import logging
import sys
from pathlib import Path
from typing import Optional

class FlowlyzerLogger:

    def __init__(self, log_file: str = "Results/log.txt",
                 log_level: str = "INFO",
                 quiet: bool = False):

        self.log_file = Path(log_file)
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.quiet = quiet

        self.log_file.parent.mkdir(exist_ok=True)

        self._setup_logging()

        self.progress_stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'flows_completed': 0,
            'protocol_counts': {},
            'start_time': None,
        }

    def _setup_logging(self):

        logging.getLogger().handlers.clear()

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(formatter)

        handlers = [file_handler]
        if not self.quiet:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(formatter)
            handlers.append(console_handler)

        logging.basicConfig(
            level=self.log_level,
            handlers=handlers,
            force=True
        )

        self.logger = logging.getLogger('DLLFlowlyzer')

    def log_start(self, input_files: list, config: dict):

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

        for i, file_path in enumerate(input_files[:10], 1):
            self.logger.info(f"  {i}. {Path(file_path).name}")
        if len(input_files) > 10:
            self.logger.info(f"  ... and {len(input_files) - 10} more files")

        self.logger.info("-" * 60)

    def log_progress(self, packets_processed: int, protocol_stats: dict, flow_stats: dict):

        self.progress_stats['packets_processed'] = packets_processed
        self.progress_stats['protocol_counts'] = protocol_stats.copy()
        self.progress_stats['flows_created'] = flow_stats.get('created', 0)
        self.progress_stats['flows_completed'] = flow_stats.get('completed', 0)

        protocol_summary = ', '.join([f"{count} {proto}" for proto, count in protocol_stats.items()])

        elapsed_time = self._get_elapsed_time()
        rate = packets_processed / elapsed_time if elapsed_time > 0 else 0

        self.logger.info(
            f"Progress: {packets_processed:,} packets processed | "
            f"{protocol_summary} | "
            f"{flow_stats.get('created', 0)} flows ({flow_stats.get('completed', 0)} completed) | "
            f"{rate:.0f} pkt/s"
        )

    def log_file_progress(self, file_index: int, total_files: int, filename: str, packets_in_file: int):

        self.logger.info(
            f"File {file_index}/{total_files}: {Path(filename).name} "
            f"({packets_in_file:,} packets)"
        )

    def log_flow_statistics(self, flow_stats: dict):

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

        self.logger.info("-" * 40)
        self.logger.info("Feature Extraction:")
        self.logger.info(f"  Processing {total_flows} flows")
        self.logger.info(f"  Extracting {feature_count} features per flow")

    def log_labeling_results(self, label_stats: dict):

        self.logger.info("-" * 40)
        self.logger.info("Flow Labeling Results:")
        total_flows = sum(label_stats.values())

        for label, count in label_stats.items():
            percentage = (count / total_flows) * 100 if total_flows > 0 else 0
            self.logger.info(f"  {label}: {count} ({percentage:.1f}%)")

    def log_export_results(self, export_info: dict):

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

        self.logger.info("=" * 60)
        self.logger.info("DLL Flowlyzer Analysis Completed")
        self.logger.info("=" * 60)

        total_packets = final_stats.get('total_packets', 0)
        total_flows = final_stats.get('total_flows', 0)
        avg_rate = total_packets / total_time if total_time > 0 else 0

        self.logger.info(f"Total time: {total_time:.2f} seconds")
        self.logger.info(f"Total packets: {total_packets:,}")
        self.logger.info(f"Total flows: {total_flows:,}")
        self.logger.info(f"Average rate: {avg_rate:.0f} packets/second")

        if 'protocol_stats' in final_stats:
            self.logger.info("\nProtocol Distribution:")
            for protocol, count in final_stats['protocol_stats'].items():
                percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                self.logger.info(f"  {protocol}: {count:,} ({percentage:.1f}%)")

        self.logger.info("=" * 60)

    def log_error(self, error_msg: str, exception: Optional[Exception] = None):

        self.logger.error(error_msg)
        if exception:
            self.logger.error(f"Exception details: {str(exception)}")

    def log_warning(self, warning_msg: str):

        self.logger.warning(warning_msg)

    def _get_elapsed_time(self) -> float:

        import time
        start_time = self.progress_stats.get('start_time')
        if start_time:
            return time.time() - start_time
        return 0.0

    def get_log_summary(self) -> dict:

        return {
            'log_file': str(self.log_file),
            'log_level': logging.getLevelName(self.log_level),
            'quiet_mode': self.quiet,
            'packets_processed': self.progress_stats['packets_processed'],
            'flows_created': self.progress_stats['flows_created'],
            'elapsed_time': self._get_elapsed_time(),
        }