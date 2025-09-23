"""
Main entry point for DLL Flowlyzer network analysis tool.
"""

import sys
import os
import gc
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd

from .utils.config_manager import ConfigManager
from .utils.logger import FlowlyzerLogger
from .utils.packet_queue import PacketQueue
from .utils.plotting import FlowlyzerPlotter
from .utils.memory_monitor import MemoryMonitor
from .flows.flow_manager import FlowManager
from .features.feature_extractor import FeatureExtractor
from .features.csv_exporter import CSVExporter
from .features.labeling import FlowLabeler, LabelingConfig

from scapy.all import PcapReader
import json


def load_folder_labeling_config(folder_path: str) -> dict:
    """Load labeling configuration from folder"""
    folder_path = Path(folder_path)
    
    # Try JSON first (priority)
    labeling_json = folder_path / "labeling.json"
    if labeling_json.exists():
        try:
            with open(labeling_json, 'r') as f:
                config = json.load(f)
                print(f"✅ Loaded JSON labeling config from {labeling_json}")
                return config
        except Exception as e:
            print(f"❌ Error loading JSON labeling: {e}")
    
    # Fallback to text file
    labeling_txt = folder_path / "labeling.txt"
    if labeling_txt.exists():
        try:
            from .features.labeling import LabelingConfig
            text_labels = LabelingConfig.load_from_text_file(str(labeling_txt))
            
            config = {'ip_attacks': [], 'mac_attacks': [], 'time_attacks': []}
            
            for label in text_labels:
                if label.attack_type == 'IP':
                    config['ip_attacks'].append({
                        'label': label.label,
                        'ips': label.criteria.get('attacker_ips', [])
                    })
                elif label.attack_type == 'MAC':
                    config['mac_attacks'].append({
                        'label': label.label, 
                        'macs': label.criteria.get('attacker_macs', [])
                    })
                elif label.attack_type == 'TIME':
                    time_ranges = []
                    for start_time, end_time in label.criteria.get('time_ranges', []):
                        time_ranges.append({
                            'start': start_time.strftime('%I:%M %p'), 
                            'end': end_time.strftime('%I:%M %p')
                        })
                    config['time_attacks'].append({
                        'label': label.label,
                        'time_ranges': time_ranges
                    })
            
            print(f"✅ Loaded text labeling config from {labeling_txt}")
            return config
        except Exception as e:
            print(f"❌ Error loading text labeling: {e}")
    
    # No labeling config found
    print(f"📁 No labeling config found in {folder_path} - all traffic will be labeled as 'Benign'")
    return None


def perform_aggressive_cleanup(flow_manager, logger, memory_monitor=None):
    """Perform aggressive memory cleanup when memory usage is high."""
    try:
        # Get memory stats before cleanup
        if memory_monitor:
            before_stats = memory_monitor.get_memory_stats()
            logger.logger.info(f"Pre-cleanup memory: {before_stats.process_mb:.1f} MB")
        
        # Force completion of oldest 70% of active flows
        stats = flow_manager.get_statistics()
        current_active = stats['active_flows']
        target_active = max(500, current_active // 3)  # Keep at least 500, or 1/3 current
        
        flow_manager.force_flow_completion(max_active_flows=target_active)
        logger.logger.info(f"Aggressive cleanup: reduced active flows from {current_active} to {target_active}")
        
        # Clear completed flows that have accumulated
        completed_flows = stats.get('completed_flows', 0)
        if completed_flows > 100:
            # Get and clear completed flows without processing (emergency)
            emergency_flows = flow_manager.get_batch_completed_flows(completed_flows)
            if emergency_flows:
                # Just clear packet data without feature extraction
                for flow in emergency_flows:
                    if hasattr(flow, 'packets'):
                        flow.packets.clear()
                    if hasattr(flow, '_features_cache'):
                        flow._features_cache = None
                del emergency_flows
                logger.logger.warning(f"Emergency: cleared {completed_flows} flows without processing")
        
        # Intensive garbage collection
        if memory_monitor:
            collected = memory_monitor.force_garbage_collection()
            logger.logger.info(f"Garbage collection: {collected} objects collected")
        else:
            for _ in range(3):
                gc.collect()
        
        # Log memory stats after cleanup
        if memory_monitor:
            after_stats = memory_monitor.get_memory_stats()
            memory_freed = before_stats.process_mb - after_stats.process_mb
            logger.logger.info(f"Post-cleanup memory: {after_stats.process_mb:.1f} MB (freed {memory_freed:.1f} MB)")
        
        new_flow_stats = flow_manager.get_memory_usage_estimate()
        logger.logger.info(f"Flow manager memory estimate: {new_flow_stats['estimated_memory_mb']:.1f} MB")
        
    except Exception as e:
        logger.logger.error(f"Error in aggressive cleanup: {e}")


def process_flow_batch(flows: list, feature_extractor, flow_labeler, csv_exporter, 
                      batch_files: dict, processing_config: dict, logger, 
                      global_protocol_stats: dict = None) -> int:
    """Process a batch of flows: extract features, apply labels, and export to CSV."""
    if not flows:
        return 0
    
    try:
        # Extract features using standard feature extractor
        flows_df = feature_extractor.extract_features(flows, global_protocol_stats)
        
        # Apply labeling
        if flow_labeler:
            flows_df = flow_labeler.label_flows(flows_df)
        else:
            flows_df['label'] = 'Benign'
        
        # Export batch to CSV (append to existing files)
        csv_exporter.export_flows_batch(
            flows_df, batch_files, processing_config['separate_l2_l3']
        )
        
        flows_count = len(flows_df)
        
        # Comprehensive memory cleanup
        for flow in flows:
            if hasattr(flow, 'packets'):
                flow.packets.clear()
            # Clear any cached features to free more memory
            if hasattr(flow, '_features_cache'):
                flow._features_cache = None
        
        # Clear references and force garbage collection
        del flows_df
        del flows
        gc.collect()
        
        logger.logger.debug(f"Processed and exported batch of {flows_count} flows with memory cleanup")
        return flows_count
        
    except Exception as e:
        logger.log_error(f"Error processing flow batch: {e}")
        return 0


def process_single_folder_batched(folder_name: str, pcap_files: list, processing_config: dict, 
                                 log_config: dict, global_labeling_config: dict, logger) -> dict:
    """Process folder with batched CSV export and memory optimization."""
    logger.logger.info(f"Processing folder (batched): {folder_name} ({len(pcap_files)} files)")
    
    # Check for folder-specific labeling configuration
    if pcap_files:
        folder_path = Path(pcap_files[0]).parent
        folder_labeling_config = load_folder_labeling_config(folder_path)
        if folder_labeling_config:
            logger.logger.info(f"Using folder-specific labeling config for {folder_name}")
            actual_labeling_config = folder_labeling_config
        else:
            logger.logger.info(f"No folder-specific labeling found for {folder_name}, using global config")
            actual_labeling_config = global_labeling_config
    else:
        actual_labeling_config = global_labeling_config
    
    # Setup flow manager with smaller max_flows for batching
    flow_manager = FlowManager(
        flow_timeout=processing_config['flow_timeout'],
        max_flows=min(processing_config.get('max_flows', 100000), 10000)  # Limit for memory
    )
    
    packet_queue = PacketQueue(
        maxsize=processing_config['queue_size'],
        num_workers=processing_config.get('workers', 4)
    )
    
    packet_queue.set_packet_processor(flow_manager.process_packet)
    packet_queue.start()
    start_time = time.time()
    total_packets = 0
    total_flows_processed = 0
    
    # Setup CSV batching
    folder_output_dir = Path(processing_config['output_dir']) / folder_name
    folder_output_dir.mkdir(parents=True, exist_ok=True)
    csv_exporter = CSVExporter(str(folder_output_dir))
    
    batch_files = csv_exporter.create_batch_files(
        f"{folder_name}_features", 
        processing_config['separate_l2_l3']
    )
    
    # Initialize feature extractor and labeler
    feature_extractor = FeatureExtractor(num_threads=processing_config.get('feature_threads', 4))
    flow_labeler = FlowLabeler() if actual_labeling_config else None
    if flow_labeler and actual_labeling_config:
        attack_labels = LabelingConfig.load_from_config(actual_labeling_config)
        flow_labeler.attack_labels = attack_labels
    
    # Initialize memory monitor
    memory_monitor = MemoryMonitor(
        warning_threshold_mb=processing_config.get('memory_warning_mb', 1024),
        critical_threshold_mb=processing_config.get('memory_critical_mb', 2048)
    )
    
    BATCH_SIZE = processing_config.get('batch_size', 30)  # Process flows in configurable batches
    CSV_BATCH_SIZE = processing_config.get('csv_batch_size', 50)  # Number of flows per CSV batch
    
    try:
        for file_index, pcap_file in enumerate(pcap_files, 1):
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, 0)
            
            packets_in_file = 0
            stats = None  # Initialize stats variable
            try:
                with PcapReader(pcap_file) as pcap_reader:
                    for frame_number, packet in enumerate(pcap_reader, total_packets + 1):
                        packet_queue.put_packet(packet, frame_number)
                        packets_in_file += 1
                        
                        # Log progress every 10,000 packets
                        if frame_number % 10000 == 0:
                            stats = flow_manager.get_statistics()
                            logger.log_progress(
                                frame_number,
                                stats['protocol_stats'],
                                stats['flow_stats']
                            )
                        
                        # Batched flow processing during file processing
                        if frame_number % (BATCH_SIZE * 10) == 0:
                            # Get batch of completed flows
                            if stats is None:
                                stats = flow_manager.get_statistics()
                            completed_batch = flow_manager.get_batch_completed_flows(CSV_BATCH_SIZE)
                            if completed_batch:
                                batch_flows_processed = process_flow_batch(
                                    completed_batch, feature_extractor, flow_labeler, 
                                    csv_exporter, batch_files, processing_config, logger,
                                    stats['protocol_stats']
                                )
                                total_flows_processed += batch_flows_processed
                                
                                if batch_flows_processed > 0:
                                    logger.logger.info(f"Processed batch: {batch_flows_processed} flows (Total: {total_flows_processed})")
                        
                        # Memory pressure monitoring and cleanup
                        if frame_number % 50000 == 0:
                            memory_stats = memory_monitor.get_memory_stats()
                            if memory_monitor.check_memory_pressure():
                                logger.logger.warning(f"Memory pressure detected: {memory_stats.process_mb:.1f} MB")
                                perform_aggressive_cleanup(flow_manager, logger, memory_monitor)
            
            except Exception as e:
                logger.log_error(f"Error processing file {pcap_file}: {e}")
                continue
            
            total_packets += packets_in_file
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, packets_in_file)
        
        # Final processing after all files
        logger.logger.info("Waiting for packet processing to complete...")
        packet_queue.wait_for_completion()
        packet_queue.stop()
        
        # Finalize remaining flows
        flow_manager.finalize_all_flows()
        
        # Process all remaining completed flows
        final_flows = flow_manager.get_batch_completed_flows(batch_size=None)  # Get all remaining
        if final_flows:
            final_stats = flow_manager.get_statistics()
            final_batch_processed = process_flow_batch(
                final_flows, feature_extractor, flow_labeler,
                csv_exporter, batch_files, processing_config, logger,
                final_stats['protocol_stats']
            )
            total_flows_processed += final_batch_processed
            logger.logger.info(f"Final batch processed: {final_batch_processed} flows")
        
        # Get final statistics
        final_stats = flow_manager.get_statistics()
        logger.log_flow_statistics(final_stats)
        
        processing_time = time.time() - start_time
        
        # Log completion
        logger.logger.info(f"Batched processing completed for {folder_name}")
        logger.logger.info(f"Total packets: {total_packets:,}")
        logger.logger.info(f"Total flows processed: {total_flows_processed:,}")
        logger.logger.info(f"Processing time: {processing_time:.2f} seconds")
        
        return {
            'folder_name': folder_name,
            'batch_files': batch_files,
            'total_packets': total_packets,
            'total_flows_processed': total_flows_processed,
            'processing_time': processing_time,
            'final_stats': final_stats
        }
        
    except Exception as e:
        logger.log_error(f"Error in batched processing for {folder_name}: {e}")
        processing_time = time.time() - start_time
        return {
            'folder_name': folder_name,
            'error': str(e),
            'total_packets': total_packets,
            'total_flows_processed': total_flows_processed,
            'processing_time': processing_time,
            'final_stats': flow_manager.get_statistics() if 'flow_manager' in locals() else {}
        }
    
    finally:
        # Cleanup
        if 'packet_queue' in locals():
            packet_queue.stop()
        gc.collect()


def process_multi_folders(config_manager, processing_config: dict, log_config: dict, 
                         global_labeling_config: dict, logger) -> int:
    """Process multiple folders with batched processing."""
    pcap_folders = config_manager.get_pcap_folders()
    logger.logger.info(f"Processing {len(pcap_folders)} folders in multi-folder mode")
    
    results = []
    for folder_name, pcap_files in pcap_folders.items():
        logger.logger.info(f"Starting folder: {folder_name} ({len(pcap_files)} files)")
        
        result = process_single_folder_batched(
            folder_name, pcap_files, processing_config, log_config, global_labeling_config, logger
        )
        results.append(result)
        
        # Create visualizations from final CSV file if it exists
        if 'batch_files' in result and os.path.exists(result['batch_files']['combined']):
            try:
                final_flows_df = pd.read_csv(result['batch_files']['combined'])
                folder_output_dir = Path(processing_config['output_dir']) / folder_name
                
                # Create standard plots
                plotter = FlowlyzerPlotter(str(folder_output_dir))
                plot_files = plotter.create_all_plots(final_flows_df, result['final_stats'])
                
                if plot_files:
                    logger.logger.info(f"Generated {len(plot_files)} visualization files for {folder_name}")
            except Exception as e:
                logger.logger.warning(f"Could not create visualizations for {folder_name}: {e}")
        
        logger.logger.info(f"Completed folder: {folder_name}")
    
    # Log overall completion
    total_packets = sum(r.get('total_packets', 0) for r in results)
    total_flows = sum(r.get('total_flows_processed', 0) for r in results)
    
    logger.logger.info("="*60)
    logger.logger.info("Multi-folder processing completed")
    logger.logger.info("="*60)
    logger.logger.info(f"Folders processed: {len(results)}")
    logger.logger.info(f"Total packets: {total_packets:,}")
    logger.logger.info(f"Total flows: {total_flows:,}")
    
    print(f"\n✅ Multi-folder analysis completed!")
    print(f"📊 Folders processed: {len(results)}")
    print(f"📦 Total packets: {total_packets:,}")
    print(f"🌊 Total flows: {total_flows:,}")
    print(f"💾 Results saved to: {processing_config['output_dir']}")
    
    return 0


def main():
    """Main entry point for DLL Flowlyzer."""
    try:
        config_manager = ConfigManager()
        args = config_manager.parse_arguments()
        
        if not config_manager.validate_config():
            sys.exit(1)
        
        config_manager.print_config_summary()
        
        processing_config = config_manager.get_processing_config()
        log_config = config_manager.get_log_config()
        labeling_config = config_manager.get_labeling_config()
        
        output_dir = Path(processing_config['output_dir'])
        output_dir.mkdir(exist_ok=True)
        
        log_file = output_dir / log_config['log_file']
        logger = FlowlyzerLogger(
            log_file=str(log_file),
            log_level=log_config['level'],
            quiet=log_config.get('quiet', False)
        )
        
        if processing_config.get('multi_folder', False):
            return process_multi_folders(config_manager, processing_config, log_config, labeling_config, logger)
        else:
            # Single file/folder processing - USE BATCHED VERSION for real-time CSV saving
            pcap_files = config_manager.get_pcap_files()
            logger.log_start(pcap_files, processing_config)
            
            # Process with real-time batching to prevent data loss and memory issues
            result = process_single_folder_batched(
                "analysis", pcap_files, processing_config, log_config, labeling_config, logger
            )
            
            # Create visualizations from the batched results
            if 'batch_files' in result and result['batch_files'] and 'combined' in result['batch_files']:
                if os.path.exists(result['batch_files']['combined']):
                    final_flows_df = pd.read_csv(result['batch_files']['combined'])
                    
                    print("📊 Generating visualization plots...")
                    plotter = FlowlyzerPlotter(processing_config['output_dir'])
                    plot_files = plotter.create_all_plots(final_flows_df, result['final_stats'])
                    
                    if plot_files:
                        logger.logger.info(f"Generated {len(plot_files)} visualization files:")
                        for plot_file in plot_files:
                            logger.logger.info(f"  - {Path(plot_file).name}")
                else:
                    logger.logger.warning(f"Combined CSV file not found: {result['batch_files']['combined']}")
            else:
                logger.logger.warning("No batch files found in result")
            
            # Log completion
            logger.log_completion(result['processing_time'], result['final_stats'])
            
            print(f"\n✅ Analysis completed successfully!")
            print(f"📊 Total packets: {result['total_packets']:,}")
            print(f"🌊 Total flows: {result.get('total_flows_processed', 0):,}")
            print(f"💾 Results saved to: {processing_config['output_dir']}")
            print(f"📝 Log file: {Path(processing_config['output_dir']) / log_config['log_file']}")
            
            return 0
        
    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())