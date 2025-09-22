import time
import sys
import os
import gc
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import rdpcap, PcapReader

from .utils.config_manager import ConfigManager
from .utils.logger import FlowlyzerLogger
from .utils.packet_queue import PacketQueue
from .utils.plotting import FlowlyzerPlotter
from .utils.memory_monitor import MemoryMonitor
from .flows.flow_manager import FlowManager
from .features.feature_extractor import FeatureExtractor
from .features.labeling import FlowLabeler, LabelingConfig
from .features.csv_exporter import CSVExporter


def load_folder_labeling_config(folder_path: str) -> dict:
    """Load labeling configuration specific to a folder by looking for labeling.json or labeling.txt"""
    import json
    folder_path = Path(folder_path)
    
    # First try to load JSON file (highest priority)
    labeling_json_file = folder_path / "labeling.json"
    if labeling_json_file.exists():
        try:
            with open(labeling_json_file, 'r') as f:
                labeling_config = json.load(f)
            print(f"✅ Loaded JSON labeling config from {labeling_json_file}")
            
            # Validate required structure
            if not isinstance(labeling_config, dict):
                print(f"❌ JSON labeling config must be a dictionary, got {type(labeling_config)}")
                return None
            
            # Set default benign label if no labeling rules found
            has_labeling_rules = (
                labeling_config.get('ip_attacks', []) or
                labeling_config.get('mac_attacks', []) or 
                labeling_config.get('time_attacks', [])
            )
            
            if not has_labeling_rules:
                print(f"📝 No labeling rules found in JSON config - all traffic will be labeled as 'Benign'")
            
            return labeling_config
        except Exception as e:
            print(f"❌ Error loading JSON labeling config from {labeling_json_file}: {e}")
            print(f"📋 Falling back to text file labeling...")
    
    # Fallback to text file
    labeling_txt_file = folder_path / "labeling.txt"
    if not labeling_txt_file.exists():
        print(f"📁 No labeling config found in {folder_path} - all traffic will be labeled as 'Benign'")
        return None
    
    try:
        from .features.labeling import LabelingConfig
        text_labels = LabelingConfig.load_from_text_file(str(labeling_txt_file))
        
        labeling_config = {
            'ip_attacks': [],
            'mac_attacks': [],
            'time_attacks': [],
        }
        
        for attack_label in text_labels:
            if attack_label.attack_type == 'IP':
                labeling_config['ip_attacks'].append({
                    'label': attack_label.label,
                    'ips': attack_label.criteria.get('attacker_ips', [])
                })
            elif attack_label.attack_type == 'MAC':
                labeling_config['mac_attacks'].append({
                    'label': attack_label.label,
                    'macs': attack_label.criteria.get('attacker_macs', [])
                })
            elif attack_label.attack_type == 'TIME':
                time_ranges = []
                for start_time, end_time in attack_label.criteria.get('time_ranges', []):
                    time_ranges.append({'start': start_time.strftime('%I:%M %p'), 'end': end_time.strftime('%I:%M %p')})
                
                labeling_config['time_attacks'].append({
                    'label': attack_label.label,
                    'time_ranges': time_ranges
                })
        
        print(f"✅ Loaded text labeling config from {labeling_txt_file}")
        return labeling_config
    
    except Exception as e:
        print(f"❌ Error loading text labeling config from {labeling_txt_file}: {e}")
        print(f"📝 All traffic will be labeled as 'Benign'")
        return None


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
    CSV_BATCH_SIZE = processing_config.get('csv_batch_size', 30)  # Number of flows per CSV batch
    
    try:
        for file_index, pcap_file in enumerate(pcap_files, 1):
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, 0)
            
            packets_in_file = 0
            try:
                with PcapReader(pcap_file) as pcap_reader:
                    for frame_number, packet in enumerate(pcap_reader, total_packets + 1):
                        packet_queue.put_packet(packet, frame_number)
                        packets_in_file += 1
                        
                        # Process batches periodically
                        if frame_number % 5000 == 0:  # Check more frequently
                            batch_flows = flow_manager.get_batch_completed_flows(CSV_BATCH_SIZE)
                            if batch_flows:
                                # Get current global protocol statistics
                                current_stats = flow_manager.get_statistics()
                                total_flows_processed += process_flow_batch(
                                    batch_flows, feature_extractor, flow_labeler, 
                                    csv_exporter, batch_files, processing_config, logger,
                                    current_stats.get('protocol_stats', {})
                                )
                            
                            # Log progress and memory stats
                            stats = flow_manager.get_statistics()
                            flow_memory_stats = flow_manager.get_memory_usage_estimate()
                            system_memory = memory_monitor.get_memory_stats()
                            
                            logger.log_progress(
                                frame_number,
                                stats['protocol_stats'],
                                stats['flow_stats']
                            )
                            logger.logger.debug(f"Memory: System={system_memory.process_mb:.1f}MB, "
                                             f"Flows={flow_memory_stats['estimated_memory_mb']:.1f}MB, "
                                             f"Active={flow_memory_stats['active_flows']}, "
                                             f"Completed={flow_memory_stats['completed_flows']}")
                            
                            # Check memory pressure and trigger cleanup if needed
                            warning_triggered, critical_triggered = memory_monitor.check_memory_pressure()
                            
                            if critical_triggered:
                                logger.logger.critical("Critical memory usage - performing aggressive cleanup")
                                perform_aggressive_cleanup(flow_manager, logger, memory_monitor)
                                
                                # Process completed flows immediately using larger CSV batches
                                emergency_batch = flow_manager.get_batch_completed_flows(CSV_BATCH_SIZE * 3)
                                if emergency_batch:
                                    current_stats = flow_manager.get_statistics()
                                    total_flows_processed += process_flow_batch(
                                        emergency_batch, feature_extractor, flow_labeler,
                                        csv_exporter, batch_files, processing_config, logger,
                                        current_stats.get('protocol_stats', {})
                                    )
                            
                            elif warning_triggered:
                                logger.logger.warning("Memory warning - performing standard cleanup")
                                memory_monitor.force_garbage_collection()
                                
                                # Process some completed flows using CSV batch size
                                warning_batch = flow_manager.get_batch_completed_flows(CSV_BATCH_SIZE)
                                if warning_batch:
                                    current_stats = flow_manager.get_statistics()
                                    total_flows_processed += process_flow_batch(
                                        warning_batch, feature_extractor, flow_labeler,
                                        csv_exporter, batch_files, processing_config, logger,
                                        current_stats.get('protocol_stats', {})
                                    )
                        
                        # Regular memory cleanup
                        if frame_number % 20000 == 0:
                            flow_manager.force_flow_completion(max_active_flows=5000)
                            
                            # Process any flows that were just completed using CSV batch size
                            cleanup_batch = flow_manager.get_batch_completed_flows(CSV_BATCH_SIZE * 2)
                            if cleanup_batch:
                                current_stats = flow_manager.get_statistics()
                                total_flows_processed += process_flow_batch(
                                    cleanup_batch, feature_extractor, flow_labeler,
                                    csv_exporter, batch_files, processing_config, logger,
                                    current_stats.get('protocol_stats', {})
                                )
                            
                            # Force garbage collection
                            gc.collect()
                            logger.logger.info(f"Performed memory cleanup at packet {frame_number}")
            
            except Exception as e:
                logger.log_error(f"Error processing file {pcap_file}: {e}")
                continue
            
            total_packets += packets_in_file
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, packets_in_file)
    
    finally:
        logger.logger.info(f"Waiting for packet processing to complete for folder: {folder_name}")
        packet_queue.wait_for_completion()
        packet_queue.stop()
        flow_manager.finalize_all_flows()
        
        # Process any remaining flows
        remaining_flows = flow_manager.get_batch_completed_flows(1000)  # Get all remaining
        if remaining_flows:
            final_stats = flow_manager.get_statistics()
            total_flows_processed += process_flow_batch(
                remaining_flows, feature_extractor, flow_labeler,
                csv_exporter, batch_files, processing_config, logger,
                final_stats.get('protocol_stats', {})
            )
            logger.logger.info(f"Processed final batch of {len(remaining_flows)} flows")
    
    final_stats = flow_manager.get_statistics()
    final_stats['total_flows_exported'] = total_flows_processed
    logger.log_flow_statistics(final_stats)
    
    # Log memory usage summary
    memory_monitor.log_memory_summary()
    memory_suggestions = memory_monitor.suggest_memory_optimization()
    if memory_suggestions:
        logger.logger.info("Memory optimization suggestions:")
        for suggestion in memory_suggestions:
            logger.logger.info(f"  - {suggestion}")
    
    processing_time = time.time() - start_time
    
    return {
        'folder_name': folder_name,
        'batch_files': batch_files,
        'final_stats': final_stats,
        'processing_time': processing_time,
        'total_packets': total_packets,
        'total_flows_processed': total_flows_processed,
        'memory_summary': memory_monitor.get_monitoring_summary()
    }


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
                logger.logger.warning(f"Emergency: cleared {len(emergency_flows) if 'emergency_flows' in locals() else completed_flows} flows without processing")
        
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
        # Extract features from batch with global protocol statistics
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


def process_single_folder(folder_name: str, pcap_files: list, processing_config: dict, 
                         log_config: dict, global_labeling_config: dict, logger) -> dict:
    """Original single folder processing (kept for compatibility)."""
    # Use batched version if batching is enabled
    if processing_config.get('enable_batching', True):
        return process_single_folder_batched(folder_name, pcap_files, processing_config, log_config, global_labeling_config, logger)
    
    logger.logger.info(f"Processing folder: {folder_name} ({len(pcap_files)} files)")
    
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
    
    flow_manager = FlowManager(
        flow_timeout=processing_config['flow_timeout'],
        max_flows=processing_config.get('max_flows', 100000)
    )
    
    packet_queue = PacketQueue(
        maxsize=processing_config['queue_size'],
        num_workers=processing_config.get('workers', 4)
    )
    
    packet_queue.set_packet_processor(flow_manager.process_packet)
    packet_queue.start()
    start_time = time.time()
    total_packets = 0
    
    try:
        for file_index, pcap_file in enumerate(pcap_files, 1):
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, 0)
            
            packets_in_file = 0
            try:
                with PcapReader(pcap_file) as pcap_reader:
                    for frame_number, packet in enumerate(pcap_reader, total_packets + 1):
                        packet_queue.put_packet(packet, frame_number)
                        packets_in_file += 1
                        
                        if frame_number % 10000 == 0:
                            stats = flow_manager.get_statistics()
                            logger.log_progress(
                                frame_number,
                                stats['protocol_stats'],
                                stats['flow_stats']
                            )
            
            except Exception as e:
                logger.log_error(f"Error processing file {pcap_file}: {e}")
                continue
            
            total_packets += packets_in_file
            logger.log_file_progress(file_index, len(pcap_files), pcap_file, packets_in_file)
    
    finally:
        logger.logger.info(f"Waiting for packet processing to complete for folder: {folder_name}")
        packet_queue.wait_for_completion()
        packet_queue.stop()
        flow_manager.finalize_all_flows()
    
    final_stats = flow_manager.get_statistics()
    logger.log_flow_statistics(final_stats)
    
    logger.log_feature_extraction(final_stats['total_flows'], len(FeatureExtractor().feature_columns))
    
    feature_extractor = FeatureExtractor(num_threads=processing_config.get('feature_threads', 4))
    all_flows = flow_manager.get_all_flows()
    flows_df = feature_extractor.extract_features(all_flows)
    
    if actual_labeling_config:
        flow_labeler = FlowLabeler()
        attack_labels = LabelingConfig.load_from_config(actual_labeling_config)
        flow_labeler.attack_labels = attack_labels
        flows_df = flow_labeler.label_flows(flows_df)
        
        if 'label' in flows_df.columns:
            label_stats = flows_df['label'].value_counts().to_dict()
            logger.log_labeling_results(label_stats)
    else:
        # If no labeling config (global or folder-specific), all flows are Benign
        flows_df['label'] = 'Benign'
        logger.logger.info(f"No labeling configuration found for {folder_name}, all flows labeled as Benign")
    
    processing_time = time.time() - start_time
    
    return {
        'folder_name': folder_name,
        'flows_df': flows_df,
        'final_stats': final_stats,
        'processing_time': processing_time,
        'total_packets': total_packets
    }


def process_multi_folders(config_manager, processing_config: dict, 
                         log_config: dict, labeling_config: dict, logger) -> int:
    try:
        pcap_folders = config_manager.get_pcap_folders()
        total_folders = len(pcap_folders)
        
        logger.logger.info(f"Multi-folder mode: Processing {total_folders} folders")
        
        overall_start_time = time.time()
        all_results = []
        
        folder_threads = processing_config.get('folder_threads', 1)
        
        if folder_threads == 1 or total_folders == 1:
            all_results = []
            for folder_index, (folder_name, pcap_files) in enumerate(pcap_folders.items(), 1):
                result = process_folder_complete(
                    folder_name, pcap_files, processing_config, log_config, 
                    labeling_config, logger, folder_index, total_folders
                )
                all_results.append(result)
        else:
            logger.logger.info(f"Processing {total_folders} folders using {folder_threads} threads")
            all_results = process_folders_parallel(
                pcap_folders, processing_config, log_config, labeling_config, 
                logger, folder_threads
            )
        
        total_time = time.time() - overall_start_time
        total_packets = sum(r.get('total_packets', 0) for r in all_results if r)
        total_flows = sum(len(r.get('flows_df', [])) for r in all_results if r and 'flows_df' in r)
        
        logger.logger.info(f"Multi-folder processing completed!")
        logger.logger.info(f"Processed {total_folders} folders in {total_time:.2f}s")
        logger.logger.info(f"Total packets: {total_packets}")
        logger.logger.info(f"Total flows: {total_flows}")
        
        print(f"\nMulti-folder analysis completed successfully!")
        print(f"Processed {total_folders} folders")
        print(f"Results saved to: {processing_config['output_dir']}")
        print(f"Log file: {Path(processing_config['output_dir']) / log_config['log_file']}")
        
        return 0
        
    except Exception as e:
        logger.log_error(f"Multi-folder processing error: {e}")
        return 1


def process_folder_complete(folder_name: str, pcap_files: list, processing_config: dict,
                           log_config: dict, labeling_config: dict, logger, 
                           folder_index: int, total_folders: int) -> dict:
    """Process a single folder completely including CSV export and visualization"""
    logger.logger.info(f"Processing folder {folder_index}/{total_folders}: {folder_name}")
    
    result = process_single_folder(
        folder_name, pcap_files, processing_config,
        log_config, labeling_config, logger
    )
    
    # Handle different result formats (batched vs non-batched)
    if 'batch_files' in result:
        # Batched processing - CSV files already created
        export_info_dict = {
            'combined_file': result['batch_files']['combined'],
            'layer2_file': result['batch_files'].get('layer2'),
            'layer3_file': result['batch_files'].get('layer3'),
            'total_flows': result.get('total_flows_processed', 0),
        }
        logger.log_export_results(export_info_dict)
        
        # Create visualizations from final CSV file
        try:
            if os.path.exists(result['batch_files']['combined']):
                import pandas as pd
                final_flows_df = pd.read_csv(result['batch_files']['combined'])
                folder_output_dir = Path(processing_config['output_dir']) / folder_name
                plotter = FlowlyzerPlotter(str(folder_output_dir))
                plot_files = plotter.create_all_plots(final_flows_df, result['final_stats'])
                
                if plot_files:
                    logger.logger.info(f"Generated {len(plot_files)} visualization files for {folder_name}")
        except Exception as e:
            logger.logger.warning(f"Could not create visualizations for {folder_name}: {e}")
    else:
        # Non-batched processing - need to export CSV
        folder_output_dir = Path(processing_config['output_dir']) / folder_name
        folder_output_dir.mkdir(parents=True, exist_ok=True)
        
        csv_exporter = CSVExporter(str(folder_output_dir))
        export_info = csv_exporter.export_flows(
            result['flows_df'],
            separate_layers=processing_config['separate_l2_l3'],
            base_filename=f"{folder_name}_features"
        )
        
        combined_file, layer2_file, layer3_file = export_info
        export_info_dict = {
            'combined_file': combined_file,
            'layer2_file': layer2_file,
            'layer3_file': layer3_file,
            'total_flows': len(result['flows_df']),
        }
        logger.log_export_results(export_info_dict)
        
        plotter = FlowlyzerPlotter(str(folder_output_dir))
        plot_files = plotter.create_all_plots(result['flows_df'], result['final_stats'])
        
        if plot_files:
            logger.logger.info(f"Generated {len(plot_files)} visualization files for {folder_name}")
    
    total_flows = result.get('total_flows_processed', len(result.get('flows_df', [])))
    logger.logger.info(f"Completed folder {folder_index}/{total_folders}: {folder_name} "
                     f"({result['total_packets']} packets, {total_flows} flows, "
                     f"{result['processing_time']:.2f}s)")
    
    return result


def process_folders_parallel(pcap_folders: dict, processing_config: dict, log_config: dict,
                           labeling_config: dict, logger, num_threads: int) -> list:
    """Process multiple folders in parallel"""
    from threading import Lock
    
    all_results = []
    results_lock = Lock()
    folder_items = list(pcap_folders.items())
    total_folders = len(folder_items)
    
    def process_folder_wrapper(args):
        folder_index, folder_name, pcap_files = args
        
        # Create a thread-local logger to avoid conflicts
        thread_log_file = Path(processing_config['output_dir']) / f"{folder_name}_thread.log"
        thread_logger = FlowlyzerLogger(
            log_file=str(thread_log_file),
            log_level=log_config['level'],
            quiet=log_config.get('quiet', False)
        )
        
        try:
            result = process_folder_complete(
                folder_name, pcap_files, processing_config, log_config,
                labeling_config, thread_logger, folder_index + 1, total_folders
            )
            
            with results_lock:
                all_results.append(result)
                logger.logger.info(f"Thread completed folder {folder_index + 1}/{total_folders}: {folder_name}")
            
            return result
        except Exception as e:
            logger.logger.error(f"Error processing folder {folder_name}: {e}")
            return None
        finally:
            # Clean up thread log file
            if thread_log_file.exists():
                thread_log_file.unlink()
    
    # Prepare arguments for parallel processing
    folder_args = [(i, name, files) for i, (name, files) in enumerate(folder_items)]
    
    # Process folders in parallel
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(process_folder_wrapper, args) for args in folder_args]
        
        for future in as_completed(futures):
            try:
                future.result()  # This will raise any exception that occurred
            except Exception as e:
                logger.logger.error(f"Parallel folder processing error: {e}")
    
    return all_results


def main():
    try:
        config_manager = ConfigManager()
        args = config_manager.parse_arguments()
        
        # Set global missing value configuration
        from .utils.constants import set_missing_value
        set_missing_value(args.missing_value)
        
        if not config_manager.validate_config():
            sys.exit(1)
        
        config_manager.print_config_summary()
        
        processing_config = config_manager.get_processing_config()
        processing_config['missing_value_type'] = args.missing_value  # Add to config
        log_config = config_manager.get_log_config()
        labeling_config = config_manager.get_labeling_config()
        
        log_file = Path(processing_config['output_dir']) / log_config['log_file']
        logger = FlowlyzerLogger(
            log_file=str(log_file),
            log_level=log_config['level'],
            quiet=log_config['quiet']
        )
        
        if processing_config.get('multi_folder', False):
            return process_multi_folders(config_manager, processing_config, log_config, labeling_config, logger)
        else:
            pcap_files = config_manager.get_pcap_files()
            logger.log_start(pcap_files, processing_config)
        
        flow_manager = FlowManager(
            flow_timeout=processing_config['flow_timeout'],
            max_flows=processing_config.get('max_flows', 100000)
        )
        
        packet_queue = PacketQueue(
            maxsize=processing_config['queue_size'],
            num_workers=processing_config.get('workers', 4)
        )
        
        packet_queue.set_packet_processor(flow_manager.process_packet)
        packet_queue.start()
        start_time = time.time()
        total_packets = 0
        
        try:
            for file_index, pcap_file in enumerate(pcap_files, 1):
                logger.log_file_progress(file_index, len(pcap_files), pcap_file, 0)
                
                packets_in_file = 0
                try:
                    # Use PcapReader for memory efficiency with large files
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
                
                except Exception as e:
                    logger.log_error(f"Error processing file {pcap_file}: {e}")
                    continue
                
                total_packets += packets_in_file
                logger.log_file_progress(file_index, len(pcap_files), pcap_file, packets_in_file)
        
        finally:
            # Wait for queue to finish and stop workers
            logger.logger.info("Waiting for packet processing to complete...")
            packet_queue.wait_for_completion()
            packet_queue.stop()
            
            # Finalize all remaining flows
            flow_manager.finalize_all_flows()
        
        # Log final flow statistics
        final_stats = flow_manager.get_statistics()
        logger.log_flow_statistics(final_stats)
        
        # Extract features
        logger.log_feature_extraction(final_stats['total_flows'], len(FeatureExtractor().feature_columns))
        
        feature_extractor = FeatureExtractor(num_threads=processing_config.get('feature_threads', 4))
        all_flows = flow_manager.get_all_flows()
        flows_df = feature_extractor.extract_features(all_flows)
        
        # Apply labeling
        if labeling_config:
            flow_labeler = FlowLabeler()
            
            # Load labeling rules
            attack_labels = LabelingConfig.load_from_config(labeling_config)
            flow_labeler.attack_labels = attack_labels
            
            # Apply labels
            flows_df = flow_labeler.label_flows(flows_df)
            
            # Log labeling results
            if 'label' in flows_df.columns:
                label_stats = flows_df['label'].value_counts().to_dict()
                logger.log_labeling_results(label_stats)
        
        # Export to CSV (CSV only, no txt metadata)
        csv_exporter = CSVExporter(processing_config['output_dir'])
        export_info = csv_exporter.export_flows(
            flows_df,
            separate_layers=processing_config['separate_l2_l3'],
            base_filename=processing_config.get('csv_file', 'features').replace('.csv', '')
        )
        
        # Update export_info format for logging
        combined_file, layer2_file, layer3_file = export_info
        export_info_dict = {
            'combined_file': combined_file,
            'layer2_file': layer2_file,
            'layer3_file': layer3_file,
            'total_flows': len(flows_df),
        }
        
        logger.log_export_results(export_info_dict)
        
        # Create plots and statistics
        plotter = FlowlyzerPlotter(processing_config['output_dir'])
        plot_files = plotter.create_all_plots(flows_df, final_stats)
        
        if plot_files:
            logger.logger.info(f"Generated {len(plot_files)} visualization files:")
            for plot_file in plot_files:
                logger.logger.info(f"  - {Path(plot_file).name}")
        
        # Log completion
        total_time = time.time() - start_time
        logger.log_completion(total_time, final_stats)
        
        # Final success message
        print(f"\nAnalysis completed successfully!")
        print(f"Results saved to: {processing_config['output_dir']}")
        print(f"Log file: {log_file}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())