"""
Configuration management system for DLL Flowlyzer.
"""

import configparser
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple


class ConfigManager:
    def __init__(self, config_file: str = "config.ini"):
        self.config_file = Path(config_file)
        self.config = configparser.ConfigParser()
        self.args = None
        
        self._load_defaults()
        
        if self.config_file.exists():
            self.config.read(self.config_file)
    
    def _load_defaults(self):
        self.config['DEFAULT'] = {
            'flow_timeout': '1200',
            'max_packets_per_flow': '10000',
            'queue_size': '100000',
            'log_level': 'INFO',
            'separate_l2_l3': 'false',
        }
        
        self.config['PROTOCOLS'] = {
            'enable_tcp': 'true',
            'enable_udp': 'true',
            'enable_quic': 'true',
            'enable_dhcp': 'true',
            'enable_stp': 'true',
            'enable_cdp': 'true',
            'enable_icmp': 'true',
            'enable_lldp': 'true',
            'enable_vtp': 'true',
            'enable_dtp': 'true',
            'enable_dns': 'true',
            'enable_isl': 'true',
            'enable_ssh': 'true',
            'enable_ftp': 'true',
        }
        
        self.config['FEATURES'] = {
            'extract_statistical': 'true',
            'extract_timing': 'true',
            'extract_size': 'true',
            'extract_protocol_specific': 'true',
        }
        
        self.config['OUTPUT'] = {
            'output_dir': 'Results',
            'log_file': 'log.txt',
            'csv_file': 'features.csv',
        }
    
    def parse_arguments(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='DLL Flowlyzer - DataLink Layer Network Flow Analyzer',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s -i single_file.pcap
  %(prog)s -i Input/ --separate-layers
  %(prog)s -i Input/ --multi-folder
  %(prog)s -i Input/ --label-ip "192.168.1.100=ARP Spoofing"
            """
        )
        
        parser.add_argument('-i', '--input', required=True, help='Input PCAP file or directory')
        parser.add_argument('--multi-folder', action='store_true', help='Process multiple folders with related PCAP files')
        parser.add_argument('-o', '--output', default='Results', help='Output directory')
        parser.add_argument('--separate-layers', action='store_true', help='Create separate L2/L3 CSV files')
        parser.add_argument('--justlayertwo', action='store_true', help='Extract only Layer 2 features from all packets (MAC addresses, Layer 2 protocols, etc.)')
        parser.add_argument('--plot', action='store_true', help='Generate visualization plots and charts')
        
        parser.add_argument('--label-ip', action='append', metavar='IP=LABEL', help='Label flows by attacker IP')
        parser.add_argument('--label-mac', action='append', metavar='MAC=LABEL', help='Label flows by attacker MAC')
        parser.add_argument('--label-time', action='append', metavar='TIME_RANGE=LABEL', help='Label flows by time range')
        parser.add_argument('--label-config', metavar='FILE', help='JSON file with labeling configuration')
        parser.add_argument('--label-file', metavar='FILE', help='Text file with labeling rules')
        
        parser.add_argument('--flow-timeout', type=int, default=1200, help='Flow timeout in seconds')
        parser.add_argument('--max-flows', type=int, default=100000, help='Maximum concurrent flows')
        parser.add_argument('--queue-size', type=int, default=100000, help='Packet queue size')
        parser.add_argument('--workers', type=int, default=4, help='Number of worker threads for packet processing')
        parser.add_argument('--feature-threads', type=int, default=4, help='Number of threads for feature extraction')
        parser.add_argument('--folder-threads', type=int, default=1, help='Number of threads for parallel folder processing')
        parser.add_argument('--batch-size', type=int, default=30, help='Number of flows to process in each batch for memory optimization')
        parser.add_argument('--csv-batch-size', type=int, default=30, help='Number of flows to write to CSV file in each batch (default: 30)')
        parser.add_argument('--disable-batching', action='store_true', help='Disable batched processing and CSV creation')
        parser.add_argument('--missing-value', choices=['nan', '-100'], default='-100', help='Value to use for missing feature data (default: -100)')
        parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Logging level')
        parser.add_argument('--quiet', action='store_true', help='Suppress progress logging')
        parser.add_argument('--config', default='config.ini', help='Configuration file path')
        
        self.args = parser.parse_args()
        
        if self.args.config != 'config.ini':
            self.config_file = Path(self.args.config)
            if self.config_file.exists():
                self.config.read(self.config_file)
        
        return self.args
    
    def get_pcap_files(self) -> List[str]:
        if not self.args:
            raise ValueError("Arguments not parsed yet")
        
        input_path = Path(self.args.input)
        pcap_files = []
        
        if input_path.is_file():
            pcap_files.append(str(input_path))
        elif input_path.is_dir():
            for ext in ['.pcap', '.pcapng', '.cap']:
                pcap_files.extend([str(f) for f in input_path.glob(f'*{ext}')])
                pcap_files.extend([str(f) for f in input_path.glob(f'*{ext}*')])
            pcap_files = sorted(set(pcap_files), key=self._natural_sort_key)
        else:
            raise FileNotFoundError(f"Input path not found: {input_path}")
        
        if not pcap_files:
            raise ValueError(f"No PCAP files found in: {input_path}")
        
        return pcap_files
    
    def get_pcap_folders(self) -> Dict[str, List[str]]:
        if not self.args:
            raise ValueError("Arguments not parsed yet")
        
        input_path = Path(self.args.input)
        pcap_folders = {}
        
        if not input_path.is_dir():
            raise ValueError("Multi-folder mode requires input to be a directory")
        
        for subdir in input_path.iterdir():
            if subdir.is_dir():
                pcap_files = []
                for ext in ['.pcap', '.pcapng', '.cap']:
                    pcap_files.extend([str(f) for f in subdir.glob(f'*{ext}')])
                    pcap_files.extend([str(f) for f in subdir.glob(f'*{ext}*')])
                
                if pcap_files:
                    pcap_files = sorted(set(pcap_files), key=self._natural_sort_key)
                    pcap_folders[subdir.name] = pcap_files
        
        if not pcap_folders:
            raise ValueError(f"No PCAP files found in subdirectories of: {input_path}")
        
        return pcap_folders
    
    def _natural_sort_key(self, text: str):
        import re
        return [int(s) if s.isdigit() else s.lower() for s in re.split(r'(\d+)', text)]
    
    def get_labeling_config(self) -> Dict[str, Any]:
        labeling_config = {
            'ip_attacks': [],
            'mac_attacks': [],
            'time_attacks': [],
        }
        
        if not self.args:
            return labeling_config
        
        # Parse IP-based attacks
        if self.args.label_ip:
            for ip_label in self.args.label_ip:
                try:
                    ip, label = ip_label.split('=', 1)
                    labeling_config['ip_attacks'].append({
                        'label': label.strip(),
                        'ips': [ip.strip()]
                    })
                except ValueError:
                    logging.warning(f"Invalid IP label format: {ip_label}")
        
        # Parse MAC-based attacks
        if self.args.label_mac:
            for mac_label in self.args.label_mac:
                try:
                    mac, label = mac_label.split('=', 1)
                    labeling_config['mac_attacks'].append({
                        'label': label.strip(),
                        'macs': [mac.strip()]
                    })
                except ValueError:
                    logging.warning(f"Invalid MAC label format: {mac_label}")
        
        # Parse time-based attacks
        if self.args.label_time:
            for time_label in self.args.label_time:
                try:
                    time_range, label = time_label.split('=', 1)
                    start_time, end_time = time_range.split('-', 1)
                    
                    labeling_config['time_attacks'].append({
                        'label': label.strip(),
                        'time_ranges': [{'start': start_time.strip(), 'end': end_time.strip()}]
                    })
                except ValueError:
                    logging.warning(f"Invalid time label format: {time_label}")
        
        # Load from JSON config file if specified
        if self.args.label_config:
            try:
                with open(self.args.label_config, 'r') as f:
                    file_config = json.load(f)
                
                # Merge file config with command-line config
                for key in ['ip_attacks', 'mac_attacks', 'time_attacks']:
                    if key in file_config:
                        labeling_config[key].extend(file_config[key])
                        
            except Exception as e:
                logging.error(f"Error loading labeling config file: {e}")
        
        # Load from text file if specified
        if self.args.label_file:
            try:
                from ..features.labeling import LabelingConfig
                text_labels = LabelingConfig.load_from_text_file(self.args.label_file)
                
                # Convert to config format
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
                        
            except Exception as e:
                logging.error(f"Error loading text labeling file: {e}")
        
        return labeling_config
    
    def get_processing_config(self) -> Dict[str, Any]:
        """Get processing configuration parameters."""
        config = {
            'flow_timeout': self.get_int('DEFAULT', 'flow_timeout'),
            'max_packets_per_flow': self.get_int('DEFAULT', 'max_packets_per_flow'),
            'queue_size': self.get_int('DEFAULT', 'queue_size'),
            'separate_l2_l3': self.get_bool('DEFAULT', 'separate_l2_l3'),
            'multi_folder': False,
            'output_dir': self.get_str('OUTPUT', 'output_dir'),
            'log_file': self.get_str('OUTPUT', 'log_file'),
            'csv_file': self.get_str('OUTPUT', 'csv_file'),
        }
        
        # Override with command-line arguments if present
        if self.args:
            if self.args.flow_timeout != 1200:  # Not default
                config['flow_timeout'] = self.args.flow_timeout
            if self.args.max_flows != 100000:  # Not default
                config['max_flows'] = self.args.max_flows
            if self.args.queue_size != 100000:  # Not default
                config['queue_size'] = self.args.queue_size
            if self.args.workers != 4:  # Not default
                config['workers'] = self.args.workers
            if hasattr(self.args, 'feature_threads') and self.args.feature_threads != 4:
                config['feature_threads'] = self.args.feature_threads
            else:
                config['feature_threads'] = 4
            if hasattr(self.args, 'folder_threads') and self.args.folder_threads != 1:
                config['folder_threads'] = self.args.folder_threads
            else:
                config['folder_threads'] = 1
            if hasattr(self.args, 'batch_size') and self.args.batch_size != 30:
                config['batch_size'] = self.args.batch_size
            else:
                config['batch_size'] = 30
            if hasattr(self.args, 'csv_batch_size') and self.args.csv_batch_size != 30:
                config['csv_batch_size'] = self.args.csv_batch_size
            else:
                config['csv_batch_size'] = 30
            if hasattr(self.args, 'disable_batching') and self.args.disable_batching:
                config['enable_batching'] = False
            else:
                config['enable_batching'] = True
            if self.args.separate_layers:
                config['separate_l2_l3'] = True
            if hasattr(self.args, 'multi_folder') and self.args.multi_folder:
                config['multi_folder'] = True
            if self.args.output != 'Results':
                config['output_dir'] = self.args.output
        
        return config
    
    def get_protocol_config(self) -> Dict[str, bool]:
        """Get protocol enablement configuration."""
        protocol_config = {}
        
        for option in self.config.options('PROTOCOLS'):
            protocol_config[option] = self.get_bool('PROTOCOLS', option)
        
        return protocol_config
    
    def get_str(self, section: str, option: str, fallback: str = '') -> str:
        """Get string configuration value."""
        return self.config.get(section, option, fallback=fallback)
    
    def get_int(self, section: str, option: str, fallback: int = 0) -> int:
        """Get integer configuration value."""
        return self.config.getint(section, option, fallback=fallback)
    
    def get_float(self, section: str, option: str, fallback: float = 0.0) -> float:
        """Get float configuration value."""
        return self.config.getfloat(section, option, fallback=fallback)
    
    def get_bool(self, section: str, option: str, fallback: bool = False) -> bool:
        """Get boolean configuration value."""
        return self.config.getboolean(section, option, fallback=fallback)
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                self.config.write(f)
            logging.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
    
    def create_sample_labeling_config(self, output_file: str = "labeling_config.json"):
        """Create a sample labeling configuration file."""
        sample_config = {
            "ip_attacks": [
                {
                    "label": "ARP Spoofing",
                    "ips": ["192.168.1.100", "192.168.1.200"]
                },
                {
                    "label": "DHCP Starvation",
                    "ips": ["192.168.1.50"]
                }
            ],
            "mac_attacks": [
                {
                    "label": "ARP Poisoning",
                    "macs": ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
                },
                {
                    "label": "CAM Flood",
                    "macs": ["de:ad:be:ef:ca:fe"]
                }
            ],
            "time_attacks": [
                {
                    "label": "DHCP Starvation",
                    "time_ranges": [
                        {"start": "10:13 AM", "end": "11:00 AM"},
                        {"start": "2:00 PM", "end": "3:30 PM"}
                    ]
                },
                {
                    "label": "CDP Flood",
                    "time_ranges": [
                        {"start": "10:00 AM", "end": "11:00 AM"},
                        {"start": "11:05 AM", "end": "12:06 PM"},
                        {"start": "12:09 PM", "end": "1:19 PM"}
                    ]
                },
                {
                    "label": "STP Attack",
                    "time_ranges": [
                        {"start": "9:00 AM", "end": "9:30 AM"}
                    ]
                }
            ]
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(sample_config, f, indent=2)
            logging.info(f"Sample labeling configuration created: {output_file}")
        except Exception as e:
            logging.error(f"Error creating sample config: {e}")
    
    def validate_config(self) -> bool:
        """Validate current configuration."""
        try:
            # Check required sections
            required_sections = ['DEFAULT', 'PROTOCOLS', 'FEATURES', 'OUTPUT']
            for section in required_sections:
                if not self.config.has_section(section) and section != 'DEFAULT':
                    logging.error(f"Missing required section: {section}")
                    return False
            
            # Validate numeric values
            try:
                self.get_int('DEFAULT', 'flow_timeout')
                self.get_int('DEFAULT', 'max_packets_per_flow')
                self.get_int('DEFAULT', 'queue_size')
            except ValueError as e:
                logging.error(f"Invalid numeric configuration: {e}")
                return False
            
            # Validate output directory
            output_dir = Path(self.get_str('OUTPUT', 'output_dir'))
            try:
                output_dir.mkdir(exist_ok=True)
            except Exception as e:
                logging.error(f"Cannot create output directory: {e}")
                return False
            
            logging.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logging.error(f"Configuration validation error: {e}")
            return False
    
    def get_log_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        log_config = {
            'level': self.get_str('DEFAULT', 'log_level', 'INFO'),
            'output_dir': self.get_str('OUTPUT', 'output_dir', 'Results'),
            'log_file': self.get_str('OUTPUT', 'log_file', 'log.txt'),
            'quiet': False,
        }
        
        # Override with command-line arguments
        if self.args:
            if hasattr(self.args, 'log_level'):
                log_config['level'] = self.args.log_level
            if hasattr(self.args, 'quiet'):
                log_config['quiet'] = self.args.quiet
            if hasattr(self.args, 'output'):
                log_config['output_dir'] = self.args.output
        
        return log_config
    
    def print_config_summary(self):
        """Print a summary of current configuration."""
        print("\nDLL Flowlyzer Configuration Summary")
        print("=" * 40)
        
        if self.args:
            print(f"Input: {self.args.input}")
            print(f"Output: {self.args.output}")
            print(f"Multi-folder Mode: {getattr(self.args, 'multi_folder', False)}")
            print(f"Separate Layers: {self.args.separate_layers}")
            print(f"Flow Timeout: {self.args.flow_timeout}s")
            print(f"Max Flows: {self.args.max_flows}")
            print(f"Queue Size: {self.args.queue_size}")
            print(f"Workers: {self.args.workers}")
            print(f"Log Level: {self.args.log_level}")
            
            # Labeling summary
            labeling_config = self.get_labeling_config()
            total_rules = (len(labeling_config['ip_attacks']) + 
                          len(labeling_config['mac_attacks']) + 
                          len(labeling_config['time_attacks']))
            print(f"Labeling Rules: {total_rules}")
            
        print("=" * 40)