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
            description='DLL Flowlyzer - Network Flow Analyzer',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Simple Examples:
  %(prog)s -i file.pcap                    # Analyze single file
  %(prog)s -i Input/                       # Analyze directory
  %(prog)s -i Input/ --multi-folder        # Process multiple folders
  %(prog)s -i Input/ --separate-layers     # Separate Layer 2/3 files
            """
        )
        
        parser.add_argument('-i', '--input', required=True, 
                          help='Input PCAP file or directory')
        parser.add_argument('-o', '--output', default='Results', 
                          help='Output directory (default: Results)')
        
        parser.add_argument('--multi-folder', action='store_true', 
                          help='Process multiple folders containing PCAP files')
        parser.add_argument('--separate-layers', action='store_true', 
                          help='Create separate Layer 2 and Layer 3 CSV files')
        
        parser.add_argument('--workers', type=int, default=4, 
                          help='Number of processing threads (default: 4)')
        parser.add_argument('--quiet', action='store_true', 
                          help='Suppress detailed progress output')
        
        self.args = parser.parse_args()
        return self.args
    
    def get_pcap_files(self) -> List[str]:
        if not self.args:
            raise ValueError("Arguments not parsed yet")
        
        input_path = Path(self.args.input)
        pcap_files = []
        
        if input_path.is_file():
            pcap_files.append(str(input_path))
        elif input_path.is_dir():
            # Standard extensions
            for ext in ['.pcap', '.pcapng', '.cap']:
                pcap_files.extend([str(f) for f in input_path.glob(f'*{ext}')])
            
            # Numbered pcap files (e.g., .pcap1, .pcap2, .pcapng1, etc.)
            for base_ext in ['.pcap', '.pcapng', '.cap']:
                pcap_files.extend([str(f) for f in input_path.glob(f'*{base_ext}[0-9]*')])
            
            # Additional flexible pattern matching
            for ext in ['.pcap', '.pcapng', '.cap']:
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
                # Standard extensions
                for ext in ['.pcap', '.pcapng', '.cap']:
                    pcap_files.extend([str(f) for f in subdir.glob(f'*{ext}')])
                
                # Numbered pcap files (e.g., .pcap1, .pcap2, .pcapng1, etc.)
                for base_ext in ['.pcap', '.pcapng', '.cap']:
                    pcap_files.extend([str(f) for f in subdir.glob(f'*{base_ext}[0-9]*')])
                
                # Additional flexible pattern matching
                for ext in ['.pcap', '.pcapng', '.cap']:
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
        """Get labeling configuration (simplified - always returns empty since all flows are UnLabeled)."""
        return {
            'ip_attacks': [],
            'mac_attacks': [],
            'time_attacks': []
        }
    
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
            'workers': 4,
            'feature_threads': 4,
            'folder_threads': 1,
            'batch_size': 30,
            'csv_batch_size': 50,
            'enable_batching': True,
        }
        
        if self.args:
            config['workers'] = self.args.workers
            config['separate_l2_l3'] = getattr(self.args, 'separate_layers', False)
            config['multi_folder'] = getattr(self.args, 'multi_folder', False)
            config['output_dir'] = getattr(self.args, 'output', config['output_dir'])
        
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
            print(f"Separate Layers: {getattr(self.args, 'separate_layers', False)}")
            print(f"Workers: {self.args.workers}")
            print(f"Quiet Mode: {getattr(self.args, 'quiet', False)}")
            print(f"All flows labeled as: UnLabeled")
            
        print("=" * 40)