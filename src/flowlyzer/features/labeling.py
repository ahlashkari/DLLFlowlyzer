"""
Flow labeling system for attack detection and classification.
"""

import logging
from datetime import datetime, time
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd


class AttackLabel:
    """Represents an attack label with associated criteria."""
    
    def __init__(self, label: str, attack_type: str):
        """
        Initialize attack label.
        
        Args:
            label: The label string to assign
            attack_type: Type of attack (IP, MAC, TIME, PROTOCOL based)
        """
        self.label = label
        self.attack_type = attack_type
        self.criteria = {}
        self.layer_2_only = False
        self.target_protocols = []
    
    def set_ip_criteria(self, attacker_ips: List[str]):
        """Set IP-based attack criteria."""
        self.criteria['attacker_ips'] = [ip.strip() for ip in attacker_ips]
        self.attack_type = 'IP'
    
    def set_mac_criteria(self, attacker_macs: List[str]):
        """Set MAC-based attack criteria."""
        self.criteria['attacker_macs'] = [mac.strip().lower() for mac in attacker_macs]
        self.attack_type = 'MAC'
    
    def set_time_criteria(self, time_ranges: List[Tuple[str, str]]):
        """
        Set time-based attack criteria.
        
        Args:
            time_ranges: List of (start_time, end_time) tuples in "HH:MM AM/PM" format
        """
        self.criteria['time_ranges'] = []
        for start_str, end_str in time_ranges:
            try:
                start_time = self._parse_time_string(start_str)
                end_time = self._parse_time_string(end_str)
                self.criteria['time_ranges'].append((start_time, end_time))
            except ValueError as e:
                logging.warning(f"Invalid time range {start_str}-{end_str}: {e}")
    
    def set_layer_2_only(self, layer_2_only: bool):
        """
        Set whether this label should only apply to Layer 2 flows.
        
        Args:
            layer_2_only: If True, only apply label to Layer 2 flows
        """
        self.layer_2_only = layer_2_only
    
    def set_protocol_criteria(self, protocols: List[str], port_filter: Optional[List[int]] = None):
        """
        Set protocol-specific attack criteria.
        
        Args:
            protocols: List of protocols to target (e.g., ['ARP', 'CDP', 'STP'])
            port_filter: Optional list of port numbers for TCP/UDP protocols
        """
        self.target_protocols = [proto.upper() for proto in protocols]
        if port_filter:
            self.criteria['port_filter'] = port_filter
        self.attack_type = 'PROTOCOL'
    
    def _parse_time_string(self, time_str: str) -> time:
        """Parse time string in format 'HH:MM AM/PM' to time object."""
        try:
            if 'AM' in time_str.upper() or 'PM' in time_str.upper():
                dt = datetime.strptime(time_str.strip().upper(), '%I:%M %p')
            else:
                dt = datetime.strptime(time_str.strip(), '%H:%M')
            return dt.time()
        except ValueError:
            raise ValueError(f"Cannot parse time string: {time_str}")
    
    def matches_flow(self, flow_features: Dict[str, Any], flow_timestamp: float) -> bool:
        """
        Check if a flow matches this attack label criteria.
        
        Args:
            flow_features: Flow feature dictionary
            flow_timestamp: Flow timestamp (Unix timestamp)
            
        Returns:
            True if flow matches attack criteria
        """
        try:
            if self.layer_2_only and not self._is_layer_2_flow(flow_features):
                return False
            
            if self.target_protocols and not self._matches_protocol_criteria(flow_features):
                return False
            
            if self.attack_type == 'IP':
                return self._matches_ip_criteria(flow_features)
            elif self.attack_type == 'MAC':
                return self._matches_mac_criteria(flow_features)
            elif self.attack_type == 'TIME':
                return self._matches_time_criteria(flow_timestamp)
            elif self.attack_type == 'PROTOCOL':
                return self._matches_protocol_criteria(flow_features)
            else:
                return False
        except Exception:
            return False
    
    def _matches_ip_criteria(self, flow_features: Dict[str, Any]) -> bool:
        """Check if flow matches IP-based criteria."""
        attacker_ips = self.criteria.get('attacker_ips', [])
        src_ip = flow_features.get('src_ip_addr', '')
        dst_ip = flow_features.get('dst_ip_addr', '')
        
        return src_ip in attacker_ips or dst_ip in attacker_ips
    
    def _matches_mac_criteria(self, flow_features: Dict[str, Any]) -> bool:
        """Check if flow matches MAC-based criteria."""
        attacker_macs = self.criteria.get('attacker_macs', [])
        src_mac = str(flow_features.get('src_mac_addr', '')).lower()
        dst_mac = str(flow_features.get('dst_mac_addr', '')).lower()
        
        return src_mac in attacker_macs or dst_mac in attacker_macs
    
    def _matches_time_criteria(self, flow_timestamp: float) -> bool:
        """Check if flow matches time-based criteria."""
        time_ranges = self.criteria.get('time_ranges', [])
        
        try:
            flow_time = datetime.fromtimestamp(flow_timestamp).time()
            
            for start_time, end_time in time_ranges:
                if self._time_in_range(flow_time, start_time, end_time):
                    return True
            
            return False
        except Exception:
            return False
    
    def _time_in_range(self, check_time: time, start_time: time, end_time: time) -> bool:
        """Check if time is within range, handling day crossover."""
        if start_time <= end_time:
            return start_time <= check_time <= end_time
        else:
            return check_time >= start_time or check_time <= end_time
    
    def _is_layer_2_flow(self, flow_features: Dict[str, Any]) -> bool:
        """
        Check if flow is a Layer 2 flow based on protocol type.
        
        Args:
            flow_features: Flow feature dictionary
            
        Returns:
            True if this is a Layer 2 flow
        """
        protocol = flow_features.get('protocol', '').upper()
        layer_2_protocols = {
            'ARP', 'STP', 'CDP', 'LLDP', 'DTP', 'VTP', 'BPDU', 
            'LLC', 'SNAP', 'ETH', 'VLAN', 'DHCP', 'BOOTP'
        }
        
        if protocol in layer_2_protocols:
            return True
        l2_indicators = [
            'num_stp_frame', 'num_cdp_frame', 'num_arp_frame', 
            'num_dhcp_frame', 'num_llc_frame', 'num_lldp_frame',
            'num_dtp_frame', 'num_vtp_frame'
        ]
        
        for indicator in l2_indicators:
            if flow_features.get(indicator, 0) > 0:
                return True
                
        return False
    
    def _matches_protocol_criteria(self, flow_features: Dict[str, Any]) -> bool:
        """
        Check if flow matches protocol-specific criteria.
        
        Args:
            flow_features: Flow feature dictionary
            
        Returns:
            True if flow matches protocol criteria
        """
        if not self.target_protocols:
            return True
            
        flow_protocol = flow_features.get('protocol', '').upper()
        
        if flow_protocol in self.target_protocols:
            return True
        protocol_mappings = {
            'ARP': ['num_arp_frame'],
            'STP': ['num_stp_frame'], 
            'CDP': ['num_cdp_frame'],
            'LLDP': ['num_lldp_frame'],
            'DHCP': ['num_dhcp_frame'],
            'LLC': ['num_llc_frame'],
            'DTP': ['num_dtp_frame'],
            'VTP': ['num_vtp_frame']
        }
        
        for target_protocol in self.target_protocols:
            if target_protocol in protocol_mappings:
                for frame_counter in protocol_mappings[target_protocol]:
                    if flow_features.get(frame_counter, 0) > 0:
                        return True
        port_filter = self.criteria.get('port_filter', [])
        if port_filter and flow_protocol in ['TCP', 'UDP']:
            src_port = flow_features.get('src_port', 0)
            dst_port = flow_features.get('dst_port', 0)
            return src_port in port_filter or dst_port in port_filter
            
        return False


class FlowLabeler:
    """
    Flow labeling system for classifying network flows as benign or attack types.
    """
    
    def __init__(self):
        """Initialize flow labeler."""
        self.attack_labels: List[AttackLabel] = []
        self.default_label = "Benign"
        self.logger = logging.getLogger(__name__)
    
    def add_ip_attack(self, label: str, attacker_ips: List[str]):
        """
        Add IP-based attack labeling rule.
        
        Args:
            label: Attack label (e.g., "ARP Spoofing")
            attacker_ips: List of attacker IP addresses
        """
        attack_label = AttackLabel(label, 'IP')
        attack_label.set_ip_criteria(attacker_ips)
        self.attack_labels.append(attack_label)
        
        self.logger.info(f"Added IP-based attack rule: {label} for IPs {attacker_ips}")
    
    def add_mac_attack(self, label: str, attacker_macs: List[str]):
        """
        Add MAC-based attack labeling rule.
        
        Args:
            label: Attack label (e.g., "ARP Poisoning")
            attacker_macs: List of attacker MAC addresses
        """
        attack_label = AttackLabel(label, 'MAC')
        attack_label.set_mac_criteria(attacker_macs)
        self.attack_labels.append(attack_label)
        
        self.logger.info(f"Added MAC-based attack rule: {label} for MACs {attacker_macs}")
    
    def add_time_attack(self, label: str, time_ranges: List[Tuple[str, str]], layer_2_only: bool = False):
        """
        Add time-based attack labeling rule.
        
        Args:
            label: Attack label (e.g., "DHCP Starvation")
            time_ranges: List of (start_time, end_time) tuples in "HH:MM AM/PM" format
            layer_2_only: If True, only apply to Layer 2 flows
        """
        attack_label = AttackLabel(label, 'TIME')
        attack_label.set_time_criteria(time_ranges)
        attack_label.set_layer_2_only(layer_2_only)
        self.attack_labels.append(attack_label)
        
        l2_info = " (Layer 2 only)" if layer_2_only else ""
        self.logger.info(f"Added time-based attack rule: {label} for time ranges {time_ranges}{l2_info}")
    
    def add_protocol_attack(self, label: str, protocols: List[str], time_ranges: Optional[List[Tuple[str, str]]] = None, 
                           port_filter: Optional[List[int]] = None, layer_2_only: bool = True):
        """
        Add protocol-specific attack labeling rule.
        
        Args:
            label: Attack label (e.g., "ARP Protocol Attack")
            protocols: List of protocols to target (e.g., ['ARP', 'CDP'])
            time_ranges: Optional time ranges when attack occurs
            port_filter: Optional port numbers for TCP/UDP protocols
            layer_2_only: If True, only apply to Layer 2 flows (default True for protocol attacks)
        """
        attack_label = AttackLabel(label, 'PROTOCOL')
        attack_label.set_protocol_criteria(protocols, port_filter)
        attack_label.set_layer_2_only(layer_2_only)
        
        if time_ranges:
            attack_label.set_time_criteria(time_ranges)
            
        self.attack_labels.append(attack_label)
        
        port_info = f" on ports {port_filter}" if port_filter else ""
        time_info = f" during {time_ranges}" if time_ranges else ""
        l2_info = " (Layer 2 only)" if layer_2_only else ""
        self.logger.info(f"Added protocol-specific attack rule: {label} for protocols {protocols}{port_info}{time_info}{l2_info}")
    
    def label_flows(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        """
        Label all flows in the DataFrame.
        
        Args:
            flows_df: DataFrame with flow features
            
        Returns:
            DataFrame with 'label' column added/updated
        """
        flows_df['label'] = 'UnLabeled'
        

        label_counts = flows_df['label'].value_counts()
        self.logger.info(f"Flow labeling completed: {dict(label_counts)}")
        
        return flows_df
    
    def _get_attack_mask(self, flows_df: pd.DataFrame, attack_label: AttackLabel) -> pd.Series:
        """Get boolean mask for flows matching attack criteria."""
        if attack_label.attack_type == 'IP':
            return self._get_ip_attack_mask(flows_df, attack_label)
        elif attack_label.attack_type == 'MAC':
            return self._get_mac_attack_mask(flows_df, attack_label)
        elif attack_label.attack_type == 'TIME':
            return self._get_time_attack_mask(flows_df, attack_label)
        else:
            return pd.Series([False] * len(flows_df), index=flows_df.index)
    
    def _get_ip_attack_mask(self, flows_df: pd.DataFrame, attack_label: AttackLabel) -> pd.Series:
        """Get mask for IP-based attacks."""
        attacker_ips = attack_label.criteria.get('attacker_ips', [])
        
        src_mask = flows_df['src_ip_addr'].isin(attacker_ips)
        dst_mask = flows_df['dst_ip_addr'].isin(attacker_ips)
        
        return src_mask | dst_mask
    
    def _get_mac_attack_mask(self, flows_df: pd.DataFrame, attack_label: AttackLabel) -> pd.Series:
        """Get mask for MAC-based attacks."""
        attacker_macs = attack_label.criteria.get('attacker_macs', [])
        
        src_mask = flows_df['src_mac_addr'].str.lower().isin(attacker_macs)
        dst_mask = flows_df['dst_mac_addr'].str.lower().isin(attacker_macs)
        
        return src_mask | dst_mask
    
    def _get_time_attack_mask(self, flows_df: pd.DataFrame, attack_label: AttackLabel) -> pd.Series:
        """Get mask for time-based attacks."""
        time_ranges = attack_label.criteria.get('time_ranges', [])
        
        if not time_ranges:
            return pd.Series([False] * len(flows_df), index=flows_df.index)
        
        return pd.Series([False] * len(flows_df), index=flows_df.index)
    
    def clear_attack_rules(self):
        """Clear all attack labeling rules."""
        self.attack_labels.clear()
        self.logger.info("Cleared all attack labeling rules")
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of configured attack rules."""
        summary = {
            'total_rules': len(self.attack_labels),
            'rules_by_type': {},
            'rules': []
        }
        
        for attack_label in self.attack_labels:
            attack_type = attack_label.attack_type
            if attack_type not in summary['rules_by_type']:
                summary['rules_by_type'][attack_type] = 0
            summary['rules_by_type'][attack_type] += 1
            
            rule_info = {
                'label': attack_label.label,
                'type': attack_label.attack_type,
                'criteria': attack_label.criteria
            }
            summary['rules'].append(rule_info)
        
        return summary


class LabelingConfig:
    """Configuration helper for setting up labeling rules."""
    
    @staticmethod
    def load_from_config(config_dict: Dict[str, Any]) -> List[AttackLabel]:
        """
        Load attack labels from configuration dictionary with enhanced Layer 2 and protocol support.
        
        Args:
            config_dict: Configuration dictionary with attack definitions
            
        Returns:
            List of AttackLabel objects
        """
        attack_labels = []
        
        global_layer_2_only = config_dict.get('layer_2_only', False)
        
        if 'time_labels' in config_dict:
            for attack_config in config_dict['time_labels']:
                label = attack_config.get('label', 'Unknown Attack')
                time_range = attack_config.get('time_range', '')
                layer_2_only = attack_config.get('layer_2_only', global_layer_2_only)
                
                time_tuples = []
                if '-' in time_range:
                    start_time, end_time = time_range.split('-', 1)
                    start_time = LabelingConfig._convert_24h_to_12h(start_time.strip())
                    end_time = LabelingConfig._convert_24h_to_12h(end_time.strip())
                    time_tuples.append((start_time, end_time))
                
                if time_tuples:
                    attack_label = AttackLabel(label, 'TIME')
                    attack_label.set_time_criteria(time_tuples)
                    attack_label.set_layer_2_only(layer_2_only)
                    attack_labels.append(attack_label)
        
        if 'protocol_specific_labels' in config_dict:
            for attack_config in config_dict['protocol_specific_labels']:
                label = attack_config.get('label', 'Protocol Attack')
                protocols = attack_config.get('protocols', [])
                time_range = attack_config.get('time_range', '')
                port_filter = attack_config.get('port_filter', None)
                layer_2_only = attack_config.get('layer_2_only', global_layer_2_only)
                
                time_tuples = []
                if time_range and '-' in time_range:
                    start_time, end_time = time_range.split('-', 1)
                    start_time = LabelingConfig._convert_24h_to_12h(start_time.strip())
                    end_time = LabelingConfig._convert_24h_to_12h(end_time.strip())
                    time_tuples.append((start_time, end_time))
                
                attack_label = AttackLabel(label, 'PROTOCOL')
                attack_label.set_protocol_criteria(protocols, port_filter)
                attack_label.set_layer_2_only(layer_2_only)
                
                if time_tuples:
                    attack_label.set_time_criteria(time_tuples)
                
                attack_labels.append(attack_label)
        
        if 'ip_labels' in config_dict:
            for attack_config in config_dict['ip_labels']:
                ip = attack_config.get('ip', '')
                label = attack_config.get('label', 'IP Attack')
                layer_2_only = attack_config.get('layer_2_only', global_layer_2_only)
                
                if ip and not ip.endswith('_PLACEHOLDER'):
                    attack_label = AttackLabel(label, 'IP')
                    attack_label.set_ip_criteria([ip])
                    attack_label.set_layer_2_only(layer_2_only)
                    attack_labels.append(attack_label)
        
        if 'mac_labels' in config_dict:
            for attack_config in config_dict['mac_labels']:
                mac = attack_config.get('mac', '')
                label = attack_config.get('label', 'MAC Attack')
                layer_2_only = attack_config.get('layer_2_only', global_layer_2_only)
                
                if mac and not mac.endswith('_PLACEHOLDER'):
                    attack_label = AttackLabel(label, 'MAC')
                    attack_label.set_mac_criteria([mac])
                    attack_label.set_layer_2_only(layer_2_only)
                    attack_labels.append(attack_label)
        
        for legacy_key in ['ip_attacks', 'mac_attacks', 'time_attacks']:
            if legacy_key in config_dict:
                attack_labels.extend(LabelingConfig._load_legacy_format(config_dict[legacy_key], legacy_key))
        
        return attack_labels
    
    @staticmethod
    def _convert_24h_to_12h(time_str: str) -> str:
        """Convert 24-hour time format to 12-hour format."""
        try:
            if ':' in time_str:
                hour, minute = time_str.split(':', 1)
                hour = int(hour)
                minute = int(minute)
                
                if hour == 0:
                    return f"12:{minute:02d} AM"
                elif hour < 12:
                    return f"{hour}:{minute:02d} AM"
                elif hour == 12:
                    return f"12:{minute:02d} PM"
                else:
                    return f"{hour-12}:{minute:02d} PM"
        except:
            pass
        return time_str
    
    @staticmethod
    def _load_legacy_format(config_list: List[Dict], attack_type: str) -> List[AttackLabel]:
        """Load legacy configuration format for backward compatibility."""
        attack_labels = []
        
        for attack_config in config_list:
            label = attack_config.get('label', 'Unknown')
            
            if attack_type == 'ip_attacks':
                ips = attack_config.get('ips', [])
                attack_label = AttackLabel(label, 'IP')
                attack_label.set_ip_criteria(ips)
                attack_labels.append(attack_label)
                
            elif attack_type == 'mac_attacks':
                macs = attack_config.get('macs', [])
                attack_label = AttackLabel(label, 'MAC')
                attack_label.set_mac_criteria(macs)
                attack_labels.append(attack_label)
                
            elif attack_type == 'time_attacks':
                time_ranges = attack_config.get('time_ranges', [])
                time_tuples = []
                for time_range in time_ranges:
                    if isinstance(time_range, dict):
                        start = time_range.get('start', '')
                        end = time_range.get('end', '')
                        time_tuples.append((start, end))
                    elif isinstance(time_range, (list, tuple)) and len(time_range) >= 2:
                        time_tuples.append((time_range[0], time_range[1]))
                
                attack_label = AttackLabel(label, 'TIME')
                attack_label.set_time_criteria(time_tuples)
                attack_labels.append(attack_label)
        
        return attack_labels
    
    @staticmethod
    def load_from_text_file(file_path: str) -> List[AttackLabel]:
        """
        Load attack labels from text file.
        
        Format examples:
        11:00 AM- 12:02 PM : arp spoofing
        mac: 12:1C:1F:11:12:2C Arp Poisoning
        ip : 192.168.1.19 Arp Spoofing
        mac: 19:1A:12:1C:FF:12 ip: 192.168.1.19 dhcp starvation
        
        Args:
            file_path: Path to text file with labeling rules
            
        Returns:
            List of AttackLabel objects
        """
        attack_labels = []
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse different formats
                    if ':' in line and ('AM' in line.upper() or 'PM' in line.upper()):
                        time_part, label_part = line.split(':', 1)
                        time_range = time_part.strip()
                        label = label_part.strip()
                        
                        if '-' in time_range:
                            start_time, end_time = time_range.split('-', 1)
                            start_time = start_time.strip()
                            end_time = end_time.strip()
                            
                            attack_label = AttackLabel(label, 'TIME')
                            attack_label.set_time_criteria([(start_time, end_time)])
                            attack_labels.append(attack_label)
                    
                    elif line.lower().startswith('mac:'):
                        
                        parts = line.split()
                        mac_addr = None
                        ip_addr = None
                        label_parts = []
                        
                        i = 0
                        while i < len(parts):
                            if parts[i].lower() == 'mac:' and i + 1 < len(parts):
                                mac_addr = parts[i + 1]
                                i += 2
                            elif parts[i].lower() == 'ip:' and i + 1 < len(parts):
                                ip_addr = parts[i + 1]
                                i += 2
                            else:
                                label_parts.append(parts[i])
                                i += 1
                        
                        label = ' '.join(label_parts)
                        
                        if mac_addr:
                            attack_label = AttackLabel(label, 'MAC')
                            attack_label.set_mac_criteria([mac_addr])
                            attack_labels.append(attack_label)
                        
                        if ip_addr:
                            attack_label = AttackLabel(label, 'IP')
                            attack_label.set_ip_criteria([ip_addr])
                            attack_labels.append(attack_label)
                    
                    elif line.lower().startswith('ip:'):
                        parts = line.split(':', 1)
                        if len(parts) >= 2:
                            ip_and_label = parts[1].strip().split(None, 1)
                            if len(ip_and_label) >= 2:
                                ip_addr = ip_and_label[0]
                                label = ip_and_label[1]
                                
                                attack_label = AttackLabel(label, 'IP')
                                attack_label.set_ip_criteria([ip_addr])
                                attack_labels.append(attack_label)
                
                except Exception as e:
                    logging.warning(f"Error parsing line {line_num} in {file_path}: {e}")
                    continue
            
            logging.info(f"Loaded {len(attack_labels)} attack labels from {file_path}")
            
        except Exception as e:
            logging.error(f"Error loading text labeling file {file_path}: {e}")
        
        return attack_labels
    
    @staticmethod
    def create_sample_config() -> Dict[str, Any]:
        """Create a sample configuration for testing purposes."""
        return {
            'ip_attacks': [
                {
                    'label': 'ARP Spoofing',
                    'ips': ['192.168.1.100', '192.168.1.200']
                }
            ],
            'mac_attacks': [
                {
                    'label': 'ARP Poisoning',
                    'macs': ['00:11:22:33:44:55', 'aa:bb:cc:dd:ee:ff']
                }
            ],
            'time_attacks': [
                {
                    'label': 'DHCP Starvation',
                    'time_ranges': [
                        {'start': '10:13 AM', 'end': '11:00 AM'},
                        {'start': '2:00 PM', 'end': '3:30 PM'}
                    ]
                },
                {
                    'label': 'CDP Flood',
                    'time_ranges': [
                        {'start': '10:00 AM', 'end': '11:00 AM'},
                        {'start': '11:05 AM', 'end': '12:06 PM'},
                        {'start': '12:09 PM', 'end': '1:19 PM'}
                    ]
                }
            ]
        }