import time
import sys
import os
import gc
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import rdpcap, PcapReader
import pandas as pd
import numpy as np
from collections import defaultdict
import json

from .utils.config_manager import ConfigManager
from .utils.logger import FlowlyzerLogger
from .features.labeling import FlowLabeler, LabelingConfig


class Layer2FeatureExtractor:
    def __init__(self):
        self.reset_stats()
    
    def reset_stats(self):
        self.packet_stats = defaultdict(int)
        self.flow_stats = defaultdict(int)
        self.protocol_features = defaultdict(list)
        
    def extract_packet_features(self, packet, frame_number):
        features = {
            'frame_number': frame_number,
            'timestamp': float(packet.time),
            'frame_length': len(packet)
        }
        
        # MAC layer features
        if packet.haslayer('Ether'):
            eth = packet.getlayer('Ether')
            features['src_mac'] = str(eth.src)
            features['dst_mac'] = str(eth.dst)
            features['eth_type'] = eth.type
        
        # Protocol detection and feature extraction
        protocol_type = 'Unknown'
        
        if packet.haslayer('IP'):
            protocol_type = 'IPv4'
            ip = packet.getlayer('IP')
            features.update({
                'src_ip': str(ip.src),
                'dst_ip': str(ip.dst),
                'ip_version': ip.version,
                'ip_proto': ip.proto,
                'ip_len': ip.len,
                'ip_ttl': ip.ttl
            })
            
            if packet.haslayer('TCP'):
                protocol_type = 'TCP'
                tcp = packet.getlayer('TCP')
                features.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': tcp.flags,
                    'tcp_window': tcp.window,
                    'tcp_seq': tcp.seq,
                    'tcp_ack': tcp.ack
                })
                
                # Check for SSH
                if tcp.sport == 22 or tcp.dport == 22:
                    protocol_type = 'SSH'
                    
            elif packet.haslayer('UDP'):
                protocol_type = 'UDP'
                udp = packet.getlayer('UDP')
                features.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'udp_len': udp.len
                })
                
                if packet.haslayer('DHCP'):
                    protocol_type = 'DHCP'
                    dhcp = packet.getlayer('DHCP')
                    features['dhcp_options'] = len(dhcp.options) if dhcp.options else 0
                    
            elif ip.proto == 1:  # ICMP
                protocol_type = 'ICMP'
                if packet.haslayer('ICMP'):
                    icmp = packet.getlayer('ICMP')
                    features.update({
                        'icmp_type': icmp.type,
                        'icmp_code': icmp.code
                    })
                    
        elif packet.haslayer('IPv6'):
            protocol_type = 'IPv6'
            ip6 = packet.getlayer('IPv6')
            features.update({
                'src_ip': str(ip6.src),
                'dst_ip': str(ip6.dst),
                'ip_version': 6,
                'ip6_plen': ip6.plen,
                'ip6_hlim': ip6.hlim
            })
            
        elif packet.haslayer('ARP'):
            protocol_type = 'ARP'
            arp = packet.getlayer('ARP')
            features.update({
                'arp_op': arp.op,
                'arp_hwsrc': str(arp.hwsrc),
                'arp_psrc': str(arp.psrc),
                'arp_hwdst': str(arp.hwdst),
                'arp_pdst': str(arp.pdst)
            })
            
        # Check for VLAN
        if packet.haslayer('Dot1Q'):
            vlan = packet.getlayer('Dot1Q')
            features.update({
                'vlan_id': vlan.vlan,
                'vlan_prio': vlan.prio,
                'has_vlan': 1
            })
            protocol_type = 'VLAN_' + protocol_type
        else:
            features['has_vlan'] = 0
            
        # Layer 2 protocol detection
        if packet.haslayer('STP'):
            protocol_type = 'STP'
            stp = packet.getlayer('STP')
            features.update({
                'stp_proto': getattr(stp, 'proto', 0),
                'stp_version': getattr(stp, 'version', 0),
                'stp_bpdutype': getattr(stp, 'bpdutype', 0)
            })
            
        # Check for CDP
        if self._is_cdp_packet(packet):
            protocol_type = 'CDP'
            features['cdp_detected'] = 1
            
        # Check for LLDP  
        if self._is_lldp_packet(packet):
            protocol_type = 'LLDP'
            features['lldp_detected'] = 1
            
        # Check for DTP
        if self._is_dtp_packet(packet):
            protocol_type = 'DTP'
            features['dtp_detected'] = 1
            
        features['protocol'] = protocol_type
        self.packet_stats[protocol_type] += 1
        self.protocol_features[protocol_type].append(features)
        
        return features
    
    def _is_cdp_packet(self, packet):
        try:
            if packet.haslayer('Ether'):
                eth = packet.getlayer('Ether')
                # Check CDP destination MAC
                if eth.dst.lower().startswith('01:00:0c:cc:cc:cc'):
                    return True
                # Check for SNAP with CDP OUI/PID
                if hasattr(packet, 'payload') and hasattr(packet.payload, 'load') and len(packet.payload.load) >= 8:
                    payload = packet.payload.load
                    if payload[0:6] == b'\xaa\xaa\x03\x00\x00\x0c' and payload[6:8] == b'\x20\x00':
                        return True
        except:
            pass
        return False
    
    def _is_lldp_packet(self, packet):
        if packet.haslayer('Ether'):
            eth = packet.getlayer('Ether')
            # Check LLDP destination MAC
            if eth.dst.lower().startswith('01:80:c2:00:00:0e'):
                return True
            if eth.type == 0x88cc:
                return True
        return False
    
    def _is_dtp_packet(self, packet):
        try:
            if packet.haslayer('Ether'):
                eth = packet.getlayer('Ether')
                if eth.dst.lower().startswith('01:00:0c:cc:cc:cc'):
                    # Check for DTP SNAP header
                    if hasattr(packet, 'payload') and hasattr(packet.payload, 'load') and len(packet.payload.load) >= 8:
                        payload = packet.payload.load
                        if payload[0:6] == b'\xaa\xaa\x03\x00\x00\x0c' and payload[6:8] == b'\x20\x04':
                            return True
        except:
            pass
        return False
    
    def generate_flow_features(self):
        flows = []
        
        # Group packets by flow (simplified: src_mac + dst_mac + protocol)
        flow_groups = defaultdict(list)
        
        for protocol, packets in self.protocol_features.items():
            for packet_features in packets:
                src_mac = packet_features.get('src_mac', '')
                dst_mac = packet_features.get('dst_mac', '')
                src_ip = packet_features.get('src_ip', '')
                dst_ip = packet_features.get('dst_ip', '')
                
                # Create flow key
                flow_key = f"{src_mac}-{dst_mac}-{src_ip}-{dst_ip}-{protocol}"
                flow_groups[flow_key].append(packet_features)
        
        for flow_key, flow_packets in flow_groups.items():
            if len(flow_packets) == 0:
                continue
                
            # Calculate flow statistics
            flow_features = self._calculate_flow_stats(flow_packets)
            flows.append(flow_features)
            
        return pd.DataFrame(flows) if flows else pd.DataFrame()
    
    def _calculate_flow_stats(self, packets):
        if not packets:
            return {}
            
        first_packet = packets[0]
        last_packet = packets[-1]
        
        features = {
            'flow_id': f"flow_{hash(str(first_packet.get('src_mac', '')))}",
            'src_mac': first_packet.get('src_mac', ''),
            'dst_mac': first_packet.get('dst_mac', ''),
            'src_ip': first_packet.get('src_ip', ''),
            'dst_ip': first_packet.get('dst_ip', ''),
            'protocol': first_packet.get('protocol', ''),
            'packet_count': len(packets),
            'duration': last_packet.get('timestamp', 0) - first_packet.get('timestamp', 0),
            'start_time': first_packet.get('timestamp', 0),
            'end_time': last_packet.get('timestamp', 0)
        }
        
        # Frame length statistics
        frame_lengths = [p.get('frame_length', 0) for p in packets]
        if frame_lengths:
            features.update({
                'total_bytes': sum(frame_lengths),
                'min_frame_length': min(frame_lengths),
                'max_frame_length': max(frame_lengths),
                'mean_frame_length': np.mean(frame_lengths),
                'std_frame_length': np.std(frame_lengths)
            })
            
        # Protocol specific features
        protocol = first_packet.get('protocol', '')
        
        if protocol in ['TCP', 'SSH']:
            tcp_flags = [p.get('tcp_flags', 0) for p in packets if 'tcp_flags' in p]
            features.update({
                'tcp_syn_count': sum(1 for f in tcp_flags if f & 0x02),
                'tcp_fin_count': sum(1 for f in tcp_flags if f & 0x01),
                'tcp_rst_count': sum(1 for f in tcp_flags if f & 0x04),
                'tcp_psh_count': sum(1 for f in tcp_flags if f & 0x08),
                'tcp_ack_count': sum(1 for f in tcp_flags if f & 0x10),
                'tcp_urg_count': sum(1 for f in tcp_flags if f & 0x20)
            })
            
        elif protocol == 'ARP':
            arp_ops = [p.get('arp_op', 0) for p in packets if 'arp_op' in p]
            features.update({
                'arp_request_count': sum(1 for op in arp_ops if op == 1),
                'arp_reply_count': sum(1 for op in arp_ops if op == 2)
            })
            
        elif protocol == 'ICMP':
            icmp_types = [p.get('icmp_type', 0) for p in packets if 'icmp_type' in p]
            features.update({
                'icmp_echo_request_count': sum(1 for t in icmp_types if t == 8),
                'icmp_echo_reply_count': sum(1 for t in icmp_types if t == 0),
                'icmp_dest_unreach_count': sum(1 for t in icmp_types if t == 3)
            })
            
        # VLAN features
        vlan_packets = [p for p in packets if p.get('has_vlan', 0)]
        features.update({
            'vlan_packet_count': len(vlan_packets),
            'vlan_packet_ratio': len(vlan_packets) / len(packets) if packets else 0
        })
        
        if vlan_packets:
            vlan_ids = [p.get('vlan_id', 0) for p in vlan_packets if 'vlan_id' in p]
            if vlan_ids:
                features['unique_vlan_count'] = len(set(vlan_ids))
                features['primary_vlan_id'] = max(set(vlan_ids), key=vlan_ids.count)
        
        # Add default values for missing features
        for key in ['tcp_syn_count', 'tcp_fin_count', 'tcp_rst_count', 'tcp_psh_count', 'tcp_ack_count', 'tcp_urg_count']:
            if key not in features:
                features[key] = 0
                
        for key in ['arp_request_count', 'arp_reply_count']:
            if key not in features:
                features[key] = 0
                
        for key in ['icmp_echo_request_count', 'icmp_echo_reply_count', 'icmp_dest_unreach_count']:
            if key not in features:
                features[key] = 0
                
        for key in ['unique_vlan_count', 'primary_vlan_id']:
            if key not in features:
                features[key] = 0
        
        return features


def load_folder_labeling_config(folder_path: str) -> dict:
    """Load labeling configuration from folder"""
    folder_path = Path(folder_path)
    
    # Try JSON first
    labeling_json = folder_path / "labeling.json"
    if labeling_json.exists():
        try:
            with open(labeling_json, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON labeling: {e}")
    
    # Try text file
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
            
            return config
        except Exception as e:
            print(f"Error loading text labeling: {e}")
    
    return None


def process_pcap_files(pcap_files: list, folder_name: str, output_dir: Path, 
                      labeling_config: dict, logger) -> dict:
    """Process PCAP files and extract features"""
    
    logger.logger.info(f"Processing folder: {folder_name} ({len(pcap_files)} files)")
    
    extractor = Layer2FeatureExtractor()
    start_time = time.time()
    total_packets = 0
    
    try:
        for file_index, pcap_file in enumerate(pcap_files, 1):
            logger.logger.info(f"File {file_index}/{len(pcap_files)}: {Path(pcap_file).name}")
            
            packets_in_file = 0
            try:
                with PcapReader(pcap_file) as pcap_reader:
                    for frame_number, packet in enumerate(pcap_reader, total_packets + 1):
                        extractor.extract_packet_features(packet, frame_number)
                        packets_in_file += 1
                        
                        if frame_number % 10000 == 0:
                            logger.logger.info(f"Processed {frame_number} packets")
            
            except Exception as e:
                logger.logger.error(f"Error processing {pcap_file}: {e}")
                continue
            
            total_packets += packets_in_file
            logger.logger.info(f"Processed {packets_in_file} packets from {Path(pcap_file).name}")
    
    except Exception as e:
        logger.logger.error(f"Error in processing: {e}")
        return None
    
    # Generate flow features
    flows_df = extractor.generate_flow_features()
    
    if flows_df.empty:
        logger.logger.warning("No flows generated")
        flows_df = pd.DataFrame({'label': []})  # Create empty DataFrame with label column
    
    # Apply labeling
    if labeling_config and not flows_df.empty:
        flow_labeler = FlowLabeler()
        attack_labels = LabelingConfig.load_from_config(labeling_config)
        flow_labeler.attack_labels = attack_labels
        flows_df = flow_labeler.label_flows(flows_df)
    else:
        flows_df['label'] = 'Benign'
    
    # Export to CSV
    timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
    csv_file = output_dir / f"{folder_name}_layer2_features_{timestamp}.csv"
    flows_df.to_csv(csv_file, index=False)
    
    # Generate protocol statistics
    protocol_stats = dict(extractor.packet_stats)
    stats_file = output_dir / f"{folder_name}_protocol_stats_{timestamp}.csv"
    pd.DataFrame([protocol_stats]).to_csv(stats_file, index=False)
    
    processing_time = time.time() - start_time
    
    logger.logger.info(f"Completed {folder_name}: {total_packets} packets, {len(flows_df)} flows")
    logger.logger.info(f"Protocol distribution: {dict(extractor.packet_stats)}")
    
    return {
        'folder_name': folder_name,
        'flows_df': flows_df,
        'csv_file': str(csv_file),
        'stats_file': str(stats_file),
        'protocol_stats': protocol_stats,
        'total_packets': total_packets,
        'total_flows': len(flows_df),
        'processing_time': processing_time
    }


def generate_charts(results: list, output_dir: Path):
    """Generate comprehensive visualization charts"""
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    plt.style.use('default')
    
    # Collect all protocol stats
    all_protocol_stats = defaultdict(int)
    all_flow_stats = []
    
    for result in results:
        if result and 'protocol_stats' in result:
            for protocol, count in result['protocol_stats'].items():
                all_protocol_stats[protocol] += count
        
        if result and 'flows_df' in result and not result['flows_df'].empty:
            all_flow_stats.append(result['flows_df'])
    
    if not all_protocol_stats:
        return
    
    # 1. Protocol distribution charts
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    protocols = list(all_protocol_stats.keys())
    counts = list(all_protocol_stats.values())
    
    # Pie chart
    ax1.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    ax1.set_title('Protocol Distribution (Packets)')
    
    # Bar chart
    ax2.bar(protocols, counts, color='skyblue')
    ax2.set_title('Protocol Packet Counts')
    ax2.set_ylabel('Packet Count')
    ax2.tick_params(axis='x', rotation=45)
    
    # Protocol percentages
    total_packets = sum(counts)
    percentages = [(c/total_packets)*100 for c in counts]
    ax3.barh(protocols, percentages, color='lightcoral')
    ax3.set_title('Protocol Distribution (%)')
    ax3.set_xlabel('Percentage')
    
    # Flow statistics
    if all_flow_stats:
        combined_flows = pd.concat(all_flow_stats, ignore_index=True)
        
        # Flow count by protocol
        flow_protocol_counts = combined_flows['protocol'].value_counts()
        ax4.bar(flow_protocol_counts.index, flow_protocol_counts.values, color='lightgreen')
        ax4.set_title('Flow Counts by Protocol')
        ax4.set_ylabel('Flow Count')
        ax4.tick_params(axis='x', rotation=45)
    else:
        ax4.text(0.5, 0.5, 'No flow data available', ha='center', va='center', transform=ax4.transAxes)
        ax4.set_title('Flow Statistics')
    
    plt.tight_layout()
    chart_file = output_dir / f"protocol_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.png"
    plt.savefig(chart_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"📊 Protocol analysis chart saved: {chart_file.name}")
    
    # 2. Generate summary statistics file
    stats_data = {
        'Protocol': protocols,
        'Packet_Count': counts,
        'Percentage': [f"{(c/total_packets)*100:.2f}%" for c in counts]
    }
    
    if all_flow_stats:
        combined_flows = pd.concat(all_flow_stats, ignore_index=True)
        flow_counts = []
        avg_packet_counts = []
        
        for protocol in protocols:
            proto_flows = combined_flows[combined_flows['protocol'] == protocol]
            flow_counts.append(len(proto_flows))
            avg_packet_counts.append(proto_flows['packet_count'].mean() if not proto_flows.empty else 0)
        
        stats_data['Flow_Count'] = flow_counts
        stats_data['Avg_Packets_Per_Flow'] = [f"{x:.2f}" for x in avg_packet_counts]
    
    stats_df = pd.DataFrame(stats_data)
    stats_file = output_dir / f"summary_statistics_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv"
    stats_df.to_csv(stats_file, index=False)
    
    print(f"📈 Summary statistics saved: {stats_file.name}")


def main():
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
        
        logger.logger.info("="*60)
        logger.logger.info("Layer 2 Network Traffic Feature Extractor Started")
        logger.logger.info("="*60)
        
        results = []
        
        if processing_config.get('multi_folder', False):
            # Multi-folder processing
            pcap_folders = config_manager.get_pcap_folders()
            logger.logger.info(f"Processing {len(pcap_folders)} folders")
            
            for folder_name, pcap_files in pcap_folders.items():
                folder_output_dir = output_dir / folder_name
                folder_output_dir.mkdir(exist_ok=True)
                
                # Check for folder-specific labeling
                if pcap_files:
                    folder_path = Path(pcap_files[0]).parent
                    folder_labeling = load_folder_labeling_config(folder_path)
                    actual_labeling = folder_labeling if folder_labeling else labeling_config
                else:
                    actual_labeling = labeling_config
                
                result = process_pcap_files(pcap_files, folder_name, folder_output_dir, 
                                          actual_labeling, logger)
                if result:
                    results.append(result)
        else:
            # Single folder processing
            pcap_files = config_manager.get_pcap_files()
            result = process_pcap_files(pcap_files, "analysis", output_dir, 
                                      labeling_config, logger)
            if result:
                results.append(result)
        
        # Generate summary charts
        if results:
            generate_charts(results, output_dir)
            
            # Print summary
            total_packets = sum(r.get('total_packets', 0) for r in results)
            total_flows = sum(r.get('total_flows', 0) for r in results)
            
            print(f"\n✅ Analysis completed successfully!")
            print(f"📊 Processed {len(results)} folder(s)")
            print(f"📦 Total packets: {total_packets:,}")
            print(f"🌊 Total flows: {total_flows:,}")
            print(f"💾 Results saved to: {output_dir}")
            print(f"📝 Log file: {log_file}")
            
            logger.logger.info(f"Analysis completed: {total_packets} packets, {total_flows} flows")
        else:
            print("❌ No results generated")
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())