"""
Plotting and statistics visualization module for DLL Flowlyzer.
"""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging


class FlowlyzerPlotter:
    """
    Visualization and plotting system for network flow analysis results.
    Creates comprehensive plots and statistics from PCAP analysis.
    """
    
    def __init__(self, output_dir: str = "Results"):
        """
        Initialize plotter.
        
        Args:
            output_dir: Directory to save plots
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        plt.style.use('default')
        sns.set_palette("husl")
        
        self.logger = logging.getLogger(__name__)
    
    def create_protocol_statistics(self, flows_df: pd.DataFrame, processing_stats: Dict[str, Any]) -> str:
        """
        Create comprehensive protocol statistics plots.
        
        Args:
            flows_df: DataFrame with flow features
            processing_stats: Processing statistics from flow manager
            
        Returns:
            Path to created plot file
        """
        try:
            fig, axes = plt.subplots(2, 3, figsize=(18, 12))
            fig.suptitle('Network Protocol Statistics', fontsize=16, fontweight='bold')
            
            protocol_stats = processing_stats.get('protocol_stats', {})
            if protocol_stats:
                protocols = list(protocol_stats.keys())
                counts = list(protocol_stats.values())
                
                axes[0, 0].pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
                axes[0, 0].set_title('Packet Distribution by Protocol')
            else:
                axes[0, 0].text(0.5, 0.5, 'No protocol data', ha='center', va='center')
                axes[0, 0].set_title('Packet Distribution by Protocol')
            
            if not flows_df.empty and 'protocol' in flows_df.columns:
                flow_protocol_counts = flows_df['protocol'].value_counts()
                
                axes[0, 1].bar(flow_protocol_counts.index, list(flow_protocol_counts.values))
                axes[0, 1].set_title('Flow Count by Protocol')
                axes[0, 1].set_xlabel('Protocol')
                axes[0, 1].set_ylabel('Number of Flows')
                axes[0, 1].tick_params(axis='x', rotation=45)
            else:
                axes[0, 1].text(0.5, 0.5, 'No flow data', ha='center', va='center')
                axes[0, 1].set_title('Flow Count by Protocol')
            
            l2_protocols = ['num_stp_frame', 'num_cdp_frame', 'num_arp_frame', 
                           'num_dhcp_frame', 'num_llc_frame', 'num_dtp_frame', 'num_isl_frame']
            
            if not flows_df.empty:
                l2_counts = {}
                for proto in l2_protocols:
                    if proto in flows_df.columns:
                        total = flows_df[proto].sum()
                        if total > 0:
                            l2_counts[proto.replace('num_', '').replace('_frame', '')] = total
                
                if l2_counts:
                    axes[0, 2].bar(list(l2_counts.keys()), list(l2_counts.values()))
                    axes[0, 2].set_title('Layer 2 Protocol Packet Counts')
                    axes[0, 2].set_xlabel('Protocol')
                    axes[0, 2].set_ylabel('Total Packets')
                    axes[0, 2].tick_params(axis='x', rotation=45)
                else:
                    axes[0, 2].text(0.5, 0.5, 'No Layer 2 data', ha='center', va='center')
                    axes[0, 2].set_title('Layer 2 Protocol Packet Counts')
            
            if not flows_df.empty and 'mean_frame_len' in flows_df.columns:
                frame_sizes = flows_df['mean_frame_len']
                frame_sizes = frame_sizes[(frame_sizes != -100) & (frame_sizes.notna())]
                if len(frame_sizes) > 0:
                    axes[1, 0].hist(frame_sizes, bins=50, alpha=0.7, edgecolor='black')
                    axes[1, 0].set_title('Frame Size Distribution')
                    axes[1, 0].set_xlabel('Mean Frame Length (bytes)')
                    axes[1, 0].set_ylabel('Number of Flows')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No frame size data', ha='center', va='center')
                    axes[1, 0].set_title('Frame Size Distribution')
            
            if not flows_df.empty and 'time_delta' in flows_df.columns:
                durations = flows_df['time_delta'].dropna()
                durations = durations[durations > 0]
                if len(durations) > 0:
                    axes[1, 1].hist(durations, bins=50, alpha=0.7, edgecolor='black')
                    axes[1, 1].set_title('Flow Duration Distribution')
                    axes[1, 1].set_xlabel('Duration (seconds)')
                    axes[1, 1].set_ylabel('Number of Flows')
                    axes[1, 1].set_yscale('log')
                else:
                    axes[1, 1].text(0.5, 0.5, 'No duration data', ha='center', va='center')
                    axes[1, 1].set_title('Flow Duration Distribution')
            
            if not flows_df.empty and 'label' in flows_df.columns:
                label_counts = flows_df['label'].value_counts()
                
                axes[1, 2].bar(label_counts.index, list(label_counts.values))
                axes[1, 2].set_title('Flow Labels Distribution')
                axes[1, 2].set_xlabel('Label')
                axes[1, 2].set_ylabel('Number of Flows')
                axes[1, 2].tick_params(axis='x', rotation=45)
                
                total_flows = len(flows_df)
                for i, (label, count) in enumerate(label_counts.items()):
                    percentage = (count / total_flows) * 100
                    axes[1, 2].text(i, count + max(label_counts.values) * 0.01, 
                                   f'{percentage:.1f}%', ha='center')
            else:
                axes[1, 2].text(0.5, 0.5, 'No label data', ha='center', va='center')
                axes[1, 2].set_title('Flow Labels Distribution')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"protocol_statistics_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Protocol statistics plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating protocol statistics plot: {e}")
            raise
    
    def create_feature_correlation_heatmap(self, flows_df: pd.DataFrame) -> str:
        """Create correlation heatmap of numeric features."""
        try:
            numeric_cols = flows_df.select_dtypes(include=[np.number]).columns
            
            dense_cols = []
            for col in numeric_cols:
                valid_data = flows_df[col][(flows_df[col] != 0) & (flows_df[col] != -100) & (flows_df[col].notna())]
                if len(valid_data) / len(flows_df) > 0.1:
                    dense_cols.append(col)
            
            if len(dense_cols) < 2:
                self.logger.warning("Not enough dense numeric columns for correlation analysis")
                return ""
            
            correlation_data = flows_df[dense_cols].replace(-100, np.nan)
            corr_matrix = correlation_data.corr()
            
            plt.figure(figsize=(20, 16))
            mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
            
            sns.heatmap(corr_matrix, mask=mask, annot=False, cmap='coolwarm', 
                       center=0, square=True, linewidths=0.1, cbar_kws={"shrink": .8})
            
            plt.title('Feature Correlation Heatmap', fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"feature_correlation_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Feature correlation heatmap saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating correlation heatmap: {e}")
            return ""
    
    def create_layer2_heatmap_analysis(self, flows_df: pd.DataFrame) -> str:
        """Create Layer 2 protocol heatmap analysis."""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(20, 16))
            fig.suptitle('Layer 2 Protocol Heatmap Analysis', fontsize=16, fontweight='bold')
            
            l2_protocol_cols = ['num_stp_frame', 'num_cdp_frame', 'num_arp_frame', 
                               'num_dhcp_frame', 'num_llc_frame', 'num_dtp_frame', 'num_isl_frame',
                               'num_lldp_frame', 'num_vtp_frame']
            
            if not flows_df.empty:
                available_l2_cols = [col for col in l2_protocol_cols if col in flows_df.columns and flows_df[col].sum() > 0]
                
                if len(available_l2_cols) >= 2:
                    l2_corr = flows_df[available_l2_cols].corr()
                    clean_names = [col.replace('num_', '').replace('_frame', '').upper() for col in available_l2_cols]
                    l2_corr.index = clean_names
                    l2_corr.columns = clean_names
                    
                    sns.heatmap(l2_corr, annot=True, cmap='RdYlBu_r', center=0, 
                               square=True, ax=axes[0, 0], fmt='.2f', cbar_kws={"shrink": .8})
                    axes[0, 0].set_title('Layer 2 Protocol Correlations')
                else:
                    axes[0, 0].text(0.5, 0.5, 'Insufficient L2 protocol data', ha='center', va='center')
                    axes[0, 0].set_title('Layer 2 Protocol Correlations')
            
            if not flows_df.empty:
                l2_feature_cols = []
                for prefix in ['stp_', 'cdp_', 'arp_', 'dhcp_', 'llc_', 'lldp_']:
                    prefix_cols = [col for col in flows_df.columns if col.startswith(prefix) 
                                  and flows_df[col].dtype in ['int64', 'float64'] and flows_df[col].sum() > 0]
                    l2_feature_cols.extend(prefix_cols[:5])
                
                if l2_feature_cols:
                    sample_size = min(50, len(flows_df))
                    sampled_flows = flows_df.sample(n=sample_size, random_state=42)
                    
                    feature_data = sampled_flows[l2_feature_cols].replace(-100, 0).fillna(0)
                    if len(feature_data.columns) > 0 and len(feature_data) > 0:
                        normalized_data = (feature_data - feature_data.min()) / (feature_data.max() - feature_data.min() + 1e-8)
                        
                        clean_cols = [col.replace('_', ' ').title() for col in normalized_data.columns]
                        normalized_data.columns = clean_cols
                        
                        sns.heatmap(normalized_data.T, cmap='viridis', ax=axes[0, 1], 
                                   cbar_kws={"shrink": .8}, yticklabels=True, xticklabels=False)
                        axes[0, 1].set_title('Layer 2 Feature Intensity (Sample)')
                        axes[0, 1].set_xlabel('Flow Samples')
                        axes[0, 1].set_ylabel('Features')
                    else:
                        axes[0, 1].text(0.5, 0.5, 'No L2 feature data', ha='center', va='center')
                        axes[0, 1].set_title('Layer 2 Feature Intensity')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No L2 features available', ha='center', va='center')
                    axes[0, 1].set_title('Layer 2 Feature Intensity')
            
            if not flows_df.empty:
                stat_combinations = {}
                
                if 'num_stp_frame' in flows_df.columns and 'num_cdp_frame' in flows_df.columns:
                    stp_total = flows_df['num_stp_frame'].sum()
                    cdp_total = flows_df['num_cdp_frame'].sum()
                    if stp_total + cdp_total > 0:
                        stat_combinations['STP/CDP Ratio'] = stp_total / (cdp_total + 1e-8)
                
                if 'num_arp_frame' in flows_df.columns and 'num_dhcp_frame' in flows_df.columns:
                    arp_total = flows_df['num_arp_frame'].sum()
                    dhcp_total = flows_df['num_dhcp_frame'].sum()
                    if arp_total + dhcp_total > 0:
                        stat_combinations['ARP/DHCP Ratio'] = arp_total / (dhcp_total + 1e-8)
                
                total_l2_packets = sum(flows_df[col].sum() for col in available_l2_cols if col in flows_df.columns)
                if total_l2_packets > 0:
                    for col in available_l2_cols:
                        if col in flows_df.columns:
                            protocol_name = col.replace('num_', '').replace('_frame', '').upper()
                            stat_combinations[f'{protocol_name} %'] = (flows_df[col].sum() / total_l2_packets) * 100
                
                if stat_combinations:
                    protocols = list(set([k.split()[0] for k in stat_combinations.keys()]))
                    metrics = list(set([' '.join(k.split()[1:]) for k in stat_combinations.keys() if len(k.split()) > 1]))
                    
                    if len(protocols) > 1:
                        heatmap_data = []
                        heatmap_index = []
                        for metric in ['%', 'Ratio']:
                            row = []
                            for protocol in protocols[:6]:
                                key = f"{protocol} {metric}"
                                if key in stat_combinations:
                                    row.append(stat_combinations[key])
                                else:
                                    row.append(0)
                            if any(x > 0 for x in row):
                                heatmap_data.append(row)
                                heatmap_index.append(metric)
                        
                        if heatmap_data:
                            heatmap_df = pd.DataFrame(heatmap_data, 
                                                    columns=protocols[:len(heatmap_data[0])], 
                                                    index=heatmap_index)
                            sns.heatmap(heatmap_df, annot=True, cmap='plasma', ax=axes[1, 0], 
                                       fmt='.2f', cbar_kws={"shrink": .8})
                            axes[1, 0].set_title('Protocol Statistical Combinations')
                        else:
                            axes[1, 0].text(0.5, 0.5, 'No statistical data', ha='center', va='center')
                            axes[1, 0].set_title('Protocol Statistical Combinations')
                    else:
                        axes[1, 0].text(0.5, 0.5, 'Insufficient protocols for comparison', ha='center', va='center')
                        axes[1, 0].set_title('Protocol Statistical Combinations')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No statistical combinations available', ha='center', va='center')
                    axes[1, 0].set_title('Protocol Statistical Combinations')
            
            if not flows_df.empty and 'src_mac_addr_vendor' in flows_df.columns:
                vendor_counts = flows_df['src_mac_addr_vendor'].value_counts().head(8)
                top_vendors = vendor_counts.index.tolist()
                
                if top_vendors and len(available_l2_cols) > 0:
                    vendor_protocol_matrix = []
                    for vendor in top_vendors:
                        vendor_flows = flows_df[flows_df['src_mac_addr_vendor'] == vendor]
                        row = []
                        for col in available_l2_cols[:6]:
                            if col in flows_df.columns:
                                row.append(vendor_flows[col].sum())
                            else:
                                row.append(0)
                        vendor_protocol_matrix.append(row)
                    
                    if vendor_protocol_matrix:
                        protocol_names = [col.replace('num_', '').replace('_frame', '').upper() 
                                        for col in available_l2_cols[:6]]
                        vendor_df = pd.DataFrame(vendor_protocol_matrix, 
                                               columns=protocol_names, 
                                               index=top_vendors)
                        
                        sns.heatmap(vendor_df, annot=True, cmap='YlOrRd', ax=axes[1, 1], 
                                   fmt='d', cbar_kws={"shrink": .8})
                        axes[1, 1].set_title('Vendor vs Protocol Activity')
                        axes[1, 1].set_xlabel('Protocols')
                        axes[1, 1].set_ylabel('MAC Vendors')
                    else:
                        axes[1, 1].text(0.5, 0.5, 'No vendor-protocol data', ha='center', va='center')
                        axes[1, 1].set_title('Vendor vs Protocol Activity')
                else:
                    axes[1, 1].text(0.5, 0.5, 'No vendor or protocol data', ha='center', va='center')
                    axes[1, 1].set_title('Vendor vs Protocol Activity')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_heatmap_analysis_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 heatmap analysis saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 heatmap analysis: {e}")
            return ""

    def create_layer2_analysis(self, flows_df: pd.DataFrame) -> str:
        """Create Layer 2 specific analysis plots."""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Layer 2 Protocol Analysis', fontsize=16, fontweight='bold')
            
            if not flows_df.empty and 'sum_stp_msg_age' in flows_df.columns and 'stp_age_div_max_age' in flows_df.columns:
                stp_flows = flows_df[flows_df['num_stp_frame'] > 0]
                if len(stp_flows) > 0:
                    valid_stp = stp_flows[(stp_flows['sum_stp_msg_age'] != -100) & (stp_flows['stp_age_div_max_age'] != -100)]
                    if len(valid_stp) > 0:
                        axes[0, 0].scatter(valid_stp['sum_stp_msg_age'], valid_stp['stp_age_div_max_age'], alpha=0.6)
                        axes[0, 0].set_title('STP Message Age Analysis')
                        axes[0, 0].set_xlabel('Total Message Age')
                        axes[0, 0].set_ylabel('Age/Max Age Ratio')
                    else:
                        axes[0, 0].text(0.5, 0.5, 'No valid STP data', ha='center', va='center')
                        axes[0, 0].set_title('STP Message Age Analysis')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No STP flows', ha='center', va='center')
                    axes[0, 0].set_title('STP Message Age Analysis')
            
            if not flows_df.empty:
                cdp_flows = flows_df[flows_df['num_cdp_frame'] > 0]
                if len(cdp_flows) > 0:
                    capability_cols = [col for col in flows_df.columns if 'cdp_capabilities_' in col and col.endswith(('router', 'switch', 'host', 'repeater'))]
                    if capability_cols:
                        capability_counts = {}
                        for col in capability_cols:
                            capability_name = col.replace('cdp_capabilities_', '')
                            capability_counts[capability_name] = cdp_flows[col].sum()
                        
                        axes[0, 1].bar(list(capability_counts.keys()), list(capability_counts.values()))
                        axes[0, 1].set_title('CDP Device Capabilities Distribution')
                        axes[0, 1].set_xlabel('Capability Type')
                        axes[0, 1].set_ylabel('Count')
                        axes[0, 1].tick_params(axis='x', rotation=45)
                    else:
                        axes[0, 1].text(0.5, 0.5, 'No CDP capability data', ha='center', va='center')
                        axes[0, 1].set_title('CDP Device Capabilities Distribution')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No CDP flows', ha='center', va='center')
                    axes[0, 1].set_title('CDP Device Capabilities Distribution')
            
            if not flows_df.empty:
                arp_flows = flows_df[flows_df['num_arp_frame'] > 0]
                if len(arp_flows) > 0 and 'arp_opcode' in flows_df.columns:
                    valid_arp = arp_flows[arp_flows['arp_opcode'] != -100]
                    if len(valid_arp) > 0:
                        arp_types = valid_arp['arp_opcode'].value_counts()
                        type_labels = {1: 'Request', 2: 'Reply', 3: 'RARP Request', 4: 'RARP Reply'}
                        
                        labels = [type_labels.get(t, f'Type {t}') for t in arp_types.index]
                        axes[1, 0].pie(list(arp_types.values), labels=labels, autopct='%1.1f%%', startangle=90)
                        axes[1, 0].set_title('ARP Operation Types')
                    else:
                        axes[1, 0].text(0.5, 0.5, 'No valid ARP data', ha='center', va='center')
                        axes[1, 0].set_title('ARP Operation Types')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No ARP flows', ha='center', va='center')
                    axes[1, 0].set_title('ARP Operation Types')
            
            if not flows_df.empty:
                dhcp_flows = flows_df[flows_df['num_dhcp_frame'] > 0]
                if len(dhcp_flows) > 0 and 'dhcp_message_type' in flows_df.columns:
                    valid_dhcp = dhcp_flows[dhcp_flows['dhcp_message_type'] != -100]
                    if len(valid_dhcp) > 0:
                        dhcp_types = valid_dhcp['dhcp_message_type'].value_counts()
                        type_labels = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 
                                      5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
                        
                        labels = [type_labels.get(t, f'Type {t}') for t in dhcp_types.index if t > 0]
                        values = [count for t, count in dhcp_types.items() if t > 0]
                        
                        if labels and values:
                            axes[1, 1].bar(labels, values)
                            axes[1, 1].set_title('DHCP Message Types')
                            axes[1, 1].set_xlabel('Message Type')
                            axes[1, 1].set_ylabel('Count')
                            axes[1, 1].tick_params(axis='x', rotation=45)
                        else:
                            axes[1, 1].text(0.5, 0.5, 'No DHCP message data', ha='center', va='center')
                            axes[1, 1].set_title('DHCP Message Types')
                    else:
                        axes[1, 1].text(0.5, 0.5, 'No valid DHCP data', ha='center', va='center')
                        axes[1, 1].set_title('DHCP Message Types')
                else:
                    axes[1, 1].text(0.5, 0.5, 'No DHCP flows', ha='center', va='center')
                    axes[1, 1].set_title('DHCP Message Types')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_analysis_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 analysis plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 analysis plot: {e}")
            return ""
    
    def create_flow_statistics_summary(self, flows_df: pd.DataFrame) -> str:
        """Create flow statistics summary plot."""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Flow Statistics Summary', fontsize=16, fontweight='bold')
            
            if not flows_df.empty and 'num_frame' in flows_df.columns:
                packet_counts = flows_df['num_frame'].dropna()
                if len(packet_counts) > 0:
                    axes[0, 0].hist(packet_counts, bins=50, alpha=0.7, edgecolor='black')
                    axes[0, 0].set_title('Packets per Flow Distribution')
                    axes[0, 0].set_xlabel('Number of Packets')
                    axes[0, 0].set_ylabel('Number of Flows')
                    axes[0, 0].set_yscale('log')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No packet count data', ha='center', va='center')
                    axes[0, 0].set_title('Packets per Flow Distribution')
            
            if not flows_df.empty and 'sum_frame_len' in flows_df.columns:
                flow_sizes = flows_df['sum_frame_len'].dropna()
                flow_sizes = flow_sizes[flow_sizes > 0]
                if len(flow_sizes) > 0:
                    axes[0, 1].hist(flow_sizes, bins=50, alpha=0.7, edgecolor='black')
                    axes[0, 1].set_title('Flow Size Distribution')
                    axes[0, 1].set_xlabel('Total Flow Size (bytes)')
                    axes[0, 1].set_ylabel('Number of Flows')
                    axes[0, 1].set_xscale('log')
                    axes[0, 1].set_yscale('log')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No flow size data', ha='center', va='center')
                    axes[0, 1].set_title('Flow Size Distribution')
            
            if not flows_df.empty and 'sum_frames_src_dst' in flows_df.columns and 'sum_frames_dst_src' in flows_df.columns:
                src_dst = flows_df['sum_frames_src_dst'].fillna(0)
                dst_src = flows_df['sum_frames_dst_src'].fillna(0)
                
                bidirectional_mask = (src_dst > 0) & (dst_src > 0)
                if bidirectional_mask.sum() > 0:
                    axes[1, 0].scatter(src_dst[bidirectional_mask], dst_src[bidirectional_mask], alpha=0.6)
                    axes[1, 0].set_title('Bidirectional Flow Analysis')
                    axes[1, 0].set_xlabel('Source → Destination (bytes)')
                    axes[1, 0].set_ylabel('Destination → Source (bytes)')
                    axes[1, 0].set_xscale('log')
                    axes[1, 0].set_yscale('log')
                    
                    max_val = max(src_dst[bidirectional_mask].max(), dst_src[bidirectional_mask].max())
                    axes[1, 0].plot([1, max_val], [1, max_val], 'r--', alpha=0.5, label='Equal traffic')
                    axes[1, 0].legend()
                else:
                    axes[1, 0].text(0.5, 0.5, 'No bidirectional flows', ha='center', va='center')
                    axes[1, 0].set_title('Bidirectional Flow Analysis')
            
            if not flows_df.empty:
                vendor_cols = ['src_mac_addr_vendor', 'dst_mac_addr_vendor']
                all_vendors = []
                
                for col in vendor_cols:
                    if col in flows_df.columns:
                        vendors = flows_df[col].dropna()
                        vendors = vendors[vendors != 'Unknown']
                        all_vendors.extend(vendors.tolist())
                
                if all_vendors:
                    vendor_counts = pd.Series(all_vendors).value_counts().head(10)
                    axes[1, 1].barh(range(len(vendor_counts)), list(vendor_counts.values))
                    axes[1, 1].set_yticks(range(len(vendor_counts)))
                    axes[1, 1].set_yticklabels(vendor_counts.index)
                    axes[1, 1].set_title('Top 10 MAC Address Vendors')
                    axes[1, 1].set_xlabel('Count')
                else:
                    axes[1, 1].text(0.5, 0.5, 'No vendor data', ha='center', va='center')
                    axes[1, 1].set_title('Top 10 MAC Address Vendors')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"flow_statistics_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Flow statistics plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating flow statistics plot: {e}")
            return ""
    
    def create_attack_analysis_plot(self, flows_df: pd.DataFrame) -> str:
        """Create attack-focused analysis plots."""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Attack Detection Analysis', fontsize=16, fontweight='bold')
            
            if not flows_df.empty and 'label' in flows_df.columns:
                attack_flows = flows_df[flows_df['label'] != 'Benign']
                
                if len(attack_flows) > 0:
                    attack_counts = attack_flows['label'].value_counts()
                    colors = plt.cm.Set3(np.linspace(0, 1, len(attack_counts)))
                    
                    axes[0, 0].pie(list(attack_counts.values), labels=attack_counts.index, 
                                  autopct='%1.1f%%', startangle=90, colors=colors)
                    axes[0, 0].set_title('Attack Type Distribution')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No attacks detected', ha='center', va='center')
                    axes[0, 0].set_title('Attack Type Distribution')
            
            if not flows_df.empty and 'label' in flows_df.columns:
                benign_flows = flows_df[flows_df['label'] == 'Benign']
                attack_flows = flows_df[flows_df['label'] != 'Benign']
                
                if len(benign_flows) > 0 and len(attack_flows) > 0:
                    if 'mean_frame_len' in flows_df.columns:
                        benign_frame_len = benign_flows['mean_frame_len'][(benign_flows['mean_frame_len'] != -100) & (benign_flows['mean_frame_len'].notna())]
                        attack_frame_len = attack_flows['mean_frame_len'][(attack_flows['mean_frame_len'] != -100) & (attack_flows['mean_frame_len'].notna())]
                        
                        if len(benign_frame_len) > 0 and len(attack_frame_len) > 0:
                            axes[0, 1].hist([benign_frame_len, attack_frame_len], 
                                           label=['Benign', 'Attack'], alpha=0.7, bins=30)
                        else:
                            axes[0, 1].text(0.5, 0.5, 'No valid frame length data', ha='center', va='center')
                        axes[0, 1].set_title('Frame Length: Benign vs Attack')
                        axes[0, 1].set_xlabel('Mean Frame Length (bytes)')
                        axes[0, 1].set_ylabel('Count')
                        axes[0, 1].legend()
                    else:
                        axes[0, 1].text(0.5, 0.5, 'No frame length data', ha='center', va='center')
                        axes[0, 1].set_title('Frame Length: Benign vs Attack')
                else:
                    axes[0, 1].text(0.5, 0.5, 'Insufficient data for comparison', ha='center', va='center')
                    axes[0, 1].set_title('Frame Length: Benign vs Attack')
            
            if not flows_df.empty and 'label' in flows_df.columns:
                attack_flows = flows_df[flows_df['label'] != 'Benign']
                if len(attack_flows) > 0:
                    protocol_cols = ['num_arp_frame', 'num_dhcp_frame', 'num_stp_frame', 'num_cdp_frame']
                    protocol_attack_stats = {}
                    
                    for col in protocol_cols:
                        if col in flows_df.columns:
                            protocol_name = col.replace('num_', '').replace('_frame', '').upper()
                            protocol_attack_stats[protocol_name] = attack_flows[col].sum()
                    
                    if protocol_attack_stats:
                        axes[1, 0].bar(list(protocol_attack_stats.keys()), list(protocol_attack_stats.values()))
                        axes[1, 0].set_title('Protocol Usage in Attack Flows')
                        axes[1, 0].set_xlabel('Protocol')
                        axes[1, 0].set_ylabel('Total Packets in Attacks')
                    else:
                        axes[1, 0].text(0.5, 0.5, 'No protocol data in attacks', ha='center', va='center')
                        axes[1, 0].set_title('Protocol Usage in Attack Flows')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No attack flows', ha='center', va='center')
                    axes[1, 0].set_title('Protocol Usage in Attack Flows')
            
            if not flows_df.empty and 'label' in flows_df.columns and 'time_delta' in flows_df.columns:
                benign_flows = flows_df[flows_df['label'] == 'Benign']
                attack_flows = flows_df[flows_df['label'] != 'Benign']
                
                if len(benign_flows) > 0 and len(attack_flows) > 0:
                    benign_duration = benign_flows['time_delta'].dropna()
                    attack_duration = attack_flows['time_delta'].dropna()
                    
                    benign_duration = benign_duration[benign_duration > 0]
                    attack_duration = attack_duration[attack_duration > 0]
                    
                    if len(benign_duration) > 0 and len(attack_duration) > 0:
                        axes[1, 1].boxplot([benign_duration, attack_duration], 
                                          labels=['Benign', 'Attack'])
                        axes[1, 1].set_title('Flow Duration: Benign vs Attack')
                        axes[1, 1].set_ylabel('Duration (seconds)')
                        axes[1, 1].set_yscale('log')
                    else:
                        axes[1, 1].text(0.5, 0.5, 'No duration data', ha='center', va='center')
                        axes[1, 1].set_title('Flow Duration: Benign vs Attack')
                else:
                    axes[1, 1].text(0.5, 0.5, 'Insufficient data for comparison', ha='center', va='center')
                    axes[1, 1].set_title('Flow Duration: Benign vs Attack')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"attack_analysis_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Attack analysis plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating attack analysis plot: {e}")
            return ""
    
    def generate_statistics_csv(self, flows_df: pd.DataFrame, processing_stats: Dict[str, Any]) -> str:
        """Generate comprehensive statistics CSV file."""
        try:
            stats_data = []
            
            stats_data.append(['Total Flows', len(flows_df)])
            stats_data.append(['Total Packets', processing_stats.get('total_packets', 0)])
            
            protocol_stats = processing_stats.get('protocol_stats', {})
            for protocol, count in protocol_stats.items():
                stats_data.append([f'{protocol} Packets', count])
            
            if not flows_df.empty:
                numeric_cols = ['num_frame', 'sum_frame_len', 'time_delta', 'mean_frame_len']
                for col in numeric_cols:
                    if col in flows_df.columns:
                        col_data = flows_df[col].dropna()
                        if len(col_data) > 0:
                            stats_data.append([f'{col}_mean', col_data.mean()])
                            stats_data.append([f'{col}_std', col_data.std()])
                            stats_data.append([f'{col}_max', col_data.max()])
                            stats_data.append([f'{col}_min', col_data.min()])
                
                l2_protocols = ['num_stp_frame', 'num_cdp_frame', 'num_arp_frame', 
                               'num_dhcp_frame', 'num_llc_frame', 'num_dtp_frame', 'num_isl_frame']
                
                for proto in l2_protocols:
                    if proto in flows_df.columns:
                        total = flows_df[proto].sum()
                        flows_with_proto = (flows_df[proto] > 0).sum()
                        stats_data.append([f'{proto}_total_packets', total])
                        stats_data.append([f'{proto}_flows_count', flows_with_proto])
                
                if 'label' in flows_df.columns:
                    label_counts = flows_df['label'].value_counts()
                    for label, count in label_counts.items():
                        percentage = (count / len(flows_df)) * 100
                        stats_data.append([f'label_{label}_count', count])
                        stats_data.append([f'label_{label}_percentage', percentage])
            
            stats_df = pd.DataFrame(stats_data, columns=['Statistic', 'Value'])
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            stats_file = self.output_dir / f"analysis_statistics_{timestamp}.csv"
            stats_df.to_csv(stats_file, index=False)
            
            self.logger.info(f"Statistics CSV saved: {stats_file}")
            return str(stats_file)
            
        except Exception as e:
            self.logger.error(f"Error creating statistics CSV: {e}")
            return ""
    
    def create_layer2_protocol_distribution_plot(self, flows_df: pd.DataFrame) -> str:
        """Create Layer 2 protocol distribution plot specifically for folder completion."""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Layer 2 Protocol Distribution Analysis', fontsize=16, fontweight='bold')
            
            l2_protocols = ['num_stp_frame', 'num_cdp_frame', 'num_arp_frame', 
                           'num_dhcp_frame', 'num_llc_frame', 'num_dtp_frame', 'num_isl_frame', 'num_lldp_frame']
            
            if not flows_df.empty:
                l2_counts = {}
                for proto in l2_protocols:
                    if proto in flows_df.columns:
                        total = flows_df[proto].sum()
                        if total > 0:
                            l2_counts[proto.replace('num_', '').replace('_frame', '').upper()] = total
                
                if l2_counts:
                    axes[0, 0].pie(list(l2_counts.values()), labels=list(l2_counts.keys()), 
                                  autopct='%1.1f%%', startangle=90)
                    axes[0, 0].set_title('Layer 2 Protocol Packet Distribution')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No Layer 2 data', ha='center', va='center')
                    axes[0, 0].set_title('Layer 2 Protocol Packet Distribution')
            
            if not flows_df.empty:
                protocol_flow_counts = {}
                for proto in l2_protocols:
                    if proto in flows_df.columns:
                        flows_with_proto = (flows_df[proto] > 0).sum()
                        if flows_with_proto > 0:
                            protocol_flow_counts[proto.replace('num_', '').replace('_frame', '').upper()] = flows_with_proto
                
                if protocol_flow_counts:
                    axes[0, 1].bar(list(protocol_flow_counts.keys()), list(protocol_flow_counts.values()))
                    axes[0, 1].set_title('Layer 2 Protocol Flow Count')
                    axes[0, 1].set_xlabel('Protocol')
                    axes[0, 1].set_ylabel('Number of Flows')
                    axes[0, 1].tick_params(axis='x', rotation=45)
                else:
                    axes[0, 1].text(0.5, 0.5, 'No Layer 2 flows', ha='center', va='center')
                    axes[0, 1].set_title('Layer 2 Protocol Flow Count')
            
            if not flows_df.empty:
                percent_cols = [col for col in flows_df.columns if col.startswith('percent_') and col.endswith('_frame')]
                if percent_cols:
                    sample_flows = flows_df[flows_df[percent_cols].sum(axis=1) > 0].head(20)
                    if len(sample_flows) > 0:
                        percent_data = sample_flows[percent_cols]
                        percent_data.columns = [col.replace('percent_', '').replace('_frame', '').upper() for col in percent_data.columns]
                        
                        percent_data.plot(kind='bar', stacked=True, ax=axes[1, 0], figsize=(10, 6))
                        axes[1, 0].set_title('Protocol Percentage Distribution (Sample Flows)')
                        axes[1, 0].set_xlabel('Flow Index')
                        axes[1, 0].set_ylabel('Percentage')
                        axes[1, 0].legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                    else:
                        axes[1, 0].text(0.5, 0.5, 'No protocol percentages', ha='center', va='center')
                        axes[1, 0].set_title('Protocol Percentage Distribution')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No percentage data', ha='center', va='center')
                    axes[1, 0].set_title('Protocol Percentage Distribution')
            
            if not flows_df.empty and l2_counts:
                total_l2_packets = sum(l2_counts.values())
                total_flows = len(flows_df)
                l2_flows = sum((flows_df[proto] > 0).sum() for proto in l2_protocols if proto in flows_df.columns)
                
                summary_data = [
                    ['Total L2 Packets', total_l2_packets],
                    ['Total Flows', total_flows],
                    ['L2 Active Flows', l2_flows],
                    ['L2 Activity %', (l2_flows / total_flows * 100) if total_flows > 0 else 0]
                ]
                
                axes[1, 1].axis('tight')
                axes[1, 1].axis('off')
                table = axes[1, 1].table(cellText=[[item[0], f"{item[1]:,.1f}" if isinstance(item[1], float) else f"{item[1]:,}"] for item in summary_data],
                                        colLabels=['Metric', 'Value'],
                                        cellLoc='center',
                                        loc='center')
                table.auto_set_font_size(False)
                table.set_fontsize(12)
                table.scale(1.2, 1.5)
                axes[1, 1].set_title('Layer 2 Activity Summary')
            else:
                axes[1, 1].text(0.5, 0.5, 'No data for summary', ha='center', va='center')
                axes[1, 1].set_title('Layer 2 Activity Summary')
            
            plt.tight_layout()
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_protocol_distribution_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 protocol distribution plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 protocol distribution plot: {e}")
            return ""

    def create_all_plots(self, flows_df: pd.DataFrame, processing_stats: Dict[str, Any]) -> List[str]:
        """Create all available plots and return list of file paths."""
        plot_files = []
        
        try:
            protocol_plot = self.create_protocol_statistics(flows_df, processing_stats)
            if protocol_plot:
                plot_files.append(protocol_plot)
            
            layer2_plot = self.create_layer2_analysis(flows_df)
            if layer2_plot:
                plot_files.append(layer2_plot)
                
            layer2_dist_plot = self.create_layer2_protocol_distribution_plot(flows_df)
            if layer2_dist_plot:
                plot_files.append(layer2_dist_plot)
            
            layer2_heatmap = self.create_layer2_heatmap_analysis(flows_df)
            if layer2_heatmap:
                plot_files.append(layer2_heatmap)
            
            flow_plot = self.create_flow_statistics_summary(flows_df)
            if flow_plot:
                plot_files.append(flow_plot)
            
            attack_plot = self.create_attack_analysis_plot(flows_df)
            if attack_plot:
                plot_files.append(attack_plot)
            
            if len(flows_df) > 10:
                corr_plot = self.create_feature_correlation_heatmap(flows_df)
                if corr_plot:
                    plot_files.append(corr_plot)
            
            stats_csv = self.generate_statistics_csv(flows_df, processing_stats)
            if stats_csv:
                plot_files.append(stats_csv)
            
            self.logger.info(f"Created {len(plot_files)} visualization files")
            
        except Exception as e:
            self.logger.error(f"Error creating plots: {e}")
        
        return plot_files