"""
Layer 2-only plotting and visualization module for --justlayertwo mode.
Creates specialized charts for MAC addresses, Layer 2 protocols, and frame analysis.
"""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging


class Layer2OnlyPlotter:
    """
    Specialized visualization system for Layer 2-only analysis results.
    Creates comprehensive plots focused on MAC addresses and Layer 2 protocols.
    """
    
    def __init__(self, output_dir: str = "Results"):
        """
        Initialize Layer 2-only plotter.
        
        Args:
            output_dir: Directory to save plots
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Set plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        self.logger = logging.getLogger(__name__)
    
    def create_mac_address_analysis(self, flows_df: pd.DataFrame) -> str:
        """Create comprehensive MAC address analysis plots."""
        try:
            fig, axes = plt.subplots(2, 3, figsize=(20, 12))
            fig.suptitle('Layer 2 MAC Address Analysis', fontsize=16, fontweight='bold')
            
            # 1. MAC vendor distribution
            if not flows_df.empty and 'src_mac_vendor' in flows_df.columns:
                vendor_counts = flows_df['src_mac_vendor'].value_counts().head(10)
                # Filter out -100 missing values
                vendor_counts = vendor_counts[vendor_counts.index != str(-100)]
                
                if len(vendor_counts) > 0:
                    axes[0, 0].barh(range(len(vendor_counts)), list(vendor_counts.values))
                    axes[0, 0].set_yticks(range(len(vendor_counts)))
                    axes[0, 0].set_yticklabels(vendor_counts.index)
                    axes[0, 0].set_title('Top MAC Vendors')
                    axes[0, 0].set_xlabel('Flow Count')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No vendor data available', ha='center', va='center')
                    axes[0, 0].set_title('Top MAC Vendors')
            
            # 2. MAC address diversity analysis
            if not flows_df.empty:
                src_diversity = flows_df.get('unique_src_mac_count', pd.Series([0]))
                dst_diversity = flows_df.get('unique_dst_mac_count', pd.Series([0]))
                
                # Filter out -100 values
                src_diversity = src_diversity[src_diversity != -100]
                dst_diversity = dst_diversity[dst_diversity != -100]
                
                if len(src_diversity) > 0 and len(dst_diversity) > 0:
                    axes[0, 1].scatter(src_diversity, dst_diversity, alpha=0.6)
                    axes[0, 1].set_title('MAC Address Diversity Analysis')
                    axes[0, 1].set_xlabel('Unique Source MACs per Flow')
                    axes[0, 1].set_ylabel('Unique Destination MACs per Flow')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No diversity data available', ha='center', va='center')
                    axes[0, 1].set_title('MAC Address Diversity Analysis')
            
            # 3. Traffic type distribution (Unicast vs Multicast vs Broadcast)
            if not flows_df.empty:
                traffic_types = {}
                if 'unicast_packet_count' in flows_df.columns:
                    unicast_total = flows_df['unicast_packet_count'].sum()
                    traffic_types['Unicast'] = unicast_total if unicast_total != -100 else 0
                
                if 'multicast_packet_count' in flows_df.columns:
                    multicast_total = flows_df['multicast_packet_count'].sum()
                    traffic_types['Multicast'] = multicast_total if multicast_total != -100 else 0
                
                if 'broadcast_packet_count' in flows_df.columns:
                    broadcast_total = flows_df['broadcast_packet_count'].sum()
                    traffic_types['Broadcast'] = broadcast_total if broadcast_total != -100 else 0
                
                if traffic_types and sum(traffic_types.values()) > 0:
                    axes[0, 2].pie(list(traffic_types.values()), labels=list(traffic_types.keys()), 
                                  autopct='%1.1f%%', startangle=90)
                    axes[0, 2].set_title('Traffic Type Distribution')
                else:
                    axes[0, 2].text(0.5, 0.5, 'No traffic type data', ha='center', va='center')
                    axes[0, 2].set_title('Traffic Type Distribution')
            
            # 4. Frame size distribution
            if not flows_df.empty and 'mean_frame_size' in flows_df.columns:
                frame_sizes = flows_df['mean_frame_size']
                # Filter out -100 missing values
                frame_sizes = frame_sizes[(frame_sizes != -100) & (frame_sizes.notna())]
                
                if len(frame_sizes) > 0:
                    axes[1, 0].hist(frame_sizes, bins=30, alpha=0.7, edgecolor='black')
                    axes[1, 0].set_title('Frame Size Distribution')
                    axes[1, 0].set_xlabel('Mean Frame Size (bytes)')
                    axes[1, 0].set_ylabel('Number of Flows')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No frame size data', ha='center', va='center')
                    axes[1, 0].set_title('Frame Size Distribution')
            
            # 5. Flow duration analysis
            if not flows_df.empty and 'flow_duration' in flows_df.columns:
                durations = flows_df['flow_duration']
                # Filter out -100 missing values and zero durations
                durations = durations[(durations != -100) & (durations > 0) & (durations.notna())]
                
                if len(durations) > 0:
                    axes[1, 1].hist(durations, bins=30, alpha=0.7, edgecolor='black')
                    axes[1, 1].set_title('Flow Duration Distribution')
                    axes[1, 1].set_xlabel('Duration (seconds)')
                    axes[1, 1].set_ylabel('Number of Flows')
                    axes[1, 1].set_yscale('log')
                else:
                    axes[1, 1].text(0.5, 0.5, 'No duration data', ha='center', va='center')
                    axes[1, 1].set_title('Flow Duration Distribution')
            
            # 6. Attack indicators
            if not flows_df.empty:
                indicators = {}
                
                if 'suspicious_mac_changes' in flows_df.columns:
                    suspicious_count = flows_df['suspicious_mac_changes'].sum()
                    indicators['Suspicious MAC Changes'] = suspicious_count if suspicious_count != -100 else 0
                
                if 'excessive_broadcast_ratio' in flows_df.columns:
                    excessive_broadcast = flows_df['excessive_broadcast_ratio'].sum() 
                    indicators['Excessive Broadcasts'] = excessive_broadcast if excessive_broadcast != -100 else 0
                
                if 'has_vlan_traffic' in flows_df.columns:
                    vlan_flows = flows_df['has_vlan_traffic'].sum()
                    indicators['VLAN Tagged Flows'] = vlan_flows if vlan_flows != -100 else 0
                
                if indicators and any(v > 0 for v in indicators.values()):
                    axes[1, 2].bar(list(indicators.keys()), list(indicators.values()))
                    axes[1, 2].set_title('Layer 2 Security Indicators')
                    axes[1, 2].set_ylabel('Count')
                    axes[1, 2].tick_params(axis='x', rotation=45)
                else:
                    axes[1, 2].text(0.5, 0.5, 'No security indicators detected', ha='center', va='center')
                    axes[1, 2].set_title('Layer 2 Security Indicators')
            
            plt.tight_layout()
            
            # Save plot
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_mac_analysis_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 MAC analysis plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 MAC analysis plot: {e}")
            return ""
    
    def create_layer2_protocol_analysis(self, flows_df: pd.DataFrame) -> str:
        """Create Layer 2 protocol-specific analysis plots."""
        try:
            fig, axes = plt.subplots(2, 3, figsize=(20, 12))
            fig.suptitle('Layer 2 Protocol Analysis', fontsize=16, fontweight='bold')
            
            # 1. Layer 2 protocol distribution
            l2_protocols = ['arp_count', 'stp_count', 'cdp_count', 'dhcp_count', 
                          'llc_count', 'isl_count', 'lldp_count', 'dtp_count']
            
            if not flows_df.empty:
                protocol_totals = {}
                for proto in l2_protocols:
                    if proto in flows_df.columns:
                        total = flows_df[proto].sum()
                        if total > 0 and total != -100:
                            protocol_name = proto.replace('_count', '').upper()
                            protocol_totals[protocol_name] = total
                
                if protocol_totals:
                    axes[0, 0].pie(list(protocol_totals.values()), labels=list(protocol_totals.keys()),
                                  autopct='%1.1f%%', startangle=90)
                    axes[0, 0].set_title('Layer 2 Protocol Distribution')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No Layer 2 protocol data', ha='center', va='center')
                    axes[0, 0].set_title('Layer 2 Protocol Distribution')
            
            # 2. Protocol diversity per flow
            if not flows_df.empty and 'active_protocol_count' in flows_df.columns:
                diversity = flows_df['active_protocol_count']
                # Filter out -100 values
                diversity = diversity[diversity != -100]
                
                if len(diversity) > 0:
                    diversity_counts = diversity.value_counts().sort_index()
                    axes[0, 1].bar(diversity_counts.index, diversity_counts.values)
                    axes[0, 1].set_title('Protocol Diversity per Flow')
                    axes[0, 1].set_xlabel('Number of Active Protocols')
                    axes[0, 1].set_ylabel('Number of Flows')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No protocol diversity data', ha='center', va='center')
                    axes[0, 1].set_title('Protocol Diversity per Flow')
            
            # 3. ARP vs DHCP activity comparison
            if not flows_df.empty:
                arp_flows = flows_df.get('arp_count', pd.Series([0]))
                dhcp_flows = flows_df.get('dhcp_count', pd.Series([0]))
                
                # Filter out -100 values
                arp_flows = arp_flows[arp_flows != -100]
                dhcp_flows = dhcp_flows[dhcp_flows != -100]
                
                if len(arp_flows) > 0 and len(dhcp_flows) > 0:
                    # Only plot flows that have both protocols
                    combined_data = pd.DataFrame({'ARP': arp_flows, 'DHCP': dhcp_flows}).fillna(0)
                    both_active = combined_data[(combined_data['ARP'] > 0) | (combined_data['DHCP'] > 0)]
                    
                    if len(both_active) > 0:
                        axes[0, 2].scatter(both_active['ARP'], both_active['DHCP'], alpha=0.6)
                        axes[0, 2].set_title('ARP vs DHCP Activity')
                        axes[0, 2].set_xlabel('ARP Packets per Flow')
                        axes[0, 2].set_ylabel('DHCP Packets per Flow')
                    else:
                        axes[0, 2].text(0.5, 0.5, 'No ARP/DHCP correlation data', ha='center', va='center')
                        axes[0, 2].set_title('ARP vs DHCP Activity')
                else:
                    axes[0, 2].text(0.5, 0.5, 'No ARP/DHCP data available', ha='center', va='center')
                    axes[0, 2].set_title('ARP vs DHCP Activity')
            
            # 4. VLAN analysis
            if not flows_df.empty and 'unique_vlan_count' in flows_df.columns:
                vlan_counts = flows_df['unique_vlan_count']
                # Filter out -100 values
                vlan_counts = vlan_counts[vlan_counts != -100]
                
                if len(vlan_counts) > 0 and vlan_counts.sum() > 0:
                    vlan_distribution = vlan_counts.value_counts().sort_index()
                    axes[1, 0].bar(vlan_distribution.index, vlan_distribution.values)
                    axes[1, 0].set_title('VLAN Diversity per Flow')
                    axes[1, 0].set_xlabel('Number of VLANs per Flow')
                    axes[1, 0].set_ylabel('Number of Flows')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No VLAN data available', ha='center', va='center')
                    axes[1, 0].set_title('VLAN Diversity per Flow')
            
            # 5. Frame size categories
            if not flows_df.empty:
                frame_categories = {}
                if 'jumbo_frame_count' in flows_df.columns:
                    jumbo_total = flows_df['jumbo_frame_count'].sum()
                    frame_categories['Jumbo (>1500)'] = jumbo_total if jumbo_total != -100 else 0
                
                if 'small_frame_count' in flows_df.columns:
                    small_total = flows_df['small_frame_count'].sum()
                    frame_categories['Small (<64)'] = small_total if small_total != -100 else 0
                
                if 'normal_frame_count' in flows_df.columns:
                    normal_total = flows_df['normal_frame_count'].sum()
                    frame_categories['Normal (64-1500)'] = normal_total if normal_total != -100 else 0
                
                if frame_categories and sum(frame_categories.values()) > 0:
                    axes[1, 1].bar(list(frame_categories.keys()), list(frame_categories.values()))
                    axes[1, 1].set_title('Frame Size Categories')
                    axes[1, 1].set_ylabel('Total Packets')
                    axes[1, 1].tick_params(axis='x', rotation=45)
                else:
                    axes[1, 1].text(0.5, 0.5, 'No frame category data', ha='center', va='center')
                    axes[1, 1].set_title('Frame Size Categories')
            
            # 6. Attack label distribution (if available)
            if not flows_df.empty and 'label' in flows_df.columns:
                label_counts = flows_df['label'].value_counts()
                
                # Create color map for attack types
                colors = ['green' if label == 'Benign' else 'red' for label in label_counts.index]
                
                axes[1, 2].bar(label_counts.index, label_counts.values, color=colors, alpha=0.7)
                axes[1, 2].set_title('Layer 2 Attack Labels')
                axes[1, 2].set_xlabel('Label')
                axes[1, 2].set_ylabel('Flow Count')
                axes[1, 2].tick_params(axis='x', rotation=45)
                
                # Add percentages
                total = len(flows_df)
                for i, (label, count) in enumerate(label_counts.items()):
                    percentage = (count / total) * 100
                    axes[1, 2].text(i, count + max(label_counts.values) * 0.01,
                                   f'{percentage:.1f}%', ha='center', fontsize=10)
            else:
                axes[1, 2].text(0.5, 0.5, 'No label data available', ha='center', va='center')
                axes[1, 2].set_title('Layer 2 Attack Labels')
            
            plt.tight_layout()
            
            # Save plot
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_protocol_analysis_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 protocol analysis plot saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 protocol analysis plot: {e}")
            return ""
    
    def create_layer2_correlation_heatmap(self, flows_df: pd.DataFrame) -> str:
        """Create Layer 2 feature correlation heatmap."""
        try:
            # Select Layer 2 relevant numeric columns
            l2_numeric_cols = []
            
            # Protocol counts
            protocol_cols = ['arp_count', 'stp_count', 'cdp_count', 'dhcp_count', 
                           'llc_count', 'isl_count', 'lldp_count', 'dtp_count']
            l2_numeric_cols.extend([col for col in protocol_cols if col in flows_df.columns])
            
            # MAC and frame features
            frame_cols = ['num_packets', 'flow_duration', 'mean_frame_size', 'total_bytes',
                         'unique_src_mac_count', 'unique_dst_mac_count', 'mac_address_diversity',
                         'multicast_packet_count', 'broadcast_packet_count', 'unicast_packet_count']
            l2_numeric_cols.extend([col for col in frame_cols if col in flows_df.columns])
            
            # Quality metrics
            quality_cols = ['active_protocol_count', 'protocol_diversity_ratio', 'vlan_packet_count',
                           'unique_vlan_count', 'jumbo_frame_count', 'small_frame_count']
            l2_numeric_cols.extend([col for col in quality_cols if col in flows_df.columns])
            
            if len(l2_numeric_cols) < 3:
                self.logger.warning("Not enough Layer 2 numeric columns for correlation analysis")
                return ""
            
            # Filter out -100 values and calculate correlation
            correlation_data = flows_df[l2_numeric_cols].replace(-100, np.nan)
            
            # Remove columns with all NaN values
            correlation_data = correlation_data.dropna(axis=1, how='all')
            
            if len(correlation_data.columns) < 3:
                self.logger.warning("Not enough valid data for Layer 2 correlation analysis")
                return ""
            
            corr_matrix = correlation_data.corr()
            
            # Create heatmap
            plt.figure(figsize=(16, 12))
            mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
            
            sns.heatmap(corr_matrix, mask=mask, annot=False, cmap='RdBu_r',
                       center=0, square=True, linewidths=0.1, cbar_kws={"shrink": .8})
            
            plt.title('Layer 2 Feature Correlation Heatmap', fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            # Save plot
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            plot_file = self.output_dir / f"layer2_correlation_heatmap_{timestamp}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Layer 2 correlation heatmap saved: {plot_file}")
            return str(plot_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 correlation heatmap: {e}")
            return ""
    
    def generate_layer2_statistics_csv(self, flows_df: pd.DataFrame) -> str:
        """Generate Layer 2-specific statistics CSV file."""
        try:
            stats_data = []
            
            # Basic Layer 2 statistics
            stats_data.append(['Total Layer 2 Flows', len(flows_df)])
            
            if not flows_df.empty:
                # Protocol statistics
                protocol_cols = ['arp_count', 'stp_count', 'cdp_count', 'dhcp_count', 
                               'llc_count', 'isl_count', 'lldp_count', 'dtp_count']
                
                for col in protocol_cols:
                    if col in flows_df.columns:
                        total_packets = flows_df[col].sum()
                        active_flows = (flows_df[col] > 0).sum()
                        protocol_name = col.replace('_count', '').upper()
                        
                        stats_data.append([f'{protocol_name}_total_packets', total_packets if total_packets != -100 else 0])
                        stats_data.append([f'{protocol_name}_active_flows', active_flows])
                
                # MAC address statistics
                if 'unique_src_mac_count' in flows_df.columns:
                    total_unique_src_macs = flows_df['unique_src_mac_count'].sum()
                    stats_data.append(['Total_unique_source_MACs', total_unique_src_macs if total_unique_src_macs != -100 else 0])
                
                if 'unique_dst_mac_count' in flows_df.columns:
                    total_unique_dst_macs = flows_df['unique_dst_mac_count'].sum()
                    stats_data.append(['Total_unique_destination_MACs', total_unique_dst_macs if total_unique_dst_macs != -100 else 0])
                
                # Traffic type statistics
                traffic_types = ['unicast_packet_count', 'multicast_packet_count', 'broadcast_packet_count']
                for traffic_type in traffic_types:
                    if traffic_type in flows_df.columns:
                        total = flows_df[traffic_type].sum()
                        stats_data.append([traffic_type.replace('_packet_count', '_total'), total if total != -100 else 0])
                
                # Frame size statistics
                if 'mean_frame_size' in flows_df.columns:
                    frame_sizes = flows_df['mean_frame_size']
                    valid_sizes = frame_sizes[(frame_sizes != -100) & (frame_sizes.notna())]
                    if len(valid_sizes) > 0:
                        stats_data.append(['Mean_frame_size_overall', valid_sizes.mean()])
                        stats_data.append(['Max_frame_size', valid_sizes.max()])
                        stats_data.append(['Min_frame_size', valid_sizes.min()])
                
                # VLAN statistics
                if 'vlan_packet_count' in flows_df.columns:
                    vlan_packets = flows_df['vlan_packet_count'].sum()
                    stats_data.append(['Total_VLAN_tagged_packets', vlan_packets if vlan_packets != -100 else 0])
                
                # Attack label statistics (if available)
                if 'label' in flows_df.columns:
                    label_counts = flows_df['label'].value_counts()
                    for label, count in label_counts.items():
                        percentage = (count / len(flows_df)) * 100
                        stats_data.append([f'Label_{label}_count', count])
                        stats_data.append([f'Label_{label}_percentage', percentage])
            
            # Create DataFrame and save
            stats_df = pd.DataFrame(stats_data, columns=['Statistic', 'Value'])
            
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            stats_file = self.output_dir / f"layer2_statistics_{timestamp}.csv"
            stats_df.to_csv(stats_file, index=False)
            
            self.logger.info(f"Layer 2 statistics CSV saved: {stats_file}")
            return str(stats_file)
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 statistics CSV: {e}")
            return ""
    
    def create_all_layer2_plots(self, flows_df: pd.DataFrame) -> List[str]:
        """Create all Layer 2 visualization plots and return file paths."""
        plot_files = []
        
        try:
            # MAC address analysis
            mac_plot = self.create_mac_address_analysis(flows_df)
            if mac_plot:
                plot_files.append(mac_plot)
            
            # Protocol analysis  
            protocol_plot = self.create_layer2_protocol_analysis(flows_df)
            if protocol_plot:
                plot_files.append(protocol_plot)
            
            # Correlation heatmap (if enough data)
            if len(flows_df) > 10:
                corr_plot = self.create_layer2_correlation_heatmap(flows_df)
                if corr_plot:
                    plot_files.append(corr_plot)
            
            # Statistics CSV
            stats_csv = self.generate_layer2_statistics_csv(flows_df)
            if stats_csv:
                plot_files.append(stats_csv)
            
            self.logger.info(f"Created {len(plot_files)} Layer 2 visualization files")
            
        except Exception as e:
            self.logger.error(f"Error creating Layer 2 plots: {e}")
        
        return plot_files