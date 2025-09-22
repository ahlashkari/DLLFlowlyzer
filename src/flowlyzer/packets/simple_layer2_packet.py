"""Simplified Layer 2 packet analyzer that avoids all subscriptable operations."""

from .base_packet import BasePacket
from .fixed_layer2_packet import MISSING_VALUE
from scapy.all import Packet
import logging


class SimpleLayer2Packet(BasePacket):
    
    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self.logger = logging.getLogger(__name__)
        self._extract_safe_features()
    
    def _extract_safe_features(self):
        """Extract features with completely safe operations - no subscripting."""
        try:
            # Basic frame info
            self.features.update({
                'frame_len': len(self.packet),
                'frame_number': self.frame_number,
                'timestamp': float(self.packet.time) if hasattr(self.packet, 'time') else self.timestamp
            })
            
            # Safe MAC extraction
            self._safe_extract_mac()
            
            # Safe protocol detection
            self._safe_extract_protocols()
            
        except Exception as e:
            self.logger.debug(f"Error in safe feature extraction: {e}")
            self._set_all_defaults()
    
    def _safe_extract_mac(self):
        """Safely extract MAC addresses without any subscripting."""
        try:
            if self.packet.haslayer('Ether'):
                eth = self.packet.getlayer('Ether')
                src_mac = str(eth.src) if hasattr(eth, 'src') else str(MISSING_VALUE)
                dst_mac = str(eth.dst) if hasattr(eth, 'dst') else str(MISSING_VALUE)
                eth_type = int(eth.type) if hasattr(eth, 'type') else MISSING_VALUE
                
                self.features.update({
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'eth_type': eth_type
                })
                
                # Safe MAC analysis
                self._analyze_mac_safe(src_mac, dst_mac)
            else:
                self._set_default_mac_features()
        except Exception as e:
            self.logger.debug(f"MAC extraction error: {e}")
            self._set_default_mac_features()
    
    def _analyze_mac_safe(self, src_mac, dst_mac):
        """Analyze MAC addresses safely without subscripting."""
        try:
            # Process source MAC
            if src_mac != str(MISSING_VALUE):
                src_parts = src_mac.split(':')
                if len(src_parts) >= 3:
                    oui = ':'.join(src_parts[0:3])
                    vendor = self._get_vendor_safe(oui)
                    is_multicast = self._is_multicast_safe(src_parts)
                    is_broadcast = (src_mac.lower() == 'ff:ff:ff:ff:ff:ff')
                    is_local = self._is_local_safe(src_parts)
                else:
                    oui = str(MISSING_VALUE)
                    vendor = str(MISSING_VALUE)
                    is_multicast = MISSING_VALUE
                    is_broadcast = MISSING_VALUE
                    is_local = MISSING_VALUE
                
                self.features.update({
                    'src_mac_oui': oui,
                    'src_mac_vendor': vendor,
                    'src_mac_is_multicast': is_multicast,
                    'src_mac_is_broadcast': is_broadcast,
                    'src_mac_is_local': is_local
                })
            else:
                self._set_src_mac_defaults()
                
            # Process destination MAC
            if dst_mac != str(MISSING_VALUE):
                dst_parts = dst_mac.split(':')
                if len(dst_parts) >= 3:
                    oui = ':'.join(dst_parts[0:3])
                    vendor = self._get_vendor_safe(oui)
                    is_multicast = self._is_multicast_safe(dst_parts)
                    is_broadcast = (dst_mac.lower() == 'ff:ff:ff:ff:ff:ff')
                    is_local = self._is_local_safe(dst_parts)
                else:
                    oui = str(MISSING_VALUE)
                    vendor = str(MISSING_VALUE)
                    is_multicast = MISSING_VALUE
                    is_broadcast = MISSING_VALUE
                    is_local = MISSING_VALUE
                
                self.features.update({
                    'dst_mac_oui': oui,
                    'dst_mac_vendor': vendor,
                    'dst_mac_is_multicast': is_multicast,
                    'dst_mac_is_broadcast': is_broadcast,
                    'dst_mac_is_local': is_local
                })
            else:
                self._set_dst_mac_defaults()
                
        except Exception as e:
            self.logger.debug(f"MAC analysis error: {e}")
            self._set_default_mac_features()
    
    def _get_vendor_safe(self, oui):
        """Get vendor safely without subscripting."""
        try:
            oui_clean = oui.replace(':', '').upper()
            vendors = {
                '000C29': 'VMware',
                '005056': 'VMware',
                '0050F2': 'Microsoft', 
                '00E04C': 'Realtek',
                '001B21': 'Intel',
                '00000C': 'Cisco',
                '0025B3': 'Apple'
            }
            return vendors.get(oui_clean, 'Unknown')
        except:
            return 'Unknown'
    
    def _is_multicast_safe(self, mac_parts):
        """Check multicast safely."""
        try:
            if len(mac_parts) > 0:
                first_octet = int(mac_parts[0], 16)
                return bool(first_octet & 0x01)
            return MISSING_VALUE
        except:
            return MISSING_VALUE
    
    def _is_local_safe(self, mac_parts):
        """Check local admin safely."""
        try:
            if len(mac_parts) > 0:
                first_octet = int(mac_parts[0], 16)
                return bool(first_octet & 0x02)
            return MISSING_VALUE
        except:
            return MISSING_VALUE
    
    def _safe_extract_protocols(self):
        """Safely extract protocol info without subscripting."""
        try:
            # Initialize protocol flags
            protocols = {
                'is_arp': False, 'is_stp': False, 'is_cdp': False,
                'is_dhcp': False, 'is_llc': False, 'is_isl': False,
                'is_lldp': False, 'is_dtp': False
            }
            self.features.update(protocols)
            
            # Check each protocol safely
            if self.packet.haslayer('ARP'):
                self.features['is_arp'] = True
                self._extract_arp_safe()
            
            if self.packet.haslayer('STP'):
                self.features['is_stp'] = True
                self._extract_stp_safe()
            
            if self.packet.haslayer('UDP'):
                self._check_dhcp_safe()
            
            # Set other protocol defaults
            self._set_protocol_defaults()
            
        except Exception as e:
            self.logger.debug(f"Protocol extraction error: {e}")
            self._set_protocol_defaults()
    
    def _extract_arp_safe(self):
        """Extract ARP features safely."""
        try:
            if self.packet.haslayer('ARP'):
                arp = self.packet.getlayer('ARP')
                self.features.update({
                    'arp_hw_type': int(arp.hwtype) if hasattr(arp, 'hwtype') else MISSING_VALUE,
                    'arp_proto_type': int(arp.ptype) if hasattr(arp, 'ptype') else MISSING_VALUE,
                    'arp_hw_len': int(arp.hwlen) if hasattr(arp, 'hwlen') else MISSING_VALUE,
                    'arp_proto_len': int(arp.plen) if hasattr(arp, 'plen') else MISSING_VALUE,
                    'arp_opcode': int(arp.op) if hasattr(arp, 'op') else MISSING_VALUE,
                    'arp_src_hw_addr': str(arp.hwsrc) if hasattr(arp, 'hwsrc') else str(MISSING_VALUE),
                    'arp_dst_hw_addr': str(arp.hwdst) if hasattr(arp, 'hwdst') else str(MISSING_VALUE),
                    'arp_src_proto_addr': str(arp.psrc) if hasattr(arp, 'psrc') else str(MISSING_VALUE),
                    'arp_dst_proto_addr': str(arp.pdst) if hasattr(arp, 'pdst') else str(MISSING_VALUE)
                })
        except Exception as e:
            self.logger.debug(f"ARP extraction error: {e}")
            self._set_arp_defaults()
    
    def _extract_stp_safe(self):
        """Extract STP features safely."""
        try:
            if self.packet.haslayer('STP'):
                stp = self.packet.getlayer('STP')
                self.features.update({
                    'stp_version': int(stp.version) if hasattr(stp, 'version') else MISSING_VALUE,
                    'stp_bpdu_type': int(stp.bpdutype) if hasattr(stp, 'bpdutype') else MISSING_VALUE,
                    'stp_flags': int(stp.bpduflags) if hasattr(stp, 'bpduflags') else MISSING_VALUE,
                    'stp_msg_age': float(stp.msg_age) / 256 if hasattr(stp, 'msg_age') else MISSING_VALUE,
                    'stp_max_age': float(stp.max_age) / 256 if hasattr(stp, 'max_age') else MISSING_VALUE,
                    'stp_hello_time': float(stp.hello_time) / 256 if hasattr(stp, 'hello_time') else MISSING_VALUE,
                    'stp_forward_delay': float(stp.forward_delay) / 256 if hasattr(stp, 'forward_delay') else MISSING_VALUE,
                    'stp_root_cost': int(stp.pathcost) if hasattr(stp, 'pathcost') else MISSING_VALUE,
                    'stp_port_id': int(stp.portid) if hasattr(stp, 'portid') else MISSING_VALUE,
                    'stp_proto_id': int(stp.proto) if hasattr(stp, 'proto') else MISSING_VALUE
                })
                
                # Safe flag extraction
                if hasattr(stp, 'bpduflags'):
                    flags = int(stp.bpduflags)
                    self.features.update({
                        'stp_flags_tc': bool(flags & 0x01),
                        'stp_flags_tcack': bool(flags & 0x80)
                    })
        except Exception as e:
            self.logger.debug(f"STP extraction error: {e}")
            self._set_stp_defaults()
    
    def _check_dhcp_safe(self):
        """Check for DHCP safely."""
        try:
            if self.packet.haslayer('UDP'):
                udp = self.packet.getlayer('UDP')
                src_port = int(udp.sport) if hasattr(udp, 'sport') else 0
                dst_port = int(udp.dport) if hasattr(udp, 'dport') else 0
                
                if (src_port in [67, 68] or dst_port in [67, 68]) and (
                    self.packet.haslayer('DHCP') or self.packet.haslayer('BOOTP')):
                    self.features['is_dhcp'] = True
                    self._extract_dhcp_safe()
        except Exception as e:
            self.logger.debug(f"DHCP check error: {e}")
    
    def _extract_dhcp_safe(self):
        """Extract DHCP features safely."""
        try:
            if self.packet.haslayer('BOOTP'):
                bootp = self.packet.getlayer('BOOTP')
                self.features.update({
                    'dhcp_op': int(bootp.op) if hasattr(bootp, 'op') else MISSING_VALUE,
                    'dhcp_hw_type': int(bootp.htype) if hasattr(bootp, 'htype') else MISSING_VALUE,
                    'dhcp_hw_len': int(bootp.hlen) if hasattr(bootp, 'hlen') else MISSING_VALUE,
                    'dhcp_hops': int(bootp.hops) if hasattr(bootp, 'hops') else MISSING_VALUE,
                    'dhcp_xid': int(bootp.xid) if hasattr(bootp, 'xid') else MISSING_VALUE,
                    'dhcp_secs': int(bootp.secs) if hasattr(bootp, 'secs') else MISSING_VALUE,
                    'dhcp_flags': int(bootp.flags) if hasattr(bootp, 'flags') else MISSING_VALUE,
                    'dhcp_cookie': 0x63825363
                })
                
                # Safe flag processing
                if hasattr(bootp, 'flags'):
                    flags = int(bootp.flags)
                    self.features.update({
                        'dhcp_flags_bc': bool(flags & 0x8000),
                        'dhcp_flags_reserved': bool(flags & 0x7FFF)
                    })
                    
            # Handle DHCP options safely
            if self.packet.haslayer('DHCP'):
                dhcp = self.packet.getlayer('DHCP')
                if hasattr(dhcp, 'options') and dhcp.options:
                    self.features['dhcp_options'] = len(dhcp.options)
                else:
                    self.features['dhcp_options'] = MISSING_VALUE
                    
        except Exception as e:
            self.logger.debug(f"DHCP extraction error: {e}")
            self._set_dhcp_defaults()
    
    def get_protocol_type(self):
        """Return protocol type safely."""
        try:
            if self.features.get('is_arp', False):
                return 'ARP'
            elif self.features.get('is_stp', False):
                return 'STP'
            elif self.features.get('is_dhcp', False):
                return 'DHCP'
            elif self.features.get('is_cdp', False):
                return 'CDP'
            elif self.features.get('is_llc', False):
                return 'LLC'
            else:
                return 'Layer2'
        except:
            return 'Layer2'
    
    # Default setters - all safe operations
    def _set_all_defaults(self):
        self.features.update({
            'frame_len': 0, 'frame_number': 0, 'timestamp': 0.0
        })
        self._set_default_mac_features()
        self._set_protocol_defaults()
    
    def _set_default_mac_features(self):
        self._set_src_mac_defaults()
        self._set_dst_mac_defaults()
    
    def _set_src_mac_defaults(self):
        self.features.update({
            'src_mac_oui': str(MISSING_VALUE),
            'src_mac_vendor': str(MISSING_VALUE),
            'src_mac_is_multicast': MISSING_VALUE,
            'src_mac_is_broadcast': MISSING_VALUE,
            'src_mac_is_local': MISSING_VALUE
        })
    
    def _set_dst_mac_defaults(self):
        self.features.update({
            'dst_mac_oui': str(MISSING_VALUE),
            'dst_mac_vendor': str(MISSING_VALUE),
            'dst_mac_is_multicast': MISSING_VALUE,
            'dst_mac_is_broadcast': MISSING_VALUE,
            'dst_mac_is_local': MISSING_VALUE
        })
    
    def _set_protocol_defaults(self):
        self._set_arp_defaults()
        self._set_stp_defaults()
        self._set_dhcp_defaults()
        self._set_cdp_defaults()
    
    def _set_arp_defaults(self):
        self.features.update({
            'arp_hw_type': MISSING_VALUE, 'arp_proto_type': MISSING_VALUE,
            'arp_hw_len': MISSING_VALUE, 'arp_proto_len': MISSING_VALUE,
            'arp_opcode': MISSING_VALUE,
            'arp_src_hw_addr': str(MISSING_VALUE), 'arp_dst_hw_addr': str(MISSING_VALUE),
            'arp_src_proto_addr': str(MISSING_VALUE), 'arp_dst_proto_addr': str(MISSING_VALUE)
        })
    
    def _set_stp_defaults(self):
        self.features.update({
            'stp_version': MISSING_VALUE, 'stp_bpdu_type': MISSING_VALUE,
            'stp_flags': MISSING_VALUE, 'stp_flags_tc': MISSING_VALUE,
            'stp_flags_tcack': MISSING_VALUE, 'stp_msg_age': MISSING_VALUE,
            'stp_max_age': MISSING_VALUE, 'stp_hello_time': MISSING_VALUE,
            'stp_forward_delay': MISSING_VALUE, 'stp_root_cost': MISSING_VALUE,
            'stp_port_id': MISSING_VALUE, 'stp_proto_id': MISSING_VALUE
        })
    
    def _set_dhcp_defaults(self):
        self.features.update({
            'dhcp_op': MISSING_VALUE, 'dhcp_hw_type': MISSING_VALUE,
            'dhcp_hw_len': MISSING_VALUE, 'dhcp_hops': MISSING_VALUE,
            'dhcp_xid': MISSING_VALUE, 'dhcp_secs': MISSING_VALUE,
            'dhcp_flags': MISSING_VALUE, 'dhcp_flags_bc': MISSING_VALUE,
            'dhcp_flags_reserved': MISSING_VALUE, 'dhcp_cookie': MISSING_VALUE,
            'dhcp_options': MISSING_VALUE, 'dhcp_options_len': MISSING_VALUE
        })
    
    def _set_cdp_defaults(self):
        self.features.update({
            'cdp_version': MISSING_VALUE, 'cdp_ttl': MISSING_VALUE,
            'cdp_checksum': MISSING_VALUE, 'cdp_tlv_count': MISSING_VALUE,
            'cdp_device_id_tlv_len': MISSING_VALUE, 'cdp_software_version_tlv_len': MISSING_VALUE,
            'cdp_platform_tlv_len': MISSING_VALUE, 'cdp_addresses_count': MISSING_VALUE,
            'cdp_capabilities': MISSING_VALUE, 'cdp_capabilities_router': MISSING_VALUE,
            'cdp_capabilities_trans_bridge': MISSING_VALUE, 'cdp_capabilities_switch': MISSING_VALUE,
            'cdp_capabilities_host': MISSING_VALUE, 'cdp_tlvs': MISSING_VALUE
        })