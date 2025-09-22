"""
Improved feature extraction system using the successful approach from DLFlowlyzer.
This module uses numpy.nan for missing features and follows the proven syntax.
"""

import numpy as np
from typing import Dict, Any


def get_missing_value(missing_value_type: str = '-100'):
    """Get the appropriate missing value based on configuration."""
    if missing_value_type == 'nan':
        return np.nan
    elif missing_value_type == '-100':
        return -100
    else:
        return -100


def extract_stp_features(data: Dict[str, Any], index: int, missing_value_type: str = '-100') -> Dict[str, Any]:
    """Extract STP features using the proven approach from DLFlowlyzer."""
    res = {'pkt_num': index}
    missing_val = get_missing_value(missing_value_type)

    try:
        res['stp_version'] = data['stp.version']
    except:
        res['stp_version'] = missing_val

    try:
        res['stp_msg_age'] = data['stp.msg_age']
    except:
        res['stp_msg_age'] = missing_val

    try:
        res['stp_forward'] = data['stp.forward']
    except:
        res['stp_forward'] = missing_val

    try:
        res['stp_flags_tc'] = data['stp.flags_tree']['stp.flags.tc']
    except:
        res['stp_flags_tc'] = missing_val

    try:
        res['stp_flags_tcack'] = data['stp.flags_tree']['stp.flags.tcack']
    except:
        res['stp_flags_tcack'] = missing_val

    try:
        res['stp_hello'] = data['stp.hello']
    except:
        res['stp_hello'] = missing_val

    try:
        root_key = [a for a in data.keys() if a.startswith("Root Identifier")]
        bridge_key = [a for a in data.keys() if a.startswith("Bridge Identifier")]
    except:
        root_key = missing_val
        bridge_key = missing_val

    if root_key != missing_val and len(root_key) > 0:
        try:
            res['stp_root_identifier_prio'] = data[root_key[0]]['stp.root.prio']
        except:
            res['stp_root_identifier_prio'] = missing_val

        try:
            res['stp_root_identifier_ext'] = data[root_key[0]]['stp.root.ext']
        except:
            res['stp_root_identifier_ext'] = missing_val
    else:
        res['stp_root_identifier_prio'] = missing_val
        res['stp_root_identifier_ext'] = missing_val

    if bridge_key != missing_val and len(bridge_key) > 0:
        try:
            res['stp_bridge_identifier_prio'] = data[bridge_key[0]]['stp.bridge.prio']
        except:
            res['stp_bridge_identifier_prio'] = missing_val

        try:
            res['stp_bridge_identifier_ext'] = data[bridge_key[0]]['stp.bridge.ext']
        except:
            res['stp_bridge_identifier_ext'] = missing_val
    else:
        res['stp_bridge_identifier_prio'] = missing_val
        res['stp_bridge_identifier_ext'] = missing_val

    try:
        res['stp_root_cost'] = data['stp.root.cost']
    except:
        res['stp_root_cost'] = missing_val

    try:
        res['stp_max_age'] = data['stp.max_age']
    except:
        res['stp_max_age'] = missing_val

    return res


def extract_arp_features(data: Dict[str, Any], index: int, missing_value_type: str = '-100') -> Dict[str, Any]:
    """Extract ARP features using the proven approach from DLFlowlyzer."""
    res = {'pkt_num': index}
    missing_val = get_missing_value(missing_value_type)

    try:
        res['arp_type'] = data['type']
    except:
        res['arp_type'] = missing_val

    try:
        res['arp_size'] = data['size']
    except:
        res['arp_size'] = missing_val

    try:
        res['arp_dst_hw_mac'] = data['dst.hw_mac']
    except:
        res['arp_dst_hw_mac'] = missing_val

    try:
        res['arp_src_hw_mac'] = data['src.hw_mac']
    except:
        res['arp_src_hw_mac'] = missing_val

    try:
        res['arp_proto_size'] = data['proto.size']
    except:
        res['arp_proto_size'] = missing_val

    try:
        res['arp_hw_size'] = data['hw.size']
    except:
        res['arp_hw_size'] = missing_val

    try:
        res['arp_hw_type'] = data['hw.type']
    except:
        res['arp_hw_type'] = missing_val

    try:
        res['arp_opcode'] = data['opcode']
    except:
        res['arp_opcode'] = missing_val

    return res


def extract_cdp_features(data: Dict[str, Any], index: int, missing_value_type: str = '-100') -> Dict[str, Any]:
    """Extract CDP features using the proven approach from DLFlowlyzer."""
    res = {'pkt_num': index}
    missing_val = get_missing_value(missing_value_type)

    try:
        res['cdp_version'] = data['cdp.version']
    except:
        res['cdp_version'] = missing_val

    try:
        res['cdp_ttl'] = data['cdp.ttl']
    except:
        res['cdp_ttl'] = missing_val

    try:
        res['cdp_checksum_status'] = data['cdp.checksum.status']
    except:
        res['cdp_checksum_status'] = missing_val

    try:
        device_id_key = [a for a in data.keys() if a.startswith("Device ID")]
        platform_key = [a for a in data.keys() if a.startswith("Platform")]
        port_id_key = [a for a in data.keys() if a.startswith("Port ID")]
        hello_id_key = [a for a in data.keys() if a.startswith("Protocol Hello")]
        vtp_key = [a for a in data.keys() if a.startswith("VTP Management")]
        vlan_key = [a for a in data.keys() if a.startswith("Native VLAN")]
        duplex_key = [a for a in data.keys() if a.startswith("Duplex")]
        trust_bitmap_key = [a for a in data.keys() if a.startswith("Trust Bitmap")]
        untrust_port_key = [a for a in data.keys() if a.startswith("Untrusted port")]
        power_key = [a for a in data.keys() if a.startswith("Power Available")]
    except:
        device_id_key = missing_val
        platform_key = missing_val
        port_id_key = missing_val
        hello_id_key = missing_val
        vtp_key = missing_val
        vlan_key = missing_val
        duplex_key = missing_val
        trust_bitmap_key = missing_val
        untrust_port_key = missing_val
        power_key = missing_val

    if device_id_key != missing_val and len(device_id_key) > 0:
        try:
            res['cdp_device_id_tlv_len'] = data[device_id_key[0]]['cdp.tlv.len']
        except:
            res['cdp_device_id_tlv_len'] = missing_val
    else:
        res['cdp_device_id_tlv_len'] = missing_val

    try:
        res['cdp_software_version_tlv_len'] = data['Software Version']['cdp.tlv.len']
    except:
        res['cdp_software_version_tlv_len'] = missing_val

    if platform_key != missing_val and len(platform_key) > 0:
        try:
            res['cdp_platform_tlv_len'] = data[platform_key[0]]['cdp.tlv.len']
        except:
            res['cdp_platform_tlv_len'] = missing_val

        try:
            res['cdp_platform'] = data[platform_key[0]]['cdp.platform']
        except:
            res['cdp_platform'] = missing_val
    else:
        res['cdp_platform_tlv_len'] = missing_val
        res['cdp_platform'] = missing_val

    try:
        res['cdp_addresses_tlv_len'] = data['Addresses']['cdp.tlv.len']
    except:
        res['cdp_addresses_tlv_len'] = missing_val

    try:
        res['cdp_addresses_count'] = data['Addresses']['cdp.number_of_addresses']
    except:
        res['cdp_addresses_count'] = missing_val

    # CDP Capabilities
    try:
        res['cdp_capabilities_router'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.router']
    except:
        res['cdp_capabilities_router'] = missing_val

    try:
        res['cdp_capabilities_trans_bridge'] = data['Capabilities']['cdp.capabilities_tree'][
            'cdp.capabilities.trans_bridge']
    except:
        res['cdp_capabilities_trans_bridge'] = missing_val

    try:
        res['cdp_capabilities_switch'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.switch']
    except:
        res['cdp_capabilities_switch'] = missing_val

    try:
        res['cdp_capabilities_host'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.host']
    except:
        res['cdp_capabilities_host'] = missing_val

    return res


def extract_dhcp_features(data: Dict[str, Any], index: int, missing_value_type: str = '-100') -> Dict[str, Any]:
    """Extract DHCP features using the proven approach from DLFlowlyzer."""
    res = {'pkt_num': index}
    missing_val = get_missing_value(missing_value_type)

    try:
        res['dhcp_hw_type'] = data['dhcp.type']
    except:
        res['dhcp_hw_type'] = missing_val

    try:
        res['dhcp_padding'] = data['dhcp.hw.addr_padding']
    except:
        res['dhcp_padding'] = missing_val

    try:
        res['dhcp_hw_len'] = data['dhcp.hw.len']
    except:
        res['dhcp_hw_len'] = missing_val

    try:
        res['dhcp_secs'] = data['dhcp.secs']
    except:
        res['dhcp_secs'] = missing_val

    try:
        res['dhcp_cookie'] = data['dhcp.cookie']
    except:
        res['dhcp_cookie'] = missing_val

    try:
        res['dhcp_type'] = data['dhcp.hw.type']
    except:
        res['dhcp_type'] = missing_val

    try:
        res['dhcp_hops'] = data['dhcp.hops']
    except:
        res['dhcp_hops'] = missing_val

    try:
        res['dhcp_flags_bc'] = data['dhcp.flags_tree']['dhcp.flags.bc']
    except:
        res['dhcp_flags_bc'] = missing_val

    try:
        res['dhcp_flags_reserved'] = data['dhcp.flags_tree']['dhcp.flags.reserved']
    except:
        res['dhcp_flags_reserved'] = missing_val

    try:
        sum_options = 0
        for option in data['dhcp.option.type_tree']:
            try:
                sum_options += int(option['dhcp.option.length'])
            except:
                continue
        res['dhcp_options_len'] = sum_options
    except:
        res['dhcp_options_len'] = missing_val

    try:
        res['dhcp_option_padding'] = data['dhcp.option.padding']
    except:
        res['dhcp_option_padding'] = missing_val

    try:
        res['dhcp_options'] = len(data['dhcp.option.type'])
    except:
        res['dhcp_options'] = missing_val

    return res


def extract_llc_features(data: Dict[str, Any], index: int, missing_value_type: str = '-100') -> Dict[str, Any]:
    """Extract LLC features using the proven approach from DLFlowlyzer."""
    res = {'pkt_num': index}
    missing_val = get_missing_value(missing_value_type)

    try:
        res['llc_control_ftype'] = data['llc.control_tree']['llc.control.ftype']
    except:
        res['llc_control_ftype'] = missing_val

    try:
        res['llc_control_u_modifier'] = data['llc.control_tree']['llc.control.u_modifier_cmd']
    except:
        res['llc_control_u_modifier'] = missing_val

    try:
        res['llc_control'] = data['llc.control']
    except:
        res['llc_control'] = missing_val

    try:
        res['llc_ssap_cr'] = data['llc.ssap_tree']['llc.ssap.cr']
    except:
        res['llc_ssap_cr'] = missing_val

    try:
        res['llc_ssap_sap'] = data['llc.ssap_tree']['llc.ssap.sap']
    except:
        res['llc_ssap_sap'] = missing_val

    try:
        res['llc_dsap_sap'] = data['llc.dsap_tree']['llc.dsap.sap']
    except:
        res['llc_dsap_sap'] = missing_val

    try:
        res['llc_dsap_ig'] = data['llc.dsap_tree']['llc.dsap.ig']
    except:
        res['llc_dsap_ig'] = missing_val

    return res