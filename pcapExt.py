import pyshark
from tqdm import tqdm
from featureExt import eth_pkt_feature_extractor, llc_ext, dtp_ext,stp_ext,arp_ext,loop_ext,isl_ext,cdp_ext,dhcp_ext


def pcap_reader(PCAP_PATH, CAP_UDP):
    pcap = pyshark.FileCapture(PCAP_PATH, use_json=True)

    pkts_info_eth=list()
    pkts_info_extra = list()

    pkts_info_llc = list()
    pkts_info_stp = list()
    pkts_info_arp = list()
    pkts_info_loop = list()
    pkts_info_dtp = list()
    pkts_info_isl = list()
    pkts_info_cdp = list()
    pkts_info_dhcp = list()


    for index, pkt in tqdm(enumerate(pcap)):
        proto = pkt.transport_layer

        pkts_info_eth.append(eth_pkt_feature_extractor(pkt.ETH._all_fields,index, proto))

        if not CAP_UDP and proto == 'UDP':
            continue

        extra_dict = {'pkt_num':index ,'frame_num':pkt.frame_info.number,
                                        'frame_len':pkt.frame_info.len, 'frame_cap_len':pkt.frame_info.cap_len,
                                        'frame_marked':pkt.frame_info.marked, 'frame_ignored':pkt.frame_info.ignored,
                                        'time_epoch':pkt.frame_info.time_epoch, 'time_utc':pkt.frame_info.time_utc, 'time_relative':pkt.frame_info.time_relative,
                                        'has_llc':0, 'has_dtp':0,'has_stp':0,'has_arp':0,'has_dhcp':0,'has_loop':0,'has_cdp':0,'has_isl':0}


        for item in ['llc', 'dtp', 'stp', 'arp', 'dhcp', 'loop', 'cdp']:
            if item in pkt.frame_info.protocols.split(':'):
                if item == 'llc':
                    pkts_info_llc.append(llc_ext(pkt[item]._all_fields, index))
                    extra_dict['has_llc'] = 1
                if item == 'dtp':
                    pkts_info_dtp.append(dtp_ext(pkt[item]._all_fields, index))
                    extra_dict['has_dtp'] = 1
                if item == 'stp':
                    pkts_info_stp.append(stp_ext(pkt[item]._all_fields, index))
                    extra_dict['has_stp'] = 1
                if item == 'arp':
                    pkts_info_arp.append(arp_ext(pkt[item]._all_fields, index))
                    extra_dict['has_arp'] = 1
                if item == 'dhcp':
                    pkts_info_dhcp.append(dhcp_ext(pkt[item]._all_fields, index))
                    extra_dict['has_dhcp'] = 1
                if item == 'loop':
                    pkts_info_loop.append(loop_ext(pkt[item]._all_fields, index))
                    extra_dict['has_loop'] = 1
                if item == 'cdp':
                    pkts_info_cdp.append(cdp_ext(pkt[item]._all_fields, index))
                    extra_dict['has_cdp'] = 1

        try:
            pkts_info_isl.append(isl_ext(pkt['isl']._all_fields, index))
            extra_dict['has_isl'] = 1
        except:
            extra_dict['has_isl'] = 0

        pkts_info_extra.append(extra_dict)
    return pkts_info_eth, pkts_info_extra,pkts_info_llc ,pkts_info_stp,pkts_info_arp,pkts_info_loop,pkts_info_dtp,pkts_info_isl,pkts_info_cdp,pkts_info_dhcp
