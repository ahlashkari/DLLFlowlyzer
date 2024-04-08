import pandas as pd
import numpy as np
from numpy.linalg import norm
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

def eth_pkt_feature_extractor(data, index, connection):
    res=dict()
    res['pkt_num'] = index

    try: res['connection']= connection
    except: res['connection']= np.nan

    try: res['dist_addr']=data['eth.dst']
    except: res['dist_addr']= np.nan

    try: res['dist_addr_vendor']=data['eth.dst'][:8]
    except: res['dist_addr_vendor']= np.nan

    try: res['dist_addr_device']=data['eth.dst'][9:]
    except: res['dist_addr_device']= np.nan

    try: res['dist_addr_vendor_name']=data['eth.dst_tree']['eth.addr.oui_resolved']
    except: res['dist_addr_vendor_name']= 'BROADCAST' if res['dist_addr'] == 'ff:ff:ff:ff:ff:ff' else 'UNKNOWN'

    try: res['dist_addr_vendor_name_known']= 0 if res['dist_addr_vendor_name'] == 'UNKNOWN' else 1
    except: res['dist_addr_vendor_name_known']= np.nan

    try: res['dist_ig']= data['eth.dst_tree']['eth.dst.ig']
    except: res['dist_ig']= np.nan

    try: res['dist_lg']= data['eth.dst_tree']['eth.dst.lg']
    except: res['dist_lg']= np.nan

    try: res['dist_oui']= data['eth.dst_tree']['eth.dst.oui']
    except: res['dist_oui']= np.nan

    try: res['src_addr']=data['eth.src']
    except: res['src_addr']= np.nan

    try: res['src_addr_vendor']=data['eth.src'][:8]
    except: res['src_addr_vendor']= np.nan

    try: res['src_addr_device']=data['eth.src'][9:]
    except: res['src_addr_device']= np.nan

    try: res['src_addr_vendor_name']=data['eth.src_tree']['eth.addr.oui_resolved']
    except: res['src_addr_vendor_name']='BROADCAST' if res['src_addr'] == 'ff:ff:ff:ff:ff:ff' else 'UNKNOWN'

    try: res['src_addr_vendor_name_known']= 0 if res['dist_addr_vendor_name'] == 'UNKNOWN' else 1
    except: res['srs_addr_vendor_name_known']= np.nan

    try: res['src_ig']= data['eth.src_tree']['eth.src.ig']
    except: res['src_ig']= np.nan

    try: res['src_lg']= data['eth.src_tree']['eth.src.lg']
    except: res['src_lg']= np.nan

    try: res['src_oui']= data['eth.src_tree']['eth.src.oui']
    except: res['src_oui']= np.nan

    try: res['eth_type']= data['eth.type']
    except: res['eth_type']= np.nan

    return res

def flow_pred(file):
    df = pd.read_csv(file)
    aaa = df.groupby(['dist_addr', 'src_addr'])
    bbb = [aaa.get_group(x) for x in aaa.groups]
    del (aaa)
    dfs = []
    checked = []
    for i in range(len(bbb)):
        for j in range(i, len(bbb)):
            if i != j:
                cond = {bbb[i].src_addr.unique()[0], bbb[i].dist_addr.unique()[0]} == {bbb[j].src_addr.unique()[0],
                                                                                   bbb[j].dist_addr.unique()[0]}
                if cond:
                    dfs.append(pd.concat([bbb[i], bbb[j]], axis=0).sort_values('pkt_num'))
                    checked += [i]
                    checked += [j]
        if i not in checked:
            dfs.append(bbb[i])
    del (checked)
    del (bbb)

    csv_dict = []
    for grp in dfs:
        grouped_df = grp.copy()
        csv_dict.append(flow_feature_ext(grouped_df))

    return csv_dict

def flow_feature_ext(data):
    res = dict()

    try: res['eth_one_addr'] = data.iloc[0]['dist_addr'] 
    except: res['eth_one_addr']= np.nan

    try: res['eth_one_addr_vendor'] = data.iloc[0]['dist_addr_vendor'] 
    except: res['eth_one_addr_vendor']= np.nan

    try: res['eth_one_addr_device'] = data.iloc[0]['dist_addr_device'] 
    except: res['eth_one_addr_device']= np.nan

    try: res['eth_one_addr_vendor_name'] = data.iloc[0]['dist_addr_vendor_name'] 
    except: res['eth_one_addr_vendor_name']= 'UNKNOWN'

    try: res['eth_one_addr_vendor_name_known'] = data.iloc[0]['dist_addr_vendor_name_known'] 
    except: res['eth_one_addr_vendor_name_known']= np.nan

    try: res['eth_one_ig'] = data.iloc[0]['dist_ig'] 
    except: res['eth_one_ig']= np.nan

    try: res['eth_one_lg'] = data.iloc[0]['dist_lg'] 
    except: res['eth_one_lg']= np.nan

    try: res['eth_one_oui'] = data.iloc[0]['dist_oui'] 
    except: res['eth_one_oui']= np.nan

    try: res['eth_two_addr'] = data.iloc[0]['src_addr'] 
    except: res['eth_two_addr']= np.nan

    try: res['eth_two_addr_vendor'] = data.iloc[0]['src_addr_vendor'] 
    except: res['eth_two_addr_vendor']= np.nan

    try: res['eth_two_addr_device'] = data.iloc[0]['src_addr_device'] 
    except: res['eth_two_addr_device']= np.nan

    try: res['eth_two_addr_vendor_name'] = data.iloc[0]['src_addr_vendor_name'] 
    except: res['eth_two_addr_vendor_name']= 'UNKNOWN'

    try: res['eth_two_addr_vendor_name_known'] = data.iloc[0]['src_addr_vendor_name_known'] 
    except: res['eth_two_addr_vendor_name_known']= np.nan

    try: res['eth_two_ig'] = data.iloc[0]['src_ig'] 
    except: res['eth_two_ig']= np.nan

    try: res['eth_two_lg'] = data.iloc[0]['src_lg'] 
    except: res['eth_two_lg']= np.nan

    try: res['eth_two_oui'] = data.iloc[0]['src_oui'] 
    except: res['eth_two_oui']= np.nan

    try: res['eth_type'] = data.iloc[0]['eth_type'] 
    except: res['eth_type']= np.nan

    try: res['connection'] = data.iloc[0]['connection'] 
    except: res['connection']= np.nan

    try: res['time_delta'] = int(data.iloc[len(data) - 1]['time_relative']) - int(data.iloc[0]['time_relative'])
    except: res['time_delta'] = np.nan

    try: res['sum_frame_len'] = sum(data['frame_len'])
    except: res['sum_frame_len'] = np.nan

    try: res['sum_frame_len_div_time'] = sum(data['frame_len']) / res['time_delta']
    except: res['sum_frame_len_div_time'] = np.nan

    try: res['num_frame_marked'] = len(data['frame_marked'].loc[data['frame_marked']==1])
    except: res['num_frame_marked'] = np.nan

    try: res['num_frame_ignored'] = len(data['frame_ignored'].loc[data['frame_ignored']==1])
    except: res['num_frame_ignored'] = np.nan

    try: res['num_llc_frame'] = len(data['has_llc'].loc[data['has_llc']==1])
    except: res['num_llc_frame'] = np.nan

    try: res['num_dtp_frame'] = len(data['has_dtp'].loc[data['has_dtp']==1])
    except: res['num_dtp_frame'] = np.nan

    try: res['num_stp_frame'] = len(data['has_stp'].loc[data['has_stp']==1])
    except: res['num_stp_frame'] = np.nan

    try: res['num_arp_frame'] = len(data['has_arp'].loc[data['has_arp']==1])
    except: res['num_arp_frame'] = np.nan

    try: res['num_dhcp_frame'] = len(data['has_dhcp'].loc[data['has_dhcp']==1])
    except: res['num_dhcp_frame'] = np.nan

    try: res['num_loop_frame'] = len(data['has_loop'].loc[data['has_loop']==1])
    except: res['num_loop_frame'] = np.nan

    try: res['num_cdp_frame'] = len(data['has_cdp'].loc[data['has_cdp']==1])
    except: res['num_cdp_frame'] = np.nan

    try: res['num_isl_frame'] = len(data['has_isl'].loc[data['has_isl']==1])
    except: res['num_isl_frame'] = np.nan

    try: res['percent_frame_marked'] = len(data['frame_marked'].loc[data['frame_marked']==1]) / len(data)
    except: res['percent_frame_marked'] = np.nan

    try: res['percent_frame_ignored'] = len(data['frame_ignored'].loc[data['frame_ignored']==1]) / len(data)
    except: res['percent_frame_ignored'] = np.nan

    try: res['percent_llc_frame'] = len(data['has_llc'].loc[data['has_llc']==1]) / len(data)
    except: res['percent_llc_frame'] = np.nan

    try: res['percent_dtp_frame'] = len(data['has_dtp'].loc[data['has_dtp']==1]) / len(data)
    except: res['percent_dtp_frame'] = np.nan

    try: res['percent_stp_frame'] = len(data['has_stp'].loc[data['has_stp']==1]) / len(data)
    except: res['percent_stp_frame'] = np.nan

    try: res['percent_arp_frame'] = len(data['has_arp'].loc[data['has_arp']==1]) / len(data)
    except: res['percent_arp_frame'] = np.nan

    try: res['percent_dhcp_frame'] = len(data['has_dhcp'].loc[data['has_dhcp']==1]) / len(data)
    except: res['percent_dhcp_frame'] = np.nan

    try: res['percent_loop_frame'] = len(data['has_loop'].loc[data['has_loop']==1]) / len(data)
    except: res['percent_loop_frame'] = np.nan

    try: res['percent_cdp_frame'] = len(data['has_cdp'].loc[data['has_cdp']==1]) / len(data)
    except: res['percent_cdp_frame'] = np.nan

    try: res['percent_isl_frame'] = len(data['has_isl'].loc[data['has_isl']==1]) / len(data)
    except: res['percent_isl_frame'] = np.nan


    try: res['sum_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].sum(skipna=True)
    except: res['sum_frames_mac1_mac2'] = np.nan

    try: res['mean_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].mean(skipna=True)
    except: res['mean_frames_mac1_mac2'] =np.nan

    try: res['max_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].max()
    except: res['max_frames_mac1_mac2'] = np.nan

    try: res['min_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].min()
    except: res['min_frames_mac1_mac2'] = np.nan

    try: res['median_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].median(skipna=True)
    except: res['median_frames_mac1_mac2'] = np.nan

    try: res['std_frames_mac1_mac2'] = data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].std(skipna=True)
    except: res['std_frames_mac1_mac2'] = np.nan

    try: res['norm_frames_mac1_mac2'] = norm(data['frame_len'].loc[data['src_addr'] == res['eth_one_addr']].values)
    except: res['norm_frames_mac1_mac2'] =np.nan

    try: res['sum_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].sum(skipna=True)
    except: res['sum_frames_mac2_mac1'] = np.nan

    try: res['mean_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].mean(skipna=True)
    except: res['mean_frames_mac2_mac1'] =np.nan

    try: res['max_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].max()
    except: res['max_frames_mac2_mac1'] = np.nan

    try: res['min_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].min()
    except: res['min_frames_mac2_mac1'] = np.nan

    try: res['median_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].median(skipna=True)
    except: res['median_frames_mac2_mac1']=np.nan

    try: res['std_frames_mac2_mac1'] = data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].std(skipna=True)
    except: res['std_frames_mac2_mac1'] = np.nan

    try: res['norm_frames_mac2_mac1'] = norm(data['frame_len'].loc[data['src_addr'] == res['eth_two_addr']].values)
    except: res['norm_frames_mac2_mac1'] =np.nan


    try: res['mean_frame_len'] = data['frame_len'].mean(skipna=True)
    except: res['mean_frame_len'] = np.nan

    try: res['max_frame_len'] = data['frame_len'].max()
    except: res['max_frame_len'] = np.nan

    try: res['min_frame_len'] = data['frame_len'].min()
    except: res['min_frame_len'] = np.nan

    try: res['median_frame_len'] = data['frame_len'].median(skipna=True)
    except: res['median_frame_len'] = np.nan

    try: res['std_frame_len'] = data['frame_len'].std(skipna=True)
    except: res['std_frame_len'] = np.nan

    try: res['norm_frame_len'] = norm(data['frame_len'].values)
    except: res['norm_frame_len'] = np.nan



    try: res['mean_llc_ssap_sap'] = data['llc_ssap_sap'].sum(skipna=True)
    except: res['mean_llc_ssap_sap'] = np.nan

    try: res['mean_llc_ssap_sap'] = data['llc_ssap_sap'].mean(skipna=True)
    except: res['mean_llc_ssap_sap'] = np.nan

    try: res['max_llc_ssap_sap'] = data['llc_ssap_sap'].max()
    except: res['max_llc_ssap_sap'] = np.nan

    try: res['min_llc_ssap_sap'] = data['llc_ssap_sap'].min()
    except: res['min_llc_ssap_sap'] = np.nan

    try: res['median_llc_ssap_sap'] = data['llc_ssap_sap'].median(skipna=True)
    except: res['median_llc_ssap_sap'] = np.nan

    try: res['std_llc_ssap_sap'] = data['llc_ssap_sap'].std(skipna=True)
    except: res['std_llc_ssap_sap'] = np.nan

    try: res['norm_llc_ssap_sap'] = norm(data['llc_ssap_sap'].values)
    except: res['norm_llc_ssap_sap'] = np.nan

    try: res['sum_llc_dsap_sap'] = data['llc_dsap_sap'].sum(skipna=True)
    except: res['sum_llc_dsap_sap'] = np.nan

    try: res['mean_llc_dsap_sap'] = data['llc_dsap_sap'].mean(skipna=True)
    except: res['mean_llc_dsap_sap'] = np.nan

    try: res['max_llc_dsap_sap'] = data['llc_dsap_sap'].max()
    except: res['max_llc_dsap_sap'] = np.nan

    try: res['min_llc_dsap_sap'] = data['llc_dsap_sap'].min()
    except: res['min_llc_dsap_sap'] = np.nan

    try: res['median_llc_dsap_sap'] = data['llc_dsap_sap'].median(skipna=True)
    except: res['median_llc_dsap_sap'] = np.nan

    try: res['std_llc_dsap_sap'] = data['llc_dsap_sap'].std(skipna=True)
    except: res['std_llc_dsap_sap'] = np.nan

    try: res['norm_llc_dsap_sap'] = norm(data['llc_dsap_sap'].values)
    except: res['norm_llc_dsap_sap'] = np.nan

    try: res['sum_llc_ssap_cr'] = data['sum_ssap_cr'].sum(skipna=True)
    except: res['mean_llc_ssap_cr'] = np.nan

    try: res['mean_llc_ssap_cr'] = data['llc_ssap_cr'].mean(skipna=True)
    except: res['mean_llc_ssap_cr'] = np.nan

    try: res['sum_llc_dsap_cr'] = data['llc_dsap_cr'].sum(skipna=True)
    except: res['mean_llc_dsap_cr'] = np.nan

    try: res['mean_llc_dsap_cr'] = data['llc_dsap_cr'].mean(skipna=True)
    except: res['mean_llc_ssap_sap'] = np.nan

    try: res['sum_stp_msg_age'] = data['stp_msg_age'].sum(skipna=True)
    except: res['sum_stp_msg_age'] = np.nan

    try: res['mean_stp_msg_age'] = data['stp_msg_age'].mean(skipna=True)
    except: res['mean_stp_msg_age'] = np.nan

    try: res['max_stp_msg_age'] = data['stp_msg_age'].max()
    except: res['max_stp_msg_age'] = np.nan

    try: res['min_stp_msg_age'] = data['stp_msg_age'].min()
    except: res['min_stp_msg_age'] = np.nan

    try: res['median_stp_msg_age'] = data['stp_msg_age'].median(skipna=True)
    except: res['median_stp_msg_age'] = np.nan

    try: res['std_stp_msg_age'] = data['stp_msg_age'].std(skipna=True)
    except: res['std_stp_msg_age'] = np.nan

    try: res['norm_stp_msg_age'] = norm(data['stp_msg_age'].values)
    except: res['norm_stp_msg_age'] = np.nan

    try: res['sum_stp_forward'] = data['stp_forward'].sum(skipna=True)
    except: res['sum_stp_forward'] = np.nan

    try: res['mean_stp_forward'] = data['stp_forward'].mean(skipna=True)
    except: res['mean_stp_forward'] = np.nan

    try: res['max_stp_forward'] = data['stp_forward'].max()
    except: res['max_stp_forward'] = np.nan

    try: res['min_stp_forward'] = data['stp_forward'].min()
    except: res['min_stp_forward'] = np.nan

    try: res['median_stp_forward'] = data['stp_forward'].median(skipna=True)
    except: res['median_stp_forward'] = np.nan

    try: res['std_stp_forward'] = data['stp_forward'].std(skipna=True)
    except: res['std_stp_forward'] = np.nan

    try: res['norm_stp_forward'] = norm(data['stp_forward'].values)
    except: res['norm_stp_msg_age'] = np.nan

    try: res['count_stp_flags_tc_1'] = len(data['stp_flags_tc'].loc[data['stp_flags_tc']==1])
    except: res['count_stp_flags_tc_1'] = np.nan

    try: res['count_stp_flags_tcack_1'] = len(data['stp_flags_tcack'].loc[data['stp_flags_tcack']==1])
    except: res['count_stp_flags_tcack_1'] = np.nan

    try: res['percent_stp_flags_tc_1'] = len(data['stp_flags_tc'].loc[data['stp_flags_tc']==1]) / len(data)
    except: res['percent_stp_flags_tc_1'] = np.nan

    try: res['percent_stp_flags_tcack_1'] = len(data['stp_flags_tcack'].loc[data['stp_flags_tcack']==1])/ len(data)
    except: res['percent_stp_flags_tcack_1'] = np.nan

    try: res['stp_age_div_max_age'] = data['stp_msg_age'].sum(skipna=True) / data['stp_max_age'].sum(skipna=True)
    except: res['stp_age_div_max_age'] = np.nan

    try: res['sum_loop_skipcount'] = data['loop_skipcount'].sum(skipna=True)
    except: res['sum_loop_skipcount'] = np.nan

    try: res['sum_dtp_tlvs'] = data['dtp_tlv_len'].sum(skipna=True) + data['dtp_sender_tlv_len'].sum(skipna=True) + data['dtp_trunk_status_tlv_len'].sum(skipna=True) + data['dtp_trunk_type_tlv_len'].sum(skipna=True)
    except: res['sum_dtp_tlvs'] = np.nan

    try: res['mean_isl_bpdu'] = data['isl_bpdu'].mean(skipna=True)
    except: res['mean_isl_bpdu'] = np.nan
    
    try: res['sum_isl_len'] = data['isl_len'].sum(skipna=True)
    except: res['sum_isl_len'] = np.nan

    try: res['mean_isl_len'] = data['isl_len'].mean(skipna=True)
    except: res['mean_isl_len'] = np.nan

    try: res['max_isl_len'] = data['isl_len'].max()
    except: res['max_isl_len'] = np.nan

    try: res['min_isl_len'] = data['isl_len'].min()
    except: res['min_isl_len'] = np.nan

    try: res['median_isl_len'] = data['isl_len'].median(skipna=True)
    except: res['median_isl_len'] = np.nan

    try: res['std_isl_len'] = data['isl_len'].std(skipna=True)
    except: res['std_isl_len'] = np.nan

    try: res['norm_isl_len'] = norm(data['isl_len'].values)
    except: res['norm_isl_len'] = np.nan

    try: res['sum_cdp_addresses_count'] = data['cdp_addresses_count'].sum(skipna=True)
    except: res['sum_cdp_addresses_count'] = np.nan

    try: res['mean_cdp_addresses_count'] = data['cdp_addresses_count'].mean(skipna=True)
    except: res['mean_cdp_addresses_count'] = np.nan

    try: res['max_cdp_addresses_count'] = data['cdp_addresses_count'].max()
    except: res['max_cdp_addresses_count'] = np.nan

    try: res['min_cdp_addresses_count'] = data['cdp_addresses_count'].min()
    except: res['min_cdp_addresses_count'] = np.nan

    try: res['median_cdp_addresses_count'] = data['cdp_addresses_count'].median(skipna=True)
    except: res['median_cdp_addresses_count'] = np.nan

    try: res['std_cdp_addresses_count'] = data['cdp_addresses_count'].std(skipna=True)
    except: res['std_cdp_addresses_count'] = np.nan

    try: res['norm_cdp_addresses_count'] = norm(data['cdp_addresses_count'].values)
    except: res['norm_cdp_addresses_count'] = np.nan

    try:
        cdp_tlv = [col for col in data.columns if 'cdp' in col and 'tlv' in col]
        sum_cdp_tlv = 0
        for col in cdp_tlv:
            sum_cdp_tlv += data[col].sum(skipskipna=True)
        res['sum_cdp_tlvs'] = sum_cdp_tlv
        del(cdp_tlv)
        del(sum_cdp_tlv)
    except: res['sum_cdp_tlvs'] = np.nan

    try:
        cdp_capabilities = [col for col in data.columns if 'cdp_capabilities' in col and 'tlv' not in col]
        sum_cdp_capabilities = 0
        for col in cdp_capabilities:
            sum_cdp_capabilities += data[col].sum(skipna=True)
        res['sum_cdp_capabilities'] = sum_cdp_capabilities
        del(cdp_capabilities)
        del(sum_cdp_capabilities)
    except: res['sum_cdp_capabilities'] = np.nan


    try: res['mean_cdp_power_sum'] = data['cdp_power_sum'].mean(skipna=True)
    except: res['mean_cdp_power_sum'] = np.nan

    try: res['max_cdp_power_sum'] = data['cdp_power_sum'].max()
    except: res['max_cdp_power_sum'] = np.nan

    try: res['min_cdp_power_sum'] = data['cdp_power_sum'].min()
    except: res['min_cdp_power_sum'] = np.nan

    try: res['median_cdp_power_sum'] = data['cdp_power_sum'].median(skipna=True)
    except: res['median_cdp_power_sum'] = np.nan

    try: res['std_cdp_power_sum'] = data['cdp_power_sum'].std(skipna=True)
    except: res['std_cdp_power_sum'] = np.nan

    try: res['norm_cdp_power_sum'] = norm(data['cdp_power_sum'].values)
    except: res['norm_cdp_power_sum'] = np.nan
    return res

def llc_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['llc_control_ftype'] = data['llc.control_tree']['llc.control.ftype']
    except: res['llc_control_ftype'] = np.nan

    try: res['llc_control_u_modifier'] = data['llc.control_tree']['llc.control.u_modifier_cmd']
    except: res['llc_control_u_modifier'] = np.nan

    try: res['llc_control'] = data['llc.control']
    except: res['llc_control'] = np.nan

    try: res['llc_ssap_cr'] = data['llc.ssap_tree']['llc.ssap.cr']
    except: res['llc_ssap_cr'] = np.nan

    try: res['llc_ssap_sap'] = data['llc.ssap_tree']['llc.ssap.sap']
    except: res['llc_ssap_sap'] = np.nan

    try: res['llc_dsap_sap'] = data['llc.dsap_tree']['llc.dsap.sap']
    except: res['llc_dsap_sap'] = np.nan

    try: res['llc_dsap_ig'] = data['llc.dsap_tree']['llc.dsap.ig']
    except: res['llc_dsap_ig'] = np.nan
    
    return res


def stp_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['stp_version'] = data['stp.version']
    except: res['stp_version'] = np.nan

    try: res['stp_msg_age'] = data['stp.msg_age']
    except: res['stp_msg_age'] = np.nan

    try: res['stp_forward'] = data['stp.forward']
    except: res['stp_forward'] = np.nan

    try: res['stp_flags_tc'] = data['stp.flags_tree']['stp.flags.tc']
    except: res['stp_flags_tc'] = np.nan

    try: res['stp_flags_tcack'] = data['stp.flags_tree']['stp.flags.tcack']
    except: res['stp_flags_tcack'] = np.nan

    try: res['stp_hello'] = data['stp.hello']
    except: res['stp_hello'] = np.nan

    try: 
        root_key= [a for a in data.keys() if a.startswith("Root Identifier")]
        bridge_key= [a for a in data.keys() if a.startswith("Bridge Identifier")]
    except: 
        root_key = np.nan
        bridge_key=np.nan
    
    if root_key != np.nan:
        try: res['stp_root_identifier_prio'] = data[root_key[0]]['stp.root.prio']
        except: res['stp_root_identifier_prio'] = np.nan

        try: res['stp_root_identifier_ext'] = data[root_key[0]]['stp.root.ext']
        except: res['stp_root_identifier_ext'] = np.nan


    if bridge_key != np.nan:
        try: res['stp_bridge_identifier_prio'] = data[bridge_key[0]]['stp.bridge.prio']
        except: res['stp_bridge_identifier_prio'] = np.nan

        try: res['stp_bridge_identifier_ext'] = data[bridge_key[0]][['stp.bridge.ext']]
        except: res['stp_bridge_identifier_ext'] = np.nan

    try: res['stp_root_cost'] = data['stp.root.cost']
    except: res['stp_root_cost'] = np.nan

    try: res['stp_max_age'] = data['stp.max_age']
    except: res['stp_max_age'] = np.nan

    return res

def arp_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['arp_type'] = data['type']
    except: res['arp_type'] = np.nan

    try: res['arp_size'] = data['size']
    except: res['arp_size'] = np.nan

    try: res['arp_dst_hw_mac'] = data['dst.hw_mac']
    except: res['arp_dst_hw_mac'] = np.nan

    try: res['arp_src_hw_mac'] = data['src.hw_mac']
    except: res['arp_src_hw_mac'] = np.nan

    try: res['arp_proto_size'] = data['proto.size']
    except: res['arp_proto_size'] = np.nan

    try: res['arp_hw_size'] = data['hw.size']
    except: res['arp_hw_size'] = np.nan

    try: res['arp_hw_type'] = data['hw.type']
    except: res['arp_hw_type'] = np.nan

    try: res['arp_opcode'] = data['opcode']
    except: res['arp_opcode'] = np.nan

    return res

def loop_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['loop_skipcount'] = data['loop.skipcount']
    except: res['loop_skipcount'] = np.nan

    try: res['loop_receipt_number'] = data['loop.receipt_number']
    except: res['loop_receipt_number'] = np.nan

    try: res['loop_function'] = data['loop.function']
    except: res['loop_function'] = np.nan

    try: res['loop_relevant_function'] = data['loop.relevant_function']
    except: res['loop_relevant_function'] = np.nan

    return res

def dtp_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['dtp_version'] = data['dtp.version']
    except: res['dtp_version'] = np.nan

    try: res['dtp_tlv_len'] = data['Domain']['dtp.tlv_len']
    except: res['dtp_tlv_len'] = np.nan
        
    try: res['dtp_trunk_status_tlv_len'] = data['Trunk Status']['dtp.tlv_len']
    except: res['dtp_trunk_status_tlv_len'] = np.nan


    try: res['dtp_trunk_type_tlv_len'] = data['Trunk Type']['dtp.tlv_len']
    except: res['dtp_trunk_type_tlv_len'] = np.nan


    try: res['dtp_sender_tlv_len'] = data['Sender ID']['dtp.tlv_len']
    except: res['dtp_sender_tlv_len'] = np.nan

    try: res['dtp_sender_id'] = data['Sender ID']['dtp.senderid']
    except: res['dtp_sender_id'] = np.nan

    return res

def isl_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['isl_reserved'] = data['reserved']
    except: res['isl_reserved'] = np.nan

    try: res['isl_index'] = data['isl.index']
    except: res['isl_index'] = np.nan

    try: res['isl_vlan_id'] = data['isl.vlan_id']
    except: res['isl_vlan_id'] = np.nan

    try: res['isl_len'] = data['isl.len']
    except: res['isl_len'] = np.nan

    try: res['isl_bpdu'] = data['isl.bpdu']
    except: res['isl_bpdu'] = np.nan

    try: res['isl_hsa'] = data['isl.hsa']
    except: res['isl_hsa'] = np.nan

    try: res['isl_dsap'] = data['isl.dsap']
    except: res['isl_dsap'] = np.nan

    try: res['isl_ssap'] = data['isl.ssap']
    except: res['isl_ssap'] = np.nan

    try: res['isl_control'] = data['isl.control']
    except: res['isl_control'] = np.nan

    try: res['isl_dst_type'] = data['isl.dst_tree']['isl.type']
    except: res['isl_dst_type'] = np.nan

    try: res['isl_dst_user_eth'] = data['isl.dst_tree']['isl.user_eth']
    except: res['isl_dst_user_eth'] = np.nan

    return res

def cdp_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['cdp_verion'] = data['cdp.version']
    except: res['cdp_verion'] = np.nan

    try: res['cdp_ttl'] = data['cdp.ttl']
    except: res['cdp_ttl'] = np.nan

    try: res['cdp_checkum_status'] = data['cdp.checksum.status']
    except: res['cdp_checkum_status'] = np.nan


    try: 
        device_id_key= [a for a in data.keys() if a.startswith("Device ID")]
        platform_key= [a for a in data.keys() if a.startswith("Platform")]
        port_id_key= [a for a in data.keys() if a.startswith("Port ID")]
        hello_id_key= [a for a in data.keys() if a.startswith("Protocol Hello")]
        vtp_key= [a for a in data.keys() if a.startswith("VTP Management")]
        vlan_key= [a for a in data.keys() if a.startswith("Native VLAN")]
        duplex_key= [a for a in data.keys() if a.startswith("Duplex")]
        trust_bitmap_key= [a for a in data.keys() if a.startswith("Trust Bitmap")]
        untrust_port_key= [a for a in data.keys() if a.startswith("Untrusted port")]
        power_key= [a for a in data.keys() if a.startswith("Power Available")]
        radio_key= [a for a in data.keys() if a.startswith("Radio")]
    except: 
        device_id_key= np.nan
        platform_key = np.nan
        port_id_key = np.nan
        hello_id_key = np.nan
        vtp_key = np.nan
        vlan_key = np.nan
        duplex_key = np.nan
        trust_bitmap_key = np.nan
        untrust_port_key = np.nan
        power_key = np.nan
        radio_key = np.nan


    if device_id_key != np.nan:
        try: res['cdp_device_id_tlv_len'] = data[device_id_key[0]]['cdp.tlv.len']
        except: res['cdp_device_id_tlv_len'] = np.nan

    try: res['cdp_softwware_version_tlv_len'] = data['Software Version']['cdp.tlv.len']
    except: res['cdp_softwware_version_tlv_len'] = np.nan

    if platform_key != np.nan:
        try: res['cdp_platform_tlv_len'] = data[platform_key[0]]['cdp.tlv.len']
        except: res['cdp_platform_tlv_len'] = np.nan

        try: res['cdp_platform'] = data[platform_key[0]]['cdp.platform']
        except: res['cdp_platform'] = np.nan

    try: res['cdp_addresses_tlv_len'] = data['Addresses']['cdp.tlv.len']
    except: res['cdp_addresses_tlv_len'] = np.nan

    try: res['cdp_addresses_count'] = data['Addresses']['cdp.number_of_addresses']
    except: res['cdp_addresses_count'] = np.nan

    try: 
        sum_pro = 0
        sum_addr = 0
        for address in [a for a in data['Addresses'].keys() if a.startswith("IP address")]:
            try: sum_pro += data['Addresses'][address]['cdp.protocol_length']
            except: pass
            try: sum_addr += data['Addresses'][address]['cdp.address_length']
            except: pass
        res['cdp_addresses_sum_len'] = sum_addr
        res['cdp_addresses_sum_protocol_len'] = sum_pro
    except: 
        res['cdp_addresses_sum_len'] = np.nan
        res['cdp_addresses_sum_protocol_len'] = np.nan


    try: 
        sum_pro = 0
        sum_addr = 0
        for address in [a for a in data['Management Addresses'].keys() if a.startswith("IP address")]:
            try: sum_pro += data['Management Addresses'][address]['cdp.protocol_length']
            except: pass
            try: sum_addr += data['Management Addresses'][address]['cdp.address_length']
            except: pass
        res['cdp_management_addresses_sum_len'] = sum_addr
        res['cdp_management_addresses_sum_protocol_len'] = sum_pro
    except: 
        res['cdp_management_addresses_sum_len'] = np.nan
        res['cdp_management_addresses_sum_protocol_len'] = np.nan

    if port_id_key != np.nan:
        try: res['cdp_port_id_tlv_len'] = data[port_id_key[0]]['cdp.tlv.len']
        except: res['cdp_port_id_tlv_len'] = np.nan

    try: res['cdp_capabilities_tlv_len'] = data['Capabilities']['cdp.tlv.len']
    except: res['cdp_capabilities_tlv_len'] = np.nan

    try: res['cdp_capabilities_router'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.router']
    except: res['cdp_capabilities_router'] = np.nan

    try: res['cdp_capabilities_trans_bridge'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.trans_bridge']
    except: res['cdp_capabilities_trans_bridge'] = np.nan

    try: res['cdp_capabilities_src_bridge'] = data['Capabilities']['cdp.capabilities_tree']['src_bridge']
    except: res['cdp_capabilities_src_bridge'] = np.nan

    try: res['cdp_capabilities_switch'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.switch']
    except: res['cdp_capabilities_switch'] = np.nan

    try: res['cdp_capabilities_host'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.host']
    except: res['cdp_capabilities_host'] = np.nan

    try: res['cdp_capabilities_igmp'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.igmp_capable']
    except: res['cdp_capabilities_iigmp'] = np.nan

    try: res['cdp_capabilities_repeater'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.repeater']
    except: res['cdp_capabilities_repeater'] = np.nan

    try: res['cdp_capabilities_repeater'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.repeater']
    except: res['cdp_capabilities_repeater'] = np.nan

    try: res['cdp_capabilities_voip_phone'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.voip_phone']
    except: res['cdp_capabilities_voip_phone'] = np.nan

    try: res['cdp_capabilities_remote'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.remote']
    except: res['cdp_capabilities_remote'] = np.nan

    try: res['cdp_capabilities_cvta'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.cvta']
    except: res['cdp_capabilities_cvta'] = np.nan

    try: res['cdp_capabilities_mac_relay'] = data['Capabilities']['cdp.capabilities_tree']['cdp.capabilities.mac_relay']
    except: res['cdp_capabilities_mac_relay'] = np.nan

    if hello_id_key != np.nan:
        try: res['cdp_hello_tlv_len'] = data[hello_id_key[0]]['cdp.tlv.len']
        except: res['cdp_hello_tlv_len'] = np.nan

        try: res['cdp_hello_oui'] = data[hello_id_key[0]]['cdp.oui']
        except: res['cdp_hello_oui'] = np.nan

        try: res['cdp_hello_num_unknown'] = len(data[hello_id_key[0]]['cdp.cluster.unknown'])
        except:  res['cdp_hello_num_unknown'] = np.nan

        try: res['cdp_hello_management_vlan'] = data[hello_id_key[0]]['cdp.cluster.management_vlan']
        except: res['cdp_hello_management_vlan'] = np.nan

    if vtp_key != np.nan:
        try: res['cdp_vtp_management_tlv_len'] = data[vtp_key[0]]['cdp.tlv.len']
        except: res['cdp_vtp_management_tlv_len'] = np.nan

    if vlan_key != np.nan:
        try: res['cdp_vlan_native_tlv_len'] = data[vlan_key[0]]['cdp.tlv.len']
        except: res['cdp_vlan_native_tlv_len'] = np.nan

        try: res['cdp_vlan_native_native_vlan'] = data[vlan_key[0]]['cdp.native_vlan']
        except: res['cdp_vlan_native_native_vlan'] = np.nan

    if duplex_key != np.nan:
        try: res['cdp_duplex_tlv_len'] = data[duplex_key[0]]['cdp.tlv.len']
        except: res['cdp_duplex_tlv_len'] = np.nan

        try: res['cdp_duplex'] = data[duplex_key[0]]['cdp.duplex']
        except: res['cdp_duplex'] = np.nan

    if trust_bitmap_key != np.nan:
        try: res['cdp_duplex_tlv_len'] = data[trust_bitmap_key[0]]['cdp.tlv.len']
        except: res['cdp_duplex_tlv_len'] = np.nan

    if untrust_port_key != np.nan:
        try: res['cdp_duplex_tlv_len'] = data[untrust_port_key[0]]['cdp.tlv.len']
        except: res['cdp_duplex_tlv_len'] = np.nan

    if power_key != np.nan:
        try: res['cdp_power_tlv_len'] = data[power_key[0]]['cdp.tlv.len']
        except: res['cdp_power_tlv_len'] = np.nan
            
    if power_key != np.nan:
        try: res['cdp_power_tlv_len'] = data[power_key[0]]['cdp.tlv.len']
        except: res['cdp_power_tlv_len'] = np.nan

        try: res['cdp_power_request_id'] = data[power_key[0]]['cdp.request_id']
        except: res['cdp_power_request_id'] = np.nan

        try: res['cdp_power_management_id'] = data[power_key[0]]['cdp.management_id']
        except: res['cdp_power_management_id'] = np.nan

        try: res['cdp_power_sum'] = sum(data[power_key[0]]['cdp.power_available'])
        except: res['cdp_power_sum'] = np.nan

    try: res['cdp_spare_pair_tlv_len'] = data['Spare Pair PoE']['cdp.tlv.len']
    except: res['cdp_spare_pair_tlv_len'] = np.nan

    try: res['cdp_spare_poe_tlv_poe'] = data['Spare Pair PoE']['cdp.spare_poe_tlv_tree']['cdp.spare_poe_tlv.poe']
    except: res['cdp_spare_poe_tlv_poe'] = np.nan

    try: res['cdp_spare_poe_tlv_spare_pair_arch'] = data['Spare Pair PoE']['cdp.spare_poe_tlv_tree']['cdp.spare_poe_tlv.spare_pair_arch']
    except: res['cdp_spare_poe_tlv_spare_pair_arch'] = np.nan

    try: res['cdp_spare_poe_tlv_req_spare_pair_poe'] = data['Spare Pair PoE']['cdp.spare_poe_tlv_tree']['cdp.spare_poe_tlv.req_spare_pair_poe']
    except: res['cdp_spare_poe_tlv_req_spare_pair_poe'] = np.nan

    try: res['cdp_spare_poe_tlv_pse_spare_pair_poe'] = data['Spare Pair PoE']['cdp.spare_poe_tlv_tree']['cdp.spare_poe_tlv.pse_spare_pair_poe']
    except: res['cdp_spare_poe_tlv_pse_spare_pair_poe'] = np.nan

    if radio_key != np.nan:
        try: res['cdp_power_tlv_len'] = data[radio_key[0]]['cdp.tlv.len']
        except: res['cdp_power_tlv_len'] = np.nan
        try: res['cdp_power_platform'] = data[radio_key[0]]['cdp.platform']
        except: res['cdp_power_platform'] = np.nan

    

    return res


def dhcp_ext(data,index):
    res = dict()
    res['pkt_num'] = index

    try: res['dhcp_hw_type'] = data['dhcp.type']
    except: res['dhcp_hw_type'] = np.nan

    try: res['dhcp_padding'] = data['dhcp.hw.addr_padding']
    except: res['dhcp_padding'] = np.nan

    try: res['dhcp_hw_len'] = data['dhcp.hw.len']
    except: res['dhcp_hw_len'] = np.nan

    try: res['dhcp_secs'] = data['dhcp.secs']
    except: res['dhcp_secs'] = np.nan

    try: res['dhcp_cookie'] = data['dhcp.cookie']
    except: res['dhcp_cookie'] = np.nan

    try: res['dhcp_type'] = data['dhcp.hw.type']
    except: res['dhcp_type'] = np.nan

    try: res['dhcp_hops'] = data['dhcp.hops']
    except: res['dhcp_hops'] = np.nan

    try: res['dhcp_hw_len'] = data['dhcp.hw.len']
    except: res['dhcp_hw_len'] = np.nan

    try: res['dhcp_flags_bc'] = data['dhcp.flags_tree']['dhcp.flags.bc']
    except: res['dhcp_flags_bc'] = np.nan

    try: res['dhcp_flags_bc'] = data['dhcp.flags_tree']['dhcp.flags.reserved']
    except: res['dhcp_flags_bc'] = np.nan

    try: 
        sum = 0
        for option in data['dhcp.option.type_tree']:
            try: sum+=int(option['dhcp.option.length'])
            except: continue
        res['dhcp_options_len'] = 0
    except: res['dhcp_options_len'] = 0

    try: res['dhcp_option_padding'] = data['dhcp.option.padding']
    except: res['dhcp_option_padding'] = np.nan

    try: res['dhcp_options'] = len(data['dhcp.option.type'])
    except: res['dhcp_options'] = np.nan