import pandas as pd
import numpy as np
from numpy.linalg import norm
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)


def flow_pred(file, EXTRA, FEATURES):
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
        csv_dict.append(flow_feature_ext(grouped_df, EXTRA, FEATURES))

    return csv_dict

def flow_feature_ext(data, EXTRA, FEATURES):
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

    try: res['percent_frame_marked'] = len(data['frame_marked'].loc[data['frame_marked']==1]) / len(data)
    except: res['percent_frame_marked'] = np.nan

    try: res['percent_frame_ignored'] = len(data['frame_ignored'].loc[data['frame_ignored']==1]) / len(data)
    except: res['percent_frame_ignored'] = np.nan

    if EXTRA:
        if 'l' in FEATURES:
            try: res['num_llc_frame'] = len(data['has_llc'].loc[data['has_llc']==1])
            except: res['num_llc_frame'] = np.nan

            try: res['percent_llc_frame'] = len(data['has_llc'].loc[data['has_llc']==1]) / len(data)
            except: res['percent_llc_frame'] = np.nan

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

        if 's' in FEATURES:
            try: res['num_stp_frame'] = len(data['has_stp'].loc[data['has_stp']==1])
            except: res['num_stp_frame'] = np.nan

            try: res['percent_stp_frame'] = len(data['has_stp'].loc[data['has_stp']==1]) / len(data)
            except: res['percent_stp_frame'] = np.nan

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

        if 't' in FEATURES: 
            try: res['sum_loop_skipcount'] = data['loop_skipcount'].sum(skipna=True)
            except: res['sum_loop_skipcount'] = np.nan

            try: res['num_loop_frame'] = len(data['has_loop'].loc[data['has_loop']==1])
            except: res['num_loop_frame'] = np.nan

            try: res['percent_loop_frame'] = len(data['has_loop'].loc[data['has_loop']==1]) / len(data)
            except: res['percent_loop_frame'] = np.nan

        if 'd' in FEATURES: 
            try: res['num_dtp_frame'] = len(data['has_dtp'].loc[data['has_dtp']==1])
            except: res['num_dtp_frame'] = np.nan

            try: res['percent_dtp_frame'] = len(data['has_dtp'].loc[data['has_dtp']==1]) / len(data)
            except: res['percent_dtp_frame'] = np.nan

            try: res['sum_dtp_tlvs'] = data['dtp_tlv_len'].sum(skipna=True) + data['dtp_sender_tlv_len'].sum(skipna=True) + data['dtp_trunk_status_tlv_len'].sum(skipna=True) + data['dtp_trunk_type_tlv_len'].sum(skipna=True)
            except: res['sum_dtp_tlvs'] = np.nan

        if 'i' in FEATURES: 
            try: res['num_isl_frame'] = len(data['has_isl'].loc[data['has_isl']==1])
            except: res['num_isl_frame'] = np.nan

            try: res['percent_isl_frame'] = len(data['has_isl'].loc[data['has_isl']==1]) / len(data)
            except: res['percent_isl_frame'] = np.nan

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

        if 'a' in FEATURES: 
            try: res['num_arp_frame'] = len(data['has_arp'].loc[data['has_arp']==1])
            except: res['num_arp_frame'] = np.nan

            try: res['percent_arp_frame'] = len(data['has_arp'].loc[data['has_arp']==1]) / len(data)
            except: res['percent_arp_frame'] = np.nan

        if 'h' in FEATURES: 
            try: res['num_dhcp_frame'] = len(data['has_dhcp'].loc[data['has_dhcp']==1])
            except: res['num_dhcp_frame'] = np.nan

            try: res['percent_dhcp_frame'] = len(data['has_dhcp'].loc[data['has_dhcp']==1]) / len(data)
            except: res['percent_dhcp_frame'] = np.nan

        if 'c' in FEATURES: 
            try: res['num_cdp_frame'] = len(data['has_cdp'].loc[data['has_cdp']==1])
            except: res['num_cdp_frame'] = np.nan
            
            try: res['percent_cdp_frame'] = len(data['has_cdp'].loc[data['has_cdp']==1]) / len(data)
            except: res['percent_cdp_frame'] = np.nan

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
        
        
