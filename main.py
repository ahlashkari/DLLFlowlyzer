from IO.pcapExt import pcap_reader
from IO.csvSave import pkt_csv,flow_csv
import argparse
import warnings
import yaml
from featureExt.flowPred import flow_pred
from featureExt.flowFeatureExt import flow_feature_ext

global PCAP_PATH
global FINAL_FILE_PATH
global FINAL_FILE_NAME
global CAP_UDP
global JUSTTCP
global EXTRA
global FEATURES


import time

warnings.filterwarnings("ignore")
parser = argparse.ArgumentParser(
                    prog='ETH_FLOW',
                    description='DataLink Layer Feature Extractor')
def extract_save():
    eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp,flow = pcap_reader(PCAP_PATH, CAP_UDP,JUSTTCP, EXTRA, FEATURES)
    pkt_csv(eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp,flow,FINAL_FILE_PATH, FINAL_FILE_NAME)
    list_dict = flow_pred(f'{FINAL_FILE_PATH}/pkts_all_{FINAL_FILE_NAME}', EXTRA, FEATURES, CAP_UDP)
    flow_csv(list_dict,FINAL_FILE_PATH, FINAL_FILE_NAME)


if __name__=="__main__":
    parser.add_argument('-R', '--result', action='store', help='base file name for results (without .csv)')
    parser.add_argument('-S', '--save', action='store', help='save folder to store the results')
    parser.add_argument('-P', '--pcap', action='store', help='path to pcap file')
    parser.add_argument('-U', '--UDP', action='store_true', help='capture udp')
    parser.add_argument('-J', '--justTCP',action='store_true', help='Extract features just in TCP connections')
    parser.add_argument('-E', '--extra', action='store_true', help='extract all extra features from pcap(llc,stp,arp,loop,dtp,isl,cdp,dhcp)')
    parser.add_argument('-F', '--features', action='store', help='select which extra features to save as below:\n'
                                                                 '** l(llc), s(stp), a(arp), t(loop), d(dtp), i(isl), c(cdp), h(dhcp) **  \n'
                                                                 '<for instance: -F latc > ## to capture llc, arp, loop, cdp ##')
    args = parser.parse_args()

    with open(r'setting.yaml') as file:
        setting = yaml.safe_load(file)

    if args.result:
        FINAL_FILE_NAME = args.result + '.csv'
    else:
        FINAL_FILE_NAME = setting[0]['Files']['FINAL_FILE_NAME']
    if args.save:
        FINAL_FILE_PATH = args.save
    else:
        FINAL_FILE_PATH = setting[0]['Files']['FINAL_FILE_PATH']
    if args.pcap:
        PCAP_PATH = args.pcap
    else:
        PCAP_PATH = setting[0]['Files']['PCAP_PATH']
    if args.UDP:
        CAP_UDP = args.UDP
    else:
        CAP_UDP = setting[1]['Capture']['CAP_UDP']
    if args.justTCP:
        JUSTTCP = args.justTCP
    else:
        JUSTTCP = setting[1]['Capture']['JUSTTCP']
    if args.extra:
        EXTRA = args.extra
    else:
        EXTRA = setting[1]['Capture']['extra']
    if args.features:
        FEATURES = [char for char in args.features]
    else:
        FEATURES = setting[1]['Capture']['features']

    print(f'SETTINGS: \nPCAP_PATH:{PCAP_PATH}\nFINAL_FILE_PATH:{FINAL_FILE_PATH}\nFINAL_FILE_NAME:{FINAL_FILE_NAME}\
          \nCAP_UDP:{CAP_UDP}\nJUSTTCP:{JUSTTCP}\nEXTRA:{EXTRA}\nFEATURES:{FEATURES}')

    start = time.time()
    extract_save()
    end = time.time()
    print(f'time is : {end-start}')