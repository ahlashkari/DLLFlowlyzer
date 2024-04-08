from pcapExt import pcap_reader
from csvSave import pkt_csv,flow_csv
import argparse
import warnings
from featureExt import flow_pred

global PCAP_PATH
PCAP_PATH = "./test.pcap"
global FINAL_FILE_PATH
FINAL_FILE_PATH='Res'
global FINAL_FILE_NAME
FINAL_FILE_NAME='FINAL.csv'
global CAP_UDP
CAP_UDP = False

warnings.filterwarnings("ignore")
parser = argparse.ArgumentParser(
                    prog='ETH_FLOW',
                    description='DataLink Layer Feature Extractor')
def extract_save():
    eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp = pcap_reader(PCAP_PATH, CAP_UDP)
    pkt_csv(eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp,FINAL_FILE_PATH, FINAL_FILE_NAME)
    list_dict = flow_pred(f'{FINAL_FILE_PATH}/pkts_all_{FINAL_FILE_NAME}')
    flow_csv(list_dict,FINAL_FILE_PATH, FINAL_FILE_NAME)

if __name__=="__main__":
    parser.add_argument('-R', '--result',action='store', help='base file name for results (without .csv)')
    parser.add_argument('-F', '--folder',action='store', help='folder to store the results')
    parser.add_argument('-P', '--pcap' ,action='store', help='path to pcap file')
    parser.add_argument('-U', '--UDP' ,default=True,action='store_true', help='capture udp')
    args = parser.parse_args()
    print(args)
    if args.result:
        FINAL_FILE_NAME = args.result + '.csv'
    if args.folder:
        FINAL_FILE_PATH = args.folder
    if args.pcap:
        PCAP_PATH = args.pcap
    if args.UDP:
        CAP_UDP = args.UDP
        
    extract_save()

   