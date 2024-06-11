import os

from datetime import datetime
from pyspark.sql import SparkSession

spark = SparkSession.builder.getOrCreate()
def pkt_csv(eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp,flow_pred,FINAL_FILE_PATH, FINAL_FILE_NAME):
    if not os.path.exists(FINAL_FILE_PATH):
        os.makedirs(FINAL_FILE_PATH)
    else:
        os.system(f'rm -rf {FINAL_FILE_PATH}/*')

    pkt_df_eth = spark.createDataFrame(eth)
    pkt_df_extra= spark.createDataFrame(extra)

    pkt_df_eth.to_csv(f'{FINAL_FILE_PATH}/pkts_eth_{FINAL_FILE_NAME}',index=False)

    protos = []
    if len(llc) >0:
        protos.append(llc)
    if len(stp) >0:
        protos.append(stp)
    if len(loop) >0:
        protos.append( loop)
    if len(dtp) >0:
        protos.append(dtp)
    if len(isl) >0:
        protos.append(isl)
    if len(cdp) >0:
        protos.append(cdp)
    if len(dhcp) >0:
        protos.append(dhcp)
    if len(arp)>0:
        protos.append(arp)

    proto_data = True
    if len(protos)==1:
        df_inner_protocols =  spark.createDataFrame(protos[0])
    elif len(protos)==2:
        df_inner_protocols = spark.createDataFrame(protos[0]).merge(spark.createDataFrame(protos[1]), on='pkt_num' ,how='outer')
    elif len(protos)>2:
        df_inner_protocols = spark.createDataFrame(protos[0]).merge( spark.createDataFrame(protos[1]),  on='pkt_num' ,how='outer')
        for i in range(2,len(protos)):
            df_inner_protocols = df_inner_protocols.merge(spark.createDataFrame(protos[i]),  on='pkt_num' ,how='outer')
    else:
        proto_data = False

    if proto_data:
        df_inner_protocols.to_csv(f'{FINAL_FILE_PATH}/pkts_protocols_{FINAL_FILE_NAME}',index=False)

    df_inner = pkt_df_eth.merge(pkt_df_extra, on='pkt_num', how='inner')
    df_inner = df_inner.merge(spark.createDataFrame(flow_pred), on='pkt_num',how='outer')
    if proto_data:
        df_inner = df_inner.merge(df_inner_protocols, on='pkt_num' ,how='outer')

    df_inner.to_csv(f'{FINAL_FILE_PATH}/pkts_all_{FINAL_FILE_NAME}', index=False)

    print(f'packets csv Created at {FINAL_FILE_PATH} and protocols data is {proto_data}')

def flow_csv(list_dict,FINAL_FILE_PATH, FINAL_FILE_NAME):
     
    dfs_list = []
    for dic in list_dict:
        dfs_list.append(spark.createDataFrame([dic]))
    if len(dfs_list)>2:
        final = dfs_list[0].union(dfs_list[1])
        for df in dfs_list[2:]:
            final = final.union(df)
    elif len(dfs_list)==2:
        final = dfs_list[0].union(dfs_list[1])
    else:
        final = dfs_list[0].copy()

    final = final.drop_duplicates(keep='last')
    final.to_csv(f'{FINAL_FILE_PATH}/{datetime.now().strftime("%Y-%m-%d")}-{datetime.now().time().strftime("%H-%M")}-final_flow-{FINAL_FILE_NAME}', index=False)
    print(f'flows csv Created at {FINAL_FILE_PATH}/{datetime.now().strftime("%Y-%m-%d")}-{datetime.now().time().strftime("%H-%M")}-final_flow-{FINAL_FILE_NAME}')