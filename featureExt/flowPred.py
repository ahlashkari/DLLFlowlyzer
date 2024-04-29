import pandas as pd
from . import flowFeatureExt
def flow_pred(file, EXTRA, FEATURES):
    df = pd.read_csv(file)
    aaa = df.groupby(['dist_addr', 'src_addr'])
    if df.connection.all() == 'UDP' or df.connection.all() == 'TCP':
        aaa = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port'])
    bbb = [aaa.get_group(x) for x in aaa.groups]
    del (aaa)
    dfs = []
    checked = []
    for i in range(len(bbb)):
        for j in range(i, len(bbb)):
            if i != j:
                cond = {bbb[i].src_addr.unique()[0], bbb[i].dist_addr.unique()[0], bbb[i].src_ip.unique()[0], bbb[i].dst_ip.unique()[0], bbb[i].src_port.unique()[0], bbb[i].dst_port.unique()[0]} == {bbb[j].src_addr.unique()[0],
                                                                                   bbb[j].dist_addr.unique()[0],bbb[j].src_ip.unique()[0],bbb[j].dst_ip.unique()[0], bbb[j].src_port.unique()[0], bbb[j].dst_port.unique()[0],}
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
        csv_dict.append(flowFeatureExt.flow_feature_ext(grouped_df, EXTRA, FEATURES))

    return csv_dict