import socket
from memory_profiler import profile
import pandas as pd
import time

@profile
def getDomain(ip):
    start_getDomain = time.time()
    try:
        return socket.gethostbyaddr(ip)
    except:
        return 'unknown.unknown.com'
    end_getDomain = time.time()
    print('Elapsed time by getDomain', end_getDomain - start_getDomain)

@profile
def dns_query(sample_df):
    start_dns = time.time()
    sample_df['Destination_IP'] = sample_df['Destination_IP'].astype(str).str.replace('"', '')
    input_df = sample_df[sample_df['Col6'].isin(['RT_FLOW_SESSION_CREATE_LS'])]
    input_df['Domain']= input_df['Destination_IP'].map(lambda IP:getDomain(IP))
    end_dns = time.time()
    print('Elapsed time by dns_query', end_dns - start_dns)
    return input_df

@profile
def cleanDomain(input_df):
    start_clean = time.time()
    #print(input_df['Domain'].head(10))
    input_df['Domain'] = input_df['Domain'].map(lambda domain:domain[0].rsplit(".",2))
    #print(input_df['Domain'].head())
    input_df['Domain'] = input_df['Domain'].map(lambda domain:domain[(len(domain)) -2] +'.'+ domain[(len(domain))-1])
    #print(input_df['Domain'].head())
    end_clean = time.time()
    print('Elapsed time by clean Domain', end_clean - start_clean)
    return input_df

@profile
# get normalised df
def normalised_df():
    start_norm = time.time()
    file1 = open('OJT_OJT_S02_SYSLOG1_2022020317020085_4.u_355')
    #Assigning sample headers to the file
    hdr = ["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","18","19","20","21","22",
      "23","24","25","26","27","28","29","30","31","32","33","34","35","36","37","38","39","40","41","42",
      "43","44","45","46","47"]
    df = pd.read_csv(file1, header=None, names= hdr, delim_whitespace = True)
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    df.columns = hdr

    #display(df.loc[:7])

    #Creating dataframe extracting desired columns
    new_df = df.drop(['1','5'], axis=1)
    #display(new_df.loc[:5])

    #Normalizing columns with desired data rom each column record
    norm_3G = new_df['8'].astype(str).str.extract(r'(".*")')
    norm_IP = new_df['9'].astype(str).str.extract(r'(".*")')
    norm_port = new_df['10'].astype(str).str.extract(r'(".*")')
    norm_dst_IP = new_df['11'].astype(str).str.extract(r'(".*")')
    norm_dst_port = new_df['12'].astype(str).str.extract(r'(".*")')
    norm_conn_tag = new_df['12'].astype(str).str.extract(r'(".*")')

    #df.columns.str.split('value.').str[-1]
    norm_service_name = new_df['14'].astype(str).str.extract(r'(".*")')
    norm_15 = new_df['15'].astype(str).str.extract(r'(".*")')
    norm_16 = new_df['16'].str.split('port=').str[-1]
    norm_18 = new_df['18'].str.split('address=').str[-1]
    norm_19 = new_df['19'].str.split('port=').str[-1]
    norm_20 = new_df['20'].str.split('tag=').str[-1]
    norm_21 = new_df['21'].str.split('type=').str[-1]
    norm_23 = new_df['23'].str.split('name=').str[-1]
    norm_24 = new_df['24'].str.split('type=').str[-1]
    norm_25 = new_df['25'].str.split('name=').str[-1]
    norm_26 = new_df['26'].str.split('id=').str[-1]
    norm_27 = new_df['27'].str.split('name=').str[-1]

    norm_28 = new_df['28'].str.split('zone-name=').str[-1]
    norm_29 = new_df['29'].str.split('zone-name=').str[-1]
    norm_30 = new_df['30'].astype(str).str.extract(r'(".*")')
    norm_31 = new_df['31'].str.split('username=').str[-1]
    norm_32 = new_df['32'].str.split('roles=').str[-1]
    norm_33 = new_df['33'].str.split('incoming-interface=').str[-1]
    norm_34 = new_df['34'].str.split('application=').str[-1]
    norm_35 = new_df['35'].str.split('encrypted=').str[-1]



    normalize_df = pd.DataFrame({
        'Timestamp': new_df['2'],
        'Col3': new_df['3'],
        'Col4':new_df['4'],
        'Col6': new_df['6'],
        'Col7':new_df['7'],
        'Logical_sys_name': norm_3G[0],
        'Source_Addr': norm_IP[0],
        'Source_port': norm_port[0],
        'Destination_IP': norm_dst_IP[0],
        'Destination_port': norm_dst_port[0],
        'Connection_tag': norm_conn_tag[0],
        'Service_Name':norm_service_name[0],
        'Nat_source_Addr':norm_15[0],
        'Nat_Source_port':norm_16[0],
        'Nat_dest_Addr':norm_18[0],
        'Nat_dest_port':norm_19[0],
        'Nat_conn_Tag':norm_20[0],
        'Nat_rule_type':norm_21[0],
        'Rule':new_df['22'],
        'NAT_Rule_Name':norm_23[0],
        'Dst_NAT_Rule_Type':norm_24[0],
        'Dst_NAT_Rule_Name':norm_25[0],
        'protocol_id':norm_26[0],
        'Policy_name':norm_27[0],
        'Source_zone_name':norm_28[0],
        'Dest_zone_name':norm_29[0],
        'Session_id_32':norm_30[0],
        'username':norm_31[0],
        'roles':norm_32[0],
        'Packet_incoming_iface': norm_33[0]})
    end_norm = time.time()
    print('Elapsed time by norm', end_norm - start_norm)
    return normalize_df

normalize_df = normalised_df()
dns_df = dns_query(normalize_df.loc[:])
clean_df =  cleanDomain(dns_df)
print(clean_df.head(3))

