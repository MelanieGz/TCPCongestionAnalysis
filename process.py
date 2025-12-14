import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np

# ----------- Processes Each Pcap File with Same Bandwidth Changes ---------------------
def process(pcap_file, bw_file):
    bw = pd.read_csv(bw_file)
    bw.columns = ['time', 'bandwidth']
    bw['time'] = pd.to_datetime(bw['time'], unit='s', utc=True).dt.tz_convert('America/Los_Angeles')
    
    with pyshark.FileCapture(pcap_file, use_json=True) as pcap:
        rows = []
        for pkt in pcap:
            if 'TCP' not in pkt:
                continue
            row = {
                'src_port': int(pkt.tcp.srcport),
                'dst_port': int(pkt.tcp.dstport),
                'time': pd.to_datetime(pkt.frame_info.time_epoch, utc=True),
                'time_sec': datetime.fromisoformat(pkt.frame_info.time_epoch.replace("Z", "+00:00")).timestamp(),
                'seq': int(pkt.tcp.seq),
                'ack': int(pkt.tcp.ack),
                'len': int(pkt.tcp.len),
                'window': int(pkt.tcp.window_size_value),
                'ip_len': int(pkt.ip.len),
            }
            rows.append(row)
    df = pd.DataFrame(rows)
    df['time'] = df['time'].dt.tz_convert('America/Los_Angeles')

    flows = df.groupby(['src_port','dst_port']).size().reset_index(name='packet_count')
    main_flow = flows.nlargest(1, 'packet_count').iloc[0]
    src, dst = main_flow['src_port'], main_flow['dst_port']

    main_df = df[((df['src_port'] == src) & (df['dst_port'] == dst)) |
             ((df['src_port'] == dst) & (df['dst_port'] == src))].reset_index(drop=True)

    t = main_df['time'].min()
    main_df['sec'] = (main_df['time'] - t).dt.total_seconds()
    bw['sec'] = (bw['time'] - t).dt.total_seconds()
    
    return main_df, bw

# ----------- Gets Congestion Window ---------------------
def get_cwnd(df, bw):
    cwnd = []
    high_seq = 0
    high_ack = 0
    for i in range(len(df)):
        seq = df.loc[i, 'seq']
        ack = df.loc[i, 'ack']
        payload_len = df.loc[i, 'len']
        high_seq = max(high_seq, seq + payload_len)
        high_ack = max(high_ack, ack)
        in_flight = max(0, high_seq - high_ack)
        cwnd.append(in_flight)

    df['cwnd'] = cwnd
    
    return df, bw

# ----------- Gets Throughput ---------------------
def get_throughput(df):
    sec = 1
    size = 0
    throughput = []
    first = df['sec'].iloc[0]
    for i in range(len(df)):
        if df['sec'].iloc[i] - first <= sec:
            size += df.loc[i, 'len']
        else:
            throughput.append((size * 8) / 1000000)
            sec += 1
            size = df.loc[i, 'len']
    throughput.append((size * 8) / 1000000)
    return throughput

# ----------- Gets Packet Retransmissions, Out Of Order, Lost ---------------------
def get_packetInfo(df):
    out_of_order = [0] * len(df)
    num = 0
    prev_seq = df.loc[0, 'seq']
    for i in range(len(df)):
        curr_seq = df.loc[i, 'seq']
        if curr_seq < prev_seq:
            num += 1
            out_of_order[i] = 1
        prev_seq = curr_seq
    df['out_of_order'] = out_of_order
    
    retransmissions = [0] * len(df)
    lost_packets = [0] * len(df)
    num = 0
    
    seen_seqs = set()
    for i in range(len(df)):
        seq = df.loc[i, 'seq']
        if seq in seen_seqs:
            num += 1 
            retransmissions[i] = 1
        else:
            seen_seqs.add(seq)
    df['retransmissions'] = retransmissions   
    
    triple = {}
    num = 0
    for i in range(len(df)):
        ack = df.loc[i, 'ack']
        if ack in triple:
            triple[ack] += 1 
            if triple[ack] == 3:
                num += 1
                lost_packets[i] = 1
        else:
            triple[ack] = 1
    df['lost_packets'] = lost_packets 
    
    df['sec_int'] = df['sec'].astype(int)
    retransmits_sum = df.groupby('sec_int')['retransmissions'].sum().reset_index()
    order_sum = df.groupby('sec_int')['out_of_order'].sum().reset_index()
    loss_sum = df.groupby('sec_int')['lost_packets'].sum().reset_index()

    return retransmits_sum, order_sum, loss_sum, df

# ----------- Change PCAP files to Dataframe ---------------------
bandwidth = input("Enter any of the following variable mobile link situations: \n10-2-15, 5-15-7, 5-10-15 \n")

reno_df, reno_bw = process(f"TCPDumpBW/{bandwidth}/Reno/romeo.pcap", f"TCPDumpBW/{bandwidth}/Reno/bandwidth_time.csv")
cubic_df, cubic_bw = process(f"TCPDumpBW/{bandwidth}/Cubic/romeo.pcap", f"TCPDumpBW/{bandwidth}/Cubic/bandwidth_time.csv")
bbr_df, bbr_bw = process(f"TCPDumpBW/{bandwidth}/BBR/romeo.pcap", f"TCPDumpBW/{bandwidth}/BBR/bandwidth_time.csv")

# ----------- Compute Packet Info  ---------------------
reno_r, reno_o, reno_l, reno_df = get_packetInfo(reno_df)
cubic_r, cubic_o, cubic_l, cubic_df = get_packetInfo(cubic_df)
bbr_r, bbr_o, bbr_l, bbr_df = get_packetInfo(bbr_df)

# ----------- Compute Throughput ---------------------
reno_throughput = get_throughput(reno_df)
cubic_throughput = get_throughput(cubic_df)
bbr_throughput = get_throughput(bbr_df)

# ----------- Compute Congestion Window ---------------------
reno_cwnd, r_bw = get_cwnd(reno_df, reno_bw)
cubic_cwnd , c_bw= get_cwnd(cubic_df, cubic_bw)
bbr_cwnd, b_bw = get_cwnd(bbr_df, bbr_bw)

# ----------- Congestion Window Plot ---------------------
fig1, axs1 = plt.subplots(2, 1, figsize=(14,8))
fig1.suptitle(f"Comparing Reno, BBR, and Cubic on a {bandwidth} Bandwidth Change Situation", fontsize=16)

axs1[0].plot(reno_cwnd['sec'], reno_cwnd['cwnd'], label='Reno', color='red')
axs1[0].plot(cubic_cwnd['sec'], cubic_cwnd['cwnd'], label='Cubic', color='green')
axs1[0].plot(bbr_cwnd['sec'], bbr_cwnd['cwnd'], label='BBR', color='purple')
axs1[0].set_title("Congestion Window")
axs1[0].set_xlabel('Time (seconds)', labelpad=30)
axs1[0].set_ylabel('Congestion Window (bytes)')
axs1[0].grid(True)
axs1[0].legend()
axs1[0].legend(loc='upper left')

ymin, ymax = axs1[0].get_ylim()
y_text = ymin - 0.05 * (ymax - ymin)

for x, bw in zip(r_bw['sec'], r_bw['bandwidth']):
    axs1[0].axvline(x, color='red', linestyle=':', alpha=0.5)
    axs1[0].text(x, y_text, f"{bw} Mbps", rotation=90, ha='center', va='top', fontsize=8)

for x, bw in zip(c_bw['sec'], c_bw['bandwidth']):
    axs1[0].axvline(x, color='green', linestyle=':', alpha=0.5)

for x, bw in zip(b_bw['sec'], b_bw['bandwidth']):
    axs1[0].axvline(x, color='purple', linestyle=':', alpha=0.5)

# ----------- Throughput Plot ---------------------
tim_r = range(len(reno_throughput))
tim_c = range(len(cubic_throughput))
tim_b = range(len(bbr_throughput))

axs1[1].plot(tim_r, reno_throughput, label='Reno', color='red')
axs1[1].plot(tim_c, cubic_throughput, label='Cubic', color='green')
axs1[1].plot(tim_b, bbr_throughput, label='BBR', color='purple')
axs1[1].set_title("Throughput")
axs1[1].set_xlabel('Time (seconds)', labelpad=30)
axs1[1].set_ylabel('Throughput (megabits per second)')
axs1[1].grid(True)
axs1[1].legend()
axs1[1].legend(loc='upper left')

ymin, ymax = axs1[1].get_ylim()
y_text = ymin - 0.05 * (ymax - ymin)

for x, bw in zip(r_bw['sec'], r_bw['bandwidth']):
    axs1[1].axvline(x, color='red', linestyle=':', alpha=0.5)
    axs1[1].text(x, y_text, f"{bw} Mbps", rotation=90, ha='center', va='top', fontsize=8)

for x, bw in zip(c_bw['sec'], c_bw['bandwidth']):
    axs1[1].axvline(x, color='green', linestyle=':', alpha=0.5)

for x, bw in zip(b_bw['sec'], b_bw['bandwidth']):
    axs1[1].axvline(x, color='purple', linestyle=':', alpha=0.5)
    
plt.tight_layout()
plt.show()

# ----------- Packet Critical Event Plots ---------------------
fig, axs = plt.subplots(2, 2, figsize=(14,8))
fig.suptitle(f"Comparing Reno, BBR, and Cubic on a {bandwidth} Bandwidth Change Situation")

axs[0,0].plot(reno_r['sec_int'], reno_r['retransmissions'], color='red', label='Retransmissions')
axs[0,0].plot(reno_o['sec_int'], reno_o['out_of_order'], color='blue', label='Out of Order')
axs[0,0].plot(reno_l['sec_int'], reno_l['lost_packets'], color='green', label='Lost')
axs[0,0].set_title("Reno Critical Events")
axs[0,0].set_ylabel("Number of Packets")
axs[0,0].set_xlabel("Time (seconds)", labelpad=30)
axs[0,0].grid(True)
axs[0,0].legend()
axs[0,0].legend(loc='upper left')

axs[0,1].plot(cubic_r['sec_int'], cubic_r['retransmissions'], color='red', label='Retransmissions')
axs[0,1].plot(cubic_o['sec_int'], cubic_o['out_of_order'], color='blue', label='Out of Order')
axs[0,1].plot(cubic_l['sec_int'], cubic_l['lost_packets'], color='green', label='Lost')
axs[0,1].set_title("Cubic Critical Events")
axs[0,1].set_ylabel("Number of Packets")
axs[0,1].set_xlabel("Time (seconds)", labelpad=30)
axs[0,1].grid(True)
axs[0,1].legend()
axs[0,1].legend(loc='upper left')

axs[1,0].plot(bbr_r['sec_int'], bbr_r['retransmissions'], color='red', label='Retransmissions')
axs[1,0].plot(bbr_o['sec_int'], bbr_o['out_of_order'], color='blue', label='Out of Order')
axs[1,0].plot(bbr_l['sec_int'], bbr_l['lost_packets'], color='green', label='Lost')
axs[1,0].set_title("BBR Critical Events")
axs[1,0].set_ylabel("Number of Packets")
axs[1,0].set_xlabel("Time (seconds)", labelpad=30)
axs[1,0].grid(True)
axs[1,0].legend(loc='upper left')

axs[1,1].axis('off')

for ax, bw_df in zip([axs[0,0], axs[0,1], axs[1,0]], [reno_bw, cubic_bw, bbr_bw]):
    ymin, ymax = ax.get_ylim()
    y_text = ymin - 0.05 * (ymax - ymin)
    for x, bw in zip(bw_df['sec'], bw_df['bandwidth']):
        ax.axvline(x, linestyle=':', alpha=0.5)
        ax.text(x, y_text, f"{bw} Mbps", rotation=90, ha='center', va='top', fontsize=8)

plt.tight_layout()
plt.show()