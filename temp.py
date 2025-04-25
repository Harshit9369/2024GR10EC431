import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
import os
import subprocess
import time
from collections import Counter, defaultdict

BASE_DIR = "5G-Core-Networks-Datasets"
PCAP_FILE = os.path.join(BASE_DIR, "Dataset1.pcapng")
CSV_FILE = os.path.join(BASE_DIR, "Dataset2.csv")

NETWORK_FUNCTIONS = {
    "192.168.0.1": "AMF",
    "192.168.0.2": "SMF",
    "192.168.0.3": "UPF",
}

def map_ip_to_function(ip):
    return NETWORK_FUNCTIONS.get(ip, ip)

def extract_sample_with_tshark(pcap_file, output_csv, sample_size=10000):
    print(f"Extracting {sample_size} packets from {pcap_file}...")
    cmd = [
        "tshark", 
        "-r", pcap_file,
        "-T", "fields",
        "-e", "frame.number", 
        "-e", "frame.time_epoch",
        "-e", "ip.src", 
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-E", "header=y",
        "-E", "separator=,",
        f"-c", str(sample_size)  
    ]
    try:
        start_time = time.time()
        with open(output_csv, 'w') as f:
            subprocess.run(cmd, stdout=f, check=True)
        duration = time.time() - start_time
        print(f"Extraction completed in {duration:.2f} seconds")
        df = pd.read_csv(output_csv)
        if len(df.columns) >= 7:  
            df.columns = ['Frame', 'Time', 'Source', 'Destination', 'Protocol_Num', 'Length', 'Protocol']
            df.to_csv(output_csv, index=False)
            print(f"Saved sample to {output_csv}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def load_existing_csv(csv_file):
    print(f"Loading data from {csv_file}...")
    try:
        df = pd.read_csv(csv_file)
        print(f"Loaded {len(df)} records from CSV")
        print(f"CSV columns: {', '.join(df.columns)}")
        return df
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return None

def analyze_traffic_patterns(df):
    print("\nAnalyzing traffic patterns...")
    total_packets = len(df)
    unique_sources = df['Source'].nunique()
    unique_destinations = df['Destination'].nunique()
    print(f"Total packets: {total_packets}")
    print(f"Unique source IPs: {unique_sources}")
    print(f"Unique destination IPs: {unique_destinations}")
    top_sources = df['Source'].value_counts().head(10)
    top_destinations = df['Destination'].value_counts().head(10)
    print("\nTop 10 Source IPs:")
    for ip, count in top_sources.items():
        print(f"  {ip}: {count} packets ({count/total_packets*100:.2f}%)")
    print("\nTop 10 Destination IPs:")
    for ip, count in top_destinations.items():
        print(f"  {ip}: {count} packets ({count/total_packets*100:.2f}%)")
    protocol_dist = df['Protocol'].value_counts()
    print("\nProtocol Distribution:")
    for protocol, count in protocol_dist.items():
        print(f"  {protocol}: {count} packets ({count/total_packets*100:.2f}%)")
    plt.figure(figsize=(12, 6))
    protocol_dist.head(10).plot(kind='bar')
    plt.title('Top 10 Protocols', fontsize=16)
    plt.xlabel('Protocol', fontsize=14)
    plt.ylabel('Packet Count', fontsize=14)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("output_metrics/protocol_distribution.png", dpi=300)
    plt.close()
    return {
        'total_packets': total_packets,
        'unique_sources': unique_sources,
        'unique_destinations': unique_destinations,
        'top_sources': top_sources,
        'top_destinations': top_destinations,
        'protocol_dist': protocol_dist
    }

def create_network_graph(df, output_file="output_metrics/network_topology.png"):
    print("\nCreating network graph...")
    G = nx.DiGraph()
    comm_counts = df.groupby(['Source', 'Destination']).size().reset_index(name='Weight')
    top_comms = comm_counts.nlargest(50, 'Weight')
    for _, row in top_comms.iterrows():
        G.add_edge(row['Source'], row['Destination'], weight=row['Weight'])
    plt.figure(figsize=(12, 10))
    node_sizes = [300 * (1 + G.degree(node)) for node in G.nodes()]
    edge_widths = [0.1 + 3 * G[u][v]['weight'] / top_comms['Weight'].max() for u, v in G.edges()]
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color='skyblue', alpha=0.8)
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True, arrowstyle='->')
    nx.draw_networkx_labels(G, pos, font_size=8)
    plt.title("Network Communication Graph (Top 50 Connections)", fontsize=16)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()
    print(f"Network graph saved to {output_file}")
    return G

def analyze_packet_lengths(df, output_file="output_metrics/packet_length_distribution.png"):
    print("\nAnalyzing packet length distribution...")
    avg_length = df['Length'].mean()
    min_length = df['Length'].min()
    max_length = df['Length'].max()
    print(f"Average packet length: {avg_length:.2f} bytes")
    print(f"Minimum packet length: {min_length} bytes")
    print(f"Maximum packet length: {max_length} bytes")
    plt.figure(figsize=(12, 6))
    sns.histplot(df['Length'], kde=True, bins=50)
    plt.title('Packet Length Distribution', fontsize=16)
    plt.xlabel('Packet Length (bytes)', fontsize=14)
    plt.ylabel('Frequency', fontsize=14)
    plt.axvline(avg_length, color='r', linestyle='--', label=f'Mean: {avg_length:.2f}')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()
    print(f"Packet length distribution saved to {output_file}")
    protocol_lengths = df.groupby('Protocol')['Length'].agg(['mean', 'median', 'std', 'min', 'max'])
    protocol_lengths = protocol_lengths.sort_values('mean', ascending=False)
    print("\nPacket Lengths by Protocol (Top 10):")
    print(protocol_lengths.head(10))
    plt.figure(figsize=(12, 6))
    top_protocols = protocol_lengths.head(10).index
    protocol_df = df[df['Protocol'].isin(top_protocols)]
    sns.boxplot(x='Protocol', y='Length', data=protocol_df)
    plt.title('Packet Lengths by Protocol (Top 10)', fontsize=16)
    plt.xlabel('Protocol', fontsize=14)
    plt.ylabel('Packet Length (bytes)', fontsize=14)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()
    return protocol_lengths

def analyze_time_patterns(df, output_file="output_metrics/packet_time_series.png"):
    print("\nAnalyzing packet timing patterns...")
    if 'Time' in df.columns:
        try:
            df['Time'] = pd.to_datetime(df['Time'], unit='s')
            time_series = df.resample('1S', on='Time').size()
            print(f"Time range: {df['Time'].min()} to {df['Time'].max()}")
            print(f"Duration: {(df['Time'].max() - df['Time'].min()).total_seconds():.2f} seconds")
            print(f"Average packets per second: {len(df) / (df['Time'].max() - df['Time'].min()).total_seconds():.2f}")
            plt.figure(figsize=(15, 6))
            time_series.plot()
            plt.title('Packets per Second', fontsize=16)
            plt.xlabel('Time', fontsize=14)
            plt.ylabel('Packet Count', fontsize=14)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(output_file, dpi=300)
            plt.close()
            print(f"Time series saved to {output_file}")
            top_protocols = df['Protocol'].value_counts().head(5).index
            plt.figure(figsize=(15, 6))
            for protocol in top_protocols:
                protocol_df = df[df['Protocol'] == protocol]
                protocol_series = protocol_df.resample('1S', on='Time').size()
                protocol_series.plot(label=protocol)
            plt.title('Packets per Second by Protocol (Top 5)', fontsize=16)
            plt.xlabel('Time', fontsize=14)
            plt.ylabel('Packet Count', fontsize=14)
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(output_file, dpi=300)
            plt.close()
        except Exception as e:
            print(f"Error processing time data: {e}")

def identify_conversation_patterns(df):
    print("\nIdentifying conversation patterns...")
    if 'Source' in df.columns and 'Destination' in df.columns:
        df['Source_Function'] = df['Source'].apply(map_ip_to_function)
        df['Dest_Function'] = df['Destination'].apply(map_ip_to_function)
    if 'Source_Function' in df.columns and 'Dest_Function' in df.columns:
        function_comm = df.groupby(['Source_Function', 'Dest_Function']).size().reset_index(name='Count')
        function_comm = function_comm.sort_values('Count', ascending=False)
        print("\nTop Communication Patterns Between Network Functions:")
        for i, (_, row) in enumerate(function_comm.head(10).iterrows()):
            print(f"{i+1}. {row['Source_Function']} → {row['Dest_Function']}: {row['Count']} packets")
    if 'Time' in df.columns:
        df_sorted = df.sort_values('Time')
        conversation_flows = defaultdict(list)
        for _, row in df_sorted.iterrows():
            key = (row['Source'], row['Destination'])
            conversation_flows[key].append(row['Protocol'])
        common_sequences = Counter()
        for flow, protocols in conversation_flows.items():
            if len(protocols) >= 3:
                for i in range(len(protocols) - 2):
                    seq = tuple(protocols[i:i+3])
                    common_sequences[seq] += 1
        print("\nCommon Protocol Sequences in Conversations:")
        for i, (seq, count) in enumerate(common_sequences.most_common(5)):
            if i < 5:
                print(f"{i+1}. {' → '.join(seq)}: observed {count} times")

def generate_summary_report(stats, output_file="5g_network_analysis_summary.txt"):
    print("\nGenerating summary report...")
    with open(output_file, 'w') as f:
        f.write("# 5G Network Analysis Summary Report\n\n")
        f.write("## Dataset Overview\n")
        f.write(f"- Total packets analyzed: {stats['total_packets']}\n")
        f.write(f"- Unique source IPs: {stats['unique_sources']}\n")
        f.write(f"- Unique destination IPs: {stats['unique_destinations']}\n\n")
        f.write("## Protocol Distribution\n")
        for protocol, count in stats['protocol_dist'].head(10).items():
            f.write(f"- {protocol}: {count} packets ({count/stats['total_packets']*100:.2f}%)\n")
        f.write("\n")
        f.write("## Network Activity\n")
        f.write("### Top Source IPs\n")
        for ip, count in stats['top_sources'].head(5).items():
            f.write(f"- {ip}: {count} packets ({count/stats['total_packets']*100:.2f}%)\n")
        f.write("\n")
        f.write("### Top Destination IPs\n")
        for ip, count in stats['top_destinations'].head(5).items():
            f.write(f"- {ip}: {count} packets ({count/stats['total_packets']*100:.2f}%)\n")
        f.write("\n")
        f.write("## Generated Visualizations\n")
        f.write("1. protocol_distribution.png - Distribution of protocols in the dataset\n")
        f.write("2. network_topology.png - Network communication graph\n")
        f.write("3. packet_length_distribution.png - Distribution of packet lengths\n")
        f.write("4. packet_lengths_by_protocol.png - Packet lengths by protocol\n")
        f.write("5. packet_time_series.png - Packet activity over time\n")
        f.write("6. time_series_by_protocol.png - Protocol-specific activity over time\n\n")
        f.write("## Analysis Methodology\n")
        f.write("This analysis was performed using a sample of packets from the dataset. ")
        f.write("The analysis focuses on protocol distribution, network topology, ")
        f.write("packet characteristics, and communication patterns.\n\n")
        f.write("## Conclusions\n")
        f.write("Based on the analysis, the following observations can be made:\n")
        f.write("1. [Add your conclusions here based on the analysis results]\n")
        f.write("2. [Add more conclusions as appropriate]\n")
        f.write("3. [Add recommendations if applicable]\n")
    print(f"Summary report saved to {output_file}")

def main():
    print("Starting 5G Network Analysis...")
    sample_csv = "sample_packets.csv"
    if not os.path.exists(CSV_FILE) and not os.path.exists(sample_csv):
        print("CSV file not found. Extracting sample from PCAP...")
        success = extract_sample_with_tshark(PCAP_FILE, sample_csv, sample_size=50000)
        if not success:
            print("Failed to extract data. Please check if tshark is installed.")
            return
        df = load_existing_csv(sample_csv)
    else:
        if os.path.exists(CSV_FILE):
            df = load_existing_csv(CSV_FILE)
        else:
            df = load_existing_csv(sample_csv)
    if df is None:
        print("Failed to load data. Exiting.")
        return
    stats = analyze_traffic_patterns(df)
    create_network_graph(df)
    analyze_packet_lengths(df)
    analyze_time_patterns(df)
    identify_conversation_patterns(df)
    generate_summary_report(stats)

if __name__ == "__main__":
    main()
