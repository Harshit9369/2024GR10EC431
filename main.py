import os
import pandas as pd
import pyshark
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx

base_dir = "5G-Core-Networks-Datasets"

def explore_directory_structure():
    print("Directory Structure:")
    for root, dirs, files in os.walk(base_dir):
        level = root.replace(base_dir, '').count(os.sep)
        indent = ' ' * 4 * level
        print(f"{indent}{os.path.basename(root)}/")
        sub_indent = ' ' * 4 * (level + 1)
        for file in files:
            size_mb = os.path.getsize(os.path.join(root, file)) / (1024 * 1024)
            print(f"{sub_indent}{file} ({size_mb:.2f} MB)")

def analyze_pcap_file(pcap_path):
    print(f"\nAnalyzing PCAP file: {pcap_path}")
    try:
        cap = pyshark.FileCapture(pcap_path, only_summaries=True)
        packet_count = 0
        protocols = []
        for packet in cap:
            packet_count += 1
            summary = packet.summary_line
            protocol = summary.split()[4] if len(summary.split()) > 4 else "Unknown"
            protocols.append(protocol)
            if packet_count <= 5:
                print(f"Sample packet {packet_count}: {summary}")
        protocol_counts = Counter(protocols)
        print(f"\nTotal packets: {packet_count}")
        print("Protocol distribution:")
        for protocol, count in protocol_counts.most_common(10):
            print(f"  {protocol}: {count} packets ({count/packet_count*100:.2f}%)")
        return protocol_counts, packet_count
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        return Counter(), 0

def analyze_csv_file(csv_path):
    print(f"\nAnalyzing CSV file: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
        print(f"CSV shape: {df.shape}")
        print("\nColumn names:")
        for col in df.columns:
            print(f"  - {col}")
        print("\nFirst 5 rows:")
        print(df.head())
        print("\nBasic statistics:")
        if 'Length' in df.columns:
            print(f"Average packet length: {df['Length'].mean():.2f} bytes")
            print(f"Min packet length: {df['Length'].min()} bytes")
            print(f"Max packet length: {df['Length'].max()} bytes")
        if 'Source' in df.columns and 'Destination' in df.columns:
            source_counts = df['Source'].value_counts().head(10)
            dest_counts = df['Destination'].value_counts().head(10)
            print("\nTop 10 source IPs:")
            for ip, count in source_counts.items():
                print(f"  {ip}: {count} packets")
            print("\nTop 10 destination IPs:")
            for ip, count in dest_counts.items():
                print(f"  {ip}: {count} packets")
        return df
    except Exception as e:
        print(f"Error analyzing CSV file: {e}")
        return pd.DataFrame()

def create_network_graph(df, output_path="output_metrics/network_topology.png"):
    if 'Source' not in df.columns or 'Destination' not in df.columns:
        print("Source or Destination columns not found in CSV.")
        return
    G = nx.DiGraph()
    edge_weights = {}
    for _, row in df.iterrows():
        source = row['Source']
        dest = row['Destination']
        if (source, dest) in edge_weights:
            edge_weights[(source, dest)] += 1
        else:
            edge_weights[(source, dest)] = 1
    for (source, dest), weight in edge_weights.items():
        G.add_edge(source, dest, weight=weight)
    if len(G.edges()) > 50:
        significant_edges = sorted(edge_weights.items(), key=lambda x: x[1], reverse=True)[:50]
        H = nx.DiGraph()
        for (source, dest), weight in significant_edges:
            H.add_edge(source, dest, weight=weight)
        G = H
    plt.figure(figsize=(12, 10))
    pos = nx.spring_layout(G, seed=42)
    nx.draw_networkx_nodes(G, pos, node_size=700, node_color='skyblue', alpha=0.8)
    edge_widths = [G[u][v]['weight']/10 for u, v in G.edges()]
    nx.draw_networkx_edges(G, pos, width=edge_widths, edge_color='gray', alpha=0.6, arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')
    plt.title("Network Communication Graph", fontsize=20)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Network graph saved to {output_path}")
    plt.close()
    return G

def plot_protocol_distribution(protocol_counts, output_path="output_metrics/protocol_distribution.png"):
    protocols = [p for p, _ in protocol_counts.most_common(10)]
    counts = [c for _, c in protocol_counts.most_common(10)]
    plt.figure(figsize=(12, 6))
    sns.barplot(x=protocols, y=counts)
    plt.title("Top 10 Protocols by Packet Count", fontsize=16)
    plt.xlabel("Protocol", fontsize=14)
    plt.ylabel("Number of Packets", fontsize=14)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"Protocol distribution plot saved to {output_path}")
    plt.close()

def plot_packet_length_distribution(df, output_path="output_metrics/packet_length_distribution.png"):
    if 'Length' not in df.columns:
        print("Length column not found in DataFrame.")
        return
    plt.figure(figsize=(12, 6))
    sns.histplot(df['Length'], bins=50, kde=True)
    plt.title("Packet Length Distribution", fontsize=16)
    plt.xlabel("Packet Length (bytes)", fontsize=14)
    plt.ylabel("Count", fontsize=14)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"Packet length distribution plot saved to {output_path}")
    plt.close()

def plot_packet_time_series(df, output_path="output_metrics/packet_time_series.png"):
    if 'Time' not in df.columns:
        print("Time column not found in DataFrame.")
        return
    if not pd.api.types.is_datetime64_any_dtype(df['Time']):
        try:
            df['Time'] = pd.to_datetime(df['Time'], format='%Y-%m-%d %H:%M:%S')
        except:
            print("Could not convert Time column to datetime format.")
            return
    time_series = df.resample('1s', on='Time').size()
    plt.figure(figsize=(15, 6))
    time_series.plot()
    plt.title("Packet Activity Over Time", fontsize=16)
    plt.xlabel("Time", fontsize=14)
    plt.ylabel("Number of Packets", fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"Time series plot saved to {output_path}")
    plt.close()

def main():
    explore_directory_structure()
    pcap_files = []
    csv_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.pcapng') or file.endswith('.pcap'):
                pcap_files.append(os.path.join(root, file))
            elif file.endswith('.csv'):
                csv_files.append(os.path.join(root, file))
    print(f"\nFound {len(pcap_files)} PCAP files and {len(csv_files)} CSV files.")
    if pcap_files:
        protocol_counts, _ = analyze_pcap_file(pcap_files[0])
        if protocol_counts:
            plot_protocol_distribution(protocol_counts)
    df = None
    if csv_files:
        df = analyze_csv_file(csv_files[0])
        if not df.empty:
            plot_packet_length_distribution(df)
            create_network_graph(df)
            if 'Time' in df.columns:
                plot_packet_time_series(df)
    print("\nAnalysis complete. Review the generated visualizations and summary statistics.")

if __name__ == "__main__":
    main()
