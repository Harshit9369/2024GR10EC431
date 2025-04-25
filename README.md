# 5G Core Network Traffic Analysis

## Overview

This project provides a comprehensive analysis of 5G Core Network traffic using real-world datasets. The primary goal is to extract, visualize, and summarize key network metrics and communication patterns from packet capture data, supporting research and education in next-generation mobile networks.

The analysis uses the [5G-Core-Networks-Datasets](https://github.com/Western-OC2-Lab/5G-Core-Networks-Datasets), which contains packet captures and CSV exports from a 5G core network emulation. The project generates summary statistics, protocol distributions, network topology graphs, and time-series visualizations to help understand the behavior and structure of 5G core network traffic.

---

## Dataset

We use the [5G-Core-Networks-Datasets](https://github.com/Western-OC2-Lab/5G-Core-Networks-Datasets), which includes:

-   **Dataset1.pcapng**: A packet capture file containing initial UE registration and over two hours of 5G core network operations.
-   **Dataset2.csv**: A CSV export with selected fields per packet (sequence number, timestamp, source/destination IP, protocol, length, and info).

The dataset captures traffic among various 5G core network functions (AMF, SMF, UPF, etc.) and user equipment, providing a realistic view of network interactions.

---

## Methods

### Data Extraction

-   **PCAP Processing**: The original implementation in [`main.py`](main.py) uses `pyshark` to analyze the `.pcapng` file directly. However, due to the large size of the dataset, this approach is time-consuming.
-   **Optimized Analysis**: To address performance issues, we use [`temp.py`](temp.py), which extracts a representative sample from the `.pcapng` file using `tshark` and processes the resulting CSV for faster analysis.

### Analysis Steps

1.  **Traffic Pattern Analysis**: Compute total packets, unique IPs, protocol distributions, and top talkers.
2.  **Network Topology Visualization**: Build a directed graph of network communications and visualize the most significant connections.
3.  **Packet Length Analysis**: Plot the distribution of packet sizes and analyze by protocol.
4.  **Time-Series Analysis**: Visualize packet activity over time and by protocol.
5.  **Conversation Patterns**: Identify common communication flows and protocol sequences between network functions.
6.  **Summary Report Generation**: Output a detailed summary of findings and visualizations.

All generated plots and the summary report are saved in the `output_metrics/` directory.

---

## Usage

1.  **Install Dependencies**  
    Ensure you have Python 3.x and install required packages:

    ```
    pip install pandas matplotlib seaborn networkx pyshark
    ```
2.  **Download the Dataset**  
    Clone or download the [5G-Core-Networks-Datasets](https://github.com/Western-OC2-Lab/5G-Core-Networks-Datasets) repository and place it in the project directory.
3.  **Run the Analysis**  
    Execute the optimized analysis script:

    ```
    python temp.py
    ```

    This will generate summary statistics, plots, and a report in `output_metrics/` and as `5g_network_analysis_summary.txt`.

---

## Project Structure

-   `main.py`: Original analysis script (slower, direct `.pcapng` processing).
-   `temp.py`: Optimized analysis using CSV extraction for faster results.
-   `output_metrics/`: Directory for generated plots and visualizations.
-   `5g_network_analysis_summary.txt`: Summary report of the analysis.
-   `5G-Core-Networks-Datasets/`: Directory containing the dataset.

---

## Educator

Dr. Bhupendra Kumar

---

## Collaborators

-   Harshit Agrawal
-   Malaika Varshney
-   Ameya Naik
