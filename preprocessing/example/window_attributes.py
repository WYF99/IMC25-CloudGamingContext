import os
import sys
import json
import re
import statistics
import argparse
import csv
from scipy import stats


def load_video_flow_packets(file_path: str) -> dict:
    packet_data = json.load(open(file_path, 'r'))
    dns_name_pattern = re.compile(r'^\d+(?:-\d+)*\.pnt\.geforcenow\.nvidiagrid\.net$')
    for flow in packet_data.values():
        if flow['Protocol'] == 6:
            # ignore TCP flows
            continue
        if flow['RemotePort'] < 10000 or flow['RemotePort']> 20000:
            # GFN servers use ports between 10000 and 20000
            continue
        if flow['LocalPort'] == 49005:
            # fixed port used for video streams on native GFN apps
            return flow
        if re.match(dns_name_pattern, flow['DNSName']):
            # DNS names for video flows typically follow the pattern of "hyphen-separated-ip-address.pnt.geforcenow.nvidiagrid.net"
            if len(flow['Packets']) > 10000:
                # ignore short flows, likely false positives
                return flow
    return None


def get_base_window_stats(file_path: str, window_size: float, first_n_seconds: float) -> dict[str, list[list[int|float]]]:
    if os.path.isdir(file_path):
        file_path = os.path.join(file_path, os.path.dirname(file_path).split('/')[-1] + '_packetStats.json')
    flow = load_video_flow_packets(file_path)
    if flow is None:
        raise ValueError("No video flow found in file")
    
    base_window_stats = {'PayloadSizes': [], 'InterArrivalTimes': []}
    num_windows = int(first_n_seconds / window_size)
    while len(base_window_stats['PayloadSizes']) <= num_windows:
        base_window_stats['PayloadSizes'].append([])
        base_window_stats['InterArrivalTimes'].append([])
    
    base_timestamp = flow['Packets'][0]['Timestamp']    # UNIX microsecond timestamp
    prev_timestamp = None
    
    for packet in flow['Packets']:
        if packet['Upstream']:
            # skip upstream packets in video flows
            continue
        packet['Timestamp'] -= base_timestamp
        packet['Timestamp'] /= 1e6    # convert to seconds
        # only consider packets within the first n seconds
        if packet['Timestamp'] > first_n_seconds:
            break
        
        # determine which window this packet belongs to
        window_idx = int(packet['Timestamp'] / window_size)    
        # calculate inter-arrival time, skip for first packet in each window
        if len(base_window_stats['PayloadSizes'][window_idx]) > 0:
            inter_arrival = packet['Timestamp'] - prev_timestamp
            base_window_stats['InterArrivalTimes'][window_idx].append(inter_arrival)
        # add payload size to current window
        base_window_stats['PayloadSizes'][window_idx].append(packet['PayloadSize'])
        
        # update previous timestamp for next iteration
        prev_timestamp = packet['Timestamp']
    
    return base_window_stats


def generate_window_attributes(file_path: str, window_size: float = 1.0, first_n_seconds: float = 5.0) -> list[dict]:
    """
    Generate window attributes from base window stats.
    For each window, 17 attributes are generated based on the packet count, payload sizes, and inter-arrival times,
    using statistical functions including sum, mean, med, min, max, std, kurtosis, skew,
    and are named as ct_sum_<window_idx>, sz_sum_<window_idx>, sz_mean_<window_idx>..., it_kurtosis_<window_idx>, it_skew_<window_idx>.
    """
    if first_n_seconds % window_size != 0:
        raise ValueError("First n seconds must be a multiple of window size")
    
    base_window_stats = get_base_window_stats(file_path, window_size, first_n_seconds)
    if base_window_stats is None:
        raise ValueError("No video flow found in json file: " + file_path)
    
    window_attributes = {}
    for window_idx in range(len(base_window_stats['PayloadSizes'])):
        # Packet count attribute
        window_attributes[f'ct_sum_{window_idx}'] = len(base_window_stats['PayloadSizes'][window_idx])
        
        # Payload size attributes
        payload_sizes = base_window_stats['PayloadSizes'][window_idx]
        if len(payload_sizes) > 0:
            window_attributes[f'sz_sum_{window_idx}'] = sum(payload_sizes)
            window_attributes[f'sz_mean_{window_idx}'] = statistics.mean(payload_sizes)
            window_attributes[f'sz_med_{window_idx}'] = statistics.median(payload_sizes)
            window_attributes[f'sz_min_{window_idx}'] = min(payload_sizes)
            window_attributes[f'sz_max_{window_idx}'] = max(payload_sizes)
            window_attributes[f'sz_std_{window_idx}'] = statistics.stdev(payload_sizes) if len(payload_sizes) > 1 else 0
            window_attributes[f'sz_kurtosis_{window_idx}'] = stats.kurtosis(payload_sizes) if len(payload_sizes) > 3 else 0
            window_attributes[f'sz_skew_{window_idx}'] = stats.skew(payload_sizes) if len(payload_sizes) > 2 else 0
        else:
            window_attributes[f'sz_sum_{window_idx}'] = 0
            window_attributes[f'sz_mean_{window_idx}'] = 0
            window_attributes[f'sz_med_{window_idx}'] = 0
            window_attributes[f'sz_min_{window_idx}'] = 0
            window_attributes[f'sz_max_{window_idx}'] = 0
            window_attributes[f'sz_std_{window_idx}'] = 0
            window_attributes[f'sz_kurtosis_{window_idx}'] = 0
            window_attributes[f'sz_skew_{window_idx}'] = 0
        
        # Inter-arrival time attributes
        inter_arrival_times = base_window_stats['InterArrivalTimes'][window_idx]
        if len(inter_arrival_times) > 0:
            window_attributes[f'it_sum_{window_idx}'] = sum(inter_arrival_times)
            window_attributes[f'it_mean_{window_idx}'] = statistics.mean(inter_arrival_times)
            window_attributes[f'it_med_{window_idx}'] = statistics.median(inter_arrival_times)
            window_attributes[f'it_min_{window_idx}'] = min(inter_arrival_times)
            window_attributes[f'it_max_{window_idx}'] = max(inter_arrival_times)
            window_attributes[f'it_std_{window_idx}'] = statistics.stdev(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
            window_attributes[f'it_kurtosis_{window_idx}'] = stats.kurtosis(inter_arrival_times) if len(inter_arrival_times) > 3 else 0
            window_attributes[f'it_skew_{window_idx}'] = stats.skew(inter_arrival_times) if len(inter_arrival_times) > 2 else 0
        else:
            window_attributes[f'it_sum_{window_idx}'] = 0
            window_attributes[f'it_mean_{window_idx}'] = 0
            window_attributes[f'it_med_{window_idx}'] = 0
            window_attributes[f'it_min_{window_idx}'] = 0
            window_attributes[f'it_max_{window_idx}'] = 0
            window_attributes[f'it_std_{window_idx}'] = 0
            window_attributes[f'it_kurtosis_{window_idx}'] = 0
            window_attributes[f'it_skew_{window_idx}'] = 0
    
    return window_attributes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate window attributes from packet stats')
    parser.add_argument('-p', '--path', type=str, default='../../data/', help='Base path to the data directory (default: ../../data/)')
    parser.add_argument('-w', '--window-size', type=float, default=1.0, help='Window size in seconds (default: 1.0)')
    parser.add_argument('-n', '--first-n-seconds', type=float, default=5.0, help='First n seconds to process (default: 5.0)')
    args = parser.parse_args()
    
    # recursively find all files ending with "_packetStats.json"
    packet_stats_files = []
    for root, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith('_packetStats.json'):
                packet_stats_files.append(os.path.join(root, file))
    
    print(f"Found {len(packet_stats_files)} packet stats files")
    
    for file_path in packet_stats_files:
        print(f"Processing {file_path}...")
        try:
            # generate window attributes
            window_attributes = generate_window_attributes(file_path, args.window_size, args.first_n_seconds)
            
            # save to CSV file in the same directory as the json file
            output_path = file_path.replace('_packetStats.json', '_window_attributes.csv')
            with open(output_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # write header row
                writer.writerow(window_attributes.keys())
                # write data row
                writer.writerow(window_attributes.values())
            print(f"CSV file saved to {output_path}")
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            continue
