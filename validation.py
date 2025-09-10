"""
This script is used to validate the cloud gaming dataset by traversing through all pcap/pcapng files in the data directory 
and reporting metadata (number of files, total duration, etc.) per user platform, game title and graphics settings.
"""

import os
import subprocess
import re
import sys
from collections import defaultdict
import time

# Configuration 
ROOT_DIR = '../data_masters'  # Change to where the dataset is actually located
CAPINFOS_PATH = "capinfos.exe" # Change to the actual path of capinfos executable (usually in the same directory as Wireshark)
                           

def get_capture_duration(file_path):
    """
    Uses capinfos -M (machine-readable output) to get the capture duration of a pcapng file.
    """
    global CAPINFOS_PATH 
    try:
        cmd = [CAPINFOS_PATH, "-M", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')

        if result.returncode != 0:
            # Error processing file
            print(f"capinfos -M failed for file: {file_path}", file=sys.stderr)
            return None

        # Parse capinfos output to find the duration line
        match = re.search(r"^Capture duration:\s+(\d+\.?\d*)\s+seconds", result.stdout, re.MULTILINE)

        if match:
            duration_str = match.group(1)
            return float(duration_str)
        else:
            # Duration line not found
            print(f"No 'Capture duration' line in capinfos output for file: {file_path}", file=sys.stderr)
            return 0.0

    except FileNotFoundError:
        # capinfos not found
        print(f"'{CAPINFOS_PATH}' not found. Check the CAPINFOS_PATH variable in the script.", file=sys.stderr)
        return None 
    
    except Exception as e:
        # Any other error
        print(f"Error processing file {file_path}: {e}", file=sys.stderr)
        return None


def analyze_pcapng_files(root_dir='.'):
    """
    Scan the directory structure, analyze pcapng files, and return summaries.
    """
    # Data structures for storing statistics
    game_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {'count': 0, 'duration': 0.0})))
    software_stats = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'duration': 0.0}))
    device_stats = defaultdict(lambda: {'count': 0, 'duration': 0.0})

    total_files_scanned = 0
    total_duration_all = 0.0
    processed_files = 0
    start_time = time.time()

    print(f"Starting scan in: {os.path.abspath(root_dir)}")

    # The directory structure is:
    # root -> device_type -> software_type -> game_name -> graphics_setting -> experiment_num -> pcapng_files
    for device_type in os.listdir(root_dir):
        device_path = os.path.join(root_dir, device_type)
        if not os.path.isdir(device_path): continue

        for software_type in os.listdir(device_path):
            software_path = os.path.join(device_path, software_type)
            if not os.path.isdir(software_path): continue

            for game_name in os.listdir(software_path):
                game_path = os.path.join(software_path, game_name)
                if not os.path.isdir(game_path): continue

                for graphics_setting in os.listdir(game_path):
                    graphics_path = os.path.join(game_path, graphics_setting)
                    if not os.path.isdir(graphics_path): continue

                    for experiment_num in os.listdir(graphics_path):
                        experiment_path = os.path.join(graphics_path, experiment_num)
                        if not os.path.isdir(experiment_path): continue

                        for filename in os.listdir(experiment_path):
                            if filename.lower().endswith(".pcapng"):
                                total_files_scanned += 1
                                file_path = os.path.join(experiment_path, filename)

                                duration = get_capture_duration(file_path)

                                if duration is None: 
                                    # Stop processing if error occurs
                                     return None 

                                # Update stats for all levels
                                game_stats[device_type][software_type][game_name]['count'] += 1
                                game_stats[device_type][software_type][game_name]['duration'] += duration
                                software_stats[device_type][software_type]['count'] += 1
                                software_stats[device_type][software_type]['duration'] += duration
                                device_stats[device_type]['count'] += 1
                                device_stats[device_type]['duration'] += duration
                                total_duration_all += duration
                                processed_files += 1

                                # Show progress periodically
                                if processed_files % 50 == 0:
                                     elapsed = time.time() - start_time
                                     print(f"... processed {processed_files} files ({elapsed:.1f}s elapsed)", end='\r')


    print(f"\n\nScan complete. Processed {processed_files} out of {total_files_scanned} scanned files.")
    if total_files_scanned > processed_files:
         print(f"[Note] {total_files_scanned - processed_files} files might have caused errors or couldn't be processed.")

    elapsed_total = time.time() - start_time
    print(f"Total processing time: {elapsed_total:.2f} seconds.")

    # Sort and structure the results for consistent output
    results = {
        'device_summary': dict(sorted(device_stats.items())),
        'software_summary': {dev: dict(sorted(sw.items())) for dev, sw in sorted(software_stats.items())},
        'game_summary': {dev: {sw: dict(sorted(game.items())) for sw, game in sorted(sw_data.items())}
                         for dev, sw_data in sorted(game_stats.items())},
        'total_files': processed_files,
        'total_duration': total_duration_all
    }
    return results


def print_summary(results):
    """
    Formats and prints the summary results.
    """
    if results is None:
        print("\nError encountered. Check script configuration.")
        return

    print("\n" + "="*60)
    print("PCAPNG File Validation Summary")
    print("="*60)

    # Device summary
    print("\n--- Summary by Device Type ---")
    if results['device_summary']:
        for device, stats in results['device_summary'].items():
            print(f"- {device}:")
            print(f"  - Total Files: {stats['count']}")
            print(f"  - Total Duration: {stats['duration']:.2f} seconds")
    else:
        print("No data found.")

    # Software summary
    print("\n--- Summary by Software Type (within Device) ---")
    if results['software_summary']:
        for device, sw_data in results['software_summary'].items():
            print(f"\nDevice: {device}")
            for software, stats in sw_data.items():
                print(f"  - {software}:")
                print(f"    - Total Files: {stats['count']}")
                print(f"    - Total Duration: {stats['duration']:.2f} seconds")
    else:
        print("No data found.")

    # Game summary
    print("\n--- Summary by Game (within Device & Software) ---")
    if results['game_summary']:
        for device, sw_data in results['game_summary'].items():
            print(f"\nDevice: {device}")
            for software, game_data in sw_data.items():
                print(f"  Software: {software}")
                for game, stats in game_data.items():
                    print(f"    - {game}:")
                    print(f"      - Total Files: {stats['count']}")
                    print(f"      - Total Duration: {stats['duration']:.2f} seconds")
    else:
         print("No data found.")

    # Total results
    print("\n" + "-"*60)
    print("Totals:")
    print(f"- Total .pcapng Files Processed: {results['total_files']}")
    print(f"- Total Capture Duration (All Files): {results['total_duration']:.2f} seconds")
    print("="*60)


if __name__ == "__main__":
    summary_results = analyze_pcapng_files(ROOT_DIR)
    if summary_results:
        print_summary(summary_results)