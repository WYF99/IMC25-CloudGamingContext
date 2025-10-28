# Validation

This directory contains a validation script that analyzes the cloud gaming dataset by traversing through all pcap/pcapng files and reporting metadata statistics.

## Usage

Run the Python script to validate the dataset:

```bash
python validation.py -p /path/to/data
```

The script will recursively scan the specified directory for `.pcapng` files and generate a summary report including:
- Number of files per device type
- Number of files per software type
- Number of files per game title
- Total capture duration for each category

**Options:**
- `-p`: Base path to the data directory (default: `../data/`)

**Output:** A console report showing statistics organized by device type, software type, and game title, along with total file counts and capture durations.

## Requirements

- Python 3.6 or higher
- Wireshark's `capinfos` utility must be installed and accessible

**Note:** You may need to update the `CAPINFOS_PATH` variable in `validation.py` (line 15) to point to your `capinfos` executable location. On Windows, this is typically in the Wireshark installation directory (e.g., `C:\Program Files\Wireshark\capinfos.exe`). On Linux/macOS, it's usually available in the system PATH as `capinfos`.

