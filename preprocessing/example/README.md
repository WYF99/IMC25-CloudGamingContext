# Example: Window-Based Attribute Generation for Game Title Classification

This directory contains an example Python script that generates window-based attributes (rather than packet-group-based) from packet statistics in the downstream game video flow for game title classification using ML models.

## Usage

First, install the required Python dependencies:

```bash
pip install scipy
```

After packet statistics are extracted using the Go preprocessing script, run the Python script to generate window-based traffic features:

```bash
python window_attributes.py -p /path/to/data -w 1.0 -n 5.0
```

This will process all `_packetStats.json` files and generate corresponding `_window_attributes.csv` files in the same directory.

**Options:**
- `-p`: Base path to the data directory (default: `../../data/`)
- `-w`: Window size in seconds (default: `1.0`)
- `-n`: Number of seconds to process from the start of each trace (default: `5.0`)

**Output:** For each `<filename>_packetStats.json`, a `<filename>_window_attributes.csv` file is created containing 17 statistical features per window, which are generated using the same metrics and statistical functions as in Fig.7 in [our paper](https://arxiv.org/pdf/2509.19669).

## Requirements

- Python 3.10 or higher
- Python packages: `scipy`

