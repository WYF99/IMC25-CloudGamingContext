# Preprocessing

This directory contains preprocessing scripts that extract packet statistics from pcapng files and store them in json format.

## Usage

First, download the required Go dependencies:

```bash
go mod download
```

Then run the Go script to extract per-flow packet statistics from all pcapng files in the dataset:

```bash
go run . -p /path/to/data
```

This will recursively scan the specified directory for `.pcapng` files and generate corresponding `_packetStats.json` files in the same directories.

**Options:**
- `-p`: Base path to the data directory (default: `../data/`)

**Output:** For each `<filename>.pcapng`, a `<filename>_packetStats.json` file is created containing per-flow packet information including the five-tuple, timestamps, payload sizes, etc.

## Requirements

- Go 1.16 or higher

