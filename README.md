# VolAutomatiq

Automated Volatility memory forensics scanner with interactive HTML reporting.

## Description

VolAutomatiq is a Python tool that automates memory forensics analysis using the Volatility Framework. It executes multiple Volatility plugins sequentially and generates HTML reports with advanced features:

- **Automated Plugin Execution**: Runs imageinfo, pslist, psscan, pstree, netscan, cmdline, and iehistory
- **Interactive Reports**: Modern tabbed interface with dark theme
- **Process Search**: Real-time search across all processes with aggregated details
- **Process Tree Visualization**: Interactive hierarchical process tree with clickable nodes
- **Resizable Side Panel**: Customizable detail panel with localStorage persistence
- **Detailed Process Information**: Aggregates data from multiple plugins (offsets, threads, handles, network connections, command lines)

## Requirements

- Python 3.13+
- UV package manager
- Volatility 2.6.1 (must be installed separately and available in PATH)

## Installation

Using UV:

```bash
uv tool install --editable .
```

Or install in development mode:

```bash
uv pip install -e .
```

## Usage

Basic usage with auto-detected profile:

```bash
volautomatiq /path/to/memory.dump
```

Specify a profile to skip imageinfo:

```bash
volautomatiq /path/to/memory.dump --profile Win7SP1x64
```

Custom output file:

```bash
volautomatiq /path/to/memory.dump --output custom_report.html
```

## Features

### Tabbed Interface
- **Raw Output**: View original Volatility plugin outputs
- **Process Tree**: Interactive hierarchical visualization
- Click on any process in the tree to view detailed information in the side panel

### Process Search
- Search by PID or process name
- View aggregated details including:
  - Virtual and physical memory offsets
  - Parent process ID (PPID)
  - Threads, handles, and session information
  - Full command line
  - Network connections

### Resizable Panels
- Drag the resize handle to adjust the side panel width
- Width preference is saved automatically
- Supports widths from 300px to 1200px

## Project Structure

```
volautomatiq/
├── volautomatiq/
│   ├── __init__.py
│   ├── cli.py           # Command-line interface
│   ├── scanner.py       # Volatility plugin orchestration
│   ├── reporter.py      # HTML report generation
│   ├── parser.py        # Output parsing and data aggregation
│   └── templates/
│       └── report.html  # Interactive HTML template
├── pyproject.toml
└── README.md
```

## License

MIT License
