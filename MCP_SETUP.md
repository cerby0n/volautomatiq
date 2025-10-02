# VolAutomatiq MCP Server Setup

This guide explains how to use VolAutomatiq as an MCP (Model Context Protocol) server with Claude Desktop, enabling Claude to autonomously perform memory forensics analysis.

## What is MCP?

MCP (Model Context Protocol) allows Claude to interact directly with tools and services. With VolAutomatiq MCP, Claude can:
- Scan memory images
- Analyze processes
- Dump suspicious executables
- Generate forensics reports
- Identify malicious activity

## Available MCP Tools

1. **scan_memory_image**: Run full Volatility scan and generate HTML report
2. **list_processes**: List all processes with details
3. **search_process**: Search for specific process by name or PID
4. **dump_process**: Dump process executable using procdump
5. **dump_files**: Dump files from memory using dumpfiles
6. **run_plugin**: Execute any Volatility plugin
7. **get_process_tree**: View hierarchical process relationships
8. **analyze_suspicious_processes**: Auto-detect suspicious activity

## Setup Instructions

### Option 1: Docker (Recommended)

1. **Build the Docker image**:
```bash
cd /home/kali/tools/dev/volautomatiq
docker build -t volautomatiq-mcp .
```

2. **Configure Claude Desktop**:

Add to your Claude Desktop MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "volautomatiq": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/path/to/your/memory/dumps:/data",
        "volautomatiq-mcp"
      ]
    }
  }
}
```

Replace `/path/to/your/memory/dumps` with the actual path to your memory dump files.

3. **Restart Claude Desktop**

### Option 2: Local Installation

1. **Install dependencies**:
```bash
cd /home/kali/tools/dev/volautomatiq
uv pip install -e .
```

2. **Install Volatility 2.6.1**:
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
git checkout 2.6.1
python setup.py install
```

3. **Configure Claude Desktop**:

```json
{
  "mcpServers": {
    "volautomatiq": {
      "command": "python",
      "args": [
        "-m",
        "volautomatiq.mcp_server"
      ],
      "cwd": "/home/kali/tools/dev/volautomatiq"
    }
  }
}
```

4. **Restart Claude Desktop**

## Usage Examples

Once configured, you can ask Claude to perform forensics analysis:

### Example 1: Full Scan
```
Claude, please scan the memory image at /data/win7crypto.vmem
using profile Win7SP0x86 and generate a report.
```

Claude will use the `scan_memory_image` tool.

### Example 2: Search for Suspicious Processes
```
Claude, analyze the memory dump and identify any suspicious processes.
```

Claude will use `analyze_suspicious_processes`.

### Example 3: Investigate Specific Process
```
Claude, search for the process 'svchost.exe' and show me detailed information.
```

Claude will use `search_process`.

### Example 4: Dump Malware
```
Claude, dump the executable for PID 2748 so I can analyze it.
```

Claude will use `dump_process`.

### Example 5: Process Tree
```
Claude, show me the process tree to understand parent-child relationships.
```

Claude will use `get_process_tree`.

## Advanced Usage with Docker Compose

For persistent services, use docker-compose:

```bash
# Start MCP server
docker-compose up volautomatiq-mcp

# Or start API server for web UI
docker-compose up volautomatiq-api
```

## Directory Structure in Docker

```
/data/              # Mount your memory dumps here
/data/dumps/        # Process dumps will be saved here
/data/reports/      # HTML reports will be saved here
```

## Troubleshooting

### MCP Server Not Connecting

1. Check Claude Desktop logs:
   - macOS: `~/Library/Logs/Claude/mcp*.log`
   - Windows: `%APPDATA%\Claude\logs\mcp*.log`

2. Test MCP server manually:
```bash
docker run -i --rm volautomatiq-mcp
```

3. Verify Volatility installation in container:
```bash
docker run -it --rm volautomatiq-mcp vol.py --version
```

### Permission Issues

If you get permission errors accessing memory dumps:

```bash
# Add proper permissions to your dumps directory
chmod -R 755 /path/to/dumps

# Or run container with user mapping
docker run -i --rm -u $(id -u):$(id -g) -v /path/to/dumps:/data volautomatiq-mcp
```

### Memory Limits

For large memory dumps, increase Docker memory:

```bash
docker run -i --rm -m 8g -v /path/to/dumps:/data volautomatiq-mcp
```

## Example Conversation

**You**: Claude, I have a suspicious Windows 7 memory dump at /data/win7crypto.vmem. Can you analyze it for me?

**Claude**: I'll scan the memory image and analyze it for suspicious activity.

*Claude uses scan_memory_image tool*

**Claude**: The scan completed successfully. I found 142 processes. Let me check for suspicious ones.

*Claude uses analyze_suspicious_processes tool*

**Claude**: I've identified 3 potentially suspicious processes:

1. **cmd.exe (PID: 2748)** - Running with suspicious command line
2. **svchost.exe (PID: 1896)** - Orphaned process (unusual parent)
3. **powershell.exe (PID: 3104)** - Has network activity

Would you like me to dump any of these for further analysis?

**You**: Yes, dump PID 2748 please.

*Claude uses dump_process tool*

**Claude**: I've dumped the executable for PID 2748 to /data/dumps/executable.2748.exe. The file is ready for static analysis.

## Security Considerations

- Always run memory dumps in an isolated environment
- Use Docker for additional isolation
- Don't expose the API server (port 5555) to untrusted networks
- Review findings before taking action on production systems

## Integration with Existing Workflow

VolAutomatiq MCP can work alongside:
- HTML reports generated by the main tool
- API server for interactive web UI
- Standard Volatility command-line usage

All three modes can share the same memory dumps and output directories.

## Next Steps

After setup, try asking Claude to:
- Perform a full forensics analysis
- Generate an investigation report
- Compare multiple memory dumps
- Identify malware persistence mechanisms
- Extract network IOCs (Indicators of Compromise)

Claude will autonomously use the appropriate MCP tools to complete the task!
