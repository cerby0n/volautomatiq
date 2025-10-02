#!/usr/bin/env python3
"""MCP Server for VolAutomatiq - Memory Forensics Analysis."""

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .scanner import VolatilityScanner
from .reporter import HTMLReporter
from .parser import VolatilityParser


# Global state
current_scanner: Optional[VolatilityScanner] = None
current_image_path: Optional[str] = None
current_profile: Optional[str] = None
scan_results = []


# Initialize MCP server
app = Server("volautomatiq")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="scan_memory_image",
            description="Run a full Volatility scan on a memory image. Executes all plugins (pslist, psscan, pstree, netscan, cmdline, getsids, dlllist, iehistory) and generates an HTML report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Path to the memory dump file (e.g., /path/to/memory.vmem)",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Volatility profile (e.g., Win7SP1x64, Win10x64_19041). If not provided, will auto-detect.",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Path for the HTML report output (default: report.html)",
                    },
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="list_processes",
            description="List all processes from the memory image with detailed information (PID, PPID, name, offsets, command line, network connections, etc.)",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="search_process",
            description="Search for a specific process by name or PID and get detailed information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Process name or PID to search for",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="dump_process",
            description="Dump a process executable from memory using procdump.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to dump",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to save the dumped file (default: ./dumps)",
                    },
                },
                "required": ["pid"],
            },
        ),
        Tool(
            name="dump_files",
            description="Dump files from memory using dumpfiles with a physical offset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "offset": {
                        "type": "string",
                        "description": "Physical offset in hex format (e.g., 0x12345678)",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to save the dumped files (default: ./dumps)",
                    },
                },
                "required": ["offset"],
            },
        ),
        Tool(
            name="run_plugin",
            description="Run a specific Volatility plugin with optional parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin": {
                        "type": "string",
                        "description": "Plugin name (e.g., handles, filescan, netscan)",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Optional: Process ID filter (for handles, etc.)",
                    },
                    "grep": {
                        "type": "string",
                        "description": "Optional: String to filter results",
                    },
                },
                "required": ["plugin"],
            },
        ),
        Tool(
            name="get_process_tree",
            description="Get a hierarchical view of the process tree showing parent-child relationships.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="analyze_suspicious_processes",
            description="Analyze processes and identify potentially suspicious ones based on heuristics (hidden processes, unusual parents, suspicious names, etc.).",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    global current_scanner, current_image_path, current_profile, scan_results

    if name == "scan_memory_image":
        image_path = arguments["image_path"]
        profile = arguments.get("profile")
        output_path = arguments.get("output_path", "report.html")

        if not Path(image_path).exists():
            return [TextContent(type="text", text=f"Error: Memory image not found: {image_path}")]

        try:
            # Initialize scanner
            scanner = VolatilityScanner(
                image_path=image_path,
                profile=profile,
                vol_path="vol.py",
            )
            current_scanner = scanner
            current_image_path = image_path
            current_profile = scanner.profile

            # Run scans
            results = scanner.scan_all()
            scan_results = results

            # Generate report
            reporter = HTMLReporter()
            reporter.generate(
                results=results,
                image_path=image_path,
                profile=scanner.profile,
                output_path=output_path,
            )

            successful = sum(1 for r in results if r.success)
            total = len(results)

            return [
                TextContent(
                    type="text",
                    text=f"✓ Scan completed successfully!\n\n"
                    f"Image: {Path(image_path).name}\n"
                    f"Profile: {scanner.profile}\n"
                    f"Plugins: {successful}/{total} successful\n"
                    f"Report saved to: {output_path}\n\n"
                    f"You can now use other tools to analyze the results.",
                )
            ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error during scan: {str(e)}")]

    elif name == "list_processes":
        if not scan_results:
            return [TextContent(type="text", text="Error: No scan results available. Run scan_memory_image first.")]

        try:
            parser = VolatilityParser()
            process_data = parser.parse_all(scan_results)

            if not process_data:
                return [TextContent(type="text", text="No processes found in scan results.")]

            output = f"Found {len(process_data)} processes:\n\n"
            for proc in sorted(process_data, key=lambda p: p['pid']):
                output += f"PID {proc['pid']}: {proc['name']}\n"
                if proc['details'].get('PPID'):
                    output += f"  └─ PPID: {proc['details']['PPID']}\n"
                if proc['details'].get('Command Line'):
                    output += f"  └─ CMD: {proc['details']['Command Line']}\n"
                output += "\n"

            return [TextContent(type="text", text=output)]

        except Exception as e:
            return [TextContent(type="text", text=f"Error listing processes: {str(e)}")]

    elif name == "search_process":
        if not scan_results:
            return [TextContent(type="text", text="Error: No scan results available. Run scan_memory_image first.")]

        query = arguments["query"].lower()

        try:
            parser = VolatilityParser()
            process_data = parser.parse_all(scan_results)

            matches = [
                p for p in process_data
                if query in p['name'].lower() or query == str(p['pid'])
            ]

            if not matches:
                return [TextContent(type="text", text=f"No processes found matching '{query}'.")]

            output = f"Found {len(matches)} matching process(es):\n\n"
            for proc in matches:
                output += f"═══ {proc['name']} (PID: {proc['pid']}) ═══\n"
                for key, value in proc['details'].items():
                    output += f"  {key}: {value}\n"
                output += "\n"

            return [TextContent(type="text", text=output)]

        except Exception as e:
            return [TextContent(type="text", text=f"Error searching processes: {str(e)}")]

    elif name == "dump_process":
        if not current_scanner:
            return [TextContent(type="text", text="Error: No active scan. Run scan_memory_image first.")]

        pid = arguments["pid"]
        output_dir = arguments.get("output_dir", "./dumps")

        try:
            result = current_scanner.run_on_demand("procdump", pid=pid)

            if result.success:
                return [
                    TextContent(
                        type="text",
                        text=f"✓ Process {pid} dumped successfully!\n\n"
                        f"Output directory: {os.path.abspath(output_dir)}\n"
                        f"Duration: {result.duration:.1f}s\n\n"
                        f"Output:\n{result.output}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error dumping process {pid}:\n{result.error or 'Unknown error'}",
                    )
                ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "dump_files":
        if not current_scanner:
            return [TextContent(type="text", text="Error: No active scan. Run scan_memory_image first.")]

        offset = arguments["offset"]
        output_dir = arguments.get("output_dir", "./dumps")

        try:
            result = current_scanner.run_on_demand("dumpfiles", grep=offset)

            if result.success:
                return [
                    TextContent(
                        type="text",
                        text=f"✓ Files dumped successfully from offset {offset}!\n\n"
                        f"Output directory: {os.path.abspath(output_dir)}\n"
                        f"Duration: {result.duration:.1f}s\n\n"
                        f"Output:\n{result.output}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error dumping files:\n{result.error or 'Unknown error'}",
                    )
                ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "run_plugin":
        if not current_scanner:
            return [TextContent(type="text", text="Error: No active scan. Run scan_memory_image first.")]

        plugin = arguments["plugin"]
        pid = arguments.get("pid")
        grep_filter = arguments.get("grep")

        try:
            result = current_scanner.run_on_demand(plugin, pid=pid, grep=grep_filter)

            if result.success:
                return [
                    TextContent(
                        type="text",
                        text=f"✓ Plugin '{plugin}' executed successfully!\n\n"
                        f"Duration: {result.duration:.1f}s\n\n"
                        f"Output:\n{result.output[:5000]}{'...(truncated)' if len(result.output) > 5000 else ''}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error running plugin '{plugin}':\n{result.error or 'Unknown error'}",
                    )
                ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "get_process_tree":
        if not scan_results:
            return [TextContent(type="text", text="Error: No scan results available. Run scan_memory_image first.")]

        try:
            parser = VolatilityParser()
            process_data = parser.parse_all(scan_results)

            # Build parent-child relationships
            process_map = {p['pid']: p for p in process_data}
            children_map = {}

            for proc in process_data:
                ppid = proc['details'].get('PPID')
                if ppid and ppid != 'N/A':
                    if ppid not in children_map:
                        children_map[ppid] = []
                    children_map[ppid].append(proc)

            # Find roots
            roots = [p for p in process_data if not p['details'].get('PPID') or p['details']['PPID'] == '0']

            def render_tree(proc, level=0):
                indent = "  " * level
                icon = "├─" if level > 0 else "▪"
                output = f"{indent}{icon} [{proc['pid']}] {proc['name']}\n"

                children = children_map.get(str(proc['pid']), [])
                for child in children:
                    output += render_tree(child, level + 1)

                return output

            output = "Process Tree:\n\n"
            for root in roots:
                output += render_tree(root)

            return [TextContent(type="text", text=output)]

        except Exception as e:
            return [TextContent(type="text", text=f"Error generating process tree: {str(e)}")]

    elif name == "analyze_suspicious_processes":
        if not scan_results:
            return [TextContent(type="text", text="Error: No scan results available. Run scan_memory_image first.")]

        try:
            parser = VolatilityParser()
            process_data = parser.parse_all(scan_results)

            suspicious = []

            for proc in process_data:
                flags = []

                # Check for hidden processes (in psscan but not pslist)
                if proc['details'].get('Offset (Physical)') and not proc['details'].get('Offset (Virtual)'):
                    flags.append("Hidden process (psscan only)")

                # Check for suspicious parent
                ppid = proc['details'].get('PPID')
                if ppid and ppid == '0' and proc['name'] not in ['System', 'smss.exe']:
                    flags.append("Orphaned process")

                # Check for suspicious names
                suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
                if any(name in proc['name'].lower() for name in suspicious_names):
                    flags.append("Potentially suspicious executable")

                # Check for network activity
                if proc['details'].get('Network Connections'):
                    flags.append("Has network activity")

                if flags:
                    suspicious.append({
                        'process': proc,
                        'flags': flags
                    })

            if not suspicious:
                return [TextContent(type="text", text="No obviously suspicious processes detected.")]

            output = f"⚠ Found {len(suspicious)} potentially suspicious process(es):\n\n"
            for item in suspicious:
                proc = item['process']
                output += f"═══ {proc['name']} (PID: {proc['pid']}) ═══\n"
                for flag in item['flags']:
                    output += f"  🚩 {flag}\n"
                if proc['details'].get('Command Line'):
                    output += f"  CMD: {proc['details']['Command Line']}\n"
                output += "\n"

            return [TextContent(type="text", text=output)]

        except Exception as e:
            return [TextContent(type="text", text=f"Error analyzing processes: {str(e)}")]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
