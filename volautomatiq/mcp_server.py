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
            name="load_memory_image",
            description="Load and initialize a memory image for analysis. Detects the Volatility profile automatically. Must be called first before using other plugins.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Path to the memory dump file (e.g., /data/dumps/memory.vmem)",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Optional: Volatility profile (e.g., Win7SP1x64). If not provided, will auto-detect.",
                    },
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="run_pslist",
            description="Run pslist plugin to list active processes with PID, PPID, threads, handles, and start time.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_psscan",
            description="Run psscan plugin to find hidden/terminated processes by scanning memory pools.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_pstree",
            description="Run pstree plugin to display process tree showing parent-child relationships.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_cmdline",
            description="Run cmdline plugin to extract command line arguments for all processes.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_netscan",
            description="Run netscan plugin to find network connections and listening ports.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="run_filescan",
            description="Run filescan plugin to list open files. WARNING: Very slow, can take 5-10 minutes. Use grep filter to search for specific files only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "grep": {
                        "type": "string",
                        "description": "REQUIRED: Filter by filename pattern (e.g., '.exe', '.dll', 'suspicious'). Makes scan faster.",
                    },
                },
                "required": ["grep"],
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
                        "description": "Directory to save the dumped files (default: /data/reports/dumps/)",
                    },
                },
                "required": ["offset"],
            },
        ),
        Tool(
            name="run_malfind",
            description="Run malfind plugin to detect injected code and malware in process memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Optional: Scan specific process only",
                    },
                },
            },
        ),
        Tool(
            name="run_handles",
            description="Run handles plugin to list handles (files, registry keys, mutexes) for a process. Much faster than filescan for targeted analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to list handles for",
                    },
                    "type": {
                        "type": "string",
                        "description": "Optional: Filter by handle type (File, Key, Mutant, Event, etc.)",
                    },
                },
                "required": ["pid"],
            },
        ),
        Tool(
            name="run_dlllist",
            description="Run dlllist plugin to list DLLs loaded by a process. Useful to detect injected or suspicious DLLs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Optional: Process ID to list DLLs for (all processes if not specified)",
                    },
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    global current_scanner, current_image_path, current_profile, scan_results

    if name == "load_memory_image":
        image_path = arguments["image_path"]
        profile = arguments.get("profile")

        if not Path(image_path).exists():
            return [TextContent(type="text", text=f"Error: Memory image not found: {image_path}")]

        try:
            # Initialize scanner
            scanner = VolatilityScanner(
                image_path=image_path,
                profile=profile,
                vol_path="vol.py",
            )

            # Detect profile if not provided
            if not profile:
                result = scanner._run_plugin("imageinfo")
                if result.success:
                    for line in result.output.split("\n"):
                        if "Suggested Profile(s)" in line:
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                profiles = parts[1].strip().split(",")
                                if profiles:
                                    scanner.profile = profiles[0].strip()
                                    break

            current_scanner = scanner
            current_image_path = image_path
            current_profile = scanner.profile

            return [
                TextContent(
                    type="text",
                    text=f"✓ Memory image loaded successfully!\n\n"
                    f"Image: {Path(image_path).name}\n"
                    f"Profile: {scanner.profile or 'Not detected'}\n"
                    f"Size: {Path(image_path).stat().st_size / (1024**3):.2f} GB\n\n"
                    f"You can now run Volatility plugins (pslist, psscan, netscan, etc.)",
                )
            ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error loading image: {str(e)}")]

    elif name in ["run_pslist", "run_psscan", "run_pstree", "run_cmdline", "run_netscan", "run_filescan", "run_malfind", "run_dlllist"]:
        if not current_scanner:
            return [TextContent(type="text", text="Error: No image loaded. Run load_memory_image first.")]

        plugin = name.replace("run_", "")
        grep_filter = arguments.get("grep")
        pid = arguments.get("pid")

        try:
            result = current_scanner.run_on_demand(plugin, pid=pid, grep=grep_filter)

            if result.success:
                # For critical plugins, don't truncate
                critical_plugins = ["pslist", "psscan", "pstree"]
                output = result.output

                if plugin not in critical_plugins and len(output) > 15000:
                    output = output[:15000] + f"\n\n...(truncated, showing first 15k of {len(result.output)} chars)"

                return [
                    TextContent(
                        type="text",
                        text=f"✓ Plugin '{plugin}' completed in {result.duration:.1f}s\n\n{output}",
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

    elif name == "run_handles":
        if not current_scanner:
            return [TextContent(type="text", text="Error: No image loaded. Run load_memory_image first.")]

        pid = arguments["pid"]
        handle_type = arguments.get("type")

        try:
            result = current_scanner.run_on_demand("handles", pid=pid, grep=handle_type)

            if result.success:
                output = result.output
                if len(output) > 15000:
                    output = output[:15000] + f"\n\n...(truncated, showing first 15k of {len(result.output)} chars)"

                return [
                    TextContent(
                        type="text",
                        text=f"✓ Handles for PID {pid} (completed in {result.duration:.1f}s)\n\n{output}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error getting handles for PID {pid}:\n{result.error or 'Unknown error'}",
                    )
                ]

        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "dump_process":
        if not current_scanner:
            return [TextContent(type="text", text="Error: No image loaded. Run load_memory_image first.")]

        pid = arguments["pid"]
        output_dir = arguments.get("output_dir", "/data/reports/dumps")

        # Create dump directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        try:
            result = current_scanner.run_on_demand("procdump", pid=pid, dump_dir=output_dir)

            if result.success:
                return [
                    TextContent(
                        type="text",
                        text=f"✓ Process {pid} dumped successfully!\n\n"
                        f"Output directory: {output_dir}\n"
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
            return [TextContent(type="text", text="Error: No image loaded. Run load_memory_image first.")]

        offset = arguments["offset"]
        output_dir = arguments.get("output_dir", "/data/reports/dumps")

        # Create dump directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        try:
            result = current_scanner.run_on_demand("dumpfiles", grep=offset, dump_dir=output_dir)

            if result.success:
                return [
                    TextContent(
                        type="text",
                        text=f"✓ Files dumped successfully from offset {offset}!\n\n"
                        f"Output directory: {output_dir}\n"
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

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
