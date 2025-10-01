"""Parser for Volatility plugin outputs to extract process information."""

import re
from typing import Any


class ProcessInfo:
    """Aggregated process information from multiple plugins."""

    def __init__(self, pid: int, name: str):
        self.pid = pid
        self.name = name
        self.details: dict[str, Any] = {}

    def add_detail(self, key: str, value: Any):
        """Add a detail to this process."""
        if value and str(value).strip():
            self.details[key] = str(value).strip()

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "pid": self.pid,
            "name": self.name,
            "details": self.details,
        }


class VolatilityParser:
    """Parses Volatility plugin outputs and aggregates process information."""

    def __init__(self):
        self.processes: dict[int, ProcessInfo] = {}

    def _get_or_create_process(self, pid: int, name: str = "") -> ProcessInfo:
        """Get existing process or create new one."""
        if pid not in self.processes:
            self.processes[pid] = ProcessInfo(pid, name)
        elif name and not self.processes[pid].name:
            self.processes[pid].name = name
        return self.processes[pid]

    def parse_pslist(self, output: str):
        """Parse pslist output.

        Expected format:
        Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
        0x...      System                    4      0     78      411 ------      0 2012-07-22 02:42:31 UTC+0000
        """
        lines = output.strip().split('\n')

        for line in lines:
            # Skip header and separator lines
            if 'Offset' in line or '---' in line or not line.strip():
                continue

            # Parse line - format varies but typically:
            # Offset Name PID PPID Thds Hnds Sess Wow64 Start Exit
            parts = line.split()
            if len(parts) >= 8:
                try:
                    offset = parts[0]
                    name = parts[1]
                    pid = int(parts[2])
                    ppid = int(parts[3])
                    threads = parts[4]
                    handles = parts[5]
                    session = parts[6]
                    wow64 = parts[7]

                    proc = self._get_or_create_process(pid, name)
                    proc.add_detail("Offset (Virtual)", offset)
                    proc.add_detail("PPID", ppid)
                    proc.add_detail("Threads", threads)
                    proc.add_detail("Handles", handles)
                    proc.add_detail("Session", session)
                    proc.add_detail("Wow64", wow64)

                    # Parse start time if present
                    if len(parts) > 8:
                        start_time = ' '.join(parts[8:])
                        if 'Exit' not in start_time:
                            proc.add_detail("Start Time", start_time.replace('UTC+0000', '').strip())

                except (ValueError, IndexError):
                    continue

    def parse_psscan(self, output: str):
        """Parse psscan output.

        Expected format:
        Offset(P)          Name                PID   PPID PDB        Time created                   Time exited
        0x...              System                4      0 0x00185000 2012-07-22 02:42:31 UTC+0000
        """
        lines = output.strip().split('\n')

        for line in lines:
            if 'Offset' in line or '---' in line or not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 5:
                try:
                    offset_physical = parts[0]
                    name = parts[1]
                    pid = int(parts[2])
                    ppid = int(parts[3])
                    pdb = parts[4]

                    proc = self._get_or_create_process(pid, name)
                    proc.add_detail("Offset (Physical)", offset_physical)
                    proc.add_detail("PDB", pdb)

                    if not proc.details.get("PPID"):
                        proc.add_detail("PPID", ppid)

                except (ValueError, IndexError):
                    continue

    def parse_cmdline(self, output: str):
        r"""Parse cmdline output.

        Expected format:
        System pid:      4
        ************************************************************************
        csrss.exe pid:    348
        Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
        """
        lines = output.strip().split('\n')
        current_process = None

        for line in lines:
            # Match process header: "processname.exe pid: 123"
            match = re.match(r'(.+?)\s+pid:\s+(\d+)', line)
            if match:
                name = match.group(1).strip()
                pid = int(match.group(2))
                current_process = self._get_or_create_process(pid, name)
                continue

            # Match command line
            if current_process and line.strip().startswith('Command line'):
                cmdline = line.split(':', 1)[1].strip() if ':' in line else ''
                current_process.add_detail("Command Line", cmdline)

    def parse_netscan(self, output: str):
        """Parse netscan output.

        Expected format:
        Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
        0x...              TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        708      svchost.exe
        """
        lines = output.strip().split('\n')

        # Group connections by PID
        connections_by_pid: dict[int, list[str]] = {}

        for line in lines:
            if 'Offset' in line or '---' in line or not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 6:
                try:
                    # Find PID (usually 6th or 7th column)
                    pid_idx = -1
                    for i, part in enumerate(parts):
                        if part.isdigit() and int(part) > 0:
                            # Check if next part looks like a process name
                            if i + 1 < len(parts) and not parts[i + 1].isdigit():
                                pid_idx = i
                                break

                    if pid_idx > 0:
                        pid = int(parts[pid_idx])
                        proto = parts[1] if len(parts) > 1 else ''
                        local_addr = parts[2] if len(parts) > 2 else ''
                        foreign_addr = parts[3] if len(parts) > 3 else ''
                        state = parts[4] if len(parts) > 4 else ''

                        conn_info = f"{proto} {local_addr} -> {foreign_addr} ({state})"

                        if pid not in connections_by_pid:
                            connections_by_pid[pid] = []
                        connections_by_pid[pid].append(conn_info)

                except (ValueError, IndexError):
                    continue

        # Add network connections to processes
        for pid, connections in connections_by_pid.items():
            if pid in self.processes:
                self.processes[pid].add_detail("Network Connections", "; ".join(connections[:5]))  # Limit to 5

    def parse_pstree(self, output: str):
        """Parse pstree output to identify parent-child relationships.

        Expected format:
        Name                                                  Pid   PPid   Thds   Hnds Time
        -------------------------------------------------- ------ ------ ------ ------ ----
        . 0xfffffa80004b09e0:System                            4      0     78    411 2012-07-22 02:42:31 UTC+0000
        .. 0xfffffa8000ce97f0:smss.exe                        208      4      2     29 2012-07-22 02:42:31 UTC+0000
        """
        lines = output.strip().split('\n')

        for line in lines:
            if 'Name' in line or '---' in line or not line.strip():
                continue

            # Count dots to determine hierarchy level
            dots = len(line) - len(line.lstrip('.'))

            # Extract process info
            match = re.search(r'0x[0-9a-fA-F]+:(.+?)\s+(\d+)\s+(\d+)', line)
            if match:
                name = match.group(1).strip()
                pid = int(match.group(2))
                ppid = int(match.group(3))

                proc = self._get_or_create_process(pid, name)
                proc.add_detail("Tree Level", str(dots // 2))  # Each level is 2 dots

                if not proc.details.get("PPID"):
                    proc.add_detail("PPID", ppid)

    def parse_all(self, results: list) -> list[dict]:
        """Parse all plugin results and return aggregated process data.

        Args:
            results: List of ScanResult objects

        Returns:
            List of process dictionaries for JSON serialization
        """
        for result in results:
            if not result.success:
                continue

            if result.plugin == 'pslist':
                self.parse_pslist(result.output)
            elif result.plugin == 'psscan':
                self.parse_psscan(result.output)
            elif result.plugin == 'cmdline':
                self.parse_cmdline(result.output)
            elif result.plugin == 'netscan':
                self.parse_netscan(result.output)
            elif result.plugin == 'pstree':
                self.parse_pstree(result.output)

        # Convert to list and sort by PID
        process_list = [p.to_dict() for p in self.processes.values()]
        process_list.sort(key=lambda x: x['pid'])

        return process_list
