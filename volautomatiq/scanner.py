"""Volatility scanner module for executing memory forensics plugins."""

import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ScanResult:
    """Result from a Volatility plugin scan."""

    plugin: str
    output: str
    success: bool
    error: Optional[str] = None
    duration: float = 0.0


class VolatilityScanner:
    """Orchestrates Volatility scans on memory images."""

    # Plugins to execute in order
    PLUGINS = [
        "imageinfo",
        "pslist",
        "psscan",
        "pstree",
        "netscan",
        "cmdline",
        "iehistory",
    ]

    def __init__(self, image_path: str, profile: Optional[str] = None, vol_path: str = "vol.py"):
        """Initialize scanner with image path and optional profile.

        Args:
            image_path: Path to memory dump file
            profile: Volatility profile (e.g., Win7SP1x64). If None, will be detected from imageinfo
            vol_path: Path to Volatility executable (default: vol.py)
        """
        self.image_path = Path(image_path)
        self.profile = profile
        self.vol_path = vol_path
        self.results: list[ScanResult] = []

        if not self.image_path.exists():
            raise FileNotFoundError(f"Memory image not found: {image_path}")

    def _run_plugin(self, plugin: str, profile: Optional[str] = None) -> ScanResult:
        """Execute a single Volatility plugin.

        Args:
            plugin: Plugin name (e.g., 'pslist')
            profile: Volatility profile to use

        Returns:
            ScanResult with output and metadata
        """
        cmd = [self.vol_path, "-f", str(self.image_path)]

        if profile:
            cmd.extend(["--profile", profile])

        cmd.append(plugin)

        print(f"  Running {plugin}...", flush=True)
        start_time = datetime.now()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout per plugin
            )

            duration = (datetime.now() - start_time).total_seconds()

            if result.returncode == 0:
                return ScanResult(
                    plugin=plugin,
                    output=result.stdout,
                    success=True,
                    duration=duration,
                )
            else:
                return ScanResult(
                    plugin=plugin,
                    output=result.stdout,
                    success=False,
                    error=result.stderr,
                    duration=duration,
                )

        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            return ScanResult(
                plugin=plugin,
                output="",
                success=False,
                error=f"Plugin timed out after {duration:.1f} seconds",
                duration=duration,
            )

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return ScanResult(
                plugin=plugin,
                output="",
                success=False,
                error=str(e),
                duration=duration,
            )

    def _detect_profile(self) -> Optional[str]:
        """Run imageinfo to detect the memory profile.

        Returns:
            Detected profile name or None if detection failed
        """
        result = self._run_plugin("imageinfo")
        self.results.append(result)

        if not result.success:
            return None

        # Parse imageinfo output to extract suggested profile
        for line in result.output.split("\n"):
            if "Suggested Profile(s)" in line:
                # Extract first suggested profile
                # Format: "Suggested Profile(s) : Win7SP1x64, Win7SP0x64, ..."
                parts = line.split(":", 1)
                if len(parts) == 2:
                    profiles = parts[1].strip().split(",")
                    if profiles:
                        profile = profiles[0].strip()
                        print(f"  Detected profile: {profile}")
                        return profile

        return None

    def scan_all(self) -> list[ScanResult]:
        """Execute all Volatility plugins in sequence.

        Returns:
            List of scan results for each plugin
        """
        print(f"\n[*] Starting VolAutomatiq scan")
        print(f"[*] Image: {self.image_path}")
        print(f"[*] Profile: {self.profile or 'Auto-detect'}\n")

        # Detect profile if not provided
        if not self.profile:
            print("[*] Detecting profile...")
            self.profile = self._detect_profile()

            if not self.profile:
                print("[!] Failed to detect profile. Continuing without profile (some plugins may fail).")

            # Skip imageinfo in main loop since we already ran it
            plugins_to_run = [p for p in self.PLUGINS if p != "imageinfo"]
        else:
            # Profile provided, skip imageinfo entirely
            plugins_to_run = [p for p in self.PLUGINS if p != "imageinfo"]
            print(f"[*] Using provided profile: {self.profile}")

        # Run remaining plugins
        print(f"\n[*] Running {len(plugins_to_run)} plugins...\n")

        for plugin in plugins_to_run:
            result = self._run_plugin(plugin, self.profile)
            self.results.append(result)

            if result.success:
                print(f"  ✓ {plugin} completed in {result.duration:.1f}s")
            else:
                print(f"  ✗ {plugin} failed: {result.error}")

        successful = sum(1 for r in self.results if r.success)
        print(f"\n[*] Scan complete: {successful}/{len(self.results)} plugins successful")

        return self.results
