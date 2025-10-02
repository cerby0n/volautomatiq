"""Command-line interface for VolAutomatiq."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .reporter import HTMLReporter
from .scanner import VolatilityScanner
from .api_server import VolatilityAPIServer


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="volautomatiq",
        description="Automated Volatility memory forensics scanner with HTML reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect profile and generate report
  volautomatiq -f memory.dump -o report.html

  # Use specific profile
  volautomatiq -f memory.dump --profile Win7SP1x64 -o report.html

  # Custom Volatility path
  volautomatiq -f memory.dump -o report.html --vol-path /opt/volatility/vol.py

For more information, visit: https://github.com/yourusername/volautomatiq
        """,
    )

    parser.add_argument(
        "-f",
        "--file",
        dest="image_path",
        required=True,
        help="Path to memory dump file",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        default="volautomatiq_report.html",
        help="Output HTML report path (default: volautomatiq_report.html)",
    )

    parser.add_argument(
        "--profile",
        dest="profile",
        help="Volatility profile (e.g., Win7SP1x64). If not specified, will be auto-detected using imageinfo",
    )

    parser.add_argument(
        "--vol-path",
        dest="vol_path",
        default="vol.py",
        help="Path to Volatility executable (default: vol.py)",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Validate image path exists
    if not Path(args.image_path).exists():
        print(f"[!] Error: Memory image not found: {args.image_path}", file=sys.stderr)
        sys.exit(1)

    # Check if Volatility is available
    try:
        import shutil

        vol_executable = shutil.which(args.vol_path)
        if not vol_executable and not Path(args.vol_path).exists():
            print(
                f"[!] Error: Volatility not found at '{args.vol_path}'",
                file=sys.stderr,
            )
            print(
                "[!] Make sure Volatility is installed and accessible in your PATH",
                file=sys.stderr,
            )
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error checking Volatility: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        # Initialize scanner
        scanner = VolatilityScanner(
            image_path=args.image_path,
            profile=args.profile,
            vol_path=args.vol_path,
        )

        # Run all scans
        results = scanner.scan_all()

        # Generate HTML report
        reporter = HTMLReporter()
        reporter.generate(
            results=results,
            image_path=args.image_path,
            profile=scanner.profile,
            output_path=args.output_path,
        )

        # Exit with error code if any scans failed
        if any(not r.success for r in results):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


def serve():
    """Start API server for on-demand plugin execution."""
    parser = argparse.ArgumentParser(
        prog="volautomatiq-server",
        description="API server for on-demand Volatility plugin execution",
    )

    parser.add_argument(
        "-f",
        "--file",
        dest="image_path",
        required=True,
        help="Path to memory dump file",
    )

    parser.add_argument(
        "--profile",
        dest="profile",
        required=True,
        help="Volatility profile (e.g., Win7SP1x64)",
    )

    parser.add_argument(
        "--vol-path",
        dest="vol_path",
        default="vol.py",
        help="Path to Volatility executable (default: vol.py)",
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5555,
        help="Port to bind to (default: 5555)",
    )

    args = parser.parse_args()

    # Validate image path exists
    if not Path(args.image_path).exists():
        print(f"[!] Error: Memory image not found: {args.image_path}", file=sys.stderr)
        sys.exit(1)

    try:
        # Initialize scanner
        scanner = VolatilityScanner(
            image_path=args.image_path,
            profile=args.profile,
            vol_path=args.vol_path,
        )

        # Start API server
        api_server = VolatilityAPIServer(scanner)
        api_server.run(host=args.host, port=args.port)

    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
        sys.exit(0)

    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
