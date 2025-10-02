"""HTML report generator for Volatility scan results."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, PackageLoader, select_autoescape

from .parser import VolatilityParser
from .scanner import ScanResult


class HTMLReporter:
    """Generates HTML reports from Volatility scan results."""

    def __init__(self):
        """Initialize the HTML reporter with Jinja2 template engine."""
        self.env = Environment(
            loader=PackageLoader("volautomatiq", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate(
        self,
        results: list[ScanResult],
        image_path: str,
        profile: Optional[str],
        output_path: str,
    ) -> None:
        """Generate HTML report from scan results.

        Args:
            results: List of scan results from VolatilityScanner
            image_path: Path to the memory image that was scanned
            profile: Volatility profile used (or None if auto-detected)
            output_path: Path where HTML report will be saved
        """
        # Parse process data from all plugins
        print("[*] Parsing process data for search functionality...")
        parser = VolatilityParser()
        process_data = parser.parse_all(results)
        print(f"[*] Extracted data for {len(process_data)} processes")

        template = self.env.get_template("report.html")

        # Prepare context data
        context = {
            "image_name": Path(image_path).name,
            "image_path": str(Path(image_path).absolute()),
            "profile": profile,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": results,
            "total_count": len(results),
            "successful_count": sum(1 for r in results if r.success),
            "process_data": process_data,
            "api_server_info": {
                "host": "127.0.0.1",
                "port": 5555,
            },
        }

        # Render template
        html_content = template.render(**context)

        # Write to file
        output_file = Path(output_path)
        output_file.write_text(html_content, encoding="utf-8")

        print(f"\n[+] Report saved to: {output_file.absolute()}")
