"""API server for on-demand Volatility plugin execution."""

import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import Optional
from pathlib import Path


class VolatilityAPIServer:
    """Flask API server for on-demand plugin execution."""

    def __init__(self, scanner):
        """Initialize API server with scanner instance.

        Args:
            scanner: VolatilityScanner instance
        """
        self.scanner = scanner
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for local HTML file access

        # Register routes
        self.app.add_url_rule('/api/handles', 'handles', self.run_handles, methods=['POST'])
        self.app.add_url_rule('/api/filescan', 'filescan', self.run_filescan, methods=['POST'])
        self.app.add_url_rule('/api/status', 'status', self.get_status, methods=['GET'])

    def run_handles(self):
        """Execute handles plugin for a specific PID.

        Expects JSON: {"pid": 1234}
        """
        data = request.get_json()
        pid = data.get('pid')

        if not pid:
            return jsonify({'error': 'PID is required'}), 400

        try:
            result = self.scanner.run_on_demand('handles', pid=int(pid))

            # Check if error indicates terminated/unlinked process
            if not result.success and result.error and 'Cannot find PID' in result.error:
                return jsonify({
                    'success': False,
                    'output': '',
                    'error': f'Cannot find PID {pid}. This process may be terminated, hidden, or unlinked.\n\nNote: The handles plugin only works with active processes visible in pslist.\nFor terminated processes, this information is not available.',
                    'duration': result.duration
                })

            return jsonify({
                'success': result.success,
                'output': result.output,
                'error': result.error,
                'duration': result.duration
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    def run_filescan(self):
        """Execute filescan plugin with optional grep filter.

        Expects JSON: {"grep": "malware.exe"}
        """
        data = request.get_json()
        grep = data.get('grep', '')

        try:
            result = self.scanner.run_on_demand('filescan', grep=grep if grep else None)

            return jsonify({
                'success': result.success,
                'output': result.output,
                'error': result.error,
                'duration': result.duration
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    def get_status(self):
        """Get server status."""
        return jsonify({
            'status': 'running',
            'image': str(self.scanner.image_path),
            'profile': self.scanner.profile
        })

    def run(self, host='127.0.0.1', port=5555):
        """Start the API server.

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        print(f"\n[*] Starting API server on http://{host}:{port}")
        print("[*] Press Ctrl+C to stop the server")
        self.app.run(host=host, port=port, debug=False, use_reloader=False)
