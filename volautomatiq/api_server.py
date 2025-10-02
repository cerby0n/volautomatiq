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
        self.app.add_url_rule('/api/procdump', 'procdump', self.run_dumpfiles, methods=['POST'])
        self.app.add_url_rule('/api/procdump-pid', 'procdump_pid', self.run_procdump, methods=['POST'])
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

    def run_dumpfiles(self):
        """Execute dumpfiles plugin to dump file from memory.

        Expects JSON: {"offset": "0x12345678", "output_dir": "./dumps"}
        """
        data = request.get_json()
        offset = data.get('offset')
        output_dir = data.get('output_dir', './dumps')

        if not offset:
            return jsonify({'error': 'Physical offset is required'}), 400

        try:
            import subprocess
            import os
            from datetime import datetime

            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Build dumpfiles command
            cmd = [
                self.scanner.vol_path,
                "-f", str(self.scanner.image_path),
                "--profile", self.scanner.profile,
                "dumpfiles",
                "-Q", offset,
                "-D", output_dir
            ]

            print(f"  Running dumpfiles with offset {offset}...")
            start_time = datetime.now()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            duration = (datetime.now() - start_time).total_seconds()

            if result.returncode == 0:
                # List files in output directory to show what was dumped
                try:
                    dumped_files = sorted(os.listdir(output_dir), key=lambda f: os.path.getmtime(os.path.join(output_dir, f)), reverse=True)
                    # Get files created in the last few seconds
                    recent_files = []
                    cutoff_time = datetime.now().timestamp() - 10
                    for f in dumped_files:
                        file_path = os.path.join(output_dir, f)
                        if os.path.getmtime(file_path) > cutoff_time:
                            recent_files.append(f)

                    if recent_files:
                        file_list = '\n'.join(recent_files)
                        return jsonify({
                            'success': True,
                            'output': result.stdout,
                            'files': recent_files,
                            'directory': os.path.abspath(output_dir),
                            'message': f'Files dumped successfully:\n{file_list}',
                            'duration': duration
                        })
                    else:
                        return jsonify({
                            'success': True,
                            'output': result.stdout,
                            'directory': os.path.abspath(output_dir),
                            'message': 'Dump completed. Check the output directory.',
                            'duration': duration
                        })
                except Exception as e:
                    return jsonify({
                        'success': True,
                        'output': result.stdout,
                        'directory': os.path.abspath(output_dir),
                        'message': 'Dump completed',
                        'duration': duration
                    })
            else:
                return jsonify({
                    'success': False,
                    'output': result.stdout,
                    'error': result.stderr or 'Dumpfiles command failed',
                    'duration': duration
                })

        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Dumpfiles timed out after 5 minutes'
            }), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    def run_procdump(self):
        """Execute procdump plugin to dump process memory by PID.

        Expects JSON: {"pid": 2748, "output_dir": "./dumps"}
        """
        data = request.get_json()
        pid = data.get('pid')
        output_dir = data.get('output_dir', './dumps')

        if not pid:
            return jsonify({'error': 'PID is required'}), 400

        try:
            import subprocess
            import os
            from datetime import datetime

            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Build procdump command
            cmd = [
                self.scanner.vol_path,
                "-f", str(self.scanner.image_path),
                "--profile", self.scanner.profile,
                "procdump",
                "-p", str(pid),
                "--dump-dir", output_dir
            ]

            print(f"  Running procdump for PID {pid}...")
            start_time = datetime.now()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            duration = (datetime.now() - start_time).total_seconds()

            if result.returncode == 0:
                # List files in output directory to show what was dumped
                try:
                    dumped_files = sorted(os.listdir(output_dir), key=lambda f: os.path.getmtime(os.path.join(output_dir, f)), reverse=True)
                    # Get files created in the last few seconds
                    recent_files = []
                    cutoff_time = datetime.now().timestamp() - 10
                    for f in dumped_files:
                        file_path = os.path.join(output_dir, f)
                        if os.path.getmtime(file_path) > cutoff_time:
                            recent_files.append(f)

                    if recent_files:
                        file_list = '\n'.join(recent_files)
                        return jsonify({
                            'success': True,
                            'output': result.stdout,
                            'files': recent_files,
                            'directory': os.path.abspath(output_dir),
                            'message': f'Process dumped successfully:\n{file_list}',
                            'duration': duration
                        })
                    else:
                        return jsonify({
                            'success': True,
                            'output': result.stdout,
                            'directory': os.path.abspath(output_dir),
                            'message': 'Dump completed. Check the output directory.',
                            'duration': duration
                        })
                except Exception as e:
                    return jsonify({
                        'success': True,
                        'output': result.stdout,
                        'directory': os.path.abspath(output_dir),
                        'message': 'Dump completed',
                        'duration': duration
                    })
            else:
                return jsonify({
                    'success': False,
                    'output': result.stdout,
                    'error': result.stderr or 'Procdump command failed',
                    'duration': duration
                })

        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Procdump timed out after 5 minutes'
            }), 500
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
