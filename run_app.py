#!/usr/bin/env python3
"""
Code Scanner Agent - Main Application Runner
Intelligent security and quality code analysis with test validation
"""
import os
import sys

# Add Back-End directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

import os
import sys
import subprocess
import time
import argparse

# Add Back-End directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

def kill_port(port_num):
    """Kill process running on specified port"""
    try:
        # Find process ID
        cmd = f"lsof -i :{port_num} -t"
        pids = subprocess.check_output(cmd, shell=True).decode().strip().split('\n')
        
        for pid in pids:
            if pid:
                print(f"⚠️  Port {port_num} is in use by PID {pid}. Killing it...")
                subprocess.run(f"kill -9 {pid}", shell=True, check=True)
        
        if pids:
            time.sleep(1)  # Wait for release
            print(f"✓ Port {port_num} released.")
    except subprocess.CalledProcessError:
        pass  # No process found, which is good
    except Exception as e:
        print(f"Warning: Could not auto-kill port {port_num}: {e}")

def run_backend(host, port, debug):
    """Start the FastAPI backend server"""
    import uvicorn
    from code_scan_api import app
    
    print(f"🚀 Starting Backend API Server on {host}:{port}")
    print(f"📄 API Docs: http://localhost:{port}/docs")
    
    if debug:
        print("🔧 Debug mode: ON (auto-reload enabled)")
        backend_path = os.path.join(os.path.dirname(__file__), 'Back-End')
        current_pythonpath = os.environ.get('PYTHONPATH', '')
        os.environ['PYTHONPATH'] = f"{backend_path}{os.pathsep}{current_pythonpath}"
    
    kill_port(port)
    uvicorn.run(
        "code_scan_api:app", 
        host=host, 
        port=port,
        reload=debug,
        reload_dirs=[os.path.join(os.path.dirname(__file__), 'Back-End')] if debug else None
    )

def run_frontend(port):
    """Start a simple HTTP server for the frontend"""
    import http.server
    import socketserver
    
    directory = "Front-End"
    if not os.path.exists(directory):
        print(f"❌ Error: {directory} directory not found!")
        return

    print(f"🌐 Starting Frontend UI Server on port {port}")
    print(f"🏠 URL: http://localhost:{port}")
    
    kill_port(port)
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

    with socketserver.TCPServer(("", port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n✓ Shutting down frontend...")
            httpd.shutdown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Code Scanner Agent Runner')
    parser.add_argument('--backend', action='store_true', help='Run only the backend API server')
    parser.add_argument('--frontend', action='store_true', help='Run only the frontend UI server')
    parser.add_argument('--port', type=int, help='Specify a custom port')
    
    args = parser.parse_args()
    
    # Configuration from environment
    default_port = int(os.getenv('PORT', 8001))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    try:
        if args.frontend:
            # If only frontend requested, default to 8000
            port = args.port or 8000
            run_frontend(port)
        elif args.backend:
            # If only backend requested, default to 8001
            port = args.port or 8001
            run_backend(host, port, debug)
        else:
            # Default behavior: Run everything (Full App) on one port
            print("📦 Starting Full Application (Combined Mode)...")
            print(f"🌐 Web UI: http://localhost:{default_port}")
            run_backend(host, default_port, debug)
            
    except KeyboardInterrupt:
        print("\n✓ Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)