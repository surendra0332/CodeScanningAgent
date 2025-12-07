#!/usr/bin/env python3
"""
Code Scanner Agent - Main Application Runner
Intelligent security and quality code analysis with test validation
"""
import os
import sys

# Add Back-End directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

if __name__ == '__main__':
    try:
        import uvicorn
        from code_scan_api import app
        
        # Configuration from environment
        port = int(os.getenv('PORT', 8000))
        host = os.getenv('HOST', '0.0.0.0')
        debug = os.getenv('DEBUG', 'false').lower() == 'true'
        
        # Startup messages
        print(f"Starting Code Scanner Agent on {host}:{port}")
        print(f"Web UI: http://localhost:{port}")
        print(f"API Docs: http://localhost:{port}/docs")
        
        if debug:
            print("Debug mode: ON (auto-reload enabled)")
        
        # Start server
        uvicorn.run(
            app, 
            host=host, 
            port=port,
            reload=debug  # Auto-reload on code changes in debug mode
        )
        
    except KeyboardInterrupt:
        print("\n✓ Shutting down gracefully...")
        sys.exit(0)
        
    except Exception as e:
        print(f"✗ Error starting application: {e}")
        sys.exit(1)