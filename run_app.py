#!/usr/bin/env python3
import os
import sys

# Add Back-End directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

if __name__ == '__main__':
    import uvicorn
    from code_scan_api import app
    
    port = int(os.getenv('PORT', 8000))
    print(f"Starting Code Scanner Agent on 0.0.0.0:{port}")
    print(f"Web UI: http://localhost:{port}")
    print(f"API Docs: http://localhost:{port}/docs")
    
    uvicorn.run(app, host='0.0.0.0', port=port)