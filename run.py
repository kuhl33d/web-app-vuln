#!/usr/bin/env python
"""
Startup script for w3bxAN Web Vulnerability Scanner

This script provides a convenient way to start the Flask application
with proper environment variable loading from .env file.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Import and run the Flask application
from app import app

if __name__ == '__main__':
    # Get port from environment variable or use default 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Run the Flask application
    app.run(
        host='0.0.0.0',  # Make the server publicly available
        port=port,
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    )
    
    print(f"w3bxAN Web Vulnerability Scanner running on http://localhost:{port}")