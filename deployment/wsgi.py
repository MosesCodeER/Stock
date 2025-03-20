"""
WSGI entry point for Stock Tracker Application
"""

import os
import sys

# Add application directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import the app
from app import app as application

if __name__ == "__main__":
    application.run()
