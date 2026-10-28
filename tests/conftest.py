"""
pytest configuration — ensure the project root is on sys.path.
"""

import sys
from pathlib import Path

# Add project root so `from app.xxx import ...` works without installation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
