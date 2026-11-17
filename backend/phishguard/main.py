"""Entry point for uvicorn:  python -m uvicorn phishguard.main:app --port 8000

Kept separate from api.py so that importing the app factory (in tests) does
not load the model or open the database.
"""
import logging

from .api import create_app

logging.basicConfig(level=logging.INFO)
app = create_app()
