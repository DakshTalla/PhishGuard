"""PhishGuard: phishing and malicious URL detection.

Package layout (read in this order):
  features/  turn a URL into numbers and facts (lexical, host, page)
  model/     train and load the machine-learning model (lexical features only)
  rules.py   hand-written checks that turn facts into scored reasons
  scanner.py glue: features -> model -> rules -> one score with reasons
  api.py     FastAPI app with caching, rate limiting and scan history
"""

__version__ = "1.0.0"
