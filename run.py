"""
BewerbungsDB — single entry point.

Web server (default):
    python run.py

MCP stdio server (for Claude Desktop):
    python run.py --mcp
"""

import sys
import uvicorn
from app.config import HOST, PORT

if __name__ == "__main__":
    if "--mcp" in sys.argv:
        from app.mcp import mcp
        mcp.run()
    else:
        uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
