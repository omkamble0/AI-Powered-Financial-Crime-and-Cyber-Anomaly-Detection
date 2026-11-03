#!/usr/bin/env python3
"""
FinCipher AI — One-Click Unified Platform Launcher
Author: Om Kamble

Single-command entry point to:
1. Initialize the FinCipher AI Cognitive Fraud & Risk Engine.
2. Launch the high-throughput ASGI FastAPI server with real-time WebSockets.
3. Automatically probe health and open the interactive Studio Dashboard in the default browser.
"""

import sys
import os
import time
import argparse
import threading
import webbrowser
import urllib.request

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def wait_and_open_browser(dashboard_url: str, health_url: str, timeout: float = 12.0):
    """Polls the local server health endpoint and launches the browser once ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(health_url, headers={"User-Agent": "FinCipher-Launcher"})
            with urllib.request.urlopen(req, timeout=1.0) as res:
                if res.status == 200:
                    time.sleep(0.4)
                    print(f"\n[FinCipher AI] Server online! Launching browser: {dashboard_url}")
                    webbrowser.open(dashboard_url)
                    return
        except Exception:
            time.sleep(0.3)

    # Fallback if health probe timed out but server is binding
    print(f"\n[FinCipher AI] Opening browser: {dashboard_url}")
    webbrowser.open(dashboard_url)


def main():
    parser = argparse.ArgumentParser(description="FinCipher AI One-Click Platform Launcher")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Start server without launching web browser")
    parser.add_argument("--reload", action="store_true", help="Enable hot-reloading for local development")
    args = parser.parse_args()

    dashboard_url = f"http://{args.host}:{args.port}/dashboard"
    health_url = f"http://{args.host}:{args.port}/health"
    docs_url = f"http://{args.host}:{args.port}/docs"

    banner = f"""
================================================================================
   🛡️  FinCipher AI — Enterprise Risk & Fraud Intelligence Citadel
   Version: v2.3 CORE / v2.4 Enterprise | Author: Om Kamble
================================================================================
   🌐 Studio Dashboard  : {dashboard_url}
   ⚡ Live Stream Radar  : {dashboard_url} (Tab: Live Stream)
   📖 Interactive API   : {docs_url}
   🩺 Cloud Health Probe : {health_url}
================================================================================
"""
    print(banner)

    if not args.no_browser:
        browser_thread = threading.Thread(
            target=wait_and_open_browser,
            args=(dashboard_url, health_url),
            daemon=True
        )
        browser_thread.start()

    try:
        import uvicorn
        uvicorn.run(
            "src.api.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n[FinCipher AI] Platform stopped cleanly by user. Farewell!")
    except Exception as e:
        print(f"\n[FinCipher AI] Startup error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

