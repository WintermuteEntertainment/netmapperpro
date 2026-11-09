"""
Run the web app under Waitress, a production WSGI server, for hosting on BBB.

    python web/serve.py

Listens on 127.0.0.1 only: the Cloudflare tunnel on the same machine is the
one way in. For local use on PT, `python web/app.py` (Flask's own server)
is still fine.
"""

import sys

from waitress import serve

import access
import app as webapp

HOST, PORT = "127.0.0.1", 7890

if __name__ == "__main__":
    mode = (f"Cloudflare Access required (team {access.TEAM})"
            if access.ENABLED else "NO Access check (local use only)")
    print(f"NetMapperPro web on http://{HOST}:{PORT}  [{mode}]", flush=True)
    sys.stdout.flush()
    # Each open browser tab holds one thread on the /stream event feed, so
    # allow comfortably more than the default four.
    serve(webapp.app, host=HOST, port=PORT, threads=16)
