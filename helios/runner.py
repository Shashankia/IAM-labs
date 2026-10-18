"""Starts the identity provider, Leave Portal, and Payroll together."""

from __future__ import annotations

import socket
import sys
import threading
import time

from werkzeug.serving import make_server

from helios.config import HOST, IDP_BASE, IDP_PORT, LAB_PASSWORD, PAYROLL_BASE, PAYROLL_PORT, PORTAL_BASE, PORTAL_PORT
from helios.idp import app as idp_app
from helios.jit import expire_due
from helios.payroll import app as payroll_app
from helios.portal import app as portal_app
from helios.store import init_db, reset_db


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((HOST, port)) != 0


def _serve(flask_app, port: int, name: str) -> threading.Thread:
    server = make_server(HOST, port, flask_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return thread


def _wait_ready() -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PAYROLL_PORT), timeout=0.4):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("Payroll did not start.")


def main() -> None:
    if "--reset" in sys.argv:
        reset_db()
        print("Lab data reset.")
    else:
        init_db()
    busy = [port for port in (IDP_PORT, PORTAL_PORT, PAYROLL_PORT) if not _port_free(port)]
    if busy:
        print("These ports are already in use:", ", ".join(str(port) for port in busy))
        print("Stop the other Helios window, or close whatever is using them, then start again.")
        sys.exit(1)
    _serve(idp_app, IDP_PORT, "idp")
    _serve(portal_app, PORTAL_PORT, "portal")
    _serve(payroll_app, PAYROLL_PORT, "payroll")
    _wait_ready()
    print()
    print("Helios IAM Lab is running. Keep this window open.")
    print()
    print(f"  Identity provider   {IDP_BASE}")
    print(f"  Leave Portal        {PORTAL_BASE}")
    print(f"  Payroll             {PAYROLL_BASE}")
    print()
    print(f"  Password for every account: {LAB_PASSWORD}")
    print("  Start as iam.admin in the identity provider.")
    print("  Full click path: docs/KAISE-PADHO.md")
    print()
    print("  Stop with Ctrl+C")
    print()
    try:
        while True:
            expire_due()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
