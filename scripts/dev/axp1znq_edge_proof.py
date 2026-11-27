# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
"""Local proof harness for the AXP1-ZnQ (Architect's eXecution
Protocol 1) probe laws (night-learning-into-darkness-1, extended by
the night-cafe-mclaren-2 rev 3 audit). Serves loopback HTTP shapes
that each law needs, then asserts the verdict paths against real
code:

  1. STALE: a frozen index is refused by the refresher law
     (--max-age-days), never written back as a survivor;
  2. exit-1 loud: a catalog with no live address makes the resolver
     fail (never a dead default), exit 1;
  3. PASS: a fresh Date header passes and the resolver picks it;
  4. malformed-HTTP DOWN: a garbage status line is a DOWN verdict
     with a narrated reason, never an escaped exception (the
     BadStatusLine class is not an OSError subclass);
  5. --first purity: stdout carries exactly one address, nothing
     else, for the $(...) capture contract;
  6. index-404 DOWN: a base URL that answers while the probe-path
     index 404s is a DOWN - the lane cannot apt from it;
  7. witness law: a 2xx with no parsable Date header is STALE under
     the refresher's freshness contract, while the resolver (no
     max-age) still picks it;
  8. duplicate honesty: two lines naming one address get one probe
     and one verdict - a flaky second read cannot bypass the
     never-empty guard into a zero-active rewrite; and no temp file
     survives the write (the atomic-write law).

Run: python3 scripts/dev/axp1znq_edge_proof.py   (binds 127.0.0.1 only)
"""

import http.server
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FROZEN_DATE = "Mon, 01 Jan 2020 00:00:00 GMT"
FRESH_DATE = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

BODY = b"-----BEGIN PGP SIGNED MESSAGE-----\nfake InRelease for the local probe proof\n"


class FrozenHandler(http.server.BaseHTTPRequestHandler):
    date = FROZEN_DATE

    def do_GET(self):
        # send_response_only: the stock send_response injects its own
        # current-time Date header, which would shadow the frozen one
        # this harness exists to test.
        self.send_response_only(200)
        self.send_header("Date", self.date)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


class GarbageHandler(http.server.BaseHTTPRequestHandler):
    """Speaks non-HTTP: the TLS-terminating-middlebox failure shape."""

    def do_GET(self):
        self.wfile.write(b"HTTP/1.1 GARBAGE-STATUS-LINE-NO-CODE\r\n\r\n")

    def log_message(self, *args):
        pass


class Index404Handler(http.server.BaseHTTPRequestHandler):
    """Answers the base URL but 404s every probe-path index."""

    def do_GET(self):
        if self.path == "/":
            self.send_response_only(200)
            self.send_header("Date", FRESH_DATE)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response_only(404)
            self.send_header("Date", FRESH_DATE)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass


class NoDateHandler(http.server.BaseHTTPRequestHandler):
    """Answers 2xx with the Date header stripped - the caching
    middlebox shape that would evade the freshness witness."""

    def do_GET(self):
        self.send_response_only(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


class FlakyFirstReadHandler(http.server.BaseHTTPRequestHandler):
    """Resets the FIRST connection, answers fresh afterwards - the
    flaky-mirror shape that could split two probes of the same
    address across one refresh run."""

    served = 0
    lock = threading.Lock()

    def do_GET(self):
        with FlakyFirstReadHandler.lock:
            FlakyFirstReadHandler.served += 1
            first = FlakyFirstReadHandler.served == 1
        if first:
            # RST the connection: the client sees ConnectionResetError.
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
            return
        self.send_response_only(200)
        self.send_header("Date", FRESH_DATE)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


def run_resolver(catalog: Path, extra=()):
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/dev/axp1znq_resolve.py"),
            "--file",
            str(catalog),
            "--attempts",
            "1",
            "--total-timeout",
            "4",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_refresher(catalog: Path, tmp_root: Path, extra=()):
    (tmp_root / "repos-for-ci").mkdir(parents=True, exist_ok=True)
    target = tmp_root / "repos-for-ci" / "edge.txt"
    target.write_text(catalog.read_text())
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/dev/axp1znq_refresh.py"),
            "--root",
            str(tmp_root / "repos-for-ci"),
            "--attempts",
            "1",
            "--total-timeout",
            "4",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=180,
    ), target


def main() -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FrozenHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tmp = Path("/tmp/axp1-edge-proof")
    tmp.mkdir(exist_ok=True)
    failures = []

    # 1. STALE law: the frozen index must be refused as a survivor.
    #    The never-empty guard keeps a 0-alive catalog untouched (the
    #    address line stays, no tombstone is written) and the lane
    #    escalates CALL THE OWNER.
    stale_catalog = tmp / "stale.txt"
    stale_catalog.write_text(f"http://127.0.0.1:{port}\n")
    refresh, target = run_refresher(stale_catalog, tmp / "t1", extra=["--max-age-days", "14"])
    body = target.read_text()
    ok = (
        "1 stale" in refresh.stdout
        and "CALL THE OWNER" in refresh.stdout
        and body.lstrip().startswith("http")  # untouched, never erased
        and "# down" not in body
    )
    print(f"TEST stale-refusal: {'PASS' if ok else 'FAIL'}")
    print(f"  refresher: {refresh.stdout.strip().splitlines()[-1:]}")
    if not ok:
        failures.append("stale refusal")

    # 2. Resolver on the frozen index with the age policy rides too:
    #    the resolver reports freshness but never blocks the pick, so
    #    the pick stands; assert it prints the address, exit 0.
    resolve = run_resolver(stale_catalog)
    ok = resolve.returncode == 0 and f"127.0.0.1:{port}" in resolve.stdout
    print(f"TEST resolver-pick-despite-reported-age: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("resolver pick despite age")

    # 3. Exit-1 loud: a catalog of dead addresses must exit 1.
    dead_catalog = tmp / "dead.txt"
    dead_catalog.write_text("https://192.0.2.1/ubuntu\n")
    resolve = run_resolver(dead_catalog, extra=["--first"])
    ok = resolve.returncode == 1
    print(f"TEST all-dead-exit-1: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("all-dead exit 1")

    # 4. PASS path: flip the handler to a fresh Date, the refresher
    #    keeps the address as a survivor and the resolver picks it.
    FrozenHandler.date = FRESH_DATE
    fresh_catalog = tmp / "fresh.txt"
    fresh_catalog.write_text(f"http://127.0.0.1:{port}\n")
    refresh, target = run_refresher(fresh_catalog, tmp / "t4", extra=["--max-age-days", "14"])
    body = target.read_text()
    ok = "1 alive" in refresh.stdout and body.lstrip().startswith("http")
    print(f"TEST fresh-kept-as-survivor: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("fresh survivor kept")

    # 5. Malformed-HTTP DOWN: a garbage status line is a DOWN verdict
    #    with a narrated reason - the exception must never escape the
    #    probe (it is not an OSError subclass), the resolver must exit
    #    1 for "none alive" WITHOUT a traceback crash riding the same
    #    exit code.
    garbage = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GarbageHandler)
    gport = garbage.server_address[1]
    threading.Thread(target=garbage.serve_forever, daemon=True).start()
    garbage_catalog = tmp / "garbage.txt"
    garbage_catalog.write_text(f"http://127.0.0.1:{gport}\n")
    resolve = run_resolver(garbage_catalog, extra=["--first"])
    ok = (
        resolve.returncode == 1
        and "Traceback" not in resolve.stderr
        and "malformed HTTP conversation" in resolve.stderr
    )
    garbage.shutdown()
    print(f"TEST malformed-HTTP-DOWN: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("malformed HTTP DOWN")

    # 6. --first purity: stdout is exactly one address, nothing else -
    #    the $(...) capture contract every wired CI seat rides.
    fresh_catalog = tmp / "fresh.txt"
    fresh_catalog.write_text(f"http://127.0.0.1:{port}\n")
    resolve = run_resolver(fresh_catalog, extra=["--first"])
    ok = resolve.returncode == 0 and resolve.stdout.strip() == f"http://127.0.0.1:{port}"
    print(f"TEST first-purity: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("first purity")

    # 7. Index-404 DOWN: the base URL answering while the probe-path
    #    index 404s is a DOWN - no live address, exit 1, no traceback.
    p404 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Index404Handler)
    pport = p404.server_address[1]
    threading.Thread(target=p404.serve_forever, daemon=True).start()
    p404_catalog = tmp / "index404.txt"
    p404_catalog.write_text(f"http://127.0.0.1:{pport}\n")
    resolve = run_resolver(p404_catalog, extra=["--first", "--probe-path", "dists/jammy/InRelease"])
    ok = resolve.returncode == 1 and "Traceback" not in resolve.stderr
    p404.shutdown()
    print(f"TEST index-404-DOWN: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("index 404 DOWN")

    # 8. Witness law: a 2xx with no parsable Date header is STALE under
    #    the refresher's freshness contract (0 alive, CALL THE OWNER,
    #    catalog untouched) while the resolver - no max-age, freshness
    #    never blocks the pick - still picks it, exit 0.
    nodate = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NoDateHandler)
    nport = nodate.server_address[1]
    threading.Thread(target=nodate.serve_forever, daemon=True).start()
    nodate_catalog = tmp / "nodate.txt"
    nodate_catalog.write_text(f"http://127.0.0.1:{nport}\n")
    refresh, target = run_refresher(
        nodate_catalog,
        tmp / "t8",
        extra=["--max-age-days", "14", "--probe-path", "dists/jammy/InRelease"],
    )
    body = target.read_text()
    ok = (
        "CALL THE OWNER" in refresh.stdout
        and "1 stale" in refresh.stdout
        and body.lstrip().startswith("http")
        and "# down" not in body
    )
    resolve = run_resolver(nodate_catalog, extra=["--first"])
    ok = ok and resolve.returncode == 0 and f"127.0.0.1:{nport}" in resolve.stdout
    nodate.shutdown()
    print(f"TEST witness-law: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("witness law")

    # 9. Duplicate honesty + atomic write: two lines naming ONE address
    #    get ONE probe (the first read resets, a separate-probe run
    #    would see DOWN-then-PASS and bypass the never-empty guard into
    #    a zero-active rewrite). With the law: one DOWN verdict, alive
    #    0, CALL THE OWNER, catalog untouched, and no .tmp file left in
    #    the catalog directory afterwards.
    flaky = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FlakyFirstReadHandler)
    fport = flaky.server_address[1]
    threading.Thread(target=flaky.serve_forever, daemon=True).start()
    dup_catalog = tmp / "dup.txt"
    addr = f"http://127.0.0.1:{fport}"
    dup_catalog.write_text(f"{addr}\n{addr}\n")
    refresh, target = run_refresher(dup_catalog, tmp / "t9", extra=["--max-age-days", "14"])
    body = target.read_text()
    leftovers = [
        p.name
        for p in target.parent.iterdir()
        if p.name.startswith(".") and p.name.endswith(".tmp")
    ]
    ok = (
        "CALL THE OWNER" in refresh.stdout
        and "1 unique address(es) (2 lines)" in refresh.stdout
        and body == f"{addr}\n{addr}\n"
        and not leftovers
    )
    flaky.shutdown()
    print(f"TEST duplicate-honesty-atomic-write: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append("duplicate honesty / atomic write")

    server.shutdown()
    if failures:
        print(f"EDGE PROOF: FAIL ({failures})")
        return 1
    print("EDGE PROOF: all nine laws hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
