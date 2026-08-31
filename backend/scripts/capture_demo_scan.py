"""Capture the PROJECT.md §21 demo: normal traffic, then an authorized
Nmap scan, written to a .pcap ready to upload.

Run:  python scripts/capture_demo_scan.py
      python scripts/capture_demo_scan.py --target 192.168.0.1 --out demo.pcap

Produces the capture for the demo chain in §21 -- generate normal traffic
-> run a controlled Nmap scan -> capture -> upload -> detect -> explain.
Upload the resulting file through POST /api/pcap/upload (or the UI) to
continue the demo.

**Authorization.** PROJECT.md §4 restricts scanning to your own machines
or lab. The default target is the local default gateway and the script
refuses to scan anything outside a private (RFC1918) range -- pass
`--target` deliberately, and only for a host you own.

Needs Npcap (sniffing) and Nmap on PATH; both ship with the project's
documented Windows setup. Prints the scan's own output and the timing
marks for validating the same window in Wireshark.

See docs/PRE-DEPLOYMENT-READINESS.md (Part C) for what the resulting
capture should produce once uploaded.
"""

import argparse
import ipaddress
import shutil
import subprocess
import tempfile
import threading
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from scapy.all import sniff, wrpcap  # noqa: E402

NORMAL_SITES = ["https://example.com", "https://www.wikipedia.org", "https://www.cloudflare.com"]
COMMON_NMAP_PATHS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def resolve_nmap() -> str | None:
    found = shutil.which("nmap")
    if found:
        return found
    return next((p for p in COMMON_NMAP_PATHS if Path(p).exists()), None)


def default_gateway() -> str | None:
    """The local default gateway, so the default target is your own router."""
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if "Default Gateway" in line and ":" in line:
            candidate = line.split(":", 1)[1].strip()
            if candidate and not candidate.startswith("fe80"):
                try:
                    if ipaddress.ip_address(candidate).is_private:
                        return candidate
                except ValueError:
                    continue
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=None,
                        help="host to scan (default: your local gateway). Must be a private address.")
    parser.add_argument("--iface", default="Wi-Fi", help="capture interface (default: Wi-Fi)")
    parser.add_argument("--out", default=None,
                        help="output .pcap path (default: a file in your temp directory)")
    parser.add_argument("--seconds", type=int, default=100, help="capture duration (default: 100)")
    parser.add_argument("--top-ports", type=int, default=100, help="nmap --top-ports (default: 100)")
    args = parser.parse_args()

    nmap = resolve_nmap()
    if not nmap:
        print("nmap not found -- install Nmap or put it on PATH.")
        return 2

    target = args.target or default_gateway()
    if not target:
        print("could not determine a default gateway; pass --target explicitly.")
        return 2
    try:
        if not ipaddress.ip_address(target).is_private:
            print(f"refusing to scan {target}: not a private address (PROJECT.md §4 -- own lab only).")
            return 2
    except ValueError:
        print(f"refusing to scan {target!r}: not a valid IP address.")
        return 2

    out = Path(args.out) if args.out else Path(tempfile.gettempdir()) / "netsentinel_demo_scan.pcap"
    marks: dict[str, object] = {}

    def workload():
        marks["normal_start"] = time.time()
        for url in NORMAL_SITES:
            try:
                subprocess.run(["curl", "-s", "-o", "NUL", "-m", "6", url], timeout=8)
            except Exception:
                pass
        marks["normal_end"] = time.time()
        time.sleep(2)
        marks["scan_start"] = time.time()
        try:
            result = subprocess.run(
                [nmap, "-sT", "--top-ports", str(args.top_ports), "-Pn", target],
                capture_output=True, text=True, timeout=180,
            )
            marks["nmap_stdout"] = result.stdout
        except Exception as exc:  # noqa: BLE001 -- surfaced below, never fatal to the capture
            marks["nmap_error"] = str(exc)
        marks["scan_end"] = time.time()

    worker = threading.Thread(target=workload, daemon=True)
    worker.start()

    print(f"target      : {target} (private, authorized)")
    print(f"interface   : {args.iface}")
    print(f"capturing   : {args.seconds}s -- normal traffic first, then the scan\n", flush=True)
    packets = sniff(iface=args.iface, timeout=args.seconds)
    worker.join(timeout=10)

    wrpcap(str(out), packets)
    print(f"captured {len(packets)} packets -> {out} ({out.stat().st_size / 1024:.0f} KB)\n")

    print("--- timing marks (use these as the Wireshark validation window) ---")
    for key in ("normal_start", "normal_end", "scan_start", "scan_end"):
        if key in marks:
            print(f"  {key:13s} {time.strftime('%H:%M:%S', time.localtime(marks[key]))}")

    if marks.get("nmap_stdout"):
        print("\n--- nmap output ---")
        for line in str(marks["nmap_stdout"]).splitlines():
            if line.strip():
                print("  " + line)
    if marks.get("nmap_error"):
        print(f"\nnmap failed: {marks['nmap_error']}")

    print(f"\nnext: upload {out} via POST /api/pcap/upload (or the UI) to continue the §21 demo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
