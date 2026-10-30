"""Find mullpod's addresses: the API from config.yaml, listeners from the running API.

python3 test/addrs.py api     -> 127.0.0.1:8088
python3 test/addrs.py main    -> 127.0.0.1:8090 (asks the running instance)
"""
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def _setting(text, key, default):
    m = re.search(rf'^{key}:\s*"?([^"#\s]+)"?', text, re.M)
    return m.group(1) if m else default


def api_addr(config=os.path.join(ROOT, "config.yaml")):
    text = open(config).read()
    return _local(_setting(text, "api", "127.0.0.1:8088"))


def _local(addr):
    host, _, port = addr.rpartition(":")
    return f"127.0.0.1:{port}" if host.strip("[]") in ("", "0.0.0.0", "::") else addr


def listener_addr(name):
    with urllib.request.urlopen(f"http://{api_addr()}/exits", timeout=5) as r:
        for l in json.load(r)["listeners"]:
            if l["name"] == name:
                return _local(l["addr"])
    raise SystemExit(f"no listener named {name!r}")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "api"
    try:
        print(api_addr() if what == "api" else listener_addr(what))
    except OSError:
        print("")
