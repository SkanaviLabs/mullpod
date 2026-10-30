"""Load a page through a sticky exit and check the IP stays the same through the proxy.

pip install playwright && playwright install chromium
python3 test/playwright_smoke.py [exit]   # default: de-fra
"""
import json
import os
import sys
import uuid

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(__file__))
from addrs import listener_addr  # noqa: E402

PROXY = "http://" + listener_addr("main")
exit_ = sys.argv[1] if len(sys.argv) > 1 else "de-fra"
user = f"{exit_}_ctx{uuid.uuid4().hex[:8]}"

with sync_playwright() as p:
    browser = p.chromium.launch(
        proxy={"server": PROXY},  # launch-level proxy is required for per-context proxies
        args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
    )
    ctx = browser.new_context(proxy={"server": PROXY, "username": user, "password": "x"})
    page = ctx.new_page()
    servers = set()
    page.on("response", lambda r: servers.add(r.headers.get("x-mullvad-server")))

    page.goto("https://en.wikipedia.org/wiki/Special:Random", wait_until="networkidle")
    print("loaded:", page.title())

    ips = set()
    for _ in range(3):
        page.goto("https://am.i.mullvad.net/json")
        info = json.loads(page.inner_text("body"))
        ips.add(info["ip"])
        print(f"exit {info['ip']} {info.get('city')}, {info.get('country')} mullvad={info.get('mullvad_exit_ip')}")
    browser.close()

assert len(ips) == 1, f"session hopped IPs: {ips}"
assert all(i is True for i in [info.get("mullvad_exit_ip")]), "not a Mullvad exit"
print(f"OK: {user} stayed on {ips.pop()}")
