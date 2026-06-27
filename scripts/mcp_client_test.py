"""End-to-end MCP client test -- proves the server works over stdio JSON-RPC."""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = str(ROOT / ".local-smoke" / "i_view64.exe")

if not Path(BINARY).exists():
    Path(BINARY).parent.mkdir(exist_ok=True)
    shutil.copy2(Path(r"C:\Program Files\IrfanView\i_view64.exe"), BINARY)


class MCPClient:
    def __init__(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "ida_headless_mcp.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(ROOT),
        )
        self._q: queue.Queue[str] = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._id = 0

    def _read_loop(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                self._q.put("")
                break
            self._q.put(line.decode("utf-8", errors="replace"))

    def call(self, method: str, params: dict | None = None, timeout: float = 300) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        return self._wait(self._id, timeout)

    def notify(self, method: str, params: dict | None = None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def _wait(self, expected_id: int, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                line = self._q.get(timeout=remaining)
            except queue.Empty:
                return {"error": "timeout"}
            if not line:
                return {"error": "server closed stdout"}
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == expected_id:
                return msg
        return {"error": "timeout"}

    def tool(self, name: str, arguments: dict, timeout: float = 300) -> dict:
        resp = self.call("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
        if "result" in resp:
            content = resp["result"].get("content", [])
            if content:
                return json.loads(content[0].get("text", "{}"))
        return resp

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    print("Starting MCP server...")
    client = MCPClient()
    time.sleep(1)
    results: dict[str, str] = {}

    try:
        # Initialize
        print("[1] initialize")
        resp = client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "0.1"},
        }, timeout=15)
        if "result" in resp:
            name = resp["result"].get("serverInfo", {}).get("name", "?")
            print(f"  server: {name}")
            results["initialize"] = "OK"
        else:
            print(f"  FAIL: {resp}")
            return 1

        client.notify("notifications/initialized")

        # List tools
        print("[2] tools/list")
        resp = client.call("tools/list", {}, timeout=10)
        tools = resp.get("result", {}).get("tools", [])
        print(f"  {len(tools)} tools")
        results["tools/list"] = f"OK ({len(tools)})"

        # Open IrfanView (the heavy one -- IDA analysis)
        print("[3] open_binary (IrfanView, expect ~30s)...")
        t0 = time.monotonic()
        data = client.tool("open_binary", {"path": BINARY}, timeout=300)
        elapsed = time.monotonic() - t0
        bid = data.get("binary_id")
        if bid:
            print(f"  {elapsed:.1f}s -- binary_id={bid}, functions={data.get('function_count')}")
            results["open_binary"] = f"OK ({data.get('function_count')} fn, {elapsed:.0f}s)"
        else:
            print(f"  FAIL: {data}")
            results["open_binary"] = "FAIL"
            return 1

        # binary_survey
        print("[4] binary_survey")
        data = client.tool("binary_survey", {"binary_id": bid}, timeout=10)
        uf = data.get("overview", {}).get("functions_user", "?")
        print(f"  user functions: {uf}")
        results["binary_survey"] = f"OK ({uf} user fn)"

        # checksec
        print("[5] checksec")
        data = client.tool("checksec", {"binary_id": bid}, timeout=5)
        print(f"  aslr={data.get('aslr_pie')}, nx={data.get('nx')}, cfg={data.get('cfg')}")
        results["checksec"] = "OK"

        # classify_behavior
        print("[6] classify_behavior")
        data = client.tool("classify_behavior", {"binary_id": bid}, timeout=10)
        cats = list(data.get("behaviors", {}).keys())
        print(f"  categories: {cats or 'none (clean app)'}")
        results["classify_behavior"] = f"OK ({len(cats)} cats)"

        # detect_anti_analysis
        print("[7] detect_anti_analysis")
        data = client.tool("detect_anti_analysis", {"binary_id": bid}, timeout=10)
        print(f"  verdict: {data.get('verdict')}")
        results["detect_anti_analysis"] = f"OK ({data.get('verdict')})"

        # entropy_analysis
        print("[8] entropy_analysis")
        data = client.tool("entropy_analysis", {"binary_id": bid}, timeout=30)
        print(f"  verdict: {data.get('verdict')}")
        results["entropy_analysis"] = f"OK ({data.get('verdict')})"

        # search_pattern(null_deref) -- THE KEY TEST
        print("[9] search_pattern(null_deref)...")
        t1 = time.monotonic()
        data = client.tool("search_pattern", {
            "binary_id": bid, "pattern_type": "null_deref", "limit": 5,
        }, timeout=120)
        elapsed = time.monotonic() - t1
        count = data.get("count", 0)
        print(f"  {elapsed:.1f}s -- {count} hits")
        for m in data.get("matches", [])[:3]:
            print(f"    {m['name']}: {m['detail']}")
        results["null_deref"] = f"OK ({count} hits, {elapsed:.0f}s)"

        # decompile the first null_deref hit
        if data.get("matches"):
            hit = data["matches"][0]
            print(f"[10] decompile({hit['name']})")
            decomp = client.tool("decompile", {
                "binary_id": bid, "address_or_name": hit["address"], "max_lines": 30,
            }, timeout=15)
            print(f"  {decomp.get('line_count', '?')} lines")
            results["decompile"] = "OK"

        # close
        client.tool("close_binary", {"binary_id": bid, "save": False}, timeout=10)
        results["close_binary"] = "OK"

    except Exception as exc:
        print(f"EXCEPTION: {type(exc).__name__}: {exc}")
        results["exception"] = str(exc)
    finally:
        client.close()

    print("\n" + "=" * 60)
    print("MCP END-TO-END RESULTS (real binary, real transport)")
    print("=" * 60)
    for name, status in results.items():
        print(f"  [{('PASS' if 'OK' in status else 'FAIL')}] {name}: {status}")
    failed = sum(1 for v in results.values() if "OK" not in v)
    total = len(results)
    print(f"\n{total - failed}/{total} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
