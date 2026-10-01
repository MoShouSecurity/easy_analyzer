#!/usr/bin/env python3
"""Loopback-only Chat Completions mock for GUI acceptance; use synthetic inputs."""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=0)
parser.add_argument("--config", required=True)
parser.add_argument("--delay", type=float, default=0)
parser.add_argument("--fail-after", type=int, default=-1)
args = parser.parse_args()
requests = 0


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global requests
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        text = "\n".join(m.get("content", "") for m in body.get("messages", []))
        ids = re.findall(r"^证据编号: (.+)$", text, flags=re.M)
        requests += 1
        time.sleep(args.delay)
        finding = {"findings": [{
            "severity": "medium",
            "title": "模拟服务：待核查的证据关联",
            "description": "此发现由本机验收模拟服务返回，已通过应用层证据引用校验。",
            "evidence_ids": ids[:1], "confidence": 0.8,
            "recommendations": ["核对原始记录；合成验收数据不构成真实事件结论。"],
        }]} if ids else {"findings": []}
        content = "{" if args.fail_after >= 0 and requests > args.fail_after else json.dumps(finding, ensure_ascii=False)
        data = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        print(f"mock request {requests}: evidence={len(ids)}", flush=True)

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
from pathlib import Path
Path(args.config).write_text(f'base_url = "http://127.0.0.1:{server.server_port}/v1"\nmodel = "gui-acceptance-mock"\napi_key = ""\ntimeout_seconds = 10\nbatch_bytes = 8192\nmax_output_tokens = 1024\n')
print(f"mock listening 127.0.0.1:{server.server_port}", flush=True)
server.serve_forever()
