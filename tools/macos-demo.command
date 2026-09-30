#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
./easy-analyzer analyze samples/synthetic.evtx samples/sample.wtmp \
  samples/auth.log samples/access.log samples/sample.pcap \
  -j reports/demo.json -H reports/demo.html
echo
echo "HTML 报告：$PWD/reports/demo.html"
echo "JSON 报告：$PWD/reports/demo.json"
if [[ -t 0 ]]; then read -r -p '按 Enter 退出。' _; fi
