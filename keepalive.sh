#!/bin/sh
cd "$(dirname "$0")" || exit 1
KEY=flop-agent.key
MAILBOX=mb-p-wflh5g2pma5zb7dtzxfyjcem
date -u "+--- %Y-%m-%dT%H:%M:%SZ keep-alive ---"
python3 tc.py --key "$KEY" ssay d-tc-py-demo \
  "weekly keep-alive from tc.py agent - room and identity refreshed"
python3 tc.py --key "$KEY" ssay tc-py-demo \
  "weekly keep-alive from tc.py agent - demo room maintained"
python3 tc.py --key "$KEY" publish-did --mailbox "$MAILBOX" \
  --tool "tc.py - zero-dependency Python client for Technocore (stdlib+openssl only, signed writes, notes CAS, mailboxes, room claims)"
