#!/bin/bash

SERVER_IP="34.152.55.206"
PORT="443"
TUN_IF="utun9"

# 1. Run VPN client in background
sudo ./bazel-bin/vpn_client $SERVER_IP $PORT $TUN_IF &

# 2. Wait for utun9 to be created
echo "Waiting for $TUN_IF..."
while ! ifconfig $TUN_IF >/dev/null 2>&1; do sleep 0.2; done
echo "$TUN_IF is up"

# 3. Assign IP and set default route
sudo ifconfig $TUN_IF inet 10.8.0.2 10.8.0.1 netmask 255.255.255.255 up
sudo route delete default || true
sudo route add default 10.8.0.1
