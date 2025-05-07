#!/bin/bash

SERVER_IP="34.152.55.206"
PORT="443"
TUN_IF="utun9"

# 1. Run the VPN client binary
sudo ./bazel-bin/vpn_client $SERVER_IP $PORT $TUN_IF &

# 2. Configure TUN interface
sudo ifconfig $TUN_IF inet 10.8.0.2 10.8.0.1 netmask 255.255.255.255 up

# 3. Set default route through VPN
sudo route delete default
sudo route add default 10.8.0.1

