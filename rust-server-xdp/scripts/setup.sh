#!/bin/bash

# NIC Configuration
ethtool -L eth0 combined 32
ethtool -G eth0 rx 4096 tx 4096
ethtool -K eth0 gro off lro off tso off gso off

# Kernel Settings
sysctl -p scripts/sysctl.conf

# CPU Isolation
echo 0 > /sys/devices/system/cpu/cpu0/online  # Example for core 0