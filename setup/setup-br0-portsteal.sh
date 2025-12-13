#!/bin/bash
set -e
# setup-br0-gwbounce-allow-l2.sh
# - single L2 bridge br0 with wlan0/wlan1 attached
# - router runs inside netns 'routerns' (veth-br0 <-> veth-rt)
# - KEYS: allow L2 forwarding between wlan0 and wlan1 (no ebtables DROP)
# - Make sure hostapd confs contain: bridge=br0 and ap_isolate=0 (or remove ap_isolate)

echo "[+] cleanup previous artifacts"
ip netns del routerns 2>/dev/null || true
ip link del br0 2>/dev/null || true
ip link del veth-br0 2>/dev/null || true
ip link del veth-rt 2>/dev/null || true

echo "[+] Create 4 simulated wlan interfaces (hwsim)"
./setup-hwsim.sh 4
sleep 2

echo "[+] Stop interfering services"
systemctl stop NetworkManager || true
systemctl stop avahi-daemon || true
systemctl stop systemd-resolved || true
airmon-ng check kill || true
sleep 2

echo "[+] Create single L2 bridge br0 (pure L2, no IP on host)"
ip link add br0 type bridge
ip link set br0 up

echo "[+] Start hostapd on wlan0/wlan1 (they MUST have bridge=br0, and ap_isolate disabled)"
cd ..
./hostap.py wlan0 --ap --config ./setup/hostapd-wpa3-personal-AE.conf &
./hostap.py wlan1 --ap --config ./setup/hostapd-wpa2-personal-AE.conf &
cd setup
sleep 3

echo "[+] Attach wlan0 and wlan1 to br0 (APs)"
ip link set wlan0 master br0
ip link set wlan1 master br0

# Ensure bridge will forward L2 traffic normally (default), and packets are not forced into iptables
modprobe br_netfilter || true
# Prefer bypassing iptables for bridge traffic to avoid surprises
sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true

echo "[+] Create router namespace and point-to-point link"
ip netns add routerns
# veth pair: veth-br0 (host) <-> veth-rt (in routerns)
ip link add veth-br0 type veth peer name veth-rt
# Attach host end to bridge (so br0 traffic reaches router)
ip link set veth-br0 master br0
ip link set veth-br0 up
# move other end to namespace
ip link set veth-rt netns routerns

echo "[+] Configure router namespace (veth-rt = GW for the single subnet)"
ip netns exec routerns ip link set lo up
ip netns exec routerns ip link set veth-rt up
# Router will own the subnet's gateway IP. Choose e.g. 192.168.100.1/24
ip netns exec routerns ip addr add 192.168.100.1/24 dev veth-rt
ip netns exec routerns sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Simulate a network latency in our virtual setup, otherwise ping replies are instant
ip netns exec routerns tc qdisc add dev veth-rt root netem delay 50ms

# Start dnsmasq inside the namespace to hand out IPs on the br0 segment.
# Create a temporary dnsmasq config file on the host and reference it from the ns.
DNSMASQ_NS_CONF="/tmp/dnsmasq-br0.conf"
cat > "$DNSMASQ_NS_CONF" <<'EOF'
interface=veth-rt
bind-interfaces
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,8.8.8.8
EOF

# Run dnsmasq in the namespace (background). Requires dnsmasq installed on host.
ip netns exec routerns bash -c "
  pgrep dnsmasq >/dev/null 2>&1 && killall dnsmasq || true
  dnsmasq --conf-file=$DNSMASQ_NS_CONF --no-daemon >/dev/null 2>&1 & disown
"

# Firewall / bridging policy: DO NOT block L2 between wlan0 and wlan1.
# Remove any ebtables rules that might block L2.
command -v ebtables >/dev/null 2>&1 && ebtables -F || true
# Ensure kernel allows forwarding on bridge ports (bridge default: forward)
# No iptables FORWARD policies required for pure L2 forwarding among bridge ports.

# OPTIONAL: If you want the router to be the only path for ARP (proxy-arp),
# enable proxy_arp in namespace (uncomment if needed)
# ip netns exec routerns sysctl -w net.ipv4.conf.all.proxy_arp=1

echo "-----------------------------------------------------------"
echo "[+] Setup complete (L2 forwarding allowed between wlan0 and wlan1)"
