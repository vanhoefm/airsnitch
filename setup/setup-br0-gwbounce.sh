#!/bin/bash
set -e

echo "[+] Clean up old"
ip netns del routerns 2>/dev/null || true
ip link del br0 2>/dev/null || true
ip link del veth-br0 2>/dev/null || true
ip link del veth-rt 2>/dev/null || true

echo "[+] Create 4 simulated wlan interfaces"
./setup-hwsim.sh 4
sleep 2

echo "[+] Stop interfering services"
systemctl stop NetworkManager || true
systemctl stop avahi-daemon || true
systemctl stop systemd-resolved || true
airmon-ng check kill || true
sleep 2

echo "[+] Create L2 bridge br0"
ip link add br0 type bridge

ip link set br0 up

echo "[+] Start hostapd on wlan0/wlan1 (config MUST have bridge=br0)"
cd ..
./hostap.py wlan0 --ap --config ./setup/hostapd-wpa3-personal-AE.conf &
./hostap.py wlan1 --ap --config ./setup/hostapd-wpa2-personal-AE.conf &
cd setup
sleep 3

echo "[+] Attach wlan0/wlan1 to br0"
ip link set wlan0 master br0
ip link set wlan1 master br0



echo "[+] Create router namespace and L3 gateway link"
ip netns add routerns
# veth: br0<->router
ip link add veth-br0 type veth peer name veth-rt
ip link set veth-br0 master br0
ip link set veth-br0 up
ip link set veth-rt netns routerns

echo "[+] Configure router namespace (gateway 192.168.100.1/24)"
ip netns exec routerns ip link set lo up
ip netns exec routerns ip link set veth-rt up
ip netns exec routerns ip addr add 192.168.100.1/24 dev veth-rt


ip netns exec routerns sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] DHCP inside router ns (serves the br0 segment via veth-rt)"

DNSMASQ_NS_CONF="/tmp/dnsmasq-br0.conf"
cat > "$DNSMASQ_NS_CONF" <<'EOF'
interface=veth-rt
bind-interfaces
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,192.168.100.1      # default gateway
dhcp-option=6,8.8.8.8,1.1.1.1    # DNS
EOF


ip netns exec routerns bash -c "
  pgrep dnsmasq >/dev/null 2>&1 && killall dnsmasq || true
  dnsmasq --conf-file=$DNSMASQ_NS_CONF --no-daemon >/dev/null 2>&1 & disown
"

echo "[+] Enforce Gateway Bouncing at L2: block direct wlan0<->wlan1 bridging"

modprobe bridge || true
modprobe br_netfilter || true


ebtables -F || true

# Block Layer-2 forwarding
ebtables -A FORWARD -i wlan0 -o wlan1 -j DROP
ebtables -A FORWARD -i wlan1 -o wlan0 -j DROP

echo "[+] Setup finished."
echo "Topology:"
echo "  STA(wlan0) ─┐"
echo "               ├─ br0 ─ veth-br0 === veth-rt (ns:routerns, 192.168.100.1)  <== L3 gateway"
echo "  STA(wlan1) ─┘"
echo
echo "DHCP: router ns hands out 192.168.100.50-150/24, GW=192.168.100.1"

