# Create 4 simulated interfaces. 
./setup-hwsim.sh 4

sleep 2

# Stop Network Manager
systemctl stop NetworkManager
systemctl stop avahi-daemon

sleep 2

airmon-ng check kill

sleep 2

# Add two bridges.
ip link add name br1 type bridge
ip link add name br2 type bridge

sleep 2

# Host 2 hostap instances.
cd ..
./hostap.py wlan0 --ap --config ./setup/hostapd-wpa3-personal-AE.conf &
./hostap.py wlan1 --ap --config ./setup/hostapd-wpa2-personal-AE.conf &

sleep 2

# Activate routing capability.
sysctl -w net.ipv4.ip_forward=1

# Disable systemd-resolved
systemctl stop systemd-resolved

cd setup
cp ./br1.conf /etc/dnsmasq.d
cp ./br2.conf /etc/dnsmasq.d
sleep 2

systemctl restart dnsmasq

ip link set wlan0 master br1
ip link set br1 up
ip addr add 192.168.100.1/24 dev br1

ip link set wlan1 master br2
ip link set br2 up
ip addr add 192.168.101.1/24 dev br2