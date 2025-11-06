from scapy.layers.dot11 import Dot11, Dot11QoS, Ether
import abc

# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import encrypt_ccmp
from library.daemon import Daemon
from library.testcase import Trigger, Action

# ----------------------------------- Station -----------------------------------------

class Station(Daemon):
	"""A station is an Authenticator or Supplicant which executes a test case."""
	
	def __init__(self,options):
		self.test = None
		if "test" in options:
			self.test = options.test
			del options.test # Irrelevant for Daemon.

		super().__init__(options)
		
		# Function handler and iface when in receive modus.
		self.receive_func = None
		self.receive_eth = self.receive_mon = False
		
		# Station-generic MAC addresses and packet numbers.
		self.bss = None
		self.pn = 5

		# IP address info
		self.ip = None
		self.peerip = None
		self.obtained_ip = False
		self.pending_trigger = None
		self.arp_sock = None

	def perform_actions(self, trigger):
		if self.test == None:
			return
		# Log Trigger only when it is triggered.
		if self.test.is_action_triggered(trigger):
			trigger_str = Trigger().__str__(trigger)
			log(STATUS, f"Trigger = {trigger_str}.", color="orange")
			# Generate the test case upon reaching the first trigger.
			if self.test.generated is False:
				log(STATUS, f"Generating {self.test.name} test case.", \
					color="green")
				self.test.generate(station=self)
				self.test.generated = True
		# Perform all actions for the respective trigger.
		while self.test.is_action_triggered(trigger):
			act = self.test.get_next_action()
			if act.delay:
				time.sleep(act.delay)
			if act.action == Action.Receive:
				self.receive_func = act.function
				self.receive_eth = act.eth
				self.receive_mon = act.mon
			if act.action == Action.Inject:
				assert(act.frame is not None)
				if act.encrypt:
					frame = self.encrypt(act.frame,self.tk)
				else: frame = act.frame
				if act.eth is True:
					self.inject_eth(frame)
				else: self.inject_mon(frame)
				log(STATUS, "Injected " + repr(frame))
			if act.action == Action.Function:
				assert(act.function is not None)
				_ = act.function(self) # Call function.
			if act.action == Action.Reconnect:
				self.reconnect( optimized=act.optimized )
				break # Reconnecting resets trigger.
			# Check if we have more actions, if not, close down.
			if act.action == Action.Terminate or act.terminate is True:
				if act.terminate_delay:
					time.sleep(act.terminate_delay)
				self.terminate()
			# Get an IP as a client, or as an AP wait until the client requested an AP.
			# Unless we already have an IP, in that case nothing must be done.
			if act.action == Action.GetIp and not self.obtained_ip:
				self.pending_trigger = trigger
				self.get_ip()
				log(DEBUG, "Waiting with next action until we have an IP")
				# Don't execute the next trigger yet, this is done after we got an IP.
				break

	def handle_started(self):
		self.perform_actions(Trigger.NoTrigger)
		
	def handle_trigger_associated(self):
		self.perform_actions(Trigger.Associated)
		
	def handle_trigger_authenticated(self):
		if not self.tk:
			self.load_keys()
		self.perform_actions(Trigger.AfterAuth)
	
	def handle_trigger_received(self):
		self.perform_actions(Trigger.Received)
		
	def handle_trigger_connected(self):
		# - The Authenticator currently doesn't have an Authenticated event, but
		#   only a Connected event. So we need to get the keys here if they haven't
		#   been loaded yet.
		# - Execute this before running any testcase triggers, becuase those
		#   triggers might want to use the keys.
		# FIXME: Assure both Supplicant and Authenticator have the same triggers?
		if not self.tk:
			self.load_keys()

		self.perform_actions(Trigger.Connected)
		
	def handle_trigger_disconnected(self):
		self.perform_actions(Trigger.Disconnected)
	
	def encrypt(self, frame, key):
		if len(key) == 16:
			self.pn += 1
			return encrypt_ccmp(frame, key, self.pn)
		return None
	
	def handle_eth(self, frame):
		if self.receive_eth and self.receive_func(self,frame):
			self.receive_eth = False
			self.handle_trigger_received()
	
	def handle_mon(self, frame):
		if self.receive_mon and self.receive_func(self,frame):
			self.receive_mon = False
			self.handle_trigger_received()

	def set_ip_addresses(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip
		self.obtained_ip = True

		if self.pending_trigger != None:
			log(DEBUG, "Continuing actions that waited on IP address")
			trigger = self.pending_trigger
			self.pending_trigger = None
			self.perform_actions(trigger)
		else:
			log(DEBUG, "Got an IP address")

	def terminate(self):
		log(STATUS, "Disconnecting.", color="green")
		self.wpaspy_command("TERMINATE")
		self.terminated = True
		
# ----------------------------------- Authenticator -----------------------------------

class Authenticator(Station):
	"""Authenticator Station."""
	
	def __init__(self,options):
		options.ap = True
		super().__init__(options)
		
		# Authenticator-specific sequence numbers.
		self.sn = 10
		self.tk = self.gtk = None
		
		# Support one client station.
		self.clientmac = None
		self.dhcp = None
		self.obtained_ip = False

	@property
	def peermac(self):
		"""
		Property that both the Station and Authenticator have so test can be written to be
		more easily switchable between Test.Supplicant and Test.Authenticator.
		"""
		return self.clientmac

	def load_keys(self):
		tk = self.wpaspy_command("GET_TK " + self.clientmac)
		self.tk = bytes.fromhex(tk)
		gtk, idx, seq = self.wpaspy_command("GET_GTK").split()
		self.gtk = bytes.fromhex(gtk)
		self.gtk_idx = int(idx)
		self.gtk_seq = int(seq, 16)
		log(STATUS, f"Loaded pairwise and group encryption keys.")

	def get_header(self, qos=True):
		"""Construct a Dot11QoS-header."""
		header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
		if qos is True:
			header[Dot11].subtype = 8
			header.add_payload(Dot11QoS())
		self.sn += 1
		header.FCfield |= 'from-DS' # From AP.
		header.addr1 = self.clientmac # Destination.
		header.addr2 = self.mac # Source.
		header.addr3 = self.mac # BSSID.
		return header
		
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(DEBUG, "daemon: " + msg)
		if "AP-STA-ASSOCIATING" in msg:
			_, clientmac = msg.split()
			self.clientmac = clientmac
			self.handle_trigger_associated()
		# FIXME: There is no authenticated event?
		if "AP-STA-CONNECTED" in msg:
			self.handle_trigger_connected()
		if "AP-STA-DISCONNECTED" in msg:
			_, clientmac = msg.split()
			if self.clientmac != clientmac:
				return
			self.clientmac = None
			self.handle_trigger_disconnected()

	def get_ip(self):
		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='example.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)
		# Configure gateway IP that will reply to ARP and ping requests
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		log(STATUS, f"Waiting on client to get IP")

	def monitor_dhcp(self, p):
		if not DHCP in p or not self.clientmac in self.dhcp.leases: return

		# This assures we only mark it as connected after receiving a DHCP Request
		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
		if req_type != 3: return

		peerip = self.dhcp.leases[self.clientmac]
		log(STATUS, f"Client {self.clientmac} with IP {peerip} has connected")
		self.set_ip_addresses('192.168.100.254', peerip)

	def handle_eth(self, p):
		# Ignore clients not connected to the AP
		if p[Ether].src != self.clientmac:
			return

		# Let clients get IP addresses
		if self.dhcp:
			# Let scapy reply to possible DHCP packets
			self.dhcp.reply(p)
			# Monitor DHCP messages to know when a client received an IP address
			if not self.obtained_ip:
				self.monitor_dhcp(p)

		super().handle_eth(p)


# ----------------------------------- Supplicant --------------------------------------

class Supplicant(Station):
	"""Supplicant Station."""

	def __init__(self,options):
		options.ap = False
		super().__init__(options)
		
		# Supplicant-specific sequence numbers and encryption keys.
		self.sn = 10
		self.tk = self.gtk = None

		self.time_retrans_dhcp = None
		self.dhcp_offer_frame =  None
		self.dhcp_xid = None
		self.arp_sock = None

	@property
	def peermac(self):
		"""
		Property that both the Station and Authenticator have so test can be written to be
		more easily switchable between Test.Supplicant and Test.Authenticator.
		"""
		return self.bss

	def load_keys(self):
		tk = self.wpaspy_command("GET tk")
		self.tk = bytes.fromhex(tk)
		gtk, idx, seq = self.wpaspy_command("GET_GTK").split()
		self.gtk = bytes.fromhex(gtk)
		self.gtk_idx = int(idx)
		self.gtk_seq = int(seq, 16)
		log(STATUS, f"Loaded pairwise and group encryption keys.")
	
	def clear_keys(self):
		self.tk = self.gtk = None
		
	def reconnect(self, optimized=None):
		log(STATUS, "Reconnecting to the AP.", color="orange")
		if optimized is not None:
			self.wpaspy_command("SET reassoc_same_bss_optim " + str(optimized))
		self.wpaspy_command("REASSOCIATE")
		#self.clear_keys()

	def get_ip(self):
		if not self.dhcp_offer_frame:
			self.send_dhcp_discover()
		else:
			self.send_dhcp_request(self.dhcp_offer_frame)

		self.time_retrans_dhcp = time.time() + 2.5

	def send_dhcp_discover(self):
		if self.dhcp_xid == None:
			self.dhcp_xid = random.randint(0, 2**31)

		rawmac = bytes.fromhex(self.mac.replace(':', ''))
		req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		req = req/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid)
		req = req/DHCP(options=[("message-type", "discover"), "end"])

		log(STATUS, f"Sending DHCP discover with XID {self.dhcp_xid}")
		self.inject_eth(req)

	def send_dhcp_request(self, offer):
		rawmac = bytes.fromhex(self.mac.replace(':', ''))
		myip = offer[BOOTP].yiaddr
		sip = offer[BOOTP].siaddr
		xid = offer[BOOTP].xid

		reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		reply = reply/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid)
		reply = reply/DHCP(options=[("message-type", "request"), ("requested_addr", myip),
					    ("hostname", "fragclient"), "end"])

		log(STATUS, f"Sending DHCP request with XID {self.dhcp_xid}")
		self.inject_eth(reply)

	def handle_eth_dhcp(self, p):
		"""Handle packets needed to connect and request an IP"""
		if not DHCP in p: return

		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')

		# DHCP Offer
		if req_type == 2:
			log(STATUS, "Received DHCP offer, sending DHCP request.")
			self.send_dhcp_request(p)
			self.dhcp_offer_frame = p

		# DHCP Ack
		elif req_type == 5:
			clientip = p[BOOTP].yiaddr
			serverip = p[IP].src
			self.time_retrans_dhcp = None
			log(STATUS, f"Received DHCP ack. My ip is {clientip} and router is {serverip}.", color="green")

			self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=ip, ARP_addr=self.mac)
			self.set_ip_addresses(clientip, serverip)

	def handle_eth(self, frame):
		if self.arp_sock != None:
			self.arp_sock.reply(frame)
		if BOOTP in frame and frame[BOOTP].xid == self.dhcp_xid:
			self.handle_eth_dhcp(frame)

		super().handle_eth(frame)

	def handle_tick(self):
		if self.time_retrans_dhcp != None and time.time() > self.time_retrans_dhcp:
			log(WARNING, "Retransmitting DHCP message", color="orange")
			self.get_ip()

	def get_header(self, qos=True):
		"""Construct a Dot11QoS-header."""
		header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
		if qos is True:
			header[Dot11].subtype = 8
			header.add_payload(Dot11QoS())
		self.sn += 1
		header.FCfield |= 'to-DS' # To AP.
		header.addr1 = self.bss # Destination.
		header.addr2 = self.mac # Source.
		header.addr3 = self.bss # BSSID.
		return header
		
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(DEBUG, "daemon: " + msg)
		if "Associated with" in msg:
			x = re.compile("Associated with (.*)")
			self.bss = x.search(msg).group(1)
			self.handle_trigger_associated()
		# FIXME: How is authenticated different from connected?
		if "WPA: Key negotiation completed with" in msg or \
			"WPA: EAPOL processing complete" in msg:
			self.handle_trigger_authenticated()
		if "CTRL-EVENT-CONNECTED" in msg:
			self.handle_trigger_connected()
		if "CTRL-EVENT-DISCONNECTED" in msg:
			self.handle_trigger_disconnected()
