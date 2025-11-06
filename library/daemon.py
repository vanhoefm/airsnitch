import sys, socket, time, subprocess, select
import argparse, atexit
import os.path

# Include dependencies.
from dependencies.libwifi.wifi import *
from dependencies.wpaspy import Ctrl

# Metadata.
NAME = "Wi-Fi Daemon"
VERSION = "1.0"

# ----------------------------------- Wi-Fi Daemon --------------------------------------------

def log_level2switch(options):
	if options.debug >= 2: return ["-dd", "-K"]
	elif options.debug >= 1: return ["-d", "-K"]
	return ["-K"]

class Daemon():
	"""Wi-Fi Daemon."""
	
	# Default configurations.
	default_hostap = "./dependencies/hostap_2_10"
	default_config = "./setup"
	default_wpaspy = "/var/run"

	def __init__(self, options):
		self.options = options
		self.process = None
		self.terminated = False
		self.nic_iface = self.nic_mon = None
		self.sock_eth = self.sock_mon = None

		# Controllor and queue for wpaspy binding.
		self.wpaspy_ctrl = None
		self.wpaspy_queue = []
		
		# Configure interfaces and sockets.
		try:
			self.__configure_interfaces()
		except Exception as ex:
			log(ERROR, "Unable to configure interfaces: " + str(ex))
			log(ERROR, "Does the interface exist? Are you running as root and in a Python virtualenv?")
			quit(1)

		self.mac = scapy.arch.get_if_hwaddr(self.nic_iface)

		# The Eterhet socket can only be created once hostap brings the interface up
		self.sock_eth = None
		self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon)
		
		# Daemons can be operating as an authenticator or supplicant.
		if self.options.ap:
			self.ctrl_iface = self.default_wpaspy + "/hostapd/" + self.nic_iface
		else:
			self.ctrl_iface = self.default_wpaspy + "/wpa_supplicant/" + self.nic_iface

			
	def __configure_interfaces(self):

		# 0. Enable Wi-Fi
		subprocess.check_output(["rfkill", "unblock", "wifi"])
		self.nic_iface = self.options.iface

		# 1. Check if the interfaces exists
		try:
			scapy.arch.get_if_addr(self.nic_iface)
		except ValueError:
			log(ERROR, f"Interface {self.nic_iface} doesn't appear to exist.")
			quit(1)

		# 2. Create second virtual interface in monitor mode. Note: some kernels
		#    don't support interface names of 15+ characters.
		self.nic_mon = "mon" + self.nic_iface[:12]

		# Only create a new monitor interface if it does not yet exist
		try:
			scapy.arch.get_if_addr(self.nic_mon)
		except ValueError:
			subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
			subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])

		# 3. Enable monitor mode. This is similar to what airmon-ng does.
		set_monitor_mode(self.nic_mon)
		log(STATUS, f"Using interface {self.nic_mon} ({get_device_driver(self.nic_mon)}) to inject frames.")


	def __wpaspy_connect(self):
		"""
		Connect to the control interface of hostapd so that we can send commands towards
		it and receive events from it.
		"""

		# Wait until daemon started
		time_abort = time.time() + 10
		while not os.path.exists(self.ctrl_iface) and time.time() < time_abort:
			time.sleep(0.1)

		# Abort if daemon didn't start properly
		if not os.path.exists(self.ctrl_iface):
			log(ERROR, "Unable to connect to control interface. Did hostapd/wpa_supplicant start properly?")
			log(ERROR, "Try recompiling them using ./build.sh and double-check client.conf and hostapd.conf.")
			quit(1)
			
		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl(self.ctrl_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly.")
			log(ERROR, "Please restart it manually and inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise

	def handle_mon(self, p):
		pass

	def handle_eth(self, p):
		log(DEBUG, "Ethernet: " + croprepr(p))
		
	def handle_wpaspy(self, msg):
		log(DEBUG, "wpaspy: " + msg)

	def handle_started(self):
		pass

	def handle_tick(self):
		pass


	def inject_mon(self, p):
		if p is None or not p.haslayer(Dot11):
			log(WARNING, "Injecting frame on monitor iface without Dot11-layer.")
		self.sock_mon.send(p)


	def inject_eth(self, p):
		if p is None or not p.haslayer(Ether):
			log(WARNING, "Injecting frame on ethernet iface witthout Ether-layer.")
		self.sock_eth.send(p)


	def wpaspy_command(self, cmd):
		# Include console prefix so we can ignore other messages sent over the control interface.
		response = self.wpaspy_ctrl.request("> " + cmd)
		while not response.startswith("> "):
			# The reply to a command starts with "> ". Messages that don't start with this
			# prefix are events. Remember these events so that they can be processed later.
			self.wpaspy_queue.append(response)
			log(DEBUG, "<appending> " + response)
			response = self.wpaspy_ctrl.recv()
			
		if "UNKNOWN COMMAND" in response:
			log(ERROR, "daemon did not recognize the command %s." % cmd.split()[0])
			log(ERROR, "Did you (re)compile wpa_supplicant/hostapd?")
			quit(1)
		elif "FAIL" in response:
			log(ERROR, f"Failed to execute command {cmd}")
			quit(1)
			
		return response[2:]


	def __get_command(self):
	
		hostap = self.default_hostap if not self.options.binary else self.options.binary
		config = self.default_config if not self.options.config else self.options.config
		
		if self.options.ap:
			if not self.options.config: config += "/hostapd.conf"
			binary = hostap+"/hostapd/hostapd" if not self.options.binary else hostap 
			if not os.path.isfile(config):
				log(ERROR, "File %s not found." % config)
				quit(1)
			cmd = [binary, "-i", self.options.iface, config]
		else:
			if not self.options.config: config += "/supplicant.conf"
			binary = hostap+"/wpa_supplicant/wpa_supplicant" if not self.options.binary else hostap 
			if not os.path.isfile(config):
				log(ERROR, "File %s not found." % config)
				quit(1)
			cmd = [binary, "-Dnl80211", "-i", self.options.iface, 
				  "-c" , config, "-W" ]
		
		cmd += log_level2switch(self.options)
		return cmd


	def run(self):
		# Remove old occurrences of the control interface that didn't get cleaned properly
		subprocess.call(["rm", "-rf", self.ctrl_iface])

		# Start either wpa_supplicant or hostapd
		cmd = self.__get_command()
		log(STATUS, "Starting daemon using: " + " ".join(cmd))
		try:
			self.process = subprocess.Popen(cmd)
		except:
			if not os.path.exists(cmd[0]):
				log(ERROR, f"File {cmd[0]} not found. Did you (re)compile the executable using build.sh?")
			raise

		# After we connected to the daemon we know all interfaces have started
		self.__wpaspy_connect()

		# Now that hostap started we can create the ethernet socket
		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)

		self.handle_started()

		# Monitor the virtual monitor interface of the client and perform the needed actions
		sockets = [self.sock_mon, self.sock_eth, self.wpaspy_ctrl.s]
		while True:
			while len(self.wpaspy_queue) > 0:
				self.handle_wpaspy(self.wpaspy_queue.pop())

			if self.terminated:
				break
			sel = select.select(sockets, [], [], 0.5)
			
			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if p != None: self.handle_mon(p)

			if self.sock_eth in sel[0]:
				p = self.sock_eth.recv()
				if p != None and Ether in p: self.handle_eth(p)

			if self.wpaspy_ctrl.s in sel[0]:
				msg = self.wpaspy_ctrl.recv()
				self.handle_wpaspy(msg)
				
			self.handle_tick()


	def stop(self):
		log(STATUS, "Closing daemon and cleaning up ...")
		if self.process:
			self.process.terminate()
			self.process.wait()
		if self.sock_eth: self.sock_eth.close()
		if self.sock_mon: self.sock_mon.close()
		self.terminated = True
	
