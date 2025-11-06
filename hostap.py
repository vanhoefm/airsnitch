#!/usr/bin/env python3
import argparse, atexit

# Import dependencies and libraries.
from dependencies.libwifi.wifi import log, STATUS, change_log_level
from library.daemon import Daemon, NAME, VERSION

# Simplified wrapper to run an Access Point or Client Daemon.
#
# Examples:
# ./hostap.py wlan0 --ap
# ./hostap.py wlan1 --config ./setup/supplicant-wpa3-personal.conf
# ./hostap.py wlan1 --binary ./dependencies/hostap_2_9/wpa_supplicant/wpa_supplicant

# ----------------------------------- Helper Functions --------------------------------

def cleanup():
	daemon.stop()

# ----------------------------------- Main Function -----------------------------------

if __name__ == "__main__":

	# Arguments.
	parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
	parser.add_argument('iface', help="Interface to use.")
	parser.add_argument('--config', type=str, default=None, help="Configuration file.")
	parser.add_argument('--binary', type=str, default=None, help="Custom hostapd/wpa_supplicant binary.")
	parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
	parser.add_argument('--ap', default=False, action="store_true", help="Start as an Access Point")
	options = parser.parse_args()

	# Set debug verbosity of the logger.
	change_log_level(-options.debug)

	# Start the daemon.
	daemon = Daemon(options)
	atexit.register(cleanup)
	daemon.run()

