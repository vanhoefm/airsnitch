# <div align="center">AirSnitch: Testing Wi-Fi Client Isolation</div>

<img align="right" src="airsnitch.png" width="200px" title="AirSnitch logo created by ChatGPT">

This repository contains AirSnitch, a tool to test the security of client isolation in home and enterprise Wi-Fi networks. Sometimes also called AP (Access Point) isolation, client isolation is not a standardized feature of Wi-Fi. Instead, vendors added client isolation as an ad-hoc defense to prevent clients from attacking each other. For instance, client isolation normally prevents traditional ARP-based MitM attacks. However, our [NDSS'26 paper](https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf) shows that client isolation is often implemented in inconsistent and insecure ways. With AirSnitch, you can test if client isolation is implemented and configured as expected in your Wi-Fi network.

<a id="id-toc"></a>
## Table of Contents

* [1. Introduction](#id-intro)
* [2. Prerequisites](#id-prereq)
* [3. Before every usage](#id-everyuse)
* [4. Main Vulnerability Tests](#id-mainflaws)
* [5. Extra Vulnerability Tests](#id-extraflaws)
* [6. Defenses](#id-defenses)
* [7. Troubleshooting](#id-troubleshooting)


<a id="id-intro"></a>
## [1. Introduction](#id-intro)

AirSnitch can test for three main attack categories to bypass client isolation. These attacks bypass Wi-Fi encryption, meaning that simply using WPA1/2/3 does not, on its own, prevent these attacks:

1. **Abusing GTK**: An adversary can abuse the group key(s) that are shared between all clients in the same Wi-Fi network. In particular, the GTK group key can be used to inject packets directly to one or more victims. Additionally, all operating systems we tested accept unicast IP packets inside broadcast Wi-Fi packets. This means an adversary can inject arbitrary packets by injecting the following Wi-Fi frame:

	```
	Dot11(dst=ff:ff:ff:ff:ff:ff, src=access point) / IP(dst=victim, src=adversary)
	```

	This packet is then encrypted using the shared group key which is known by all clients, including by malicious insiders. Only the client with the specified destination IP address will then process the injected packet, meaning targeted attacks remain possible. This is similar the [WPA Too: Hole 196](https://defcon.org/html/links/dc-archives/dc-18-archive.html#Ahmad) attack, but now in the context of bypassing client isolation, which was not previously studied.


2. **Gateway Bouncing**: Many networks only enforce client isolation at the MAC/Ethernet layer. This allows an adversary to bypass client isolation by tricking the gateway into forwarding packets to the victim at the IP layer, i.e., by ‘bouncing’ packets at the gateway. Concretely, an adversary can send the following type of packet:

	```
	Ethernet(src=attacker, dst=gateway) / IP(src=attacker, dst=victim)
	```

	This packet does not get blocked by client isolation, because at the MAC/Ethernet layer, the packet is destined to the gateway and not another client. However, the gateway will then route the packet at the IP layer.


3. **Port Stealing** (across BSSIDs): An adversary can manipulate internal switches and bridges to forward the victim’s uplink *and* downlink traffic to the adversary. The idea to intercept *uplink* traffic is illustrated in the following figure:

	<div align="center"><img src="steal-uplink.png" width="500px"></div>

	Here the victim is connected to the access point AP2, and the adversary then connects to a different access point AP1 while spoofing the MAC address of the internal gateway (step 1). As a result, when the victim now tries to send uplink traffic to the real gateway, the traffic is instead routed to the attacker (step 2). The red line represent spoofed traffic to manipulate routing tables, and the blue line represented the intercepted uplink traffic.
	
	To intercept *downlink* traffic, a similar attack is possible, where the adversary spoofs the victim’s MAC address, causing the network to route the victim’s uplink frames to the adversary (see [this figure](steal-downlink.png)).


<a id="id-impact"></a>
### [1.1 Practical Impact](#id-impact)

All combined, the above techniques enable an adversary to **restore MitM capabilities even in the face of client isolation**. In our [NDSS'26 paper](https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf), we found that most home routers are vulnerable, find lacking security guarantees in enterprise devices, and confirm vulnerabilities in real-world enterprise networks. Important highlights are:

- Against home routers that enable the creation of a guest network, in addition to the main network, our attacks allow breakig the isolation between the guest and main network. That is, a device within the guest network can attack devices in the main network.

- Even when only injecting packets to a victim, without yet establishing a full MitM, impactful attacks are possible. For instance, injecting malicious ICMPv6 Router Advertisements can trick a client into using a malicious DNS server, enabling subsequent interception of all IP-based traffic. See [FragAttacks](https://papers.mathyvanhoef.com/fragattacks-overview.pdf) for details.

- Our techniques can also be used to inject packets towards, or intercept packets from/to, _internal_ network devices. A notable example is that, depending on the network configuration, is is possible to intercept the RADIUS packets generated by an Access Point. This can enable RADIUS credential theft and the subsequent creation of rogue Enterprise networks.

- Our attacks, in particular port stealing, can be effectively accross different APs and BSSIDs, and even accross different networks. Against one university network, an adversary could even use port stealing to leak a victim client's traffic from a WPA2/3 network into an open network, allowing anyone within radio range to capture the leaked traffic.

- Note that to obtain a full MitM without disrupting traffic, some extra techniques are needed that are further covered in our paper, e.g., _Server-Triggered Port Restoration_ or _Inter-NIC Relaying_.


<a id="id-compare-macstealer"></a>
### [1.2 Comparison to MacStealer](#id-compare-macstealer)

Our [USENIX Security '23 framing frames](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers) paper, and its [MacStealer tool](https://github.com/vanhoefm/macstealer), also contains a client isolation bypass. AirSnitch extends this work. Summarized, MacStealer corresponds the `--c2c-port-steal` test of AirSnitch in the specific case where the victim and adversary connect to the _same BSSID_. **All other tests below of AirSnitch are novel** and aren't covered in the framing frames paper. Put differently, the original MacStealer tool only covers port stealing against a single BSSID and only for downlink traffic.

Patching the original 'MacStealer' bypass is also [non-trivial](https://github.com/vanhoefm/macstealer/blob/main/README.md#id-mitigations), where an ideal fix may even require that both access points _and_ clients implement the ["Reassociating STA recognition" extension](https://mentor.ieee.org/802.11/dcn/23/11-23-0537-07-000m-reassociating-sta-recognition.docx) to the (draft) IEEE 802.11 standard. As a result, this flaw was left as an open problem by most vendors. In contrast, most new issues covered by AirSnitch are considered implementation and configuration flaws, and are therefore easier to fix in practice.


<a id="id-prereq"></a>
## [2. Prerequisites](#id-prereq)

Our scripts were tested on **Ubuntu 22.04.5 LTS**. To easily test the below scripts, we therefore recommend to **download and install [Ubuntu 22.04](https://releases.ubuntu.com/jammy/)**. You can do this in [VirtualBox](https://www.virtualbox.org/wiki/Downloads) if you have USB Wi-Fi dongles.

The following steps only need to be executed once to initialize the repository and to compile the necessary executables on your machine. First, install the necessary dependencies:

	sudo apt update
	sudo apt install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
	libssl-dev libdbus-1-dev pkg-config build-essential net-tools python3-venv \
	aircrack-ng rfkill git dnsmasq tcpreplay macchanger

Next, clone this repository, and run the following script in the root directory of the repository to compile our modified hostap release:

	./setup.sh
	cd airsnitch/research
	./build.sh
	./pysetup.sh


<a id="id-everyuse"></a>
## [3. Before every usage](#id-everyuse)

<a id="id-everyuse-env"></a>
### [3.1. Execution environment](#id-everyuse-env)

Before every use, you must load the Python environment as root:

	cd airsnitch/research
	sudo su
	source venv/bin/activate

You should now [disable Wi-Fi in your network manager](https://github.com/vanhoefm/libwifi/blob/master/docs/linux_tutorial.md#id-disable-wifi) so it will not interfere with AirSnitch. Optionally, check using `sudo airmon-ng check` to see which other processes might be using the wireless network card and might interfere with AirSnitch.

<a id="id-everyuse-net"></a>
### [3.2. Network configuration](#id-everyuse-net)

The next step is to edit [`client.conf`](research/client.conf) with the information of the network that you want to test. This is a configuration for [`wpa_supplicant`](https://wiki.archlinux.org/title/wpa_supplicant#Connecting_with_wpa_passphrase) that must contain two network blocks: one representing the victim and one representing the attacker. An example configuration file to test isolation between the WPA2/3 networks `main-network` and `guest-network` is:

	# Don't change this line, otherwise AirSnitch won't work
	ctrl_interface=wpaspy_ctrl

	network={
		# Don't change this field, the script relies on it
		id_str="victim"

		# Network to test: network/SSID that the simulated victim is in
		ssid="main-network"
		key_mgmt=WPA-PSK
		psk="main-password"
	}

	network={
		# Don't change this field, the script relies on it
		id_str="attacker"

		# Network to test: network/SSID that the simulated adversary is in
		ssid="guest-network"
		key_mgmt=WPA-PSK
		psk="guest-password"
	}

In the part "network to test" you must provide the name of the network being tested, its security configuration, and any applicable credentials. See [wpa_supplicant.conf](wpa_supplicant/wpa_supplicant.conf) for documentation on to write/edit configuration files and for example network blocks for various types of Wi-Fi networks. In the first network block, under "victim login", you must specify the network that the victim belongs to. In the second network block, you specify the network information of the simulated attacker.

In the above example, AirSnitch will test an attack where an adversary in the guest network will try to attack a victim in the main network.

By default the script uses the configuration file `client.conf`. You can use a different configuration file by providing the `--config network.conf` paramater, where you can replace `network.conf` with the configuration file that you want to use.

This repository also contains the following example configuration files:

- [`eap.conf`](airsnitch/research/eap.conf): A configuration file to test an Enterprise network that uses PEAP-MSCHAPv2 for authentication, with unique usernames and passwords for the victim and attacker.

- [`multipsk.conf`](airsnitch/research/multipsk.conf): A configuration file to test a network that uses multi-PSK where one password is used by trusted devices and a second password is given to guests.

- [`saepk.conf`](airsnitch/research/saepk.conf): A configuration file to test a public hotspot that uses SAE-PK.


<a id="id-everyuse-bssid"></a>
### [3.3. BSSID selection](#id-everyuse-bssid)

By default, the simulated victim and attacker are forced to connect to the same AP/BSSID. Additionally, AirSnitch will quit if the victim and attacker are configured to connect to a different SSID, and AirSnitch will quit if both the victim and attacker are using the same credentials. These strict sanity checks are not always needed and can be disabled using the following parameters:

- `--other-bss`: this will force the victim and attacker to connect to _different_ BSSIDs.

- `--no-ssid-check`: this will disable the check that the victim and attacker connect to the same SSID. Specifying this parameter is, for instance, needed to check isolation between a guest and main network that have a different network name.

- `--no-id-check`: **explain VLAN per user identity, that's why different identities (credentials) are preferred, but you can also opt to test using the same identities for convenience.**

Note that it is also possible to edit the network block(s) to test a [specific AP/BSS](#id-test-bss).



<a id="id-mainflaws"></a>
## [4. Main Vulnerability Tests](#id-mainflaws)

**TODO: by default set no-ssid-check and no-id-check? Or at least document these?**

**TODO: Verify the functionaity of --other-bss parameter - does that still work?**

<a id="id-mainflaws-gtk"></a>
### [4.1. GTK Abuse](#id-mainflaws-gtk)

Execute the following command to simulate the adversary and victim:

	python3 airsnitch.py wlan2 --check-gtk-shared wlan3 --no-ssid-check --no-id-check [--other-bss]

The script will then output the following:

	>>> The victim's GTK is (XXX)."
	>>> The attacker's GTK is (YYY)."

If the keys XXX and YYY are identitical, then the network is vulnerable, meaning adversary can attack the victim by abusing the shared group key.

**TODO: Consider testing THE SAME bssid.**

<a id="id-mainflaws-bounce"></a>
### [4.2. Gateway Bouncing](#id-mainflaws-bounce)

Execute the following command to simulate the adversary and victim:

	python3 airsnitch.py wlan2 --c2c-ip wlan3 --no-ssid-check --no-id-check [--other-bss]

The attack is successful, meaning the network is vulnerable, if the following output in red is shown:

	>>> Client to client traffic at IP layer is allowed (PSK{passphrase_atkr} to SAE{passphrase_victim})

The text between parenthesis will differ based on the networks being tested and the network credentials used.

<a id="id-mainflaws-port-down"></a>
### [4.3. Downlink Port Stealing](#id-mainflaws-port-down)

**TODO: Explain the `--server` parameter. Is a real responding server needed?**

Execute the following command to simulate the adversary and victim:

	python3 airsnitch.py wlan2 --c2c-port-steal wlan3 --other-bss --no-ssid-check --no-id-check --server 192.168.100.1

The attack is successful if the following output in red is shown:

	>>> Downlink port stealing is successful.

<a id="id-mainflaws-port-up"></a>
### [4.4. Uplink port stealing](#id-mainflaws-port-up)

Execute the following command to simulate the adversary and victim:

	python3 airsnitch.py wlan2 --c2c-port-steal-uplink wlan3 --other-bss --no-ssid-check --no-id-check --server 192.168.100.1

The attack is successful if the following output in red is shown:

	>>> Uplink port stealing is successful.


<a id="id-extraflaws"></a>
## [5. Extra Vulnerability Tests](#id-extraflaws)

### 5.1. Broadcast Reflection

Broadcast Reflection: `--c2c-broadcast`

<a id="id-test-bss"></a>
### 5.2. Testing a specific Access Point / BSS

By default, AirSnitch will automatically select an AP/BSS of the network to connect with and test. In case you have a network with multiple APs/BSSes, you can test a specific one by specifying this AP/BSS in the network block of the victim using the `bssid` keyword. For example, you can use:

	...

	network={
		# Don't change this field, the script relies on it
		id_str="victim"

		# Network to test: network/SSID that the simulated victim is in
		ssid="main-network"
		key_mgmt=WPA-PSK
		psk="main-password"

		# This a specific AP/BSS
		bssid=00:11:22:33:44:55
	}

	...

With the above configuration, AirSnitch will connect to `00:11:22:33:44:55` as the simulated victim. The simulated adversary can connect to any AP/BSS, unless the `bssid` keyword is also used in the network block of the attacker.

- When the above example is combined with the `--other-bss` parameter, the victim will still connect to `00:11:22:33:44:55`, but the attacker will then always connect to a _different_ BSSID.

- Another option is to specify an explicit BSS/AP in the network block of the victim _and_ attacker.

**TODO: Introduce the parameters --same-bssid and --other-bssid? What would be meaninful defaults?**
**TODO: Considerations are: (1) both interfaces might detect different BSSIDs; (2) the macstealer attack is _probably_ most effective against the same BSSID, though actively sending data frames after connecting to trigger port stealing could improve effectiveness against different BSSIDs; (3) the port stealing attacks are only reliable against different BSSIDs.**

**This means it will connect both as the victim _and as the attacker_ to this AP.**

Note that AirSnitch will search for at most 30 seconds for the given AP/BSS. If it cannot
find the specified AP/BSS the tool will quit.

### 5.3. Manual tests

Some aspects are not directly covered by this scripts and require manual testing:

- Testing whether the IGTK is randomized under client isolation.


<a id="id-defenses"></a>
## [6. Defenses](#id-defenses)

We give the following recommendations to mitigate or prevent attacks, ordered from least to most complex to implement:

1. **Proper client isolation documentation:** A core problem is that client isolation is not standardized, meaning most vendors use different terminology to refer to client isolation or its variants, and each vendor may offer different security guarantees. We therefore first strongly recommand to document the security guarantees of client isolation in your products. This documentation should, for instance, cover the following aspects:

	- Is client isolation only enforced at the MAC/Ethernet layer or also at the IP layer?

	- When you offer a 'guest' network in addition to a 'main' network, explicitly document when traffic is allowed and which traffic is not allowed. In particular: (1) are clients in the main network allowed to initiate connections to clients in the guest network,and vice versa; (1) are clients in the guest network allocated to communicate with each other; and (3) **WHAT MORE HERE**.

	- Are clients in the 'guest' and 'main' network given different group keys?
	
	- Is each client in the 'guest' network given a randomized group key? And if so, is this randomized group key distributed in all possible handshakes, e.g., **4-way handshake, FILS, FT, wak-up frames, etc**.

	- Is broadcast traffic also blocked when enabling client isolation?

	- Are broadcast Wi-Fi packets containing unicast IPv4 or IPv6 packets accepted?

	- Are clients blocked from using a MAC address that is already in use by an internal wired device, e.g., are clients prevented from using the same MAC address as the gateway, DNS server, DHCP server, or other essential internal devices?

	- Client isolation in an open network, or a network with a shared WPA password, is useless from a security perspective. Does the device/GUI give a warning about this when enbling client isolation in an open or PSK-protected network? **TODO: More nuance?**

	- Is there isolation between clients that use the same EAP identity?

	- Are some devices, by exception, always reachable, e.g., the DNS/DHCP server, a detected printer, etc?

2. **Client isolation configuration:**

	- Linux clients: set the sysctl `drop_unicast_in_l2_multicast=1` to make GTK Abuse harder.

3. **Secure by default:** help push for a community-wide definition of client isolation, and provide an easy option to guarentee this definition.


<a id="id-troubleshooting"></a>
# [7. Troubleshooting](#id-troubleshooting)

- When using Ubuntu 22.04 on VirtualBox 7 or higher, we noticed that the terminal may not properly start after installation. To fix this, follow [these steps](https://askubuntu.com/questions/1435918/terminal-not-opening-on-ubuntu-22-04-on-virtual-box-7-0-0). Alternatively, when installing Ubuntu 22.04, check/enable the option "Skip Unattended Installation".

- The test `--c2c-gtk-inject` relies on the Linux machine having set the sysctl `drop_unicast_in_l2_multicast` to `0`, since the simulated victim is a Linux client itself and the script monitors the managed interface for the injected frame.

