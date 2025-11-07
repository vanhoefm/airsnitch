# EtherExists: Demystifying and Breaking Client Isolation in Wi-Fi Networks
## 1. Introduction
This repo contains EtherExists, a set of tools to evaluate Wi-Fi networks for client isolation flaws within the Wi-Fi standards and concrete implementations. Our attacks can inject/write and intercept/read Wi-Fi frames over the wireless medium in a way that bypasses AP-enforced client isolation and Wi-Fi encryption, enabling unintended connectivity and/or MitM attacks between otherwise separated clients. These vulnerabilities affect worldwide Wi-Fi deployments with malicious outsiders/insiders, where our techniques can break client isolation to achieve Man-in-the-Middle for all WPA versions, i.e., from WEP up to WPA2/WPA3, and for all personal and even enterprise networks. Some attack variants allow breaking the isolation between guest networks and main networks.

This codebase builds upon the public repository [macstealer](https://github.com/vanhoefm/macstealer/).

## 2. Demystifying Wi-Fi Client Isolation and Encryption

We give a brief summary of the attack techniques used in EtherExists to provide a high-level overview. 

### Attacks Exploiting Shared Keys

Man-on-the-Side & Rogue AP (Home WPA2/WPA3-Personal) – Possession of a shared passphrase allows an insider to derive session keys or lure clients to a cloned AP, bypassing isolation trivially.

Abusing GTK – Wrapping unicast traffic inside broadcast/multicast frames encrypted with the Group Temporal Key lets an attacker inject packets directly to victims, bypassing AP forwarding rules. GTKs often remain valid long after client disconnection.

Passpoint Flaws – Even when per-client GTKs are intended, certain handshakes (group key, FT, FILS, WNM-Sleep) leak the real GTK. IGTKs are never randomized, enabling indirect GTK-based injection via WNM-Sleep frames.

### Routing-Layer Injection

Gateway Bouncing – Layer-2 isolation is nullified if the gateway forwards IP packets between clients. An attacker sends packets with the victim’s IP but the gateway’s MAC as the L2 destination; the gateway “bounces” them back to the victim, enabling client-to-client injection via Layer-3 routing.

### Switching-Layer Interception & Injection

Port Stealing Across Virtual BSSIDs – By authenticating with the victim’s MAC address on a different BSSID, the attacker poisons the AP’s MAC-to-port mapping so that victim traffic is encrypted with the attacker’s PTK. This can also be used with spoofed gateway MACs to capture uplink traffic from all clients. In some cases, WPA-protected traffic is leaked in plaintext.

Broadcast Reflection – Crafting ToDS=1 frames with a broadcast address forces the AP to re-encrypt them with the victim’s GTK and deliver them. This allows unicast injection without knowing the GTK and works across BSSIDs/open networks.

### Achieving Full Bidirectional MitM

By combining interception and injection primitives, we demonstrate full man-in-the-middle positioning in both single-AP and multi-AP enterprise environments:

Maintaining Downlink & Uplink Control – Use port stealing for interception; reinject via GTK abuse, gateway bouncing, or client-triggered port restoration (eliciting victim replies to restore port mappings).

Server-Triggered Port Restoration – Coordinate with an external server to restore gateway MAC mappings periodically, enabling sustained uplink relaying.

Inter-NIC Relaying – Relay intercepted traffic through a second NIC to forward it to the real gateway while keeping control of stolen ports.

Cross-AP MitM – Extend port stealing to distribution switches to intercept traffic from victims on entirely different APs.

### Real-World Impact & Higher-Layer Exploits

The attacks were validated on 5 home routers, 2 open-source firmware distributions, and live university WPA2-Enterprise networks. Beyond raw traffic access, these primitives enable:

RADIUS credential theft to set up rogue enterprise APs.

DNS/DHCP poisoning, plaintext credential theft, and traffic analysis even against HTTPS.

## 3. Key Takeaway
Wi-Fi client isolation, as deployed today, is neither cryptographically sound nor consistently enforced. The demonstrated attack techniques—spanning Wi-Fi encryption, routing, and switching layers—show that determined insiders can reliably obtain full MitM capabilities even in modern WPA2/3 networks with isolation enabled. The work calls for standardized definitions, multi-layer enforcement, per-client group keys, VLAN-based segregation, and stronger spoofing prevention to close these gaps. Full details are in the paper. 

# Usage
As our tool is an extension of macstealer, you can follow macstealer's [README](https://github.com/vanhoefm/macstealer/blob/main/README.md) to install and use it. 
In the extended [macstealer.py](https://github.com/zhouxinan/EtherExists/blob/main/macstealer/research/macstealer.py), we add several new options:

`--check-gtk-shared`: Checking if second given interface receives the same GTK from BSSID.

`--c2c-port-steal`: Second interface to test port stealing (downlink).

`--c2c-port-steal-uplink`: Second interface to test port stealing (uplink).
