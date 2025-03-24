# Test cases for Device Provisioning Protocol (DPP) version 3
# Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import os
import time

import hostapd
from wlantest import WlantestCapture
from test_dpp import check_dpp_capab, run_dpp_auto_connect, wait_auth_success, update_hapd_config, params1_ap_connector, params1_csign, params1_ap_netaccesskey, params1_sta_connector, params1_sta_connector, params1_sta_netaccesskey
from utils import *

def test_dpp_network_intro_version(dev, apdev):
    """DPP Network Introduction and protocol version"""
    check_dpp_capab(dev[0], min_ver=3)

    try:
        id, hapd = run_dpp_auto_connect(dev, apdev, 1, stop_after_prov=True)
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def test_dpp_network_intro_version_change(dev, apdev):
    """DPP Network Introduction and protocol version change"""
    check_dpp_capab(dev[0], min_ver=3)

    try:
        dev[0].set("dpp_version_override", "2")
        id, hapd = run_dpp_auto_connect(dev, apdev, 1, stop_after_prov=True)
        dev[0].set("dpp_version_override", "3")
        dev[0].select_network(id, freq=2412)
        dev[0].wait_connected()
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def test_dpp_network_intro_version_missing_req(dev, apdev):
    """DPP Network Introduction and protocol version missing from request"""
    check_dpp_capab(dev[0], min_ver=3)

    try:
        dev[0].set("dpp_version_override", "2")
        id, hapd = run_dpp_auto_connect(dev, apdev, 1, stop_after_prov=True)
        dev[0].set("dpp_version_override", "3")
        dev[0].set("dpp_test", "92")
        dev[0].select_network(id, freq=2412)
        ev = dev[0].wait_event(["DPP-INTRO"], timeout=10)
        if ev is None:
            raise Exception("DPP network introduction result not seen on STA")
        if "status=8" not in ev:
            raise Exception("Unexpected network introduction result on STA: " + ev)
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def run_dpp_tcp_pkex(dev0, dev1, cap_lo, sae=False, status=False):
    check_dpp_capab(dev0, min_ver=3)
    check_dpp_capab(dev1, min_ver=3)

    wt = WlantestCapture('lo', cap_lo)
    time.sleep(1)

    # Controller
    if sae:
        ssid = binascii.hexlify("sae".encode()).decode()
        password = binascii.hexlify("sae-password".encode()).decode()
        val = "conf=sta-sae ssid=%s pass=%s" % (ssid, password)
        if status:
            val += " conn_status=1"
        dev1.set("dpp_configurator_params", val)
    else:
        conf_id = dev1.dpp_configurator_add()
        dev1.set("dpp_configurator_params",
                 "conf=sta-dpp configurator=%d" % conf_id)

    req = "DPP_CONTROLLER_START"
    own = None
    if "OK" not in dev1.request(req):
        raise Exception("Failed to start Controller")

    code = "secret"

    id1 = dev1.dpp_bootstrap_gen(type="pkex")
    cmd = "own=%d" % id1
    cmd += " code=%s" % code
    res = dev1.request("DPP_PKEX_ADD " + cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")

    dev0.dpp_pkex_init(identifier=None, code=code, role="enrollee",
                       tcp_addr="127.0.0.1")

    res = wait_auth_success(dev1, dev0, configurator=dev1, enrollee=dev0,
                            allow_enrollee_failure=True,
                            allow_configurator_failure=True)
    if status:
        if 'wait_conn_status' not in res or not res['wait_conn_status']:
            raise Exception("wait_conn_status not reported")

    time.sleep(0.5)
    wt.close()

def test_dpp_tcp_pkex(dev, apdev, params):
    """DPP/PKEXv2 over TCP"""
    prefix = "dpp_tcp_pkex"
    cap_lo = os.path.join(params['logdir'], prefix + ".lo.pcap")
    try:
        run_dpp_tcp_pkex(dev[0], dev[1], cap_lo)
    finally:
        dev[1].request("DPP_CONTROLLER_STOP")

def run_dpp_tcp_pkex_auto_connect_2(dev, apdev, params, status, start_ap=True):
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    cap_lo = params['prefix'] + ".lo.pcap"

    params = {"ssid": "sae",
              "wpa": "2",
              "wpa_key_mgmt": "SAE",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "sae_password": "sae-password"}
    if start_ap:
        hapd = hostapd.add_ap(apdev[0], params)
    try:
        dev[0].set("dpp_config_processing", "2")
        run_dpp_tcp_pkex(dev[0], dev[1], cap_lo, sae=True, status=status)
        if start_ap:
            dev[0].wait_connected()
        if status:
            ev = dev[1].wait_event(["DPP-CONN-STATUS-RESULT"], timeout=16)
            if ev is None:
                raise Exception("Connection status resutl not reported")
            if start_ap and "result=0" not in ev:
                raise Exception("Unexpected result in success case: " + ev)
            if (not start_ap) and "result=10" not in ev:
                raise Exception("Unexpected result in failure case: " + ev)
            if "ssid=sae " not in ev:
                raise Exception("Missing SSID: " + ssid)
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)
        dev[1].request("DPP_CONTROLLER_STOP")

def test_dpp_tcp_pkex_auto_connect_2(dev, apdev, params):
    """DPP/PKEXv2 over TCP and automatic connection"""
    run_dpp_tcp_pkex_auto_connect_2(dev, apdev, params, False)

def test_dpp_tcp_pkex_auto_connect_2_status(dev, apdev, params):
    """DPP/PKEXv2 over TCP and automatic connection status"""
    run_dpp_tcp_pkex_auto_connect_2(dev, apdev, params, True)

def test_dpp_tcp_pkex_auto_connect_2_status_fail(dev, apdev, params):
    """DPP/PKEXv2 over TCP and automatic connection status for failure"""
    run_dpp_tcp_pkex_auto_connect_2(dev, apdev, params, True, start_ap=False)

def test_dpp_tcp_pkex_while_associated(dev, apdev, params):
    """DPP/PKEXv2 over TCP while associated"""
    try:
        run_dpp_tcp_pkex_while_associated(dev, apdev, params, False)
    finally:
        dev[1].request("DPP_CONTROLLER_STOP")
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def test_dpp_tcp_pkex_while_associated_conn_status(dev, apdev, params):
    """DPP/PKEXv2 over TCP while associated (conn status)"""
    try:
        run_dpp_tcp_pkex_while_associated(dev, apdev, params, True)
    finally:
        dev[1].request("DPP_CONTROLLER_STOP")
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def run_dpp_tcp_pkex_while_associated(dev, apdev, params, status):
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    cap_lo = params['prefix'] + ".lo.pcap"

    params = {"ssid": "current",
              "wpa": "2",
              "wpa_key_mgmt": "SAE",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "sae_password": "password"}
    hapd = hostapd.add_ap(apdev[0], params)

    params = {"ssid": "sae",
              "wpa": "2",
              "wpa_key_mgmt": "SAE",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "sae_password": "sae-password"}
    hapd2 = hostapd.add_ap(apdev[1], params)

    dev[0].set("dpp_config_processing", "2")
    dev[0].set("sae_groups", "")
    dev[0].connect("current", psk="password", key_mgmt="SAE", ieee80211w="2",
                   scan_freq="2412")
    run_dpp_tcp_pkex(dev[0], dev[1], cap_lo, sae=True, status=status)
    if status:
        ev = dev[1].wait_event(["DPP-CONN-STATUS-RESULT"], timeout=16)
        if ev is None:
            raise Exception("Connection status result not reported")
        if "result=0" not in ev:
            raise Exception("Unexpected result in success case: " + ev)
    dev[0].wait_connected(timeout=30)

def test_dpp_controller_relay_pkex(dev, apdev, params):
    """DPP Controller/Relay with PKEX"""
    try:
        run_dpp_controller_relay_pkex(dev, apdev, params)
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)
        dev[1].request("DPP_CONTROLLER_STOP")

def run_dpp_controller_relay_pkex(dev, apdev, params):
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)
    prefix = "dpp_controller_relay_pkex"
    cap_lo = os.path.join(params['logdir'], prefix + ".lo.pcap")

    wt = WlantestCapture('lo', cap_lo)

    # Controller
    conf_id = dev[1].dpp_configurator_add()
    dev[1].set("dpp_configurator_params",
               "conf=sta-dpp configurator=%d" % conf_id)
    id_c = dev[1].dpp_bootstrap_gen()
    res = dev[1].request("DPP_BOOTSTRAP_INFO %d" % id_c)
    pkhash = None
    for line in res.splitlines():
        name, value = line.split('=')
        if name == "pkhash":
            pkhash = value
            break
    if not pkhash:
        raise Exception("Could not fetch public key hash from Controller")
    if "OK" not in dev[1].request("DPP_CONTROLLER_START"):
        raise Exception("Failed to start Controller")

    # Relay
    params = {"ssid": "unconfigured",
              "channel": "6",
              "dpp_controller": "ipaddr=127.0.0.1 pkhash=" + pkhash}
    relay = hostapd.add_ap(apdev[1], params)
    check_dpp_capab(relay)

    # Enroll Relay to the network
    id_h = relay.dpp_bootstrap_gen(chan="81/6", mac=True)
    uri_r = relay.request("DPP_BOOTSTRAP_GET_URI %d" % id_h)
    dev[1].dpp_auth_init(uri=uri_r, conf="ap-dpp", configurator=conf_id)
    wait_auth_success(relay, dev[1], configurator=dev[1], enrollee=relay)
    update_hapd_config(relay)

    code = "secret"
    id1 = dev[1].dpp_bootstrap_gen(type="pkex")
    cmd = "own=%d" % id1
    cmd += " code=%s" % code
    res = dev[1].request("DPP_PKEX_ADD " + cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (Controller)")

    dev[0].flush_scan_cache()

    # Initiate PKEX from Enrollee
    dev[0].set("dpp_config_processing", "2")
    dev[0].dpp_pkex_init(identifier=None, code=code, role="enrollee")
    wait_auth_success(dev[1], dev[0], configurator=dev[1], enrollee=dev[0],
                      allow_enrollee_failure=True,
                      allow_configurator_failure=True)
    ev = dev[0].wait_event(["DPP-NETWORK-ID"], timeout=1)
    if ev is None:
        raise Exception("DPP network id not reported")
    network = int(ev.split(' ')[1])
    dev[0].wait_connected()
    dev[0].dump_monitor()

    time.sleep(0.5)
    wt.close()

def dpp_pb_ap(apdev):
    params = {"ssid": "sae",
              "dpp_configurator_connectivity": "1",
              "wpa": "2",
              "wpa_key_mgmt": "SAE",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "sae_password": "sae-password"}
    return hostapd.add_ap(apdev, params)

def test_dpp_push_button(dev, apdev):
    """DPP push button"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    try:
        dev[0].set("dpp_config_processing", "2")
        if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the AP")
        if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the station")
        ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on station")
        ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=1)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on AP")
        dev[0].wait_connected()
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)

def test_dpp_push_button_unsupported_ap_conf(dev, apdev):
    """DPP push button and unsupported AP configuration"""
    check_dpp_capab(dev[0], min_ver=3)

    params = {"ssid": "open",
              "dpp_configurator_connectivity": "1"}
    hapd = hostapd.add_ap(apdev[0], params)
    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None or "failed" not in ev:
        raise Exception("Push button bootstrapping did not fail on AP")
    while True:
        ev = dev[0].wait_event(["DPP-PB-RESULT", "DPP-RX"], timeout=100)
        if ev is None:
            raise Exception("Push button result not reported on station")
        if "DPP-PB-RESULT failed" in ev:
            break
        if "type=18" in ev:
            raise Exception("Unexpected PKEX initiation seen")

def test_dpp_push_button_session_overlap_sta(dev, apdev):
    """DPP push button and session overlap detected by STA"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    params = {"ssid": "another",
              "channel": "6",
              "wpa": "2",
              "wpa_key_mgmt": "SAE",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "sae_password": "sae-password"}
    hapd2 = hostapd.add_ap(apdev[1], params)

    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = dev[0].wait_event(["DPP-PB-STATUS"], timeout=30)
    if ev is None:
        raise Exception("Push button status not reported on station")
    # Force bootstrap key change since both instances share the same global
    # DPP state for PB.
    hapd.request("DPP_STOP_LISTEN")
    if "OK" not in hapd2.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP2")
    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None:
        raise Exception("Push button result not reported on station")
    if "session-overlap" not in ev:
        raise Exception("Unexpected push button result on station: " + ev)
    ev = hapd.wait_event(["DPP-CONF-SENT"], timeout=0.1)
    if ev:
        raise Exception("AP sent configuration")
    ev = hapd2.wait_event(["DPP-CONF-SENT"], timeout=0.1)
    if ev:
        raise Exception("AP2 sent configuration")

def test_dpp_push_button_session_overlap_ap(dev, apdev):
    """DPP push button and session overlap detected by AP"""
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])

    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station(0)")
    if "OK" not in dev[1].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station(1)")

    ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None:
        raise Exception("Push button result not reported on AP")
    if "session-overlap" not in ev:
        raise Exception("Unexpected push button result on AP: " + ev)

    dev[0].request("DPP_STOP_LISTEN")
    dev[1].request("DPP_STOP_LISTEN")

def test_dpp_push_button_session_overlap_configurator(dev, apdev):
    """DPP push button and session overlap detected by Configurator"""
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)
    check_dpp_capab(dev[2], min_ver=3)

    dev[0].dpp_listen(2437)
    conf_id = dev[1].dpp_configurator_add()
    ssid = "example"
    ssid_hex = binascii.hexlify(ssid.encode()).decode()
    cmd = "DPP_PUSH_BUTTON role=configurator conf=sta-dpp ssid=%s configurator=%d" % (ssid_hex, conf_id)
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to press push button on the Configurator")

    if "OK" not in dev[1].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station(1)")
    if "OK" not in dev[2].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station(2)")

    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None:
        raise Exception("Push button result not reported on Configurator")
    if "session-overlap" not in ev:
        raise Exception("Unexpected push button result on Configurator: " + ev)

    dev[1].request("DPP_STOP_LISTEN")
    dev[2].request("DPP_STOP_LISTEN")

def test_dpp_push_button_2sta(dev, apdev):
    """DPP push button with two STAs"""
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    dev[0].set("sae_groups", "")
    dev[1].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    try:
        dev[0].set("dpp_config_processing", "2")
        if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the AP(0)")
        if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the station(0)")
        ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on station(0)")
        ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=30)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on AP(0)")
        dev[0].wait_connected()

        dev[1].set("dpp_config_processing", "2")
        if "OK" not in dev[1].request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the station(1)")
        time.sleep(1)
        if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
            raise Exception("Failed to press push button on the AP(1)")
        ev = dev[1].wait_event(["DPP-PB-RESULT"], timeout=30)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on station(1)")
        ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=30)
        if ev is None or "success" not in ev:
            raise Exception("Push button bootstrapping did not succeed on AP(0)")
        dev[1].wait_connected()
    finally:
        dev[0].set("dpp_config_processing", "0", allow_fail=True)
        dev[1].set("dpp_config_processing", "0", allow_fail=True)

def test_dpp_push_button_r_hash_mismatch_sta(dev, apdev):
    """DPP push button - Responder hash mismatch from STA"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    dev[0].set("dpp_test", "98")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None or "failed" not in ev:
        raise Exception("Push button bootstrapping did not fail correctly on AP")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_push_button_i_hash_mismatch_ap(dev, apdev):
    """DPP push button - Initiator hash mismatch from AP"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    hapd.set("dpp_test", "99")
    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None or "failed" not in ev:
        raise Exception("Push button bootstrapping did not fail correctly on STA")

def test_dpp_push_button_r_hash_mismatch_ap(dev, apdev):
    """DPP push button - Responder hash mismatch from AP"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])
    dev[0].set("sae_groups", "")

    hapd = dpp_pb_ap(apdev[0])
    hapd.set("dpp_test", "100")
    if "OK" not in hapd.request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=30)
    if ev is None or "session-overlap" not in ev:
        raise Exception("Push button bootstrapping did not fail correctly on STA")

def test_dpp_push_button_ext_conf(dev, apdev):
    """DPP push button"""
    check_dpp_capab(dev[0], min_ver=3)
    check_sae_capab(dev[0])

    hapd = dpp_pb_ap(apdev[0])
    conf_id = hapd.dpp_configurator_add()
    ssid = "example"
    ssid_hex = binascii.hexlify(ssid.encode()).decode()
    cmd = "DPP_PUSH_BUTTON conf=sta-dpp ssid=%s configurator=%d" % (ssid_hex, conf_id)
    if "OK" not in hapd.request(cmd):
        raise Exception("Failed to press push button on the AP")
    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = dev[0].wait_event(["DPP-CONFOBJ-AKM"], timeout=30)
    if ev is None or "dpp" not in ev:
        raise Exception("Did not receive DPP AKM config")
    ev = dev[0].wait_event(["DPP-CONFOBJ-SSID"], timeout=1)
    if ev is None or ssid not in ev:
        raise Exception("Did not receive correct SSID in config")
    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=1)
    if ev is None or "success" not in ev:
        raise Exception("Push button bootstrapping did not succeed on station")
    ev = hapd.wait_event(["DPP-PB-RESULT"], timeout=1)
    if ev is None or "success" not in ev:
        raise Exception("Push button bootstrapping did not succeed on AP")

def test_dpp_push_button_wpas_conf(dev, apdev):
    """DPP push button with wpa_supplicant as Configurator"""
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)

    dev[1].dpp_listen(2437)
    conf_id = dev[1].dpp_configurator_add()
    ssid = "example"
    ssid_hex = binascii.hexlify(ssid.encode()).decode()
    cmd = "DPP_PUSH_BUTTON role=configurator conf=sta-dpp ssid=%s configurator=%d" % (ssid_hex, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to press push button on the Configurator")

    if "OK" not in dev[0].request("DPP_PUSH_BUTTON"):
        raise Exception("Failed to press push button on the station")
    ev = dev[0].wait_event(["DPP-CONFOBJ-AKM"], timeout=30)
    if ev is None or "dpp" not in ev:
        raise Exception("Did not receive DPP AKM config")
    ev = dev[0].wait_event(["DPP-CONFOBJ-SSID"], timeout=1)
    if ev is None or ssid not in ev:
        raise Exception("Did not receive correct SSID in config")
    ev = dev[0].wait_event(["DPP-PB-RESULT"], timeout=1)
    if ev is None or "success" not in ev:
        raise Exception("Push button bootstrapping did not succeed on station")

    ev = dev[1].wait_event(["DPP-PB-RESULT"], timeout=1)
    if ev is None or "success" not in ev:
        raise Exception("Push button bootstrapping did not succeed on Configurator")

def test_dpp_private_peer_introduction(dev, apdev):
    """DPP private peer introduction"""
    check_dpp_capab(dev[0], min_ver=3)
    check_dpp_capab(dev[1], min_ver=3)

    params = {"ssid": "dpp",
              "wpa": "2",
              "wpa_key_mgmt": "DPP",
              "ieee80211w": "2",
              "rsn_pairwise": "CCMP",
              "dpp_connector": params1_ap_connector,
              "dpp_csign": params1_csign,
              "dpp_netaccesskey": params1_ap_netaccesskey}
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    id = dev[0].connect("dpp", key_mgmt="DPP", scan_freq="2412",
                        ieee80211w="2",
                        dpp_csign=params1_csign,
                        dpp_connector=params1_sta_connector,
                        dpp_netaccesskey=params1_sta_netaccesskey,
                        dpp_connector_privacy="1")
    val = dev[0].get_status_field("key_mgmt")
    if val != "DPP":
        raise Exception("Unexpected key_mgmt: " + val)
