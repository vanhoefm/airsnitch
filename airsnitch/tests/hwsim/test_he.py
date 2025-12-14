# HE tests
# Copyright (c) 2019, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import subprocess, time

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import *
from test_dfs import wait_dfs_event

def test_he_open(dev, apdev):
    """HE AP with open mode configuration"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ax=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")
    sta = hapd.get_sta(dev[0].own_addr())
    if "[HE]" not in sta['flags']:
        raise Exception("Missing STA flag: HE")

def test_he_disabled_on_sta(dev, apdev):
    """HE AP and HE disabled on STA"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15"}
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412", disable_he="1")
    sta = hapd.get_sta(dev[0].own_addr())
    if "[HE]" in sta['flags']:
        raise Exception("Unexpected STA flag: HE")

def test_he_params(dev, apdev):
    """HE AP parameters"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15",
              "he_su_beamformer": "0",
              "he_su_beamformee": "0",
              "he_default_pe_duration": "4",
              "he_twt_required": "1",
              "he_rts_threshold": "64",
              "he_basic_mcs_nss_set": "65535",
              "he_mu_edca_qos_info_param_count": "0",
              "he_mu_edca_qos_info_q_ack": "0",
              "he_mu_edca_qos_info_queue_request": "1",
              "he_mu_edca_qos_info_txop_request": "0",
              "he_mu_edca_ac_be_aifsn": "0",
              "he_mu_edca_ac_be_ecwmin": "15",
              "he_mu_edca_ac_be_ecwmax": "15",
              "he_mu_edca_ac_be_timer": "255",
              "he_mu_edca_ac_bk_aifsn": "0",
              "he_mu_edca_ac_bk_aci": "1",
              "he_mu_edca_ac_bk_ecwmin": "15",
              "he_mu_edca_ac_bk_ecwmax": "15",
              "he_mu_edca_ac_bk_timer": "255",
              "he_mu_edca_ac_vi_ecwmin": "15",
              "he_mu_edca_ac_vi_ecwmax": "15",
              "he_mu_edca_ac_vi_aifsn": "0",
              "he_mu_edca_ac_vi_aci": "2",
              "he_mu_edca_ac_vi_timer": "255",
              "he_mu_edca_ac_vo_aifsn": "0",
              "he_mu_edca_ac_vo_aci": "3",
              "he_mu_edca_ac_vo_ecwmin": "15",
              "he_mu_edca_ac_vo_ecwmax": "15",
              "he_mu_edca_ac_vo_timer": "255",
              "he_spr_sr_control": "0",
              "he_spr_non_srg_obss_pd_max_offset": "0",
              "he_spr_srg_obss_pd_min_offset": "0",
              "he_spr_srg_obss_pd_max_offset": "0",
              "he_spr_srg_bss_colors": "1 2 10 63",
              "he_spr_srg_partial_bssid": "0 1 3 63",
              "he_6ghz_max_ampdu_len_exp": "7",
              "he_6ghz_rx_ant_pat": "1",
              "he_6ghz_tx_ant_pat": "1",
              "he_6ghz_max_mpdu": "2",
              "he_oper_chwidth": "0",
              "he_oper_centr_freq_seg0_idx": "1",
              "he_oper_centr_freq_seg1_idx": "0"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ax=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")

def test_he_spr_params(dev, apdev):
    """HE AP spatial reuse parameters"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_spr_sr_control": "12",
              "he_spr_non_srg_obss_pd_max_offset": "1",
              "he_spr_srg_obss_pd_min_offset": "2",
              "he_spr_srg_obss_pd_max_offset": "3",
              "he_spr_srg_bss_colors": "1 2 10 63",
              "he_spr_srg_partial_bssid": "0 1 3 63",
              "he_oper_chwidth": "0",
              "he_oper_centr_freq_seg0_idx": "1",
              "he_oper_centr_freq_seg1_idx": "0"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ax=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")

def he_supported():
    cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
    reg = cmd.stdout.read().decode()
    if "@ 80)" in reg or "@ 160)" in reg:
        return True
    return False

def test_he80(dev, apdev):
    """HE with 80 MHz channel width"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_capab": "[MAX-MPDU-11454]",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42"}
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=80 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        est = dev[0].get_bss(bssid)['est_throughput']
        if est != "600502":
            raise Exception("Unexpected BSS est_throughput: " + est)
        status = dev[0].get_status()
        if status["ieee80211ac"] != "1":
            raise Exception("Unexpected STATUS ieee80211ac value (STA)")
        status = hapd.get_status()
        logger.info("hostapd STATUS: " + str(status))
        if status["ieee80211n"] != "1":
            raise Exception("Unexpected STATUS ieee80211n value")
        if status["ieee80211ac"] != "1":
            raise Exception("Unexpected STATUS ieee80211ac value")
        if status["ieee80211ax"] != "1":
            raise Exception("Unexpected STATUS ieee80211ax value")
        if status["secondary_channel"] != "1":
            raise Exception("Unexpected STATUS secondary_channel value")
        if status["vht_oper_chwidth"] != "1":
            raise Exception("Unexpected STATUS vht_oper_chwidth value")
        if status["vht_oper_centr_freq_seg0_idx"] != "42":
            raise Exception("Unexpected STATUS vht_oper_centr_freq_seg0_idx value")
        if "vht_caps_info" not in status:
            raise Exception("Missing vht_caps_info")
        if status["he_oper_chwidth"] != "1":
            raise Exception("Unexpected STATUS he_oper_chwidth value")
        if status["he_oper_centr_freq_seg0_idx"] != "42":
            raise Exception("Unexpected STATUS he_oper_centr_freq_seg0_idx value")

        sta = hapd.get_sta(dev[0].own_addr())
        logger.info("hostapd STA: " + str(sta))
        if "[HT]" not in sta['flags']:
            raise Exception("Missing STA flag: HT")
        if "[VHT]" not in sta['flags']:
            raise Exception("Missing STA flag: VHT")
        if "[HE]" not in sta['flags']:
            raise Exception("Missing STA flag: HE")

    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

def _test_he_wifi_generation(dev, apdev, conf, scan_freq):
    """HE and wifi_generation"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "ieee80211n": "1",
                  "ieee80211ax": "1"}
        params.update(conf)
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", key_mgmt="NONE", scan_freq=scan_freq)
        status = dev[0].get_status()
        if 'wifi_generation' not in status:
            # For now, assume this is because of missing kernel support
            raise HwsimSkip("Association Request IE reporting not supported")
            #raise Exception("Missing wifi_generation information")
        if status['wifi_generation'] != "6":
            raise Exception("Unexpected wifi_generation value: " + status['wifi_generation'])

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
        wpas.connect("he", key_mgmt="NONE", scan_freq=scan_freq)
        status = wpas.get_status()
        if 'wifi_generation' not in status:
            # For now, assume this is because of missing kernel support
            raise HwsimSkip("Association Request IE reporting not supported")
            #raise Exception("Missing wifi_generation information (connect)")
        if status['wifi_generation'] != "6":
            raise Exception("Unexpected wifi_generation value (connect): " + status['wifi_generation'])
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

def test_he_wifi_generation(dev, apdev):
    conf = {
        "vht_oper_chwidth": "1",
        "hw_mode": "a",
        "channel": "36",
        "ht_capab": "[HT40+]",
        "vht_oper_centr_freq_seg0_idx": "42",
        "he_oper_chwidth": "1",
        "he_oper_centr_freq_seg0_idx": "42",
        "vht_capab": "[MAX-MPDU-11454]",
        "ieee80211ac": "1",
    }
    _test_he_wifi_generation(dev, apdev, conf, "5180")

def test_he_wifi_generation_24(dev, apdev):
    conf = {
        "hw_mode": "g",
        "channel": "1",
    }
    _test_he_wifi_generation(dev, apdev, conf, "2412")

def he80_test(apdev, dev, channel, ht_capab):
    clear_scan_cache(apdev)
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": str(channel),
                  "ht_capab": ht_capab,
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42"}
        hapd = hostapd.add_ap(apdev, params)
        bssid = apdev['bssid']

        dev[0].connect("he", key_mgmt="NONE",
                       scan_freq=str(5000 + 5 * channel))
        hwsim_utils.test_connectivity(dev[0], hapd)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he80b(dev, apdev):
    """HE with 80 MHz channel width (HT40- channel 40)"""
    he80_test(apdev[0], dev, 40, "[HT40-]")

def test_he80c(dev, apdev):
    """HE with 80 MHz channel width (HT40+ channel 44)"""
    he80_test(apdev[0], dev, 44, "[HT40+]")

def test_he80d(dev, apdev):
    """HE with 80 MHz channel width (HT40- channel 48)"""
    he80_test(apdev[0], dev, 48, "[HT40-]")

def test_he80_params(dev, apdev):
    """HE with 80 MHz channel width and number of optional features enabled"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+][SHORT-GI-40][DSS_CCK-40]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_capab": "[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1][MAX-A-MPDU-LEN-EXP0]",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "require_vht": "1",
                  "require_he": "1",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42",
                  "he_su_beamformer": "1",
                  "he_mu_beamformer": "1",
                  "he_bss_color":"1",
                  "he_default_pe_duration":"1",
                  "he_twt_required":"1",
                  "he_rts_threshold":"1"}
        hapd = hostapd.add_ap(apdev[0], params)

        dev[1].connect("he", key_mgmt="NONE", scan_freq="5180",
                       disable_vht="1", wait_connect=False)
        dev[0].connect("he", key_mgmt="NONE", scan_freq="5180")
        dev[2].connect("he", key_mgmt="NONE", scan_freq="5180",
                       disable_sgi="1")
        ev = dev[1].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
        if ev is None:
            raise Exception("Association rejection timed out")
        if "status_code=104" not in ev:
            raise Exception("Unexpected rejection status code")
        dev[1].request("DISCONNECT")
        dev[1].request("REMOVE_NETWORK all")
        dev[1].dump_monitor()
        dev[1].connect("he", key_mgmt="NONE", scan_freq="5180",
                       disable_he="1", wait_connect=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
        sta0 = hapd.get_sta(dev[0].own_addr())
        sta2 = hapd.get_sta(dev[2].own_addr())
        capab0 = int(sta0['vht_caps_info'], base=16)
        capab2 = int(sta2['vht_caps_info'], base=16)
        if capab0 & 0x60 == 0:
            raise Exception("dev[0] did not support SGI")
        if capab2 & 0x60 != 0:
            raise Exception("dev[2] claimed support for SGI")
        ev = dev[1].wait_event(["CTRL-EVENT-ASSOC-REJECT"])
        if ev is None:
            raise Exception("Association rejection timed out (2)")
        if "status_code=124" not in ev:
            raise Exception("Unexpected rejection status code (2): " + ev)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev, count=3)

def test_he80_invalid(dev, apdev):
    """HE with invalid 80 MHz channel configuration (seg1)"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "vht_oper_centr_freq_seg1_idx": "159",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42",
                  "he_oper_centr_freq_seg1_idx": "155",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to unexpected seg1 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he80_invalid2(dev, apdev):
    """HE with invalid 80 MHz channel configuration (seg0)"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "46",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to invalid seg0 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he_20(devs, apdevs):
    """HE and 20 MHz channel"""
    dev = devs[0]
    ap = apdevs[0]
    try:
        hapd = None
        params = {"ssid": "test-he20",
                  "country_code": "DE",
                  "hw_mode": "a",
                  "channel": "36",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "ht_capab": "",
                  "vht_capab": "",
                  "vht_oper_chwidth": "0",
                  "vht_oper_centr_freq_seg0_idx": "0",
                  "supported_rates": "60 120 240 360 480 540",
                  "require_vht": "1",
                  "he_oper_chwidth": "0",
                  "he_oper_centr_freq_seg0_idx": "0"}
        hapd = hostapd.add_ap(ap, params)
        dev.connect("test-he20", scan_freq="5180", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev, hapd)
    finally:
        dev.request("DISCONNECT")
        clear_regdom(hapd, devs)

def test_he_40(devs, apdevs):
    """HE and 40 MHz channel"""
    dev = devs[0]
    ap = apdevs[0]
    try:
        hapd = None
        params = {"ssid": "test-he40",
                  "country_code": "DE",
                  "hw_mode": "a",
                  "channel": "36",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "ht_capab": "[HT40+]",
                  "vht_capab": "",
                  "vht_oper_chwidth": "0",
                  "vht_oper_centr_freq_seg0_idx": "38",
                  "he_oper_chwidth": "0",
                  "he_oper_centr_freq_seg0_idx": "38",
                  "he_su_beamformer": "1",
                  "he_mu_beamformer": "1"}
        hapd = hostapd.add_ap(ap, params)
        dev.connect("test-he40", scan_freq="5180", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev, hapd)
    finally:
        dev.request("DISCONNECT")
        clear_regdom(hapd, devs)

@long_duration_test
def test_he160(dev, apdev):
    """HE with 160 MHz channel width (1)"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "vht_capab": "[VHT160]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "2",
                  "vht_oper_centr_freq_seg0_idx": "50",
                  "he_oper_chwidth": "2",
                  "he_oper_centr_freq_seg0_idx": "50",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        bssid = apdev[0]['bssid']

        ev = wait_dfs_event(hapd, "DFS-CAC-START", 5)
        if "DFS-CAC-START" not in ev:
            raise Exception("Unexpected DFS event")

        state = hapd.get_status_field("state")
        if state != "DFS":
            if state == "DISABLED" and not os.path.exists("dfs"):
                # Not all systems have recent enough CRDA version and
                # wireless-regdb changes to support 160 MHz and DFS. For now,
                # do not report failures for this test case.
                raise HwsimSkip("CRDA or wireless-regdb did not support 160 MHz")
            raise Exception("Unexpected interface state: " + state)

        logger.info("Waiting for CAC to complete")

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed")
        if "freq=5180" not in ev:
            raise Exception("Unexpected DFS freq result")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state")

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5180")
        dev[0].wait_regdom(country_ie=True)
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        est = dev[0].get_bss(bssid)['est_throughput']
        if est != "1201002":
            raise Exception("Unexpected BSS est_throughput: " + est)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        dev[0].disconnect_and_stop_scan()
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=0.5)
        dev[0].flush_scan_cache()

@long_duration_test
def test_he160b(dev, apdev):
    """HE with 160 MHz channel width (2)"""
    try:
        hapd = None

        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "104",
                  "ht_capab": "[HT40-]",
                  "vht_capab": "[VHT160]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "2",
                  "vht_oper_centr_freq_seg0_idx": "114",
                  "he_oper_chwidth": "2",
                  "he_oper_centr_freq_seg0_idx": "114",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[1], params, wait_enabled=False)

        ev = wait_dfs_event(hapd, "DFS-CAC-START", 5)
        if "DFS-CAC-START" not in ev:
            raise Exception("Unexpected DFS event(2)")

        state = hapd.get_status_field("state")
        if state != "DFS":
            if state == "DISABLED" and not os.path.exists("dfs"):
                # Not all systems have recent enough CRDA version and
                # wireless-regdb changes to support 160 MHz and DFS. For now,
                # do not report failures for this test case.
                raise HwsimSkip("CRDA or wireless-regdb did not support 160 MHz")
            raise Exception("Unexpected interface state: " + state)

        logger.info("Waiting for CAC to complete")

        ev = wait_dfs_event(hapd, "DFS-CAC-COMPLETED", 70)
        if "success=1" not in ev:
            raise Exception("CAC failed(2)")
        if "freq=5520" not in ev:
            raise Exception("Unexpected DFS freq result(2)")

        ev = hapd.wait_event(["AP-ENABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out(2)")

        state = hapd.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state(2)")

        freq = hapd.get_status_field("freq")
        if freq != "5520":
            raise Exception("Unexpected frequency(2)")

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5520")
        dev[0].wait_regdom(country_ie=True)
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5520" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        dev[0].disconnect_and_stop_scan()
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=0.5)
        dev[0].flush_scan_cache()

def test_he160_no_dfs_100_plus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (100 plus)"""
    run_ap_he160_no_dfs(dev, apdev, "100", "[HT40+]")

def test_he160_no_dfs(dev, apdev):
    """HE with 160 MHz channel width and no DFS (104 minus)"""
    run_ap_he160_no_dfs(dev, apdev, "104", "[HT40-]")

def test_he160_no_dfs_108_plus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (108 plus)"""
    run_ap_he160_no_dfs(dev, apdev, "108", "[HT40+]")

def test_he160_no_dfs_112_minus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (112 minus)"""
    run_ap_he160_no_dfs(dev, apdev, "112", "[HT40-]")

def test_he160_no_dfs_116_plus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (116 plus)"""
    run_ap_he160_no_dfs(dev, apdev, "116", "[HT40+]")

def test_he160_no_dfs_120_minus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (120 minus)"""
    run_ap_he160_no_dfs(dev, apdev, "120", "[HT40-]")

def test_he160_no_dfs_124_plus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (124 plus)"""
    run_ap_he160_no_dfs(dev, apdev, "124", "[HT40+]")

def test_he160_no_dfs_128_minus(dev, apdev):
    """HE with 160 MHz channel width and no DFS (128 minus)"""
    run_ap_he160_no_dfs(dev, apdev, "128", "[HT40-]")

def run_ap_he160_no_dfs(dev, apdev, channel, ht_capab):
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "ZA",
                  "hw_mode": "a",
                  "channel": channel,
                  "ht_capab": ht_capab,
                  "vht_capab": "[VHT160]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "2",
                  "vht_oper_centr_freq_seg0_idx": "114",
                  "he_oper_chwidth": "2",
                  "he_oper_centr_freq_seg0_idx": "114",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        ev = hapd.wait_event(["AP-ENABLED"], timeout=2)
        if not ev:
            cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
            reg = cmd.stdout.readlines()
            for r in reg:
                if b"5490" in r and b"DFS" in r:
                    raise HwsimSkip("ZA regulatory rule did not have DFS requirement removed")
            raise Exception("AP setup timed out")

        freq = str(int(channel) * 5 + 5000)
        dev[0].connect("he", key_mgmt="NONE", scan_freq=freq)
        dev[0].wait_regdom(country_ie=True)
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=" + freq not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=160 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he160_no_ht40(dev, apdev):
    """HE with 160 MHz channel width and HT40 disabled"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "ZA",
                  "hw_mode": "a",
                  "channel": "108",
                  "ht_capab": "",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "2",
                  "vht_oper_centr_freq_seg0_idx": "114",
                  "he_oper_chwidth": "2",
                  "he_oper_centr_freq_seg0_idx": "114",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=2)
        if not ev:
            cmd = subprocess.Popen(["iw", "reg", "get"], stdout=subprocess.PIPE)
            reg = cmd.stdout.readlines()
            for r in reg:
                if "5490" in r and "DFS" in r:
                    raise HwsimSkip("ZA regulatory rule did not have DFS requirement removed")
            raise Exception("AP setup timed out")
        if "AP-ENABLED" in ev:
            # This was supposed to fail due to sec_channel_offset == 0
            raise Exception("Unexpected AP-ENABLED")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he80plus80(dev, apdev):
    """HE with 80+80 MHz channel width"""
    try:
        hapd = None
        hapd2 = None
        params = {"ssid": "he",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "52",
                  "ht_capab": "[HT40+]",
                  "vht_capab": "[VHT160-80PLUS80]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "3",
                  "vht_oper_centr_freq_seg0_idx": "58",
                  "vht_oper_centr_freq_seg1_idx": "155",
                  "he_oper_chwidth": "3",
                  "he_oper_centr_freq_seg0_idx": "58",
                  "he_oper_centr_freq_seg1_idx": "155",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This will actually fail since DFS on 80+80 is not yet supported
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        # ignore result to avoid breaking the test once 80+80 DFS gets enabled

        params = {"ssid": "he2",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "vht_capab": "[VHT160-80PLUS80]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "3",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "vht_oper_centr_freq_seg1_idx": "155",
                  "he_oper_chwidth": "3",
                  "he_oper_centr_freq_seg0_idx": "42",
                  "he_oper_centr_freq_seg1_idx": "155"}
        hapd2 = hostapd.add_ap(apdev[1], params, wait_enabled=False)

        ev = hapd2.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=5)
        if not ev:
            raise Exception("AP setup timed out(2)")
        if "AP-DISABLED" in ev:
            # Assume this failed due to missing regulatory update for now
            raise HwsimSkip("80+80 MHz channel not supported in regulatory information")

        state = hapd2.get_status_field("state")
        if state != "ENABLED":
            raise Exception("Unexpected interface state(2)")

        dev[1].connect("he2", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[1], hapd2)
        sig = dev[1].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=80+80 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        if "CENTER_FRQ1=5210" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(3): " + str(sig))
        if "CENTER_FRQ2=5775" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(4): " + str(sig))
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        if hapd2:
            hapd2.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def test_he80plus80_invalid(dev, apdev):
    """HE with invalid 80+80 MHz channel"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "3",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "vht_oper_centr_freq_seg1_idx": "0",
                  "he_oper_chwidth": "3",
                  "he_oper_centr_freq_seg0_idx": "42",
                  "he_oper_centr_freq_seg1_idx": "0",
                  'ieee80211d': '1',
                  'ieee80211h': '1'}
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        # This fails due to missing(invalid) seg1 configuration
        ev = hapd.wait_event(["AP-DISABLED"], timeout=5)
        if ev is None:
            raise Exception("AP-DISABLED not reported")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80/160 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he80_csa(dev, apdev):
    """HE with 80 MHz channel width and CSA"""
    csa_supported(dev[0])
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "US",
                  "hw_mode": "a",
                  "channel": "149",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "155",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "155"}
        hapd = hostapd.add_ap(apdev[0], params)

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5745")
        hwsim_utils.test_connectivity(dev[0], hapd)

        hapd.request("CHAN_SWITCH 5 5180 ht vht he blocktx center_freq1=5210 sec_channel_offset=1 bandwidth=80")
        ev = hapd.wait_event(["CTRL-EVENT-STARTED-CHANNEL-SWITCH"], timeout=10)
        if ev is None:
            raise Exception("Channel switch start event not seen")
        if "freq=5180" not in ev:
            raise Exception("Unexpected channel in CS started")
        ev = hapd.wait_event(["CTRL-EVENT-CHANNEL-SWITCH"], timeout=10)
        if ev is None:
            raise Exception("Channel switch completion event not seen")
        if "freq=5180" not in ev:
            raise Exception("Unexpected channel in CS completed")
        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=10)
        if ev is None:
            raise Exception("CSA finished event timed out")
        if "freq=5180" not in ev:
            raise Exception("Unexpected channel in CSA finished event")
        time.sleep(0.5)
        hwsim_utils.test_connectivity(dev[0], hapd)

        hapd.request("CHAN_SWITCH 5 5745")
        ev = hapd.wait_event(["AP-CSA-FINISHED"], timeout=10)
        if ev is None:
            raise Exception("CSA finished event timed out")
        if "freq=5745" not in ev:
            raise Exception("Unexpected channel in CSA finished event")
        time.sleep(0.5)
        hwsim_utils.test_connectivity(dev[0], hapd)

        # This CSA to same channel will fail in kernel, so use this only for
        # extra code coverage.
        hapd.request("CHAN_SWITCH 5 5745")
        hapd.wait_event(["AP-CSA-FINISHED"], timeout=1)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

def test_he_on_24ghz(dev, apdev):
    """Subset of HE features on 2.4 GHz"""
    hapd = None
    params = {"ssid": "test-he-2g",
              "hw_mode": "g",
              "channel": "1",
              "ieee80211n": "1",
              "ieee80211ax": "1",
              "vht_oper_chwidth": "0",
              "vht_oper_centr_freq_seg0_idx": "1",
              "he_oper_chwidth": "0",
              "he_oper_centr_freq_seg0_idx": "1"}
    hapd = hostapd.add_ap(apdev[0], params)
    try:
        dev[0].connect("test-he-2g", scan_freq="2412", key_mgmt="NONE")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sta = hapd.get_sta(dev[0].own_addr())

        dev[1].connect("test-he-2g", scan_freq="2412", key_mgmt="NONE")
        sta = hapd.get_sta(dev[1].own_addr())

    finally:
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        if hapd:
            hapd.request("DISABLE")
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].flush_scan_cache()
        dev[1].flush_scan_cache()

def test_he80_pwr_constraint(dev, apdev):
    """HE with 80 MHz channel width and local power constraint"""
    hapd = None
    try:
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211d": "1",
                  "local_pwr_constraint": "3",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42"}
        hapd = hostapd.add_ap(apdev[0], params)

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5180")
        dev[0].wait_regdom(country_ie=True)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        if hapd:
            hapd.request("DISABLE")
        dev[0].disconnect_and_stop_scan()
        subprocess.call(['iw', 'reg', 'set', '00'])
        dev[0].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=0.5)
        dev[0].flush_scan_cache()

def test_he_use_sta_nsts(dev, apdev):
    """HE with 80 MHz channel width and use_sta_nsts=1"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42",
                  "use_sta_nsts": "1"}
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", key_mgmt="NONE", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        clear_regdom(hapd, dev)

def test_he_tkip(dev, apdev):
    """HE and TKIP"""
    skip_without_tkip(dev[0])
    try:
        hapd = None
        params = {"ssid": "he",
                  "wpa": "1",
                  "wpa_key_mgmt": "WPA-PSK",
                  "wpa_pairwise": "TKIP",
                  "wpa_passphrase": "12345678",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42"}
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", psk="12345678", scan_freq="5180")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5180" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=20 MHz (no HT)" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        status = hapd.get_status()
        logger.info("hostapd STATUS: " + str(status))
        if status["ieee80211n"] != "0":
            raise Exception("Unexpected STATUS ieee80211n value")
        if status["ieee80211ac"] != "0":
            raise Exception("Unexpected STATUS ieee80211ac value")
        if status["ieee80211ax"] != "0":
            raise Exception("Unexpected STATUS ieee80211ax value")
        if status["secondary_channel"] != "0":
            raise Exception("Unexpected STATUS secondary_channel value")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

def test_he_40_fallback_to_20(devs, apdevs):
    """HE and 40 MHz channel configuration falling back to 20 MHz"""
    dev = devs[0]
    ap = apdevs[0]
    try:
        hapd = None
        params = {"ssid": "test-he40",
                  "country_code": "US",
                  "hw_mode": "a",
                  "basic_rates": "60 120 240",
                  "channel": "161",
                  "ieee80211d": "1",
                  "ieee80211h": "1",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "ht_capab": "[HT40+][SHORT-GI-20][SHORT-GI-40][DSSS_CCK-40]",
                  "vht_capab": "[RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC1][MAX-MPDU-11454][MAX-A-MPDU-LEN-EXP7]",
                  "vht_oper_chwidth": "0",
                  "vht_oper_centr_freq_seg0_idx": "155",
                  "he_oper_chwidth": "0",
                  "he_oper_centr_freq_seg0_idx": "155"}
        hapd = hostapd.add_ap(ap, params)
        dev.connect("test-he40", scan_freq="5805", key_mgmt="NONE")
        dev.wait_regdom(country_ie=True)
        hwsim_utils.test_connectivity(dev, hapd)
    finally:
        clear_regdom(hapd, devs)

def test_he80_to_24g_he(dev, apdev):
    """HE with 80 MHz channel width reconfigured to 2.4 GHz HE"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "FI",
                  "hw_mode": "a",
                  "channel": "36",
                  "ht_capab": "[HT40+]",
                  "ieee80211n": "1",
                  "ieee80211ac": "1",
                  "ieee80211ax": "1",
                  "vht_oper_chwidth": "1",
                  "vht_capab": "[MAX-MPDU-11454]",
                  "vht_oper_centr_freq_seg0_idx": "42",
                  "he_oper_chwidth": "1",
                  "he_oper_centr_freq_seg0_idx": "42"}
        hapd = hostapd.add_ap(apdev[0], params)
        bssid = apdev[0]['bssid']

        hapd.disable()
        hapd.set("ieee80211ac", "0")
        hapd.set("hw_mode", "g")
        hapd.set("channel", "1")
        hapd.set("ht_capab", "")
        hapd.set("vht_capab", "")
        hapd.set("he_oper_chwidth", "")
        hapd.set("he_oper_centr_freq_seg0_idx", "")
        hapd.set("vht_oper_chwidth", "")
        hapd.set("vht_oper_centr_freq_seg0_idx", "")
        hapd.enable()

        dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("80 MHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

def test_he_twt(dev, apdev):
    """HE and TWT"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_twt_required":"1"}
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")
    if "OK" not in dev[0].request("TWT_SETUP"):
        raise Exception("TWT_SETUP failed")
    if "OK" not in dev[0].request("TWT_TEARDOWN"):
        raise Exception("TWT_SETUP failed")
    if "OK" not in dev[0].request("TWT_SETUP dialog=123 exponent=9 mantissa=10 min_twt=254 setup_cmd=1 twt=1234567890 requestor=1 trigger=0 implicit=0 flow_type=0 flow_id=2 protection=1 twt_channel=3 control=16"):
        raise Exception("TWT_SETUP failed")
    if "OK" not in dev[0].request("TWT_TEARDOWN flags=255"):
        raise Exception("TWT_SETUP failed")

def test_he_6ghz(dev, apdev):
    """HE with 20 MHz channel width on 6 GHz"""
    try:
        dev[0].set("sae_pwe", "1")
        hapd = None
        params = {"ssid": "he",
                  "country_code": "DE",
                  "op_class": "131",
                  "channel": "5",
                  "ieee80211ax": "1",
                  "wpa": "2",
                  "rsn_pairwise": "CCMP",
                  "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1",
                  "sae_password": "password",
                  "ieee80211w": "2"}
        hapd = hostapd.add_ap(apdev[0], params, set_channel=False)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", sae_password="password", key_mgmt="SAE",
                       ieee80211w="2", scan_freq="5975")
        hwsim_utils.test_connectivity(dev[0], hapd)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        if "FREQUENCY=5975" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=20 MHz" not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))
        status = dev[0].get_status()
        if 'wifi_generation' not in status:
            # For now, assume this is because of missing kernel support
            raise HwsimSkip("Association Request IE reporting not supported")
            #raise Exception("Missing wifi_generation information")
        if status['wifi_generation'] != "6":
            raise Exception("Unexpected wifi_generation value: " + status['wifi_generation'])
        status = hapd.get_status()
        logger.info("hostapd STATUS: " + str(status))
        if status["ieee80211ax"] != "1":
            raise Exception("Unexpected STATUS ieee80211ax value")
        if status["he_oper_chwidth"] != "0":
            raise Exception("Unexpected STATUS he_oper_chwidth value")

        sta = hapd.get_sta(dev[0].own_addr())
        logger.info("hostapd STA: " + str(sta))
        if "[HE]" not in sta['flags']:
            raise Exception("Missing STA flag: HE")

    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("HE 6 GHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        dev[0].set("sae_pwe", "0")
        clear_regdom(hapd, dev)

def test_he_6ghz_auto_security(dev, apdev):
    """HE on 6 GHz and automatic security settings on STA"""
    try:
        hapd = None
        params = {"ssid": "he",
                  "country_code": "DE",
                  "op_class": "131",
                  "channel": "5",
                  "ieee80211ax": "1",
                  "wpa": "2",
                  "ieee80211w": "2",
                  "rsn_pairwise": "CCMP",
                  "wpa_key_mgmt": "SAE",
                  "sae_password": "password"}
        hapd = hostapd.add_ap(apdev[0], params, set_channel=False)
        bssid = apdev[0]['bssid']

        dev[0].connect("he", psk="password", key_mgmt="SAE WPA-PSK",
                       ieee80211w="1", scan_freq="5975")
        status = dev[0].get_status()
        if "pmf" not in status:
            raise Exception("pmf missing from status")
        if status["pmf"] != "2":
            raise Exception("Unexpected pmf status value: " + status["pmf"])

        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["hostapdMFPR"] != "1":
            raise Exception("STA did not indicate MFPR=1")
    except Exception as e:
        if isinstance(e, Exception) and str(e) == "AP startup failed":
            if not he_supported():
                raise HwsimSkip("HE 6 GHz channel not supported in regulatory information")
        raise
    finally:
        dev[0].request("DISCONNECT")
        clear_regdom(hapd, dev)

    params = hostapd.wpa2_params(ssid="he", passphrase="password")
    hapd = hostapd.add_ap(apdev[1], params)
    bssid = apdev[1]['bssid']
    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("RECONNECT")
    dev[0].wait_connected()
    status = dev[0].get_status()
    if "pmf" in status:
        raise Exception("Unexpected pmf status value(2): " + status["pmf"])
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if "[MFP]" in sta["flags"]:
        raise Exception("MFP reported unexpectedly(2)")

def test_he_6ghz_security(dev, apdev):
    """HE AP and 6 GHz security parameter validation"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "op_class": "131",
              "channel": "1"}
    hapd = hostapd.add_ap(apdev[0], params, no_enable=True)

    # Pre-RSNA security methods are not allowed in 6 GHz
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Invalid configuration accepted(1)")

    # Management frame protection is required in 6 GHz"
    hapd.set("wpa", "2")
    hapd.set("wpa_passphrase", "12345678")
    hapd.set("wpa_key_mgmt", "SAE")
    hapd.set("rsn_pairwise", "CCMP")
    hapd.set("ieee80211w", "1")
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Invalid configuration accepted(2)")

    # Invalid AKM suite for 6 GHz
    hapd.set("ieee80211w", "2")
    hapd.set("wpa_key_mgmt", "SAE WPA-PSK")
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Invalid configuration accepted(3)")

    # Invalid pairwise cipher suite for 6 GHz
    hapd.set("wpa_key_mgmt", "SAE")
    hapd.set("rsn_pairwise", "CCMP TKIP")
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Invalid configuration accepted(4)")

    # Invalid group cipher suite for 6 GHz
    hapd.set("wpa_key_mgmt", "SAE")
    hapd.set("rsn_pairwise", "CCMP")
    hapd.set("group_cipher", "TKIP")
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Invalid configuration accepted(5)")

def test_he_prefer_he20(dev, apdev):
    """Preference on HE20 over HT20"""
    params = {"ssid": "he",
              "channel": "1",
              "ieee80211ax": "0",
              "ieee80211n": "1"}
    hapd = hostapd.add_ap(apdev[0], params)
    bssid = apdev[0]['bssid']
    params = {"ssid": "test",
              "channel": "1",
              "ieee80211ax": "1",
              "ieee80211n": "1"}
    hapd2 = hostapd.add_ap(apdev[1], params)
    bssid2 = apdev[1]['bssid']

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].scan_for_bss(bssid2, freq=2412)
    dev[0].connect("test", key_mgmt="NONE", scan_freq="2412")
    if dev[0].get_status_field('bssid') != bssid2:
        raise Exception("Unexpected BSS selected")

    est = dev[0].get_bss(bssid)['est_throughput']
    if est != "65000":
        raise Exception("Unexpected BSS0 est_throughput: " + est)

    est = dev[0].get_bss(bssid2)['est_throughput']
    if est != "143402":
        raise Exception("Unexpected BSS1 est_throughput: " + est)

def test_he_capab_parsing(dev, apdev):
    """HE AP and capability parsing"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15"}
    hapd = hostapd.add_ap(apdev[0], params)

    hapd.set("ext_mgmt_frame_handling", "1")
    bssid = hapd.own_addr().replace(':', '')
    addr = "020304050607"
    addr_ = "02:03:04:05:06:07"

    tests = []
    mac_capa = binascii.unhexlify("0178c81a4000")
    phy_capa = binascii.unhexlify("00bfce0000000000000000")
    mcs_nss = binascii.unhexlify("faff")
    payload = mac_capa + phy_capa + 2*mcs_nss
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    phy_capa = binascii.unhexlify("08bfce0000000000000000")
    payload = mac_capa + phy_capa + 4*mcs_nss
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    phy_capa = binascii.unhexlify("10bfce0000000000000000")
    payload = mac_capa + phy_capa + 4*mcs_nss
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    phy_capa = binascii.unhexlify("18bfce0000000000000000")
    payload = mac_capa + phy_capa + 6*mcs_nss
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    # Missing PPE Threshold field
    phy_capa = binascii.unhexlify("00bfce0000008000000000")
    payload = mac_capa + phy_capa + 2*mcs_nss
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, False) ]

    # Truncated PPE Threshold field
    phy_capa = binascii.unhexlify("00bfce0000008000000000")
    payload = mac_capa + phy_capa + 2*mcs_nss + struct.pack('B', 0x79)
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, False) ]

    # Extra field at the end (without PPE Threshold field)
    phy_capa = binascii.unhexlify("00bfce0000000000000000")
    payload = mac_capa + phy_capa + 2*mcs_nss
    payload += struct.pack('B', 0)
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    # Extra field at the end (with PPE Threshold field)
    phy_capa = binascii.unhexlify("00bfce0000008000000000")
    payload = mac_capa + phy_capa + 2*mcs_nss
    payload += binascii.unhexlify("79000000000000")
    payload += struct.pack('B', 0)
    hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
    tests += [ (hdr + payload, True) ]

    ppet = []
    # NSTS=1 (i.e., NSTS field value 0), RU Index Bitmask=0x0
    # --> 3 + 4 + 0 * 6 * 1 = 7 bits --> 1 octet
    ppet += ["00"]
    # NSTS=1 (i.e., NSTS field value 0), RU Index Bitmask=0x1
    # --> 3 + 4 + 1 * 6 * 1 = 13 bits --> 2 octets
    ppet += ["08" + "00"]
    # NSTS=1 (i.e., NSTS field value 0), RU Index Bitmask=0x8
    # --> 3 + 4 + 1 * 6 * 1 = 13 bits --> 2 octets
    ppet += ["40" + "00"]
    # NSTS=2 (i.e., NSTS field value 1), RU Index Bitmask=0xf
    # --> 3 + 4 + 4 * 6 * 2 = 55 bits --> 7 octets
    ppet += ["79" + 6*"00"]
    # NSTS=3 (i.e., NSTS field value 2), RU Index Bitmask=0xf
    # --> 3 + 4 + 4 * 6 * 3 = 79 bits --> 10 octets
    ppet += ["7a" + 9*"00"]
    # NSTS=4 (i.e., NSTS field value 3), RU Index Bitmask=0x5
    # --> 3 + 4 + 2 * 6 * 4 = 55 bits --> 7 octets
    ppet += ["2b" + 6*"00"]
    # NSTS=8 (i.e., NSTS field value 7), RU Index Bitmask=0xf
    # --> 3 + 4 + 4 * 6 * 8 = 199 bits --> 25 octets
    ppet += ["ff" + 24*"00"]
    for p in ppet:
        phy_capa = binascii.unhexlify("00bfce0000008000000000")
        payload = mac_capa + phy_capa + 2*mcs_nss + binascii.unhexlify(p)
        hdr = struct.pack('BBB', 255, 1 + len(payload), 35)
        tests += [ (hdr + payload, True) ]

    for capab, result in tests:
        auth = "b0003a01" + bssid + addr + bssid + '1000000001000000'
        if "OK" not in hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % auth):
            raise Exception("MGMT_RX_PROCESS failed")

        he_capab = binascii.hexlify(capab).decode()

        ies = "00026865" # SSID
        ies += "010802040b160c121824" # Supp Rates
        ies += "32043048606c" # Ext Supp Rates
        ies += "2d1afe131bffff000000000000000000000100000000000000000000" # HT Capab
        ies += "7f0b04004a0201404040000120" # Ext Capab
        ies += he_capab
        ies += "3b155151525354737475767778797a7b7c7d7e7f808182" # Supp Op Classes
        ies += "dd070050f202000100" # WMM

        assoc_req = "00003a01" + bssid + addr + bssid + "2000" + "21040500" + ies
        if "OK" not in hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % assoc_req):
            raise Exception("MGMT_RX_PROCESS failed")

        sta = hapd.get_sta(addr_)
        if result:
            if "[HE]" not in sta['flags']:
                raise Exception("Missing STA flag: HE (HE Capab: %s)" % he_capab)
        else:
            if "[HE]" in sta['flags']:
                raise Exception("Unexpected STA flag: HE (HE Capab: %s)" % he_capab)

        deauth = "c0003a01" + bssid + addr + bssid + "3000" + "0300"
        if "OK" not in hapd.request("MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=%s" % deauth):
            raise Exception("MGMT_RX_PROCESS failed")

        hapd.dump_monitor()
