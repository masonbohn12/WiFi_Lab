#!/usr/bin/env python
"""
common/tests/test_captive_bypass.py

Captive portal bypass test: only fully applicable to the captive
portal lab. Open and WPA2 labs still call this (for a complete,
identical results.jsonl schema across all three networks) but pass
applicable=False, which records a clean "not applicable" result
instead of attempting the bypass techniques.

For the captive lab itself, this tests three common bypass vectors:
  1. DNS tunneling before the portal redirect engages
  2. Reaching non-HTTP services the portal's redirect rule doesn't cover
  3. MAC spoofing an already-authorized client's address
"""

import os
import time


def run(attacker_node, network_type, out_dir, applicable=True,
        authorized_mac=None, gateway_ip='10.0.0.1'):
    """
    attacker_node: Mininet-WiFi station object attempting the bypass
    network_type: 'open' | 'captive' | 'wpa2'
    out_dir: results/<network_type> directory
    applicable: False for open/wpa2 labs where no portal exists
    authorized_mac: a known-authorized client's MAC, for the spoof test
                     (captive lab only; pass this in once a client has
                     completed portal auth during the run)
    gateway_ip: portal gateway IP
    """
    if not applicable:
        return {
            'network_type': network_type,
            'method': 'captive_bypass',
            'applicable': False,
            'notes': f'No captive portal present on {network_type} network; test skipped by design.',
        }

    iface = f'{attacker_node.name}-wlan0'
    findings = {}

    # 1. DNS tunneling / pre-auth DNS reachability
    dns_test = attacker_node.cmd(f'dig +short +time=2 example.com @{gateway_ip}')
    findings['dns_reachable_pre_auth'] = bool(dns_test.strip())

    # 2. Non-HTTP service reachability (portal typically only redirects :80/:443)
    #    e.g. check if attacker can reach an arbitrary TCP port directly
    nc_test = attacker_node.cmd(f'timeout 2 nc -zv {gateway_ip} 22 2>&1')
    findings['non_http_port_reachable'] = 'succeeded' in nc_test.lower() or 'open' in nc_test.lower()

    # 3. MAC spoofing an authorized client
    mac_spoof_result = None
    if authorized_mac:
        attacker_node.cmd(f'ip link set {iface} down')
        attacker_node.cmd(f'macchanger -m {authorized_mac} {iface}')
        attacker_node.cmd(f'ip link set {iface} up')
        time.sleep(2)
        post_spoof_test = attacker_node.cmd(f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 3 http://1.1.1.1')
        mac_spoof_result = post_spoof_test.strip()
    findings['mac_spoof_http_status'] = mac_spoof_result

    bypass_achieved = (
        findings['dns_reachable_pre_auth']
        or findings['non_http_port_reachable']
        or (mac_spoof_result == '200')
    )

    return {
        'network_type': network_type,
        'method': 'captive_bypass',
        'applicable': True,
        'findings': findings,
        'bypass_achieved': bypass_achieved,
        'notes': (
            'bypass_achieved=True indicates at least one vector (DNS tunnel, '
            'non-HTTP port, or MAC spoof) allowed network access without '
            'completing portal authentication.'
        ),
    }