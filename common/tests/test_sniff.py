#!/usr/bin/env python
"""
common/tests/test_sniff.py

Passive sniffing test: attacker station runs tcpdump on its own
interface for the test window while bot_traffic.py is running, then we
score how much of the synthetic traffic was recoverable in cleartext.

This measures the baseline risk of simply being associated with the
network -- no active attack, just listening.
"""

import os
import time
from common.exposure import score_exposure


def run(attacker_node, duration, out_dir, network_type, iface=None):
    """
    attacker_node: Mininet-WiFi station object for the sniffing node
    duration: seconds to capture (should match bot traffic run length)
    out_dir: results/<network_type> directory
    network_type: 'open' | 'captive' | 'wpa2' (for logging/labeling only)
    iface: override interface name; defaults to '<node>-wlan0'
    """
    iface = iface or f'{attacker_node.name}-wlan0'
    pcap_path = os.path.join(out_dir, 'sniff_capture.pcap')

    attacker_node.cmd(f'tcpdump -i {iface} -w {pcap_path} &')
    # Give tcpdump a moment to attach before traffic starts counting
    time.sleep(2)

    time.sleep(duration)

    # Stop tcpdump cleanly
    attacker_node.cmd('pkill -f "tcpdump -i %s"' % iface)
    time.sleep(1)  # let the pcap flush to disk

    sent_log_path = os.environ.get('BOT_SENT_LOG', os.path.join(out_dir, '..', '..', 'common', 'bot_sent_log.jsonl'))
    # Prefer a copy inside out_dir if the topo script redirected it there
    local_sent_log = os.path.join(out_dir, 'bot_sent_log.jsonl')
    if os.path.exists(local_sent_log):
        sent_log_path = local_sent_log

    result = score_exposure(pcap_path, sent_log_path)
    result.update({
        'network_type': network_type,
        'method': 'passive_sniff',
        'duration_sec': duration,
        'pcap_path': pcap_path,
    })
    return result