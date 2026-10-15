#!/usr/bin/env python
"""
common/tests/test_evil_twin.py

Evil twin / rogue AP test: stands up a second AP with the same SSID
(different BSSID/channel), checks which stations associate to the
rogue AP instead of the legitimate one, and captures traffic on the
rogue AP's interface the same way test_sniff does.

For WPA2: a true evil twin without the passphrase can't complete a
real association, so this test instead measures a more realistic
risk -- whether a client *attempts* to associate /probes for the SSID
in a way that would be useful for an attacker running a credential-
harvesting captive portal clone. Record that distinction in `notes`.
"""

import os
import time
from common.exposure import score_exposure


def run(net, legit_ap, stations, out_dir, network_type, ap_kwargs, capture_duration=60):
    """
    net: the running Mininet_wifi instance
    legit_ap: the original AP node
    stations: list of client station nodes
    out_dir: results/<network_type> directory
    network_type: 'open' | 'captive' | 'wpa2'
    ap_kwargs: the SAME ssid as the legit AP, used to build the rogue AP
    capture_duration: seconds to run the rogue AP + capture window
    """
    rogue_kwargs = dict(ap_kwargs)
    rogue_kwargs['channel'] = '6' if ap_kwargs.get('channel') != '6' else '11'

    is_wpa2 = ap_kwargs.get('encrypt') == 'wpa2'
    if is_wpa2:
        # Rogue AP broadcasts the same SSID but WITHOUT the passphrase,
        # simulating an attacker who doesn't know the real key. Clients
        # should fail to associate -- that failure IS the result for WPA2.
        rogue_kwargs.pop('passwd', None)
        rogue_kwargs['encrypt'] = None

    rogue_ap = net.addAccessPoint('ap_rogue', **rogue_kwargs)
    net.configureWifiNodes()
    rogue_ap.start([])

    time.sleep(3)  # let beacons go out

    # Check association: in Mininet-WiFi, iw dev <iface> link on a
    # station reports which BSSID it's connected to.
    associations = {}
    for sta in stations:
        iface = f'{sta.name}-wlan0'
        link_info = sta.cmd(f'iw dev {iface} link')
        associations[sta.name] = link_info.strip()

    pcap_path = os.path.join(out_dir, 'evil_twin_capture.pcap')
    rogue_iface = 'ap_rogue-wlan1'
    rogue_ap.cmd(f'tcpdump -i {rogue_iface} -w {pcap_path} &')
    time.sleep(capture_duration)
    rogue_ap.cmd(f'pkill -f "tcpdump -i {rogue_iface}"')
    time.sleep(1)

    local_sent_log = os.path.join(out_dir, 'bot_sent_log.jsonl')
    exposure = score_exposure(pcap_path, local_sent_log) if os.path.exists(local_sent_log) else {
        'records_sent': 0, 'records_exposed': 0, 'exposure_rate': 0.0,
        'time_to_first_exposure_sec': None, 'exposed_fields_breakdown': {}
    }

    associated_to_rogue = sum(
        1 for info in associations.values() if 'ap_rogue' in info.lower() or 'Not connected' not in info
    )

    result = {
        'network_type': network_type,
        'method': 'evil_twin',
        'rogue_ssid': rogue_kwargs.get('ssid'),
        'rogue_encrypt': rogue_kwargs.get('encrypt'),
        'station_associations': associations,
        'capture_duration_sec': capture_duration,
        'pcap_path': pcap_path,
        'notes': (
            'WPA2 rogue AP lacked the passphrase; evaluate station_associations '
            'to confirm clients correctly refused to join.' if is_wpa2 else
            'Open/captive rogue AP requires no credentials; evaluate whether '
            'clients silently associated to it over the legitimate AP.'
        ),
    }
    result.update(exposure)
    return result