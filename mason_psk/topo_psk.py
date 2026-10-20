#!/usr/bin/env python
"""
member_D_shared_psk/topo_shared_psk.py

Fourth lab: same WPA2 encryption as member_C's lab, but modeling a
network where the passphrase is handed out to many people (an office,
a shared household, a small business) -- the attacker station here is
built as a LEGITIMATE client that knows the passphrase, same as every
other station. The question this lab answers is different from the
WPA2 lab: not "can an outsider get in," but "once someone has the
password, what can they see of OTHER people's traffic."

Run:
    sudo python3 topo_shared_psk.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mininet.log import setLogLevel, info
from common.base_topo import build_base_net, get_logger, write_result, teardown, run_cli

NETWORK_TYPE = 'shared_psk'

# Same encryption as the WPA2 lab -- the variable under test here is
# NOT the encryption type, it's whether a credentialed insider can
# decrypt other clients' traffic. Keep ssid/passwd distinct from
# member_C's lab just so captures/logs are never ambiguous about which
# lab they came from.
AP_KWARGS = dict(
    ssid='shared-psk-test-network',
    mode='g',
    channel='1',
    encrypt='wpa2',
    passwd='OfficeWifi2026!',   # synthetic passphrase, "known to everyone"
)

BOT_TRAFFIC_DURATION_SEC = 300  # keep identical to the other three labs
PSK_CAPTURE_DURATION_SEC = 120  # separate window for the decrypt test;
                                 # needs to be long enough to catch another
                                 # client's handshake -- see notes below


def main():
    setLogLevel('info')
    logger, out_dir = get_logger(NETWORK_TYPE)
    logger.info(f'Starting {NETWORK_TYPE} lab topology')

    net, ap1, stations, bot, attacker = build_base_net(ap_kwargs=AP_KWARGS)

    try:
        info('*** Testing connectivity\n')
        net.pingAll()

        info('*** Starting bot traffic (synthetic PII / file sharing)\n')
        bot.cmd(
            f'python3 {os.path.join(os.path.dirname(__file__), "..", "common", "bot_traffic.py")} '
            f'{ap1.IP() if hasattr(ap1, "IP") else "10.0.0.1"} > '
            f'{out_dir}/bot_traffic.log 2>&1 &'
        )
        logger.info('Bot traffic started')

        from common.tests import test_sniff, test_evil_twin, test_mitm, test_captive_bypass, test_psk_decrypt

        # Standard four tests, same as every other lab, for apples-to-
        # apples comparison in the final results table.
        logger.info('Running sniffing test (attacker WITHOUT psk, baseline)')
        sniff_result = test_sniff.run(attacker, duration=BOT_TRAFFIC_DURATION_SEC,
                                       out_dir=out_dir, network_type=NETWORK_TYPE)
        write_result(out_dir, 'sniff', sniff_result)

        logger.info('Running evil twin test')
        et_result = test_evil_twin.run(net, ap1, stations, out_dir=out_dir,
                                        network_type=NETWORK_TYPE, ap_kwargs=AP_KWARGS)
        write_result(out_dir, 'evil_twin', et_result)

        logger.info('Running MITM (ARP spoof) test')
        mitm_result = test_mitm.run(attacker, target=stations[0], gateway_ip='10.0.0.1',
                                     duration=BOT_TRAFFIC_DURATION_SEC,
                                     out_dir=out_dir, network_type=NETWORK_TYPE)
        write_result(out_dir, 'mitm', mitm_result)

        logger.info('Running captive portal bypass test (not applicable)')
        captive_result = test_captive_bypass.run(attacker, network_type=NETWORK_TYPE,
                                                   out_dir=out_dir, applicable=False)
        write_result(out_dir, 'captive_bypass', captive_result)

        # The fifth, lab-specific test: attacker associates WITH the
        # known shared PSK (same as every other client) and tries to
        # decrypt another client's traffic from the capture.
        logger.info('Associating attacker to AP using the shared PSK')
        attacker_iface = f'{attacker.name}-wlan0'
        attacker.cmd(
            f'wpa_supplicant -B -i {attacker_iface} -c <(wpa_passphrase '
            f'"{AP_KWARGS["ssid"]}" "{AP_KWARGS["passwd"]}")'
        )

        logger.info('Running shared-PSK decryption test')
        psk_result = test_psk_decrypt.run(
            attacker, out_dir=out_dir, network_type=NETWORK_TYPE,
            ssid=AP_KWARGS['ssid'], passphrase=AP_KWARGS['passwd'],
            duration=PSK_CAPTURE_DURATION_SEC,
        )
        write_result(out_dir, 'psk_decrypt', psk_result)

        logger.info(f'All tests complete. Results in {out_dir}/results.jsonl')

    finally:
        if '--auto' not in sys.argv:
            run_cli(net)
        teardown(net)


if __name__ == '__main__':
    main()