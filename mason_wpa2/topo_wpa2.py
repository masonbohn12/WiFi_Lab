#!/usr/bin/env python
"""
member_C_wpa2/topo_wpa2.py

WPA2-Personal lab. The ONLY thing that should differ from the other two
team members' scripts is the ap_kwargs block below — everything else
(station count, bot traffic, test scripts, logging/results schema)
comes from common/base_topo.py so the three labs stay comparable.

Run:
    sudo python3 topo_wpa2.py
"""

import sys
import os
import time

# Make the shared `common` package importable regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mininet.log import setLogLevel, info
from common.base_topo import build_base_net, get_logger, write_result, teardown, run_cli

NETWORK_TYPE = 'wpa2'

# The only network-specific config in this file
AP_KWARGS = dict(
    ssid='wpa2-test-network',
    mode='g',
    channel='1',
    encrypt='wpa2',
    passwd='TestPass123!',   # synthetic test passphrase, not reused anywhere real
)

# Agreed-upon constant across all three labs (set this the same in every
# member's script before running — do not change independently)
BOT_TRAFFIC_DURATION_SEC = 300  # 5 minutes


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

        # --- Run the four standard tests ---
        # Each test script is shared/common and writes into out_dir via
        # write_result(). They are imported here rather than hardcoded so
        # the attack logic can't drift between the three member scripts.
        from common.tests import test_sniff, test_evil_twin, test_mitm, test_captive_bypass

        logger.info('Running sniffing test')
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

        logger.info('Running captive portal bypass test (expected: N/A for WPA2)')
        captive_result = test_captive_bypass.run(attacker, network_type=NETWORK_TYPE,
                                                   out_dir=out_dir, applicable=False)
        write_result(out_dir, 'captive_bypass', captive_result)

        logger.info(f'All tests complete. Results in {out_dir}/results.jsonl')

    finally:
        # Drop to CLI for manual inspection before teardown if run interactively
        if '--auto' not in sys.argv:
            run_cli(net)
        teardown(net)


if __name__ == '__main__':
    main()