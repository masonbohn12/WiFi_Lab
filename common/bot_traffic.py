#!/usr/bin/env python
"""
common/bot_traffic.py

Generates synthetic "realistic" traffic as the constant controlled
variable across all three labs: fake file transfers, fake login/PII
POSTs. ALL data is synthetic/fabricated via Faker -- never real
credentials, real SSNs, or real personal data of any kind. This is
intentional: the project measures exposure of realistic-*format* data,
not real information, which keeps the lab safe to run and share.

DO NOT EDIT per-member. This file must be byte-identical across the
three labs for the comparison to be valid.

Usage:
    python3 bot_traffic.py <target_ip> [--portal-url URL] [--duration SEC]

Each record sent is tagged with a unique record_id and logged to
bot_sent_log.jsonl in the current working directory (each member's
topo script redirects stdout/this log into their own results/ dir).
This is what the sniff/MITM test scripts grep against to compute
exposure rate.
"""

import sys
import os
import json
import time
import random
import argparse
import uuid
from datetime import datetime

try:
    from faker import Faker
except ImportError:
    sys.exit('Missing dependency: pip install faker --break-system-packages')

try:
    import requests
except ImportError:
    sys.exit('Missing dependency: pip install requests --break-system-packages')

fake = Faker()

LOG_PATH = os.environ.get('BOT_SENT_LOG', 'bot_sent_log.jsonl')
SAMPLE_FILE_DIR = os.path.join(os.path.dirname(__file__), 'fake_data', 'files')


def log_sent_record(record):
    """Append a record of what the bot actually sent, for later
    cross-referencing against sniffed/captured traffic."""
    record['logged_at'] = datetime.utcnow().isoformat() + 'Z'
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(record) + '\n')


def make_synthetic_record():
    """One fabricated 'user' record. Formats resemble real PII/credentials
    but every value is generated, not sourced from a real person."""
    return {
        'record_id': str(uuid.uuid4()),
        'name': fake.name(),
        'email': fake.email(),
        'password': fake.password(length=12, special_chars=True),
        'ssn': fake.ssn(),                      # synthetic-format only
        'credit_card': fake.credit_card_number(),  # test/sandbox-style number
        'address': fake.address().replace('\n', ', '),
    }


def ensure_sample_file():
    """Create a small dummy file to simulate file-sharing traffic, if one
    doesn't already exist."""
    os.makedirs(SAMPLE_FILE_DIR, exist_ok=True)
    path = os.path.join(SAMPLE_FILE_DIR, 'sample_doc.txt')
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write('Synthetic test document for WiFi risk assessment lab.\n')
            f.write(f'Generated: {datetime.utcnow().isoformat()}Z\n')
    return path


def simulate_login_post(target_url, record, timeout=3):
    """Simulate a login/PII form submission. Logs what was sent and
    whether the send itself succeeded (not whether it was intercepted --
    interception is measured separately by the sniff/MITM test scripts)."""
    payload = {
        'record_id': record['record_id'],
        'email': record['email'],
        'password': record['password'],
        'ssn': record['ssn'],
        'credit_card': record['credit_card'],
    }
    try:
        requests.post(target_url, data=payload, timeout=timeout, verify=False)
        sent_ok = True
    except Exception as e:
        sent_ok = False
    log_sent_record({**record, 'channel': 'http_post', 'target': target_url, 'sent_ok': sent_ok})


def simulate_file_share(target_ip, filepath):
    """Simulate a file transfer over the network segment (plain HTTP PUT
    to a simple receiver, or scp if one is set up). Falls back to a
    best-effort HTTP PUT since that's easiest to sniff and interpret."""
    url = f'http://{target_ip}:8000/upload'
    try:
        with open(filepath, 'rb') as f:
            requests.post(url, files={'file': f}, timeout=3, verify=False)
        sent_ok = True
    except Exception:
        sent_ok = False
    log_sent_record({
        'record_id': str(uuid.uuid4()),
        'channel': 'file_share',
        'filename': os.path.basename(filepath),
        'target': url,
        'sent_ok': sent_ok,
    })


def run_bot_loop(target_ip, portal_url=None, duration=None, interval=(10, 20)):
    """Main loop. Runs forever unless `duration` (seconds) is given, in
    which case it stops after that long -- use this for fixed-length
    test windows so all three labs get an identical traffic volume."""
    sample_file = ensure_sample_file()
    start = time.time()

    login_target = portal_url if portal_url else f'http://{target_ip}/login'

    while True:
        record = make_synthetic_record()
        simulate_login_post(login_target, record)
        simulate_file_share(target_ip, sample_file)

        if duration is not None and (time.time() - start) >= duration:
            break
        time.sleep(random.uniform(*interval))


def main():
    parser = argparse.ArgumentParser(description='Synthetic bot traffic generator for WiFi risk lab')
    parser.add_argument('target_ip', help='Gateway / server IP to send traffic toward')
    parser.add_argument('--portal-url', default=None,
                         help='Captive portal login URL, if applicable to this lab')
    parser.add_argument('--duration', type=int, default=None,
                         help='Stop after N seconds (default: run until killed)')
    args = parser.parse_args()

    run_bot_loop(args.target_ip, portal_url=args.portal_url, duration=args.duration)


if __name__ == '__main__':
    main()