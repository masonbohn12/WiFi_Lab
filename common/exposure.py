#!/usr/bin/env python
"""
common/exposure.py

Shared scoring helper: given a pcap file and the bot's sent-record log,
determine how many synthetic records were recoverable in cleartext and
how long it took for the first one to appear. Used by every test
module so "exposure" is computed the same way regardless of which
attack produced the capture.
"""

import json
import os
from datetime import datetime


def load_sent_log(log_path):
    """Loads bot_sent_log.jsonl into a list of dicts. Returns [] if the
    bot hasn't produced any records yet (e.g. test run before/without
    bot_traffic.py)."""
    records = []
    if not os.path.exists(log_path):
        return records
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _pcap_raw_text(pcap_path):
    """Reads a pcap and returns a single lowercase string of all
    reassembled payload bytes (best-effort), for simple substring
    matching. Uses scapy; falls back gracefully if a packet can't be
    decoded."""
    try:
        from scapy.all import rdpcap, Raw
    except ImportError:
        raise SystemExit('Missing dependency: pip install scapy --break-system-packages')

    if not os.path.exists(pcap_path):
        return ''

    chunks = []
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return ''

    for pkt in packets:
        if pkt.haslayer(Raw):
            try:
                chunks.append(bytes(pkt[Raw].load).decode('utf-8', errors='ignore').lower())
            except Exception:
                continue
    return '\n'.join(chunks)


def score_exposure(pcap_path, sent_log_path, fields=('email', 'password', 'ssn', 'credit_card', 'record_id')):
    """
    Compares the bot's sent records against what's recoverable in the
    pcap. A record counts as "exposed" if ANY of the given sensitive
    fields appear verbatim in the capture (cleartext).

    Returns a dict matching the project's standard results schema:
        {
          records_sent, records_exposed, exposure_rate,
          time_to_first_exposure_sec, exposed_fields_breakdown
        }
    """
    sent = load_sent_log(sent_log_path)
    raw_text = _pcap_raw_text(pcap_path)

    records_sent = len(sent)
    exposed_count = 0
    first_exposure_time = None
    field_hits = {f: 0 for f in fields}

    for rec in sent:
        exposed_this_record = False
        for field in fields:
            val = rec.get(field)
            if val and str(val).lower() in raw_text:
                field_hits[field] += 1
                exposed_this_record = True
        if exposed_this_record:
            exposed_count += 1
            if first_exposure_time is None and 'logged_at' in rec:
                first_exposure_time = rec['logged_at']

    time_to_first_exposure_sec = None
    if first_exposure_time and sent:
        try:
            first_sent = min(
                datetime.fromisoformat(r['logged_at'].replace('Z', ''))
                for r in sent if 'logged_at' in r
            )
            exposed_at = datetime.fromisoformat(first_exposure_time.replace('Z', ''))
            time_to_first_exposure_sec = (exposed_at - first_sent).total_seconds()
        except Exception:
            time_to_first_exposure_sec = None

    return {
        'records_sent': records_sent,
        'records_exposed': exposed_count,
        'exposure_rate': (exposed_count / records_sent) if records_sent else 0.0,
        'time_to_first_exposure_sec': time_to_first_exposure_sec,
        'exposed_fields_breakdown': field_hits,
    }