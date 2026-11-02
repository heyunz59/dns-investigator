"""Frozen constructed mixed inputs, captured before this fix; never probe/model."""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
BEFORE = BASE / 'results/published/v06-final-review/20261102/before.json'


def cases():
    """Fresh copies. Original live tags describe test inputs, not new measurements.

    HTTP/TCP and timeout rows were constructed; DNSSEC material came from the
    controlled v0.5 DS-mismatch ledger. INDETERMINATE is a constructed override.
    No new DNSSEC proof or public-network/model validation is claimed here.
    """
    return {name: row['input'] for name, row in
            json.loads(BEFORE.read_text(encoding='utf-8'))['cases'].items()}
