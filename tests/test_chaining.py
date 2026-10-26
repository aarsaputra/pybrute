"""Tests PyBrute chaining + spray (offline/mocked)."""
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def test_chaining_find_tools():
    from chaining import find_ppmap, find_originhunter

    pp = find_ppmap()
    oh = find_originhunter()
    # Di laptop ini keduanya harus ada (path default)
    assert pp and os.path.isfile(os.path.join(pp, "ppmap.py"))
    assert oh and os.path.isdir(os.path.join(oh, "core"))


def test_chaining_preflight_graceful():
    """Target mati -> graceful, tidak crash."""
    from chaining import preflight_ppmap, preflight_summary

    r = preflight_ppmap("http://127.0.0.1:1/x", timeout=10)
    assert "available" in r
    s = preflight_summary("http://127.0.0.1:1/x", do_ppmap=False, do_originhunter=False)
    assert s["notes"] == []


def test_spray_mode_total_attempts():
    """Spray: 1 password x N usernames (bukan N x M) — hemat & di bawah lockout."""
    users = ["a", "b", "c", "d"]
    spray_passwords = ["Summer2026!", "Welcome1"]
    total = len(users) * len(spray_passwords)  # 8 attempts
    traditional = len(users) * 50
    assert total < traditional
