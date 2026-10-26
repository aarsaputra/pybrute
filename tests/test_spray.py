"""Tests spray mode (offline, tanpa delay nyata — monkeypatch time.sleep)."""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


@pytest.fixture
def spray_mod():
    import spray
    # Matikan delay nyata pada test
    spray.time.sleep = lambda s: None
    return spray


def test_build_spray_batches_order(spray_mod):
    batches = spray_mod.build_spray_batches(["P1", "P2"], ["u1", "u2"], shuffle_users=False)
    # Password luar, user dalam: (u1,P1),(u2,P1),(u1,P2),(u2,P2)
    assert batches == [("u1", "P1"), ("u2", "P1"), ("u1", "P2"), ("u2", "P2")]


def test_build_spray_batches_shuffle(spray_mod):
    batches = spray_mod.build_spray_batches(["X"], ["a", "b", "c"], shuffle_users=True)
    assert len(batches) == 3
    assert all(pwd == "X" for _, pwd in batches)
    assert {u for u, _ in batches} == {"a", "b", "c"}


def test_spray_attack_hit_stops(spray_mod):
    calls = []

    def attempt_fn(user, pwd):
        calls.append((user, pwd))
        return {"success": user == "alice" and pwd == "P2"}

    users = ["alice", "bob"]
    res = spray_mod.spray_attack(
        "http://x", users, ["P1", "P2"], attempt_fn,
        wave_delay=0, inter_delay=0, log=lambda m: None,
    )
    assert res["hits"] and res["hits"][0]["user"] == "alice"
    assert res["attempts"] == len(calls)
    # stop_on_hit=True => tidak semua batch dieksekusi
    assert res["attempts"] < res["total_planned"] + 1


def test_spray_attack_max_per_user(spray_mod):
    calls = []

    def attempt_fn(user, pwd):
        calls.append(user)
        return {"success": False}

    spray_mod.spray_attack(
        "http://x", ["u1"], ["P1", "P2", "P3"], attempt_fn,
        wave_delay=0, inter_delay=0, max_attempts_per_user=2,
        log=lambda m: None,
    )
    assert len([c for c in calls if c == "u1"]) == 2


def test_spray_attack_counts_waves(spray_mod):
    def attempt_fn(u, p):
        return {"success": False}

    res = spray_mod.spray_attack(
        "http://x", ["a"], ["P1", "P2"], attempt_fn,
        wave_delay=0, inter_delay=0, log=lambda m: None,
    )
    assert res["waves"] == 2
    assert res["attempts"] == 2
