"""PyBrute chaining module (v2.1) — integrasi tool pentest lain.

Filosofi: pybrute tidak harus sendirian. Modul ini menjembatani:
1. **ppmap (pentest_proto)** — sebelum brute: cek target rentan Prototype
   Pollution/XSS (bisa jadi jalur akses lebih mudah daripada brute).
2. **OriginHunter** — sebelum brute: pastikan kita mengenali WAF/CDN & origin,
   supaya brute tidak salah menyimpulkan (WAF page = "failed attempt").
3. **Amass/subfinder export** — intake wordlist username dari subdomain-style
   recon (opsional, kalau file tersedia).

Semua integrasi OPT-IN (flag CLI) & graceful-degrade (tool tidak ada = skip,
bukan crash). Tidak menjalankan tool lain secara otomatis tanpa flag.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional

# Kandidat path tool (bisa dioverride env var)
PPMAP_CANDIDATES = [
    os.environ.get("PPMAP_PATH", ""),
    "/home/lota1337/python/pentest_proto",
    os.path.expanduser("~/python/pentest_proto"),
]
ORIGINHUNTER_CANDIDATES = [
    os.environ.get("ORIGINHUNTER_PATH", ""),
    "/home/lota1337/python/OriginHunter",
    os.path.expanduser("~/python/OriginHunter"),
]


def _find_tool(candidates: List[str], marker_file: str) -> Optional[str]:
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, marker_file)):
            return c
    return None


def find_ppmap() -> Optional[str]:
    return _find_tool(PPMAP_CANDIDATES, "ppmap.py")


def find_originhunter() -> Optional[str]:
    for c in ORIGINHUNTER_CANDIDATES:
        if c and os.path.isdir(os.path.join(c, "core")):
            return c
    return None


def preflight_ppmap(target_url: str, timeout: int = 90) -> Dict:
    """Jalankan ppmap --poc (QuickPoC non-destruktif) pada target.

    Return: {'available': bool, 'prototype_pollution': bool, 'output_hash': str}
    Dipakai untuk memutuskan: kalau PP ditemukan, brute mungkin tidak perlu
    (bisa langsung jelajah via PP gadget) & user harus tahu.
    """
    ppmap_dir = find_ppmap()
    if not ppmap_dir:
        return {"available": False, "reason": "ppmap.py tidak ditemukan (set PPMAP_PATH)"}
    python = shutil.which("python3") or "python3"
    try:
        out = subprocess.run(
            [python, "ppmap.py", "--poc", target_url],
            cwd=ppmap_dir, capture_output=True, text=True, timeout=timeout,
        )
        text = (out.stdout or "") + (out.stderr or "")
        is_pp = "CONFIRMED" in text and "Prototype Pollution" in text
        import hashlib
        return {
            "available": True,
            "prototype_pollution": is_pp,
            "output_sha256": hashlib.sha256(text.encode()).hexdigest()[:16],
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "prototype_pollution": False, "reason": "timeout"}
    except Exception as e:
        return {"available": True, "prototype_pollution": False, "reason": str(e)}


def preflight_originhunter(domain: str, timeout: int = 180) -> Dict:
    """Jalankan OriginHunter scan (passive) utk mendeteksi CDN/WAF & origin.

    Kalau domain terlindungi WAF kuat → pybrute harus tahu (banyak 'failure'
    palsu karena WAF interstitial). Kalau origin ter-expose → minta konfirmasi
    user sebelum brute langsung ke origin (bypass WAF).
    """
    oh_dir = find_originhunter()
    if not oh_dir:
        return {"available": False, "reason": "OriginHunter tidak ditemukan (set ORIGINHUNTER_PATH)"}
    python = shutil.which("python3") or "python3"
    try:
        out = subprocess.run(
            [python, "main.py", "scan", domain, "--json"],
            cwd=oh_dir, capture_output=True, text=True, timeout=timeout,
        )
        text = out.stdout or ""
        # Cari JSON object terakhir di stdout
        json_start = text.find("{")
        parsed = {}
        if json_start >= 0:
            try:
                parsed = json.loads(text[json_start:])
            except json.JSONDecodeError:
                parsed = {}
        return {
            "available": True,
            "parsed": bool(parsed),
            "findings_count": len(parsed.get("findings", [])) if isinstance(parsed, dict) else 0,
            "raw_length": len(text),
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "parsed": False, "reason": "timeout"}
    except Exception as e:
        return {"available": True, "parsed": False, "reason": str(e)}


def preflight_summary(target_url: str, do_ppmap: bool = False,
                      do_originhunter: bool = False) -> Dict:
    """Jalankan preflight yang diminta + summary keputusan."""
    result: Dict = {"target": target_url, "ppmap": None, "originhunter": None}
    if do_ppmap:
        result["ppmap"] = preflight_ppmap(target_url)
    if do_originhunter:
        # domain = strip scheme/path
        domain = target_url.split("://", 1)[-1].split("/")[0].split(":")[0]
        result["originhunter"] = preflight_originhunter(domain)

    # Keputusan sederhana (hanya REKOMENDASI, tidak membatalkan brute)
    notes = []
    if result.get("ppmap", {}) and result["ppmap"].get("prototype_pollution"):
        notes.append("Target rentan Prototype Pollution — pertimbangkan jalur PP (mungkin lebih cepat dari brute).")
    if result.get("originhunter", {}) and result["originhunter"].get("parsed"):
        notes.append("OriginHunter menghasilkan data — periksa WAF/CDN sebelum tafsir hasil brute.")
    result["notes"] = notes
    return result
