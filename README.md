# PyBrute Login - Brute Force & Analyzer  

PyBrute Login adalah tools multifungsi berbasis Python untuk:  
1. **Analisis parameter form login (POST request analyzer).**  
2. **Brute force login** menggunakan wordlist username & password.  

Cocok digunakan untuk **pembelajaran penetration testing**, CTF, atau eksplorasi keamanan web (hanya untuk tujuan legal!).  

---

## Fitur
- Analisis otomatis form login (menampilkan method, action, input field).  
- Ekstrak format `POST data` secara cepat untuk keperluan brute force.  
- Brute force login dengan metode:  
  - `threading` → menjalankan percobaan login per thread.  
  - `concurrent` → menggunakan `ThreadPoolExecutor` (lebih cepat & efisien).  
- Menampilkan progres percobaan login dalam persentase.  

---

## Instalasi  

Pastikan sudah install **Python 3.7+**.  

Clone repository:  
```bash
git clone https://github.com/aarsaputra/pybrute.git
cd repo
```
Install library yang dibutuhkan:
```bash
pip install requests beautifulsoup4
```
#Cara Pakai
**1. Analisis Parameter POST**

Untuk menganalisis form login di suatu halaman:
```bash
python pybrute.py analyze -u http://target.com/login
```
Output yang ditampilkan:
Method (GET/POST).
Action (endpoint tujuan).
Input field (name, type, default value).
Contoh format POST data untuk brute force.

**2. Brute Force Login**

Jalankan brute force dengan wordlist username & password:
```bash
python pybrute.py bruteforce \
    -H http://target.com/login \
    -u user.txt \
    -p pass.txt \
    --post "log=$user&pwd=$pass" \
    --respon "Welcome" \
    --method concurrent
```
Parameter:

-H → URL target login.

-u → file berisi daftar username.

-p → file berisi daftar password.

--post → format data POST ($user untuk username, $pass untuk password).

--respon → teks respons yang menandakan login berhasil.

--method → threading atau concurrent (default: concurrent).


---


