# PyBrute

Tools Dengan Cek data respon Post dan Brute force login

## 🚀 Fitur

- ✅ Analisis form login otomatis
- ✅ Brute force dengan multi-threading
- ✅ Mode OTP auto-generate (0000-9999)
- ✅ Auto stop saat berhasil
- ✅ Deteksi sukses otomatis (status code & redirect)
- ✅ Silent / Verbose mode
- ✅ Resume brute force (lanjut dari tengah)
- ✅ Progress bar real-time
- ✅ Delay & timeout konfigurasi

## 📦 Instalasi

### 1. Clone Repository
```bash
git clone https://github.com/aarsaputra/pybrute.git
cd pybrute
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

Atau manual:
```bash
pip install requests beautifulsoup4
```

### 3. Verifikasi Instalasi
```bash
python pybrute.py --help
```

## 📖 Penggunaan

### Mode 1: Analisis Form Login

Untuk menganalisis form login dan mendapatkan template POST:

```bash
python pybrute.py --url http://example.com/login --analyze
```

**Output:**
```
[+] Form #1
    Method: POST
    Action: http://example.com/login
    Input Fields:
        - Name: username, Type: text
        - Name: password, Type: password
    
    [!] Format POST data untuk brute force:
    --post "username=$user&password=$pass"
```

### Mode 2: Brute Force Login (Username & Password)

```bash
python pybrute.py \
  --url http://example.com/login \
  --post "username=$user&password=$pass" \
  --userlist users.txt \
  --passlist passwords.txt \
  --confirm-authorized \
  --threads 10
```

### Mode 3: Brute Force OTP (Auto-Generate)

```bash
python pybrute.py \
  --url http://localhost:4001/auth/otp_challenge \
  --post "otp=$pass" \
  --otp-mode \
  --otp-length 4 \
  --confirm-authorized \
  --threads 10 \
  --delay 0.01
```

**Penjelasan:**
- `--otp-mode`: Aktifkan mode OTP (auto-generate 0000-9999 untuk 4 digit)
- `--otp-length 4`: Panjang OTP (4 digit = 10,000 kombinasi)
- Tidak perlu `--userlist` dan `--passlist` karena auto-generate

### Mode 4: Silent Mode (Hanya Tampilkan Hasil)

```bash
python pybrute.py \
  --url http://example.com/login \
  --post "username=$user&password=$pass" \
  --userlist users.txt \
  --passlist passwords.txt \
  --confirm-authorized \
  --silent
```

### Mode 5: Resume Brute Force

Jika brute force terhenti (Ctrl+C atau error), lanjutkan dengan:

```bash
python pybrute.py \
  --url http://example.com/login \
  --post "username=$user&password=$pass" \
  --userlist users.txt \
  --passlist passwords.txt \
  --confirm-authorized \
  --resume
```

## 🔧 Parameter Lengkap

| Parameter | Deskripsi | Default | Wajib |
|-----------|-----------|---------|-------|
| `--url` | URL target login page | - | ✅ |
| `--analyze` | Mode analisis form | - | ❌ |
| `--post` | Template POST data (gunakan $user dan $pass) | - | ✅ (brute force) |
| `--userlist` | File berisi daftar username | - | ✅ (kecuali OTP mode) |
| `--passlist` | File berisi daftar password | - | ✅ (kecuali OTP mode) |
| `--otp-mode` | Mode OTP auto-generate | - | ❌ |
| `--otp-length` | Panjang OTP digit | 4 | ❌ |
| `--success` | String indikator login berhasil | - | ❌ |
| `--threads` | Jumlah thread concurrent | 5 | ❌ |
| `--timeout` | Request timeout (detik) | 10 | ❌ |
| `--delay` | Delay antar request (detik) | 0.0 | ❌ |
| `--silent` | Silent mode (hanya hasil) | - | ❌ |
| `--verbose` | Verbose mode (detail lengkap) | - | ❌ |
| `--resume` | Lanjutkan dari checkpoint | - | ❌ |
| `--confirm-authorized` | Konfirmasi izin testing | - | ✅ (brute force) |

## 📝 Contoh Kasus Penggunaan

### Contoh 1: Brute Force OTP 6 Digit
```bash
python pybrute.py \
  --url http://target.com/verify \
  --post "otp=$pass" \
  --otp-mode \
  --otp-length 6 \
  --threads 20 \
  --delay 0.05 \
  --confirm-authorized
```

### Contoh 2: Custom Success Detection
```bash
python pybrute.py \
  --url http://example.com/admin \
  --post "user=$user&pass=$pass" \
  --userlist admins.txt \
  --passlist common.txt \
  --success "Dashboard" \
  --confirm-authorized
```

### Contoh 3: Silent Mode dengan Resume
```bash
python pybrute.py \
  --url http://example.com/login \
  --post "username=$user&password=$pass" \
  --userlist users.txt \
  --passlist rockyou.txt \
  --silent \
  --resume \
  --confirm-authorized
```

## ⚠️ Disclaimer dan Etika

**PENTING:** Tool ini hanya untuk:
- ✅ Penetration testing dengan izin tertulis
- ✅ Testing keamanan sistem Anda sendiri
- ✅ Pembelajaran di lingkungan lab/controlled

**JANGAN** gunakan untuk:
- ❌ Sistem yang bukan milik Anda
- ❌ Tanpa izin eksplisit dari pemilik
- ❌ Aktivitas ilegal/cybercrime

Penggunaan tanpa izin dapat melanggar hukum di berbagai negara. Flag `--confirm-authorized` wajib digunakan untuk konfirmasi izin.

## 🛠️ Troubleshooting

### Rate Limiting
Jika mendapat error "Too Many Requests":
```bash
--delay 1.0  # Tambah delay 1 detik
--threads 1  # Kurangi thread
```

### OTP Expired
OTP biasanya expire dalam 30-300 detik. Gunakan:
```bash
--threads 50  # Lebih banyak thread
--delay 0     # Tanpa delay
```

### Resume Tidak Bekerja
Hapus checkpoint file dan mulai ulang:
```bash
rm .pybrute_checkpoint
```

## 📄 License

MIT License - Gunakan dengan bertanggung jawab.

## 👨‍💻 Author

**aarsaputra**

---

**Remember:** With great power comes great responsibility. Use ethically! 🔐
