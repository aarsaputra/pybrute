````markdown
# PyBrute

Tools Dengan Cek data respon Post dan Brute force login

## Disclaimer dan Etika
**Penting:** Alat ini dapat digunakan untuk tujuan pengujian keamanan (penetration testing) tetapi juga dapat disalahgunakan untuk melakukan akses tanpa izin. Anda hanya boleh menjalankan alat ini pada target yang Anda miliki izin eksplisit untuk diuji.

Sebelum menjalankan brute-force, jalankan dengan flag `--confirm-authorized` untuk mengonfirmasi bahwa Anda telah memperoleh izin. Penggunaan tanpa izin dapat melanggar hukum.

## Perbaikan pada versi ini
- Penambahan CLI dengan argparse
- Penanganan request yang lebih aman (timeout, session reuse, exception handling)
- Parsing POST template yang lebih robust
- Flag `--confirm-authorized` wajib untuk mode brute-force

## Contoh penggunaan
1. Analisa form dan dapatkan template POST (contoh):

```bash
python pybrute.py --url "https://example.com/login" --analyze
```

Output akan memberikan saran format `--post "field1=value1&userfield=$user&passfield=$pass"`.

2. Menjalankan brute-force (contoh):

```bash
python pybrute.py --url "https://example.com/login" \
  --post "username=$user&password=$pass" \
  --userlist users.txt --passlist passwords.txt \
  --success "Welcome," --threads 5 --confirm-authorized
```

## Dependensi
- requests
- beautifulsoup4

````
