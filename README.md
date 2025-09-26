# Skrip Pengecek Respon

Skrip ini menyediakan analisis mendetail dari sebuah URL web, termasuk alamat IP, informasi SSL/TLS, header HTTP, dan peta CDN yang tertaut. Skrip ini juga memiliki opsi untuk mengirim laporan analisis langsung ke obrolan Telegram.

## Prasyarat

- Python 3
- Git

## Instalasi

1.  **Clone repositori ini:**
    ```bash
    git clone <url_repositori>
    cd <direktori_repositori>
    ```
    *(Catatan: Ganti `<url_repositori>` dan `<direktori_repositori>` dengan URL dan nama folder yang sebenarnya)*

2.  **Instal library Python yang dibutuhkan:**
    Skrip ini menggunakan beberapa library Python. Anda dapat menginstalnya menggunakan file `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

## Cara Menjalankan

1.  **Jalankan skrip:**
    Jalankan skrip dari terminal Anda:
    ```bash
    python3 response_checker.py
    ```

2.  **Ikuti menu yang tampil:**
    Skrip akan menampilkan menu dengan opsi berikut:
    - **1. Jalankan cek & tampilkan di terminal:** Meminta Anda memasukkan URL dan menampilkan analisis langsung di terminal.
    - **2. Jalankan cek & kirim ke Telegram:** Mengirimkan analisis ke obrolan Telegram yang telah Anda konfigurasikan.
    - **3. Konfigurasi Bot Telegram:** Untuk mengatur koneksi ke bot Telegram Anda.
    - **4. Keluar:** Menutup skrip.

### Catatan Penting Mengenai URL

Saat diminta, Anda harus memasukkan **URL lengkap**, termasuk skema (`http://` atau `https://`).

-   **Benar:** `https://udemy.com`
-   **Salah:** `udemy.com`

## Integrasi Telegram

Untuk mengirim laporan ke Telegram, Anda harus mengkonfigurasi bot terlebih dahulu:

1.  **Dapatkan kredensial Anda:**
    -   **Token Bot:** Buat bot baru dengan berbicara kepada [BotFather](https://t.me/botfather) di Telegram untuk mendapatkan token unik Anda.
    -   **Chat ID:** Dapatkan ID Obrolan Anda dengan mengirim pesan ke bot seperti [@userinfobot](https://t.me/userinfobot).

2.  **Konfigurasi skrip:**
    -   Jalankan skrip dan pilih opsi `3`.
    -   Masukkan Token Bot dan ID Obrolan Anda saat diminta.
    -   Kredensial akan disimpan dalam file `config.json` di direktori yang sama.

Setelah dikonfigurasi, Anda dapat menggunakan opsi `2` untuk mengirim laporan analisis langsung ke obrolan admin pertama yang terdaftar.

## Mode Bot (Otomatis)

Anda juga bisa menjalankan skrip ini dalam "Mode Bot" yang akan terus berjalan di latar belakang. Dalam mode ini, Anda bisa mengirim URL langsung ke bot Anda kapan saja, dan bot akan membalas dengan hasil analisis secara otomatis (jika Anda memiliki izin).

### Cara Menjalankan Mode Bot

1.  Pastikan Anda sudah melakukan [konfigurasi bot](#integrasi-telegram) terlebih dahulu.
2.  Jalankan skrip dengan menambahkan flag `--bot`:
    ```bash
    python3 response_checker.py --bot
    ```
3.  Skrip akan berjalan di latar belakang. Sekarang Anda bisa mengirimkan URL (contoh: `https://google.com`) ke bot Anda di Telegram, dan bot akan membalas dengan analisisnya.
4.  Untuk menghentikan bot, kembali ke terminal tempat Anda menjalankan skrip dan tekan `Ctrl + C`.

## Fitur Admin (Bot Mode)

Saat berjalan dalam mode bot, admin dapat menggunakan perintah-perintah berikut:

-   `/ping`
    -   Memeriksa apakah bot aktif dan merespon.
-   `/adduser <user_id>`
    -   Memberikan izin kepada pengguna baru untuk menggunakan fitur analisis.
    -   Contoh: `/adduser 123456789`
-   `/deluser <user_id>`
    -   Mencabut izin dari seorang pengguna.
    -   Contoh: `/deluser 123456789`
-   `/listusers`
    -   Menampilkan daftar semua pengguna yang telah diberi izin.
-   `/broadcast <pesan>`
    -   Mengirim pesan ke semua pengguna yang pernah berinteraksi dengan bot.
    -   Contoh: `/broadcast Halo semua, bot sedang dalam maintenance.`
