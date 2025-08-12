Deteksi Serangan Slow Read
Repositori ini berisi implementasi sistem deteksi serangan Slow Read DoS menggunakan Suricata IDS dan model Random Forest. Sistem membaca log Suricata secara real-time dan memprediksi apakah koneksi bersifat Normal atau Serangan Slow Read.

Struktur Repositori
rf_model.pkl — Model Random Forest hasil pelatihan

live_predict.py — Skrip pemantauan log Suricata & prediksi

datatrain/ — Dataset pelatihan

datatest/ — Dataset pengujian

rule/ — Rules Suricata untuk deteksi Slow Read

normal.jmx — Konfigurasi Apache JMeter untuk trafik normal

slowreadattack.sh — Skrip simulasi serangan Slow Read

Cara Menjalankan
Jalankan Suricata dan pastikan log tersimpan di:

swift
Copy
Edit
/var/log/suricata/eve.json
Gunakan rules dari folder rule/ dan aktifkan di konfigurasi Suricata.

Jalankan skrip deteksi di direktori log Suricata:

bash
Copy
Edit
cd /var/log/suricata/
sudo python3 /path/to/live_predict.py
Uji trafik normal:

bash
Copy
Edit
jmeter -n -t normal.jmx
Uji serangan Slow Read:

bash
Copy
Edit
./slowreadattack.sh
Lihat hasil prediksi di terminal:

css
Copy
Edit
NORMAL
SLOW READ ATTACK
Kalau mau, aku bisa buatkan versi skripsi yang ada diagram alur prosesnya supaya langsung masuk di lampiran skripsi.
Mau aku buatkan juga?








You said:
buat yangg bisa di copy paste langsung


ChatGPT said:
Oke, ini versi README sederhana yang bisa langsung kamu copy-paste ke file README.md skripsimu.

Deteksi Serangan Slow Read
Repositori ini berisi implementasi sistem deteksi serangan Slow Read DoS menggunakan Suricata IDS dan model Random Forest.
Sistem membaca log Suricata secara real-time dan memprediksi apakah koneksi bersifat Normal atau Serangan Slow Read.

Struktur Repositori
rf_model.pkl — Model Random Forest hasil pelatihan

live_predict.py — Skrip pemantauan log Suricata & prediksi

datatrain/ — Dataset pelatihan

datatest/ — Dataset pengujian

rule/ — Rules Suricata untuk deteksi Slow Read

normal.jmx — Konfigurasi Apache JMeter untuk trafik normal

slowreadattack.sh — Skrip simulasi serangan Slow Read

Cara Menjalankan
Jalankan Suricata dan pastikan log tersimpan di:

swift
Copy
Edit
/var/log/suricata/eve.json
Gunakan rules dari folder rule/ dan aktifkan di konfigurasi Suricata.

Jalankan skrip deteksi di direktori log Suricata:

bash
Copy
Edit
cd /var/log/suricata/
sudo python3 /path/to/live_predict.py
Uji trafik normal:

bash
Copy
Edit
jmeter -n -t normal.jmx
Uji serangan Slow Read:

bash
Copy
Edit
./slowreadattack.sh
Lihat hasil prediksi di terminal:

css
Copy
Edit
NORMAL
SLOW READ ATTACK
