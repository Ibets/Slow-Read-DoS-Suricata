# Deteksi Serangan Slow Read

Repositori ini berisi implementasi sistem deteksi serangan **Slow Read DoS** menggunakan **Suricata IDS** dan model **Random Forest**.  
Sistem membaca log Suricata secara *real-time* dan memprediksi apakah koneksi bersifat **Normal** atau **Serangan Slow Read**.

---

## Struktur Repositori

- **rf_model.pkl** — Model Random Forest hasil pelatihan
- **live_predict.py** — Skrip pemantauan log Suricata & prediksi
- **datatrain/** — Dataset pelatihan
- **datatest/** — Dataset pengujian
- **rule/** — Rules Suricata untuk deteksi Slow Read
- **normal.jmx** — Konfigurasi Apache JMeter untuk trafik normal
- **slowreadattack.sh** — Skrip simulasi serangan Slow Read

---

## Cara Menjalankan

1. **Jalankan Suricata** dan pastikan log tersimpan di:
