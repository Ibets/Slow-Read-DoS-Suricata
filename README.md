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
   ```
   /var/log/suricata/eve.json
   ```
   Gunakan rules dari folder `rule/` dan aktifkan di konfigurasi Suricata.

2. **Jalankan skrip deteksi** di direktori log Suricata:
   ```bash
   cd /var/log/suricata/
   sudo python3 /path/to/live_predict.py
   ```

3. **Uji trafik normal**:
   ```bash
   jmeter -n -t normal.jmx
   ```

4. **Uji serangan Slow Read**:
   ```bash
   ./slowreadattack.sh
   ```

5. **Lihat hasil prediksi di terminal**:
   ```
   [2025-06-29T09:06:53.201127+0700] 192.168.100.6 ➔ 192.168.100.4 | Flow ID: 1619699257938753 | Prediction: SLOWREAD
   [+] Classification saved for Flow ID 1619699257938753. Now removing from tracking.

   ```

---
