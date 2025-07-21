Deteksi Serangan Slow Read

Repositori ini berisi:

rf_model.pkl : Model Random Forest
live_predict.py : Skrip pemantauan log Suricata
datatrain/ : Data pelatihan
datatest/ : Data uji prediksi menggunakan skrip dan model

Cara Menjalankan

Jalankan Suricata
Jalankan skrip prediksi:

Skrip akan membaca log dari /var/log/suricata/eve.json dan memprediksi apakah koneksi merupakan serangan Slow Read atau normal menggunakan model rf_model.pkl.

Hasil prediksi akan ditampilkan di terminal.
