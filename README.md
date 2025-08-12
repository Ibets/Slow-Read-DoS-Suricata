Deteksi Serangan Slow Read

Repositori ini berisi:

rf_model.pkl : Model Random Forest
live_predict.py : Skrip pemantauan log Suricata
datatrain/ : Data pelatihan
datatest/ : Data uji prediksi menggunakan skrip dan model

Cara Menjalankan

Jalankan Suricata dan lakukan konfigurasi . gunakan rules pada rule di reposiitory dan konfigurasikan pada config suricata
Jalankan Script pada direktori /var/log/suricata/ dengan perintah ' sudo python3 live_predict.py'

Jalankan Serangan dengan menggunakan perintah 'slowreadattack.sh/'
Jalankan Trafik Normal dengan menggunakan Jmeter denggan konfigurasi 'normal.jmx'

Skrip akan membaca log dari /var/log/suricata/eve.json dan memprediksi apakah koneksi merupakan serangan Slow Read atau normal menggunakan model rf_model.pkl.

Hasil prediksi akan ditampilkan di terminal.
