
## Şeytani İkiz (Evil Twin) Nedir?

Şeytani İkiz (Evil Twin) saldırısı, bir saldırganın mevcut bir Wi-Fi ağının sahte bir kopyasını oluşturması ve kullanıcıları bu ağa bağlanmaya kandırmasıyla gerçekleşen bir saldırı türüdür.
Bu saldırı, özellikle halka açık Wi-Fi ağlarında (örneğin kafeler, oteller, havaalanları) yaygındır ve Man-in-the-Middle (MitM) saldırılarının bir parçası olarak kullanılır.

### Evil Twin Saldırısı Nasıl Çalışır?

- 1️⃣ Saldırgan, mevcut bir Wi-Fi ağının adını (SSID) ve şifreleme yöntemini kopyalar.
- 2️⃣ Kurbanlar, bu sahte ağa bağlanırken fark etmezler ve giriş bilgilerini girerler.
- 3️⃣ Saldırgan, kullanıcının trafiğini izleyebilir, oturum çerezlerini çalabilir veya kimlik bilgilerini ele geçirebilir.

## Airgeddon Nedir ve Nasıl Kullanılır?


## Airgeddon, kablosuz ağları test etmek için kullanılan çok amaçlı bir pentest aracıdır. Özellikle Wi-Fi şifre kırma, Evil Twin saldırıları ve WPA/WPA2 saldırıları için kullanılır.


### Kurulum

Kali Linux’ta yüklü değilse şu komutlarla yükleyebilirsin:
```bash
```
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
```bash
bash airgeddon.sh
```
> Not: Kullanım için Monitor Mode (Monitör Modu) açmalısın.
```bash
airmon-ng start wlan0
```

### Temel Kullanım Adımları

- 1️⃣ Aracı Başlat
```bash
bash airgeddon.sh
```
- 2️⃣ Kablosuz Ağ Arayüzünü Seç
Kullanılacak Wi-Fi adaptörünü seç.
Monitor Mode aktif olmalı.
- 3️⃣ Hedef Ağları Tara
- "Scan for targets" seçeneği ile yakındaki Wi-Fi ağlarını listele.
- 4️⃣ Saldırı Yöntemini Seç
Handshake Yakalama → WPA/WPA2 şifre kırma için.
Evil Twin Attack → Sahte Wi-Fi ile parola toplama.
Deauth Attack → Cihazları ağdan düşürmek.
- 5️⃣ Handshake Yakalama ve Şifre Kırma
Deauth Saldırısı Başlat (aireplay-ng -0 10 -a [BSSID] wlan0mon)
Handshake Dosyasını Kaydet
Hashcat veya John the Ripper ile Şifre Kırma
```bash
aircrack-ng -w wordlist.txt -b [BSSID] captured_handshake.cap
```

## 📌 Airgeddon ile Evil Twin Attack (Sahte Wi-Fi)

Bu yöntem, kullanıcıları sahte bir erişim noktasına bağlayarak şifrelerini çalmaya dayanır.
- "Evil Twin Attack" seçeneğini seç.
Hedef ağı belirle ve sahte Wi-Fi oluştur.
Fake Captive Portal ayarla (Kurban giriş yapınca şifresi kaydedilir).
Bağlanan cihazların loglarını izle.

## 📌 Airgeddon ile Evil Twin Saldırısı Adım Adım


## 💀 Evil Twin, hedefin sahte bir Wi-Fi ağına bağlanmasını sağlayarak şifre veya oturum bilgilerini ele geçirme saldırısıdır. Airgeddon, bu saldırıyı otomatikleştiren güçlü bir araçtır.


## 🔹 1️⃣ Airgeddon Kurulumu


## 📌 Airgeddon’u sistemine kur ve çalıştır.

Kali Linux veya Parrot OS kullanıyorsan:
```bash
```
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
chmod +x airgeddon.sh
./airgeddon.sh

### Başlatınca, root yetkisi isteyecektir.

**🔹 2️⃣ Kablosuz Ağ Kartını Monitör Moduna Al**


## 📌 Airgeddon, Wi-Fi kartını monitör moduna geçirmeden çalışmaz.


## Airgeddon içinden "Enable Monitor Mode" seçeneğini kullanabilir veya manuel yapabilirsin:

```bash
airmon-ng start wlan0
```

### Eğer kartın wlan0mon gibi farklı bir isim aldıysa, bunu kullanmalısın.

**🔹 3️⃣ Hedef Ağın Seçilmesi**


## 📌 Airgeddon arayüzünde hedef Wi-Fi ağını tarayıp seç.

- "Select Target" seçeneğini kullan.
Etrafındaki tüm Wi-Fi ağlarını listele.
Hedef Wi-Fi’yi seç (örneğin, bir kafe veya şirket ağı).
**🔹 4️⃣ Evil Twin Erişim Noktası Oluştur**


### Hedef ağa aynı isimde bir sahte Wi-Fi ağı kur.

Fake AP (Access Point) oluştur.
Ağ ismini (SSID) hedef ağ ile aynı yap.
Gerçek ağa bağlı istemcileri sahte ağa çekmek için "Deauthentication Attack" başlat.
**🔹 5️⃣ Deauthentication (Bağlı Kullanıcıları Düşürme)**


### Gerçek Wi-Fi ağına bağlı kullanıcıları düşürerek sahte ağa bağlanmaya zorla.

- "Deauth Attack" başlat.
Gerçek ağdaki kullanıcıları tek tek at.
Mağdurlar, sahte Wi-Fi ağına bağlanmak zorunda kalacak.
```bash
aireplay-ng --deauth 100 -a [Hedef MAC] wlan0mon
```
**🔹 6️⃣ Sahte Giriş Sayfası (Captive Portal) Aç**


### Bağlanan kullanıcıdan şifre almak için bir sahte giriş sayfası göster.


## Airgeddon üzerinden sahte giriş portalı başlat.

Gerçek Wi-Fi servis sağlayıcısının giriş sayfasını taklit et (örneğin, "Kahveci Wi-Fi Girişi").
Bağlanan kullanıcı, Wi-Fi şifresini girmeye çalışacak.

### Sonuç: Kullanıcı Wi-Fi şifresini girince, bilgiler log dosyasına kaydedilir!

**🔹 7️⃣ Yakalanan Şifreyi Görüntüle**


### Sahte giriş ekranında girilen şifreyi kontrol et.

```bash
```
cat /var/www/html/captured.txt

## Eğer Airgeddon içinden loglara bakmak istiyorsan:

- "View Captured Data" seçeneğini seç.
Şifreyi gör!

## 📌 SONUÇ

**✅ Bu saldırı, saldırganın hedefin Wi-Fi şifresini öğrenmesini sağlar.**

**✅ Ağ güvenliği testleri ve sızma testlerinde kullanılır.**

**✅ Kurban, gerçek Wi-Fi olduğunu sanarak sahte ağa bağlanır ve giriş bilgilerini girer.**


## 📌 Nasıl Korunabilirim?

**🚀 WPA3/WPA2-PSK kullan**

**🚀 Ağını düzenli kontrol et (Bağlı cihazları izle)**

**🚀 Ortadaki Adam (MITM) saldırılarından korunmak için VPN kullan**

**🚀 Sahte Wi-Fi ağlarına bağlanma!**
