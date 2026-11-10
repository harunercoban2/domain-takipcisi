# Domain Takipçisi

Alan adı bitiş tarihlerini takip eden, kurulum gerektirmeyen küçük bir web uygulaması.

## Özellikler

- Alan adını yazın → bitiş tarihi, kayıt firması, DNS sunucuları **RDAP / WHOIS** üzerinden otomatik bulunur
- Toplu ekleme (virgül, boşluk ya da satır başıyla ayrılmış liste yapıştırın)
- Kalan gün rozetleri: **süresi dolmuş / yaklaşan / güvende / bilinmiyor**, ayarlanabilir uyarı eşiği (7–90 gün)
- Arama, filtreleme, sütuna göre sıralama
- Not, etiket ve elle bitiş tarihi girme (sorgulanamayan uzantılar için)
- Arka planda her gün otomatik yenileme
- Dışa aktarma: **CSV** (Excel), **.ics takvim** (30 ve 7 gün önceden hatırlatmalı), **JSON yedek** ve geri yükleme
- Türkçe alan adları (IDN) desteklenir, açık/koyu tema otomatik

## Çalıştırma

Gerekli olan tek şey [Node.js](https://nodejs.org) 18 veya üstü. Ek paket kurulumu yok.

```bash
cd domaintakip
node server.js        # ya da: npm start
```

Tarayıcıda **http://localhost:3000** adresini açın.

macOS'ta `baslat.command` dosyasına çift tıklayarak da başlatabilirsiniz (ilk seferde
`chmod +x baslat.command` gerekebilir).

### Ayarlar (ortam değişkenleri)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `PORT` | `3000` | Sunucu portu |
| `HOST` | `127.0.0.1` | Ağdaki diğer cihazlardan erişim için `0.0.0.0` yapın |
| `AUTO_REFRESH_HOURS` | `24` | Otomatik yeniden sorgulama aralığı (saat) |

## Veriler

Tüm kayıtlar `data/domains.json` dosyasında tutulur. Yedeklemek için bu dosyayı kopyalamanız
ya da arayüzdeki **Yedek al** seçeneğini kullanmanız yeterli.

## Notlar

- `.com`, `.net`, `.org`, `.io`, `.dev` gibi uzantıların çoğu RDAP ile sorgulanır; RDAP'i olmayan
  uzantılarda (ör. bazı ülke uzantıları) WHOIS (port 43) denenir.
- Bazı kayıt otoriteleri bitiş tarihini paylaşmaz (ör. `.de`, `.eu`). Bu durumda tarihi
  **Düzenle** penceresinden elle girebilirsiniz; elle girilen tarih, sorgu yeni bir tarih bulana
  kadar korunur.

## Yapı

```
server.js        Node.js sunucusu (API + RDAP/WHOIS sorgusu + otomatik yenileme)
public/          Arayüz (index.html, app.js, style.css, icon.svg)
data/            Veri dosyası (ilk kayıtta oluşur)
```

## Geliştirici

[Harun Erçoban](https://harunercoban.com) — web tasarım, yazılım ve SEO.

## Lisans

MIT
