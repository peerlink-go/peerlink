# PeerLink — Mesh VPN & WireGuard Ağı (Tailscale Klonu)

PeerLink, Tailscale benzeri, merkezi koordinasyonlu ancak **uçtan uca WireGuard şifrelemeli** bir mesh VPN sistemidir.

## Temel Özellikler

- **WireGuard Tabanlı Mesh:** Veri paketleri doğrudan cihazlar arasında WireGuard tüneliyle akar. Koordinasyon sunucusu veri trafiğini görmez.
- **NAT Traversal & Magicsock:** STUN ile otomatik public IP keşfi ve doğrudan P2P hole-punching.
- **Relay / DERP Fallback:** Katı güvenlik duvarı arkasındaki cihazlar için şifreli WebSocket relay aktarımı.
- **PeerLink SSH:** Tailscale SSH gibi, SSH anahtarlarıyla uğraşmadan WireGuard kimliği üzerinden şifresiz/anahtarsız güvenli SSH bağlantısı.
- **MagicDNS:** Cihazların `cihaz-adi.peerlink` olarak çözümlenmesi (`100.100.100.100`).
- **ACL & Paket Filtresi:** Hangi kullanıcının hangi porta ve hangi makineye erişebileceğini belirleyen HuJSON politika motoru.
- **Web Admin Paneli:** Tarayıcı üzerinden cihaz onaylama, auth key üretimi ve ACL yönetimi.
- **Çoklu Platform:** macOS, Linux ve Windows desteği.

---

## Proje Bileşenleri

1. **`peerlink-control`**: Koordinasyon sunucusu, SQLite veritabanı, NetMap dağıtımı ve Web Admin Paneli.
2. **`peerlinkd`**: Cihaz üzerinde çalışan arka plan servisi (WireGuard TUN motoru + Magicsock).
3. **`peerlink`**: Kullanıcı CLI komut satırı aracı (`up`, `down`, `status`, `ip`, `ssh`, `configure`).
4. **`peerlink-relay`**: STUN sunucusu ve yedek HTTPS/WebSocket aktarma sunucusu.

---

## Derleme

Tüm ikili dosyaları derlemek için:

```bash
make build
```

Derlenen dosyalar `bin/` dizinine yerleştirilir:
- `bin/peerlink-control`
- `bin/peerlink-relay`
- `bin/peerlinkd`
- `bin/peerlink`

Tüm testleri çalıştırmak için:
```bash
make test
```

---

## Hızlı Başlangıç

### 1. Koordinasyon Sunucusunu Başlatma

```bash
# İlk yönetici kullanıcısını oluşturun
./bin/peerlink-control create-user -email admin@example.com -password "parola1234" -role admin

# Sunucuyu başlatın
./bin/peerlink-control serve -listen :8080 -url http://localhost:8080
```
Artık tarayıcınızda `http://localhost:8080` adresine giderek web admin paneline giriş yapabilirsiniz.

### 2. Cihaz için Auth Key Üretme

İster web panelinden ister CLI ile tek komutla:
```bash
./bin/peerlink-control create-auth-key -user 1 -desc "Laptop" -preauth=true
```

### 3. Cihazda Daemon'ı Başlatma (`peerlinkd`)

```bash
sudo ./bin/peerlinkd -control-url http://localhost:8080
```
*(Geliştirme veya root yetkisi olmayan testlerde `-sim-tun` bayrağıyla çalıştırılabilir.)*

### 4. Ağa Bağlanma (`peerlink`)

```bash
# Auth Key ile anında bağlanma
peerlink up --auth-key <ANAHTAR> --login-server http://localhost:8080 --ssh

# Ağ durumunu görme
peerlink status

# Cihazın IP adresini alma
peerlink ip
```

### 5. PeerLink SSH Kullanımı

```bash
# Cihaz adına doğrudan SSH yapma
peerlink ssh root@sunucu

# Veya standart OpenSSH yapılandırmasını kurup 'ssh sunucu.peerlink' kullanma
peerlink configure ssh
ssh root@sunucu.peerlink
```

---

## Docker ile Dağıtım

```bash
cd deploy
docker-compose up -d
```
Bu komut `peerlink-control` (port 8080) ve `peerlink-relay` (port 8443 + 3478 UDP STUN) servislerini ayağa kaldırır.
