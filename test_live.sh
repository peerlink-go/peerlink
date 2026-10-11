#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTRUN="$DIR/testrun"

# Önceki test süreçlerini sonlandır
pkill -f "$DIR/bin/peerlink" 2>/dev/null || true
sleep 1

rm -rf "$TESTRUN"
mkdir -p "$TESTRUN"

echo "=== 1. SQLite Veritabanı ve Kullanıcı Hazırlanıyor ==="
"$DIR/bin/peerlink-control" create-user -db "$TESTRUN/control.db" -email "alice@peerlink.local" -name "Alice" -password "supersecret123" -role admin

echo "=== 2. Cihazlar için Auth-Key Oluşturuluyor ==="
AUTH_KEY_OUTPUT=$("$DIR/bin/peerlink-control" create-auth-key -db "$TESTRUN/control.db" -user 1 -reusable)
AUTH_KEY=$(echo "$AUTH_KEY_OUTPUT" | awk '/Anahtar/ {print $NF}')
echo "Üretilen Auth-Key: $AUTH_KEY"

echo "=== 3. peerlink-control Sunucusu Başlatılıyor (Port 8085) ==="
"$DIR/bin/peerlink-control" serve -listen "127.0.0.1:8085" -db "$TESTRUN/control.db" -url "http://127.0.0.1:8085" > "$TESTRUN/control.log" 2>&1 &
CONTROL_PID=$!
sleep 1

# Sunucu kontrol
curl -s http://127.0.0.1:8085/peerlink/key > "$TESTRUN/server.pub"
echo "Control Server Public Key: $(cat "$TESTRUN/server.pub")"

echo "=== 4. peerlink-relay & STUN Başlatılıyor (Port 8445 / 3479) ==="
"$DIR/bin/peerlink-relay" -listen "127.0.0.1:8445" -stun "127.0.0.1:3479" > "$TESTRUN/relay.log" 2>&1 &
RELAY_PID=$!
sleep 1

cleanup() {
    echo "Servisler kapatılıyor..."
    kill $NODE1_PID $NODE2_PID $CONTROL_PID $RELAY_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 5. Node 1 Başlatılıyor (sim-tun, peerlinkd) ==="
"$DIR/bin/peerlinkd" \
    -config "$TESTRUN/node1.json" \
    -socket "$TESTRUN/node1.sock" \
    -control-url "http://127.0.0.1:8085" \
    -sim-tun > "$TESTRUN/node1.log" 2>&1 &
NODE1_PID=$!
sleep 1

echo "=== 6. Node 1 Ağa Bağlanıyor (peerlink up) ==="
PEERLINK_SOCKET="$TESTRUN/node1.sock" "$DIR/bin/peerlink" up \
    --auth-key "$AUTH_KEY" \
    --hostname "macbook-node1" \
    --ssh

echo "Node 1 IP Adresi:"
PEERLINK_SOCKET="$TESTRUN/node1.sock" "$DIR/bin/peerlink" ip

echo "=== 7. Node 2 Başlatılıyor (sim-tun, peerlinkd) ==="
"$DIR/bin/peerlinkd" \
    -config "$TESTRUN/node2.json" \
    -socket "$TESTRUN/node2.sock" \
    -control-url "http://127.0.0.1:8085" \
    -sim-tun > "$TESTRUN/node2.log" 2>&1 &
NODE2_PID=$!
sleep 1

echo "=== 8. Node 2 Ağa Bağlanıyor (peerlink up) ==="
PEERLINK_SOCKET="$TESTRUN/node2.sock" "$DIR/bin/peerlink" up \
    --auth-key "$AUTH_KEY" \
    --hostname "linux-node2" \
    --ssh

echo "Node 2 IP Adresi:"
PEERLINK_SOCKET="$TESTRUN/node2.sock" "$DIR/bin/peerlink" ip

sleep 2

echo "=== 9. Ağ Durumu (Node 1 Açısından) ==="
PEERLINK_SOCKET="$TESTRUN/node1.sock" "$DIR/bin/peerlink" status

echo "=== 10. Ağ Durumu (Node 2 Açısından) ==="
PEERLINK_SOCKET="$TESTRUN/node2.sock" "$DIR/bin/peerlink" status

echo "=== 11. Koordinasyon Sunucusundaki Düğümler ==="
"$DIR/bin/peerlink-control" list-nodes -db "$TESTRUN/control.db"

echo "=== 12. Web Admin Paneli Testi ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8085/)
echo "Admin paneli HTTP yanıt kodu: $HTTP_CODE"

echo "=== TEST BAŞARIYLA TAMAMLANDI! ==="
