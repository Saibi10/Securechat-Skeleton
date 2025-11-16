#!/bin/bash
# Test with expired certificate

echo "=================================="
echo "Test 3: Expired Certificate"
echo "=================================="

# Backup original client certificate
cp certs/client.crt certs/client.crt.backup
cp certs/client.key certs/client.key.backup

echo ""
echo "[+] Creating expired certificate..."

# Load CA
CA_KEY="certs/ca.key"
CA_CERT="certs/ca.crt"

# Generate new key
openssl genrsa -out certs/client.key 2048 2>/dev/null

# Create certificate request
openssl req -new -key certs/client.key -out certs/client.csr \
    -subj "/CN=expired-client/O=FAST-NUCES/C=PK" 2>/dev/null

# Sign with CA but set dates in the past (expired)
openssl x509 -req -in certs/client.csr -CA $CA_CERT -CAkey $CA_KEY \
    -CAcreateserial -out certs/client.crt -days 1 \
    -set_serial 0x$(openssl rand -hex 16) \
    -not_before "20200101120000Z" -not_after "20200102120000Z" 2>/dev/null

rm certs/client.csr

echo "[✓] Created expired certificate (valid: Jan 1-2, 2020)"
echo ""
echo "Now run the client. Server should reject with 'Certificate has expired'"
echo ""
read -p "Press Enter when ready to restore original certificate..."

# Restore original certificate
mv certs/client.crt.backup certs/client.crt
mv certs/client.key.backup certs/client.key

echo "[✓] Original certificate restored"
