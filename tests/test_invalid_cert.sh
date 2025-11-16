#!/bin/bash
# Test certificate validation with invalid certificates

echo "=================================="
echo "Test 2: Invalid Certificate"
echo "=================================="

# Backup original client certificate
cp certs/client.crt certs/client.crt.backup
cp certs/client.key certs/client.key.backup

echo ""
echo "[+] Creating self-signed certificate (not signed by CA)..."

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout certs/client.key -out certs/client.crt \
    -days 365 -nodes -subj "/CN=fake-client/O=Attacker/C=XX" 2>/dev/null

echo "[✓] Created fake self-signed certificate"
echo ""
echo "Now run the client. Server should reject with 'BAD_CERT'"
echo ""
read -p "Press Enter when ready to restore original certificate..."

# Restore original certificate
mv certs/client.crt.backup certs/client.crt
mv certs/client.key.backup certs/client.key

echo "[✓] Original certificate restored"
