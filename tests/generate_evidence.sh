#!/bin/bash
# Generate evidence and documentation

echo "=================================="
echo "Evidence Collection"
echo "=================================="

EVIDENCE_DIR="evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo ""
echo "[+] Collecting certificates..."
cp certs/ca.crt "$EVIDENCE_DIR/"
cp certs/server.crt "$EVIDENCE_DIR/"
cp certs/client.crt "$EVIDENCE_DIR/"

# Certificate inspection
echo "[+] Inspecting certificates..."
openssl x509 -in certs/ca.crt -text -noout > "$EVIDENCE_DIR/ca_cert_details.txt"
openssl x509 -in certs/server.crt -text -noout > "$EVIDENCE_DIR/server_cert_details.txt"
openssl x509 -in certs/client.crt -text -noout > "$EVIDENCE_DIR/client_cert_details.txt"

# Verify certificate chains
echo "[+] Verifying certificate chains..."
openssl verify -CAfile certs/ca.crt certs/server.crt > "$EVIDENCE_DIR/server_cert_verification.txt" 2>&1
openssl verify -CAfile certs/ca.crt certs/client.crt > "$EVIDENCE_DIR/client_cert_verification.txt" 2>&1

echo "[+] Collecting transcripts..."
cp transcripts/*.txt "$EVIDENCE_DIR/" 2>/dev/null || echo "No transcripts found"
cp transcripts/*.json "$EVIDENCE_DIR/" 2>/dev/null || echo "No receipts found"

echo "[+] Collecting packet captures..."
cp captures/*.pcapng "$EVIDENCE_DIR/" 2>/dev/null || echo "No packet captures found"

echo "[+] Creating database dump..."
mysqldump -u securechat_user -p securechat users > "$EVIDENCE_DIR/database_dump.sql" 2>/dev/null || echo "Database dump failed"

echo "[+] Collecting logs..."
cp logs/*.log "$EVIDENCE_DIR/" 2>/dev/null || echo "No logs found"

echo ""
echo "[✓] Evidence collected in: $EVIDENCE_DIR"
echo ""
echo "Contents:"
ls -lh "$EVIDENCE_DIR/"
