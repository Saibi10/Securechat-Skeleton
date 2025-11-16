# SecureChat System - Test Report

**Student Name:** [Your Name]  
**Roll Number:** [Your Roll Number]  
**Date:** [Date]  
**Course:** Information Security - Assignment 2

---

## 1. Executive Summary

This report documents comprehensive security testing of the SecureChat system, including:
- PKI infrastructure and certificate validation
- Encrypted communication using AES-128 and DH key exchange
- Digital signatures for message integrity and authenticity
- Non-repudiation through session transcripts
- Security testing against common attacks

---

## 2. System Architecture

### 2.1 Components
- **CA (Certificate Authority):** Self-signed root CA for issuing certificates
- **Server:** Handles authentication, key exchange, and message routing
- **Client:** User interface for secure messaging
- **Database:** MariaDB for secure credential storage

### 2.2 Security Protocols
- **Certificate Exchange:** Mutual X.509 certificate validation
- **Authentication:** Salted SHA-256 password hashing
- **Key Agreement:** Diffie-Hellman (2048-bit)
- **Encryption:** AES-128 in CBC mode with PKCS#7 padding
- **Signatures:** RSA with SHA-256 and PSS padding

---

## 3. Test Cases

### 3.1 Test Case 1: Normal Communication

**Objective:** Verify complete secure communication flow

**Steps:**
1. Start server
2. Connect client
3. Exchange certificates
4. Register/login user
5. Perform DH key exchange
6. Exchange encrypted messages
7. End session and generate receipts

**Results:**
- ✅ Certificate validation: PASSED
- ✅ Authentication: PASSED
- ✅ Key exchange: PASSED
- ✅ Message encryption: PASSED
- ✅ Message signatures: PASSED
- ✅ Transcript generation: PASSED
- ✅ Receipt generation: PASSED

**Evidence:**
- Screenshot: `screenshots/01_normal_communication.png`
- Wireshark capture: `captures/normal_communication.pcapng`
- Transcript: `evidence_XXXXXX/client_transcript_XXXXXX.txt`
- Receipt: `evidence_XXXXXX/receipt_client_XXXXXX.json`

**Wireshark Analysis:**
```
Filter used: tcp.port == 5555
Observations:
- All message payloads are base64-encoded ciphertext
- No plaintext messages visible
- Certificate exchange visible in initial packets
```

---

### 3.2 Test Case 2: Invalid Certificate Rejection

**Objective:** Verify server rejects invalid/untrusted certificates

**Steps:**
1. Generate self-signed certificate (not signed by CA)
2. Replace client certificate
3. Attempt connection

**Expected:** Server rejects with "BAD_CERT"

**Results:**
- ✅ Self-signed certificate rejected: PASSED
- ✅ Error message displayed: "BAD_CERT: Certificate signature verification failed"

**Evidence:**
- Screenshot: `screenshots/02_invalid_cert_rejected.png`
- Server logs showing rejection

---

### 3.3 Test Case 3: Expired Certificate Rejection

**Objective:** Verify expired certificates are rejected

**Steps:**
1. Generate certificate with past expiration date
2. Replace client certificate
3. Attempt connection

**Expected:** Server rejects with "Certificate has expired"

**Results:**
- ✅ Expired certificate detected: PASSED
- ✅ Connection refused: PASSED

**Evidence:**
- Screenshot: `screenshots/03_expired_cert_rejected.png`

---

### 3.4 Test Case 4: Message Tampering Detection

**Objective:** Verify message integrity through signature verification

**Steps:**
1. Complete a normal chat session
2. Modify ciphertext in transcript
3. Verify transcript with receipt

**Expected:** Verification fails with hash mismatch

**Results:**
- ✅ Tampering detected: PASSED
- ✅ Transcript hash mismatch: PASSED
- ✅ Verification failed correctly: PASSED

**Evidence:**
- Screenshot: `screenshots/04_tampering_detected.png`
- Original transcript: `evidence_XXXXXX/client_transcript_XXXXXX.txt`
- Tampered transcript: `evidence_XXXXXX/client_transcript_XXXXXX_TAMPERED.txt`

---

### 3.5 Test Case 5: Replay Attack Protection

**Objective:** Verify sequence number prevents replay attacks

**Steps:**
1. Send message with seqno=1
2. Send message with seqno=2
3. Attempt to resend message with seqno=1

**Expected:** Server rejects with "REPLAY ATTACK DETECTED"

**Results:**
- ✅ Sequence number validation: PASSED
- ✅ Old message rejected: PASSED

**Evidence:**
- Screenshot: `screenshots/05_replay_attack_blocked.png`
- Server logs showing replay detection

---

### 3.6 Test Case 6: Non-Repudiation Verification

**Objective:** Verify session receipts provide non-repudiation

**Steps:**
1. Complete chat session
2. Verify transcript with receipt
3. Verify receipt signature with certificate

**Expected:** Both verifications succeed

**Results:**
- ✅ Transcript hash matches receipt: PASSED
- ✅ Receipt signature valid: PASSED
- ✅ Certificate fingerprint matches: PASSED

**Evidence:**
- Screenshot: `screenshots/06_nonrepudiation_verified.png`
- Verification output

---

## 4. Security Analysis

### 4.1 Confidentiality
- **Achieved through:** AES-128 encryption with unique session keys
- **Key derivation:** Diffie-Hellman with SHA-256
- **Evidence:** Wireshark shows only encrypted payloads

### 4.2 Integrity
- **Achieved through:** SHA-256 hashing and RSA signatures
- **Per-message protection:** Each message signed individually
- **Evidence:** Tampering test shows detection

### 4.3 Authenticity
- **Achieved through:** X.509 certificates and digital signatures
- **Mutual authentication:** Both parties verify each other
- **Evidence:** Invalid certificate rejection tests

### 4.4 Non-Repudiation
- **Achieved through:** Signed transcripts and receipts
- **Cryptographic proof:** RSA signatures bind messages to sender
- **Evidence:** Successful verification of receipts

---

## 5. Database Security

### 5.1 Credential Storage
- Passwords hashed with SHA-256
- 16-byte random salt per user
- No plaintext passwords stored

### 5.2 Database Schema
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Evidence:**
- Database dump: `evidence_XXXXXX/database_dump.sql`
- Screenshot showing hashed passwords

---

## 6. Wireshark Analysis

### 6.1 Capture Details
- **Interface:** Loopback (lo)
- **Filter:** `tcp.port == 5555`
- **Duration:** [X] minutes
- **Packets captured:** [X] packets

### 6.2 Observations
1. **Certificate Exchange:**
   - PEM-encoded certificates visible in JSON
   - No sensitive data exposed

2. **Encrypted Messages:**
   - All message content base64-encoded
   - Format: `{"type":"msg","seqno":X,"ts":X,"iv":"...","ct":"...","sig":"..."}`
   - No plaintext visible

3. **Key Exchange:**
   - DH public values (p, g, A, B) visible
   - Shared secret never transmitted

**Evidence:**
- Packet capture: `captures/normal_communication.pcapng`
- Screenshots with filters applied

---

## 7. Conclusion

The SecureChat system successfully implements all required security properties:

✅ **Confidentiality:** AES-128 encryption protects message content  
✅ **Integrity:** SHA-256 hashing detects any tampering  
✅ **Authenticity:** X.509 certificates and RSA signatures verify identities  
✅ **Non-Repudiation:** Signed transcripts provide cryptographic proof  

All test cases passed successfully, demonstrating robust security against:
- Eavesdropping (encrypted traffic)
- Man-in-the-middle attacks (certificate validation)
- Message tampering (signature verification)
- Replay attacks (sequence number validation)
- Identity spoofing (PKI infrastructure)

---

## 8. Appendices

### Appendix A: Certificate Details
[Paste output from certificate inspection]

### Appendix B: Wireshark Filters Used
```
tcp.port == 5555
tcp.port == 5555 && tcp.len > 0
tcp.port == 5555 && json
```

### Appendix C: Commands Used
```bash
# Generate CA
python3 scripts/gen_ca.py

# Generate certificates
python3 scripts/gen_cert.py

# Start server
python3 server.py

# Start client
python3 client.py

# Verify transcript
python3 verify_transcript.py transcript <transcript> <receipt> <cert>

# Database dump
mysqldump -u securechat_user -p securechat users > database_dump.sql
```

### Appendix D: GitHub Repository
- Repository URL: https://github.com/[your-username]/securechat-skeleton
- Commits: [X] commits showing progressive development
- Branches: main

---

**End of Test Report**
