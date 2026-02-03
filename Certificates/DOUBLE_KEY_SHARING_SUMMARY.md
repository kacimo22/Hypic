Catalyst Certificate Generator - DOUBLE KEY SHARING SUMMARY
=======================================================================

DOUBLE KEY SHARING STRATEGY:
1. Classical keys shared by classical_alg_family
2. ML-DSA keys shared by ML-DSA variant (44/65/87)

CONFIGURATION:
- Total certificates: 20
- Classical key families: 13
- ML-DSA key families: 3 (ONLY 3 ML-DSA key pairs!)
- Classical key sharing ratio: 65.0%
- ML-DSA key sharing: 100% (only 3 key pairs total!)

KEY SHARING BY FAMILY:
======================

🔑 CLASSICAL KEY SHARING:
========================================

ecdsa-p256:
  Key File: classical_ecdsa_p256.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA44-ECDSA-P256-SHA256

ecdsa-p384:
  Key File: classical_ecdsa_p384.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA65-ECDSA-P384-SHA384

ecdsa-p521:
  Key File: classical_ecdsa_p521.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA87-ECDSA-P521-SHA512

ed25519:
  Key File: classical_ed25519.pem
  Certificates using this key: 2
  Shared by design: 2 algorithms
  • CATALYST-MLDSA44-Ed25519-SHA512
  • CATALYST-MLDSA65-Ed25519-SHA512

ed448:
  Key File: classical_ed448.pem
  Certificates using this key: 2
  Shared by design: 2 algorithms
  • CATALYST-MLDSA65-Ed448-SHAKE256
  • CATALYST-MLDSA87-Ed448-SHAKE256

rsa-2048-pkcs1:
  Key File: classical_rsa2048_pkcs1.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA44-RSA2048-PKCS15-SHA256

rsa-2048-pss:
  Key File: classical_rsa2048_pss.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA44-RSA2048-PSS-SHA256

rsa-2048-pss-pss:
  Key File: classical_rsa2048_pss_pss.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA44-RSA2048-PSS-PSS-SHA256

rsa-3072-pkcs1:
  Key File: classical_rsa3072_pkcs1.pem
  Certificates using this key: 2
  Shared by design: 2 algorithms
  • CATALYST-MLDSA44-RSA3072-PKCS15-SHA256
  • CATALYST-MLDSA65-RSA3072-PKCS15-SHA384

rsa-3072-pss:
  Key File: classical_rsa3072_pss.pem
  Certificates using this key: 3
  Shared by design: 3 algorithms
  • CATALYST-MLDSA44-RSA3072-PSS-SHA384
  • CATALYST-MLDSA65-RSA3072-PSS-SHA512
  • CATALYST-MLDSA87-RSA3072-PSS-SHA512

rsa-4096-pkcs1:
  Key File: classical_rsa4096_pkcs1.pem
  Certificates using this key: 1
  Shared by design: 1 algorithms
  • CATALYST-MLDSA65-RSA4096-PKCS15-SHA512

rsa-4096-pss:
  Key File: classical_rsa4096_pss.pem
  Certificates using this key: 2
  Shared by design: 2 algorithms
  • CATALYST-MLDSA65-RSA4096-PSS-SHA512
  • CATALYST-MLDSA87-RSA4096-PSS-SHA512

rsa-4096-pss-pss:
  Key File: classical_rsa4096_pss_pss.pem
  Certificates using this key: 2
  Shared by design: 2 algorithms
  • CATALYST-MLDSA44-RSA4096-PSS-PSS-SHA384
  • CATALYST-MLDSA65-RSA4096-PSS-PSS-SHA512

⚡ ML-DSA KEY SHARING (ONLY 3 KEY PAIRS!):
========================================

MLDSA44 (MLDSA44-Ed25519-SHA512):
  Key File: pq_priv_mldsa44.pem
  Certificates using this key: 8
  Shared by: 8 certificates
  • CATALYST-MLDSA44-Ed25519-SHA512
  • CATALYST-MLDSA44-ECDSA-P256-SHA256
  • CATALYST-MLDSA44-RSA2048-PSS-SHA256
  • CATALYST-MLDSA44-RSA3072-PSS-SHA384
  • CATALYST-MLDSA44-RSA2048-PSS-PSS-SHA256
  • CATALYST-MLDSA44-RSA4096-PSS-PSS-SHA384
  • CATALYST-MLDSA44-RSA2048-PKCS15-SHA256
  • CATALYST-MLDSA44-RSA3072-PKCS15-SHA256

MLDSA65 (MLDSA65-Ed25519-SHA512):
  Key File: pq_priv_mldsa65.pem
  Certificates using this key: 8
  Shared by: 8 certificates
  • CATALYST-MLDSA65-Ed25519-SHA512
  • CATALYST-MLDSA65-Ed448-SHAKE256
  • CATALYST-MLDSA65-ECDSA-P384-SHA384
  • CATALYST-MLDSA65-RSA3072-PSS-SHA512
  • CATALYST-MLDSA65-RSA4096-PSS-SHA512
  • CATALYST-MLDSA65-RSA4096-PSS-PSS-SHA512
  • CATALYST-MLDSA65-RSA3072-PKCS15-SHA384
  • CATALYST-MLDSA65-RSA4096-PKCS15-SHA512

MLDSA87 (MLDSA87-Ed448-SHAKE256):
  Key File: pq_priv_mldsa87.pem
  Certificates using this key: 4
  Shared by: 4 certificates
  • CATALYST-MLDSA87-Ed448-SHAKE256
  • CATALYST-MLDSA87-ECDSA-P521-SHA512
  • CATALYST-MLDSA87-RSA3072-PSS-SHA512
  • CATALYST-MLDSA87-RSA4096-PSS-SHA512

📊 DOUBLE KEY SHARING STATISTICS:
========================================
Total certificates generated: 20
Classical keys generated: 13
ML-DSA keys generated: 3
Storage saved (classical): 7 key pairs
Storage saved (ML-DSA): 17 key pairs
Total storage saved: 24 key pairs
Overall efficiency: 40.0% fewer key pairs

🎯 EXAMPLES OF DOUBLE KEY SHARING:
========================================

• Shares classical_ed25519.pem AND pq_priv_mldsa44.pem:
  Classical key: classical_ed25519.pem
  ML-DSA key: pq_priv_mldsa44.pem
  Certificate: catalyst_cert_MLDSA44_Ed25519_SHA512.pem

• Shares classical_rsa3072_pss.pem AND pq_priv_mldsa65.pem:
  Classical key: classical_rsa3072_pss.pem
  ML-DSA key: pq_priv_mldsa65.pem
  Certificate: catalyst_cert_MLDSA65_RSA3072_PSS_SHA512.pem
