#!/usr/bin/env python3
"""
Catalyst Certificate Generator & Validator - DOUBLE Key Sharing
Generate ML-DSA backed certificates for ALL TLS signature algorithms.
Share BOTH classical keys AND ML-DSA keys:
- Classical keys shared by classical_alg_family
- ML-DSA keys shared by ML-DSA variant (44/65/87)
"""
import logging
import subprocess
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from cryptography.x509.oid import ObjectIdentifier, ExtensionOID, NameOID, SignatureAlgorithmOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, rsa, ec, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime
import tempfile
import argparse
import ipaddress
import json


# ============================================================================
# TLS SIGNATURE ALGORITHM MAPPING
# ============================================================================

# TLS 1.3 signature algorithm codes (from Hypic)
class SignatureAlgorithm:
    """TLS 1.3 Signature Schemes (RFC 8446)"""
    # RSA schemes
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806


    # ECDSA schemes
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603

    # EdDSA schemes
    ED25519 = 0x0807
    ED448 = 0x0808

    # Legacy schemes
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203


# ============================================================================
# DOUBLE KEY SHARING CONFIGURATION
# ============================================================================

# Group certificates for BOTH classical and ML-DSA key sharing
TLS_ALGORITHM_CONFIGS = {
    # ============================================
    # EDDSA FAMILY - Ed25519 keys (ONE key)
    # ============================================
    "MLDSA44-Ed25519-SHA512": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "ed25519",
        "classical_alg_family": "ed25519",  # SHARED classical key
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.ED25519,
        "tls_name": "ED25519",
        "key_size": 256,
        "hash_alg": "sha512",
        "padding": None,
        "oid": "1.3.6.1.5.5.7.6.39",
        "common_name": "CATALYST-MLDSA44-Ed25519-SHA512",
        "cert_suffix": "_MLDSA44_Ed25519_SHA512",
        "classical_key_file": "classical_ed25519.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ed25519.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_Ed25519_SHA512.der",  # UNIQUE signature
        "security_level": 128
    },
    "MLDSA65-Ed25519-SHA512": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "ed25519",
        "classical_alg_family": "ed25519",  # SAME classical key family
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.ED25519,
        "tls_name": "ED25519",
        "key_size": 256,
        "hash_alg": "sha512",
        "padding": None,
        "oid": "1.3.6.1.5.5.7.6.48",
        "common_name": "CATALYST-MLDSA65-Ed25519-SHA512",
        "cert_suffix": "_MLDSA65_Ed25519_SHA512",
        "classical_key_file": "classical_ed25519.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ed25519.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_Ed25519_SHA512.der",  # UNIQUE signature
        "security_level": 128
    },

    # ============================================
    # EDDSA FAMILY - Ed448 keys (ONE key)
    # ============================================
    "MLDSA65-Ed448-SHAKE256": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "ed448",
        "classical_alg_family": "ed448",  # SHARED classical key
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key (same as Ed25519 ML-DSA-65)
        "tls_code": SignatureAlgorithm.ED448,
        "tls_name": "ED448",
        "key_size": 456,
        "hash_alg": "shake256",
        "padding": None,
        "oid": "1.3.6.1.4.1.2.267.999.1.3",
        "common_name": "CATALYST-MLDSA65-Ed448-SHAKE256",
        "cert_suffix": "_MLDSA65_Ed448_SHAKE256",
        "classical_key_file": "classical_ed448.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ed448.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_Ed448_SHAKE256.der",  # UNIQUE signature
        "security_level": 192
    },
    "MLDSA87-Ed448-SHAKE256": {
        "pq_alg": "ML-DSA-87",
        "classical_alg": "ed448",
        "classical_alg_family": "ed448",  # SAME classical key family
        "pq_key_family": "mldsa87",  # SHARED ML-DSA-87 key
        "tls_code": SignatureAlgorithm.ED448,
        "tls_name": "ED448",
        "key_size": 456,
        "hash_alg": "shake256",
        "padding": None,
        "oid": "1.3.6.1.5.5.7.6.51",
        "common_name": "CATALYST-MLDSA87-Ed448-SHAKE256",
        "cert_suffix": "_MLDSA87_Ed448_SHAKE256",
        "classical_key_file": "classical_ed448.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ed448.pem",
        "pq_key_file": "pq_priv_mldsa87.pem",  # SHARED ML-DSA-87 key
        "pq_pub_file": "pq_pub_mldsa87.pem",
        "pq_pub_der_file": "pq_pub_mldsa87.der",
        "pq_sig_file_suffix": "_MLDSA87_Ed448_SHAKE256.der",  # UNIQUE signature
        "security_level": 224
    },

    # ============================================
    # ECDSA FAMILY (ONE key)
    # ============================================
    "MLDSA44-ECDSA-P256-SHA256": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "ecdsa",
        "classical_alg_family": "ecdsa-p256",  # SHARED classical key
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.ECDSA_SECP256R1_SHA256,
        "tls_name": "ECDSA-P256-SHA256",
        "curve": "secp256r1",
        "key_size": 256,
        "hash_alg": "sha256",
        "padding": None,
        "oid": "1.3.6.1.5.5.7.6.40",
        "common_name": "CATALYST-MLDSA44-ECDSA-P256-SHA256",
        "cert_suffix": "_MLDSA44_ECDSA_P256_SHA256",
        "classical_key_file": "classical_ecdsa_p256.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ecdsa_p256.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_ECDSA_P256_SHA256.der",  # UNIQUE signature
        "security_level": 128
    },
    # "MLDSA65-ECDSA-P256-SHA512": {
    #     "pq_alg": "ML-DSA-65",
    #     "classical_alg": "ecdsa",
    #     "classical_alg_family": "ecdsa-p256",  # SAME classical key family
    #     "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
    #     "tls_code": SignatureAlgorithm.ECDSA_SECP256R1_SHA512, #simulated, not supported by TLS 1.3
    #     "tls_name": "ECDSA-P256-SHA512",
    #     "curve": "secp256r1",
    #     "key_size": 256,
    #     "hash_alg": "sha512",
    #     "padding": None,
    #     "oid": "1.3.6.1.5.5.7.6.45",
    #     "common_name": "CATALYST-MLDSA65-ECDSA-P256-SHA512",
    #     "cert_suffix": "_MLDSA65_ECDSA_P256_SHA512",
    #     "classical_key_file": "classical_ecdsa_p256.pem",  # SHARED classical key
    #     "classical_pub_file": "classical_pub_ecdsa_p256.pem",
    #     "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
    #     "pq_pub_file": "pq_pub_mldsa65.pem",
    #     "pq_pub_der_file": "pq_pub_mldsa65.der",
    #     "pq_sig_file_suffix": "_MLDSA65_ECDSA_P256_SHA512.der",  # UNIQUE signature
    #     "security_level": 128
    # },

    "MLDSA65-ECDSA-P384-SHA384": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "ecdsa",
        "classical_alg_family": "ecdsa-p384",  # SHARED classical key
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.ECDSA_SECP384R1_SHA384 ,
        "tls_name": "ECDSA-P384-SHA384",
        "curve": "secp384r1",
        "key_size": 384,
        "hash_alg": "sha384",
        "padding": None,
        "oid": "1.3.6.1.4.1.2.267.999.2.1", #not supported by draft-ietf-lamps-pq-composite-sigs-13
        "common_name": "CATALYST-MLDSA65-ECDSA-P384-SHA384",
        "cert_suffix": "_MLDSA65_ECDSA_P384_SHA384",
        "classical_key_file": "classical_ecdsa_p384.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_ecdsa_p384.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_ECDSA_P384_SHA384.der",  # UNIQUE signature
        "security_level": 192
    },

    # "MLDSA65-ECDSA-P384-SHA512": {
    #     "pq_alg": "ML-DSA-65",
    #     "classical_alg": "ecdsa",
    #     "classical_alg_family": "ecdsa-p384",  # SHARED classical key
    #     "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
    #     "tls_code": SignatureAlgorithm.ECDSA_SECP384R1_SHA512, #not supported by TLS 1.3
    #     "tls_name": "ECDSA-P384-SHA512",
    #     "curve": "secp384r1",
    #     "key_size": 384,
    #     "hash_alg": "sha512",
    #     "padding": None,
    #     "oid": "1.3.6.1.5.5.7.6.46",
    #     "common_name": "CATALYST-MLDSA65-ECDSA-P384-SHA512",
    #     "cert_suffix": "_MLDSA65_ECDSA_P384_SHA512",
    #     "classical_key_file": "classical_ecdsa_p384.pem",  # SHARED classical key
    #     "classical_pub_file": "classical_pub_ecdsa_p384.pem",
    #     "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
    #     "pq_pub_file": "pq_pub_mldsa65.pem",
    #     "pq_pub_der_file": "pq_pub_mldsa65.der",
    #     "pq_sig_file_suffix": "_MLDSA65_ECDSA_P384_SHA512.der",  # UNIQUE signature
    #     "security_level": 192
    # },
    # "MLDSA87-ECDSA-P384-SHA512": {
    #     "pq_alg": "ML-DSA-87",
    #     "classical_alg": "ecdsa",
    #     "classical_alg_family": "ecdsa-p384",  # SAME classical key family
    #     "pq_key_family": "mldsa87",  # SHARED ML-DSA-87 key
    #     "tls_code": SignatureAlgorithm.ECDSA_SECP384R1_SHA512, # Not supported by TLS 1.3
    #     "tls_name": "ECDSA-P384-SHA512",
    #     "curve": "secp384r1",
    #     "key_size": 384,
    #     "hash_alg": "sha512",
    #     "padding": None,
    #     "oid": "1.3.6.1.5.5.7.6.49",
    #     "common_name": "CATALYST-MLDSA87-ECDSA-P384-SHA512",
    #     "cert_suffix": "_MLDSA87_ECDSA_P384_SHA512",
    #     "classical_key_file": "classical_ecdsa_p384.pem",  # SHARED classical key
    #     "classical_pub_file": "classical_pub_ecdsa_p384.pem",
    #     "pq_key_file": "pq_priv_mldsa87.pem",  # SHARED ML-DSA-87 key
    #     "pq_pub_file": "pq_pub_mldsa87.pem",
    #     "pq_pub_der_file": "pq_pub_mldsa87.der",
    #     "pq_sig_file_suffix": "_MLDSA87_ECDSA_P384_SHA512.der",  # UNIQUE signature
    #     "security_level": 192
    # },

    "MLDSA87-ECDSA-P521-SHA512": {
        "pq_alg": "ML-DSA-87",
        "classical_alg": "ecdsa",
        "classical_alg_family": "ecdsa-p521",  # SINGLE - No sharing
        "pq_key_family": "mldsa87",  # SHARED ML-DSA-87 key
        "tls_code": SignatureAlgorithm.ECDSA_SECP521R1_SHA512,
        "tls_name": "ECDSA-P521-SHA512",
        "curve": "secp521r1",
        "key_size": 521,
        "hash_alg": "sha512",
        "padding": None,
        "oid": "1.3.6.1.5.5.7.6.54",
        "common_name": "CATALYST-MLDSA87-ECDSA-P521-SHA512",
        "cert_suffix": "_MLDSA87_ECDSA_P521_SHA512",
        "classical_key_file": "classical_ecdsa_p521.pem",
        "classical_pub_file": "classical_pub_ecdsa_p521.pem",
        "pq_key_file": "pq_priv_mldsa87.pem",  # SHARED ML-DSA-87 key
        "pq_pub_file": "pq_pub_mldsa87.pem",
        "pq_pub_der_file": "pq_pub_mldsa87.der",
        "pq_sig_file_suffix": "_MLDSA87_ECDSA_P521_SHA512.der",  # UNIQUE signature
        "security_level": 256
    },

    # ============================================
    # RSA-PSS FAMILY -  (ONE key)
    # ============================================
    "MLDSA44-RSA2048-PSS-SHA256": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-2048-pss",  # SINGLE - No sharing
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
        "tls_name": "RSA-PSS-RSAE-SHA256",
        "key_size": 2048,
        "hash_alg": "sha256",
        "padding": "pss",
        "oid": "1.3.6.1.5.5.7.6.37",
        "common_name": "CATALYST-MLDSA44-RSA2048-PSS-SHA256",
        "cert_suffix": "_MLDSA44_RSA2048_PSS_SHA256",
        "classical_key_file": "classical_rsa2048_pss.pem",
        "classical_pub_file": "classical_pub_rsa2048_pss.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA2048_PSS_SHA256.der",  # UNIQUE signature
        "security_level": 112
    },
    "MLDSA44-RSA3072-PSS-SHA384": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-3072-pss",  # SAME classical key family
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA384, #recommanded
        "tls_name": "RSA-PSS-RSAE-SHA384",
        "key_size": 3072,
        "hash_alg": "sha384",
        "padding": "pss",
        "oid": "1.3.6.1.4.1.2.267.999.3.1",
        "common_name": "CATALYST-MLDSA44-RSA3072-PSS-SHA384",
        "cert_suffix": "_MLDSA44_RSA3072_PSS_SHA384",
        "classical_key_file": "classical_rsa3072_pss.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_rsa3072_pss.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA3072_PSS_SHA384.der",  # UNIQUE signature
        "security_level": 128
    },
    "MLDSA65-RSA3072-PSS-SHA512": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-3072-pss",  # SHARED classical key
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
        "tls_name": "RSA-PSS-RSAE-SHA512",
        "key_size": 3072,
        "hash_alg": "sha512",
        "padding": "pss",
        "oid": "1.3.6.1.5.5.7.6.41",
        "common_name": "CATALYST-MLDSA65-RSA3072-PSS-SHA512",
        "cert_suffix": "_MLDSA65_RSA3072_PSS_SHA512",
        "classical_key_file": "classical_rsa3072_pss.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_rsa3072_pss.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_RSA3072_PSS_SHA512.der",  # UNIQUE signature
        "security_level": 128
    },
    "MLDSA87-RSA3072-PSS-SHA512": {
        "pq_alg": "ML-DSA-87",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-3072-pss",  # SAME classical key family
        "pq_key_family": "mldsa87",  # SHARED ML-DSA-87 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
        "tls_name": "RSA-PSS-RSAE-SHA512",
        "key_size": 3072,
        "hash_alg": "sha512",
        "padding": "pss",
        "oid": "1.3.6.1.5.5.7.6.52",
        "common_name": "CATALYST-MLDSA87-RSA3072-PSS-SHA512",
        "cert_suffix": "_MLDSA87_RSA3072_PSS_SHA512",
        "classical_key_file": "classical_rsa3072_pss.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_rsa3072_pss.pem",
        "pq_key_file": "pq_priv_mldsa87.pem",  # SHARED ML-DSA-87 key
        "pq_pub_file": "pq_pub_mldsa87.pem",
        "pq_pub_der_file": "pq_pub_mldsa87.der",
        "pq_sig_file_suffix": "_MLDSA87_RSA3072_PSS_SHA512.der",  # UNIQUE signature
        "security_level": 128
    },


    # ============================================
    # RSA-PSS FAMILY - RSA-4096 PSS key (ONE key)
    # ============================================
    "MLDSA65-RSA4096-PSS-SHA512": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-4096-pss",  # SHARED classical key
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
        "tls_name": "RSA-PSS-RSAE-SHA512",
        "key_size": 4096,
        "hash_alg": "sha512",
        "padding": "pss",
        "oid": "1.3.6.1.5.5.7.6.43",
        "common_name": "CATALYST-MLDSA65-RSA4096-PSS-SHA512",
        "cert_suffix": "_MLDSA65_RSA4096_PSS_SHA512",
        "classical_key_file": "classical_rsa4096_pss.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_rsa4096_pss.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_RSA4096_PSS_SHA512.der",  # UNIQUE signature
        "security_level": 140
    },
    "MLDSA87-RSA4096-PSS-SHA512": {
        "pq_alg": "ML-DSA-87",
        "classical_alg": "rsa-pss-rsae",
        "classical_alg_family": "rsa-4096-pss",  # SAME classical key family
        "pq_key_family": "mldsa87",  # SHARED ML-DSA-87 key
        "tls_code": SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
        "tls_name": "RSA-PSS-RSAE-SHA512",
        "key_size": 4096,
        "hash_alg": "sha512",
        "padding": "pss",
        "oid": "1.3.6.1.5.5.7.6.53",
        "common_name": "CATALYST-MLDSA87-RSA4096-PSS-SHA512",
        "cert_suffix": "_MLDSA87_RSA4096_PSS_SHA512",
        "classical_key_file": "classical_rsa4096_pss.pem",  # SHARED classical key
        "classical_pub_file": "classical_pub_rsa4096_pss.pem",
        "pq_key_file": "pq_priv_mldsa87.pem",  # SHARED ML-DSA-87 key
        "pq_pub_file": "pq_pub_mldsa87.pem",
        "pq_pub_der_file": "pq_pub_mldsa87.der",
        "pq_sig_file_suffix": "_MLDSA87_RSA4096_PSS_SHA512.der",  # UNIQUE signature
        "security_level": 140
    },

    # ============================================
    # RSA-PSS-PSS FAMILY (PSS-encoded keys)
    # ============================================
    "MLDSA44-RSA2048-PSS-PSS-SHA256": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa-pss-pss",
        "classical_alg_family": "rsa-2048-pss-pss",  # SINGLE - No sharing
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.RSA_PSS_PSS_SHA256,
        "tls_name": "RSA-PSS-PSS-SHA256",
        "key_size": 2048,
        "hash_alg": "sha256",
        "padding": "pss",
        "oid": "1.3.6.1.4.1.2.267.999.4.1",
        "common_name": "CATALYST-MLDSA44-RSA2048-PSS-PSS-SHA256",
        "cert_suffix": "_MLDSA44_RSA2048_PSS_PSS_SHA256",
        "classical_key_file": "classical_rsa2048_pss_pss.pem",
        "classical_pub_file": "classical_pub_rsa2048_pss_pss.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA2048_PSS_PSS_SHA256.der",  # UNIQUE signature
        "security_level": 112
    },
    "MLDSA44-RSA4096-PSS-PSS-SHA384": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa-pss-pss",
        "classical_alg_family": "rsa-4096-pss-pss",  # SINGLE - No sharing
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.RSA_PSS_PSS_SHA384,
        "tls_name": "RSA-PSS-PSS-SHA384",
        "key_size": 4096,
        "hash_alg": "sha384",
        "padding": "pss",
        "oid": "1.3.6.1.4.1.2.267.999.4.2",
        "common_name": "CATALYST-MLDSA44-RSA4096-PSS-PSS-SHA384",
        "cert_suffix": "_MLDSA44_RSA4096_PSS_PSS_SHA384",
        "classical_key_file": "classical_rsa4096_pss_pss.pem",
        "classical_pub_file": "classical_pub_rsa4096_pss_pss.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA4096_PSS_PSS_SHA384.der",  # UNIQUE signature
        "security_level": 140
    },
    "MLDSA65-RSA4096-PSS-PSS-SHA512": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "rsa-pss-pss",
        "classical_alg_family": "rsa-4096-pss-pss",  # SINGLE - No sharing (but could share with SHA384 variant)
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-87 key
        "tls_code": SignatureAlgorithm.RSA_PSS_PSS_SHA512,
        "tls_name": "RSA-PSS-PSS-SHA512",
        "key_size": 4096,
        "hash_alg": "sha512",
        "padding": "pss",
        "oid": "1.3.6.1.4.1.2.267.999.4.3",
        "common_name": "CATALYST-MLDSA65-RSA4096-PSS-PSS-SHA512",
        "cert_suffix": "_MLDSA65_RSA4096_PSS_PSS_SHA512",
        "classical_key_file": "classical_rsa4096_pss_pss.pem",
        "classical_pub_file": "classical_pub_rsa4096_pss_pss.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-87 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_RSA4096_PSS_PSS_SHA512.der",  # UNIQUE signature
        "security_level": 140
    },

    # ============================================
    # RSA-PKI FAMILY
    # ============================================
"MLDSA44-RSA2048-PKCS15-SHA256": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa",
        "classical_alg_family": "rsa-2048-pkcs1",  # SINGLE - No sharing
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.RSA_PKCS1_SHA256,
        "tls_name": "RSA-PKCS1-SHA256",
        "key_size": 2048,
        "hash_alg": "sha256",
        "padding": "pkcs1",
        "oid": "1.3.6.1.5.5.7.6.38",
        "common_name": "CATALYST-MLDSA44-RSA2048-PKCS15-SHA256",
        "cert_suffix": "_MLDSA44_RSA2048_PKCS15_SHA256",
        "classical_key_file": "classical_rsa2048_pkcs1.pem",
        "classical_pub_file": "classical_pub_rsa2048_pkcs1.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA2048_PKCS15_SHA256.der",  # UNIQUE signature
        "security_level": 112
    },
    "MLDSA44-RSA3072-PKCS15-SHA256": {
        "pq_alg": "ML-DSA-44",
        "classical_alg": "rsa",
        "classical_alg_family": "rsa-3072-pkcs1",  # SINGLE - No sharing
        "pq_key_family": "mldsa44",  # SHARED ML-DSA-44 key
        "tls_code": SignatureAlgorithm.RSA_PKCS1_SHA256,
        "tls_name": "RSA-PKCS1-SHA256",
        "key_size": 3072,
        "hash_alg": "sha256",
        "padding": "pkcs1",
        "oid": "1.3.6.1.4.1.2.267.999.5.1",
        "common_name": "CATALYST-MLDSA44-RSA3072-PKCS15-SHA256",
        "cert_suffix": "_MLDSA44_RSA3072_PKCS15_SHA256",
        "classical_key_file": "classical_rsa3072_pkcs1.pem",
        "classical_pub_file": "classical_pub_rsa3072_pkcs1.pem",
        "pq_key_file": "pq_priv_mldsa44.pem",  # SHARED ML-DSA-44 key
        "pq_pub_file": "pq_pub_mldsa44.pem",
        "pq_pub_der_file": "pq_pub_mldsa44.der",
        "pq_sig_file_suffix": "_MLDSA44_RSA3072_PKCS15_SHA256.der",  # UNIQUE signature
        "security_level": 128
    },
    "MLDSA65-RSA3072-PKCS15-SHA384": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "rsa",
        "classical_alg_family": "rsa-3072-pkcs1",  # SINGLE - No sharing
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.RSA_PKCS1_SHA384,
        "tls_name": "RSA-PKCS1-SHA384",
        "key_size": 3072,
        "hash_alg": "sha384",
        "padding": "pkcs1",
        "oid": "1.3.6.1.5.5.7.6.42",
        "common_name": "CATALYST-MLDSA65-RSA3072-PKCS15-SHA384",
        "cert_suffix": "_MLDSA65_RSA3072_PKCS15_SHA384",
        "classical_key_file": "classical_rsa3072_pkcs1.pem",
        "classical_pub_file": "classical_pub_rsa3072_pkcs1.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_RSA3072_PKCS15_SHA384.der",  # UNIQUE signature
        "security_level": 128
    },
    "MLDSA65-RSA4096-PKCS15-SHA512": {
        "pq_alg": "ML-DSA-65",
        "classical_alg": "rsa",
        "classical_alg_family": "rsa-4096-pkcs1",  # SINGLE - No sharing
        "pq_key_family": "mldsa65",  # SHARED ML-DSA-65 key
        "tls_code": SignatureAlgorithm.RSA_PKCS1_SHA512,
        "tls_name": "RSA-PKCS1-SHA512",
        "key_size": 4096,
        "hash_alg": "sha512",
        "padding": "pkcs1",
        "oid": "1.3.6.1.5.5.7.6.44",
        "common_name": "CATALYST-MLDSA65-RSA4096-PKCS15-SHA512",
        "cert_suffix": "_MLDSA65_RSA4096_PKCS15_SHA512",
        "classical_key_file": "classical_rsa4096_pkcs1.pem",
        "classical_pub_file": "classical_pub_rsa4096_pkcs1.pem",
        "pq_key_file": "pq_priv_mldsa65.pem",  # SHARED ML-DSA-65 key
        "pq_pub_file": "pq_pub_mldsa65.pem",
        "pq_pub_der_file": "pq_pub_mldsa65.der",
        "pq_sig_file_suffix": "_MLDSA65_RSA4096_PKCS15_SHA512.der",  # UNIQUE signature
        "security_level": 140
    },
}

# Create mapping from OID to algorithm name
CATALYST_OIDS_EXTENDED = {}
for alg_name, config in TLS_ALGORITHM_CONFIGS.items():
    CATALYST_OIDS_EXTENDED[config["oid"]] = alg_name

# Track classical key families
CLASSICAL_KEY_FAMILIES = {}
for alg_name, config in TLS_ALGORITHM_CONFIGS.items():
    family = config["classical_alg_family"]
    if family not in CLASSICAL_KEY_FAMILIES:
        CLASSICAL_KEY_FAMILIES[family] = []
    CLASSICAL_KEY_FAMILIES[family].append(alg_name)

# Track ML-DSA key families
MLDSA_KEY_FAMILIES = {
    "mldsa44": [],
    "mldsa65": [],
    "mldsa87": []
}
for alg_name, config in TLS_ALGORITHM_CONFIGS.items():
    family = config["pq_key_family"]
    if family in MLDSA_KEY_FAMILIES:
        MLDSA_KEY_FAMILIES[family].append(alg_name)


ML_DSA_SIZES = {
    1334: "ML-DSA-44",  # 1312 + 22 bytes DER overhead
    1974: "ML-DSA-65",  # 1952 + 22 bytes DER overhead
    2614: "ML-DSA-87"  # 2592 + 22 bytes DER overhead
}

# Default subjectAltName configurations
DEFAULT_SAN_DOMAINS = [
    "localhost",
    "localhost.localdomain",
    "*.localhost"
]

DEFAULT_SAN_IPS = [
    "127.0.0.1",
    "::1"
]


def get_certificate_algorithm_info(cert):
    """Get detailed algorithm information from certificate - CORRECTED VERSION"""
    sig_oid = cert.signature_algorithm_oid

    info = {
        "oid": str(sig_oid),
        "name": sig_oid._name if hasattr(sig_oid, '_name') else str(sig_oid),
        "certificate_oid": str(sig_oid),
    }

    # Get public key for additional info
    public_key = cert.public_key()

    # EdDSA algorithms
    if sig_oid == SignatureAlgorithmOID.ED25519:
        info["tls_code"] = SignatureAlgorithm.ED25519  # 0x0807
        info["tls_name"] = "ED25519"
        info["classical_type"] = "ed25519"
        info["classical_alg"] = "ed25519"
        info["key_size"] = 256
        info["hash_alg"] = "sha512"  # Ed25519 always uses SHA512 internally



    elif sig_oid == SignatureAlgorithmOID.ED448:
        info["tls_code"] = SignatureAlgorithm.ED448  # 0x0808
        info["tls_name"] = "ED448"
        info["classical_type"] = "ed448"
        info["classical_alg"] = "ed448"
        info["key_size"] = 456
        info["hash_alg"] = "shake256"  # Ed448 uses SHAKE256


    # ECDSA algorithms - IMPORTANT: Need to check curve AND hash
    elif sig_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
        info["classical_type"] = "ecdsa"
        info["classical_alg"] = "ecdsa"
        info["hash_alg"] = "sha256"

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            curve = public_key.curve
            info["key_size"] = public_key.key_size

            if curve.name == 'secp256r1' or '256' in str(curve.name).lower():
                info["tls_code"] = SignatureAlgorithm.ECDSA_SECP256R1_SHA256  # 0x0403
                info["tls_name"] = "ECDSA-P256-SHA256"
                info["curve"] = "secp256r1"
            elif curve.name == 'secp384r1' or '384' in str(curve.name).lower():
                # SHA256 with P-384 - not standard TLS 1.3, but matches your config
                info["tls_code"] = 0  # Not standard TLS
                info["tls_name"] = "ECDSA-P384-SHA256"
                info["curve"] = "secp384r1"
            else:
                info["tls_code"] = 0
                info["tls_name"] = f"ECDSA-{curve.name}-SHA256"
                info["curve"] = curve.name

    elif sig_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA384:
        info["classical_type"] = "ecdsa"
        info["classical_alg"] = "ecdsa"
        info["hash_alg"] = "sha384"

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            curve = public_key.curve
            info["key_size"] = public_key.key_size

            if curve.name == 'secp384r1' or '384' in str(curve.name).lower():
                info["tls_code"] = SignatureAlgorithm.ECDSA_SECP384R1_SHA384  # 0x0503
                info["tls_name"] = "ECDSA-P384-SHA384"
                info["curve"] = "secp384r1"
            elif curve.name == 'secp256r1' or '256' in str(curve.name).lower():
                # SHA384 with P-256 - unusual but possible
                info["tls_code"] = 0  # Not standard
                info["tls_name"] = "ECDSA-P256-SHA384"
                info["curve"] = "secp256r1"
            else:
                info["tls_code"] = 0
                info["tls_name"] = f"ECDSA-{curve.name}-SHA384"
                info["curve"] = curve.name

    elif sig_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA512:
        info["classical_type"] = "ecdsa"
        info["classical_alg"] = "ecdsa"
        info["hash_alg"] = "sha512"

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            curve = public_key.curve
            info["key_size"] = public_key.key_size

            if curve.name == 'secp521r1' or '521' in str(curve.name).lower():
                info["tls_code"] = SignatureAlgorithm.ECDSA_SECP521R1_SHA512  # 0x0603
                info["tls_name"] = "ECDSA-P521-SHA512"
                info["curve"] = "secp521r1"
            elif curve.name == 'secp384r1' or '384' in str(curve.name).lower():
                # SHA512 with P-384 - matches your config entries
                info["tls_code"] = SignatureAlgorithm.ECDSA_SECP384R1_SHA512  # Your custom code
                info["tls_name"] = "ECDSA-P384-SHA512"
                info["curve"] = "secp384r1"
            elif curve.name == 'secp256r1' or '256' in str(curve.name).lower():
                # SHA512 with P-256 - matches your config
                info["tls_code"] = SignatureAlgorithm.ECDSA_SECP256R1_SHA512  # Your custom code
                info["tls_name"] = "ECDSA-P256-SHA512"
                info["curve"] = "secp256r1"
            else:
                info["tls_code"] = 0
                info["tls_name"] = f"ECDSA-{curve.name}-SHA512"
                info["curve"] = curve.name

    # RSA-PSS algorithms
    elif sig_oid == SignatureAlgorithmOID.RSASSA_PSS:
        info["classical_type"] = "rsa"
        info["classical_alg"] = "rsa"
        info["padding"] = "pss"

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            info["key_size"] = key_size

            # Determine hash from certificate extensions or subject
            # Default to SHA256, but check for hints
            hash_alg = _detect_rsa_pss_hash(cert)
            info["hash_alg"] = hash_alg

            # Map to your TLS codes based on key size and hash
            if key_size == 2048:
                if hash_alg == "sha256":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA256  # 0x0804
                    info["tls_name"] = "RSA-PSS-RSAE-SHA256"
                else:
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA256
                    info["tls_name"] = f"RSA-PSS-RSAE-{hash_alg.upper()}-2048"

            elif key_size == 3072:
                if hash_alg == "sha256":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA256  # 0x0804
                    info["tls_name"] = "RSA-PSS-RSAE-SHA256"
                elif hash_alg == "sha384":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA384  # 0x0805
                    info["tls_name"] = "RSA-PSS-RSAE-SHA384"
                elif hash_alg == "sha512":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA512  # 0x0806
                    info["tls_name"] = "RSA-PSS-RSAE-SHA512"
                else:
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA256
                    info["tls_name"] = f"RSA-PSS-RSAE-{hash_alg.upper()}-3072"

            elif key_size == 4096:
                if hash_alg == "sha384":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA384  # 0x0805
                    info["tls_name"] = "RSA-PSS-RSAE-SHA384"
                elif hash_alg == "sha512":
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA512  # 0x0806
                    info["tls_name"] = "RSA-PSS-RSAE-SHA512"
                else:
                    info["tls_code"] = SignatureAlgorithm.RSA_PSS_RSAE_SHA512
                    info["tls_name"] = f"RSA-PSS-RSAE-{hash_alg.upper()}-4096"

    # RSA-PKCS1 algorithms
    elif sig_oid == SignatureAlgorithmOID.RSA_WITH_SHA256:
        info["classical_type"] = "rsa"
        info["classical_alg"] = "rsa"
        info["padding"] = "pkcs1"
        info["hash_alg"] = "sha256"

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            info["key_size"] = key_size

            info["tls_code"] = SignatureAlgorithm.RSA_PKCS1_SHA256  # 0x0401
            info["tls_name"] = "RSA-PKCS1-SHA256"

    elif sig_oid == SignatureAlgorithmOID.RSA_WITH_SHA384:
        info["classical_type"] = "rsa"
        info["classical_alg"] = "rsa"
        info["padding"] = "pkcs1"
        info["hash_alg"] = "sha384"

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            info["key_size"] = key_size

            info["tls_code"] = SignatureAlgorithm.RSA_PKCS1_SHA384  # 0x0501
            info["tls_name"] = "RSA-PKCS1-SHA384"

    elif sig_oid == SignatureAlgorithmOID.RSA_WITH_SHA512:
        info["classical_type"] = "rsa"
        info["classical_alg"] = "rsa"
        info["padding"] = "pkcs1"
        info["hash_alg"] = "sha512"

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            info["key_size"] = key_size

            info["tls_code"] = SignatureAlgorithm.RSA_PKCS1_SHA512  # 0x0601
            info["tls_name"] = "RSA-PKCS1-SHA512"


    # RSA-PSS-PSS (PSS encoded keys) - treated as RSA-PSS in cert OID
    # Note: This is tricky because RSA-PSS-PSS uses same OID as RSA-PSS
    # Need to check certificate subject or extensions for hints

    # Legacy RSA algorithms
    elif sig_oid == SignatureAlgorithmOID.RSA_WITH_SHA1:
        info["classical_type"] = "rsa"
        info["classical_alg"] = "rsa"
        info["padding"] = "pkcs1"
        info["hash_alg"] = "sha1"
        info["tls_code"] = SignatureAlgorithm.RSA_PKCS1_SHA1  # 0x0201
        info["tls_name"] = "RSA-PKCS1-SHA1"



    elif sig_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA1:
        info["classical_type"] = "ecdsa"
        info["classical_alg"] = "ecdsa"
        info["hash_alg"] = "sha1"
        info["tls_code"] = SignatureAlgorithm.ECDSA_SHA1  # 0x0203
        info["tls_name"] = "ECDSA-SHA1"



    else:
        # Unknown algorithm
        info["tls_code"] = 0
        info["tls_name"] = f"Unknown ({sig_oid})"
        info["classical_type"] = "Unknown"
        info["classical_alg"] = "unknown"

    return info


def _detect_rsa_pss_hash(cert):
    """Try to detect hash algorithm used in RSA-PSS certificate"""
    # Check subject Common Name for hints
    subject = cert.subject.rfc4514_string()

    if 'SHA256' in subject.upper():
        return "sha256"
    elif 'SHA384' in subject.upper():
        return "sha384"
    elif 'SHA512' in subject.upper():
        return "sha512"

    # Check key size for likely hash
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size == 2048:
            return "sha256"  # Most common for 2048-bit
        elif key_size == 3072:
            return "sha512"  # Most common for 3072-bit
        elif key_size == 4096:
            return "sha512"  # Most common for 4096-bit

    return "sha256"  # Default


def read_length(data, offset):
    """Read ASN.1 length field"""
    first = data[offset]
    offset += 1

    if first < 128:
        return first, offset

    n = first & 0x7F
    length = 0
    for _ in range(n):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def decode_octet_string(data, offset):
    """Decode ASN.1 OCTET STRING"""
    if data[offset] != 0x04:
        raise ValueError("Expected OCTET STRING tag (0x04)")
    offset += 1

    length, offset = read_length(data, offset)
    value = data[offset:offset + length]
    return value, offset + length


def decode_sequence(data):
    """Decode ASN.1 SEQUENCE containing two OCTET STRINGS"""
    offset = 0
    if data[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag (0x30)")
    offset += 1

    length, offset = read_length(data, offset)
    end = offset + length

    items = []
    while offset < end:
        item, offset = decode_octet_string(data, offset)
        items.append(item)

    if len(items) != 2:
        raise ValueError(f"Expected exactly 2 elements, found {len(items)}")

    return items


def encode_octet_string(data):
    """ASN.1 encode octet string"""
    tag = b'\x04'
    length = len(data)

    if length < 128:
        length_bytes = bytes([length])
    else:
        length_bytes = b''
        while length > 0:
            length_bytes = bytes([length & 0xFF]) + length_bytes
            length >>= 8
        length_bytes = bytes([0x80 | len(length_bytes)]) + length_bytes

    return tag + length_bytes + data

def get_hash_algorithm(hash_name):
    """Get hash algorithm object"""
    hash_map = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    return hash_map.get(hash_name)

def encode_sequence(items):
    """ASN.1 encode sequence"""
    encoded_items = b''.join(items)
    tag = b'\x30'
    length = len(encoded_items)

    if length < 128:
        length_bytes = bytes([length])
    else:
        length_bytes = b''
        while length > 0:
            length_bytes = bytes([length & 0xFF]) + length_bytes
            length >>= 8
        length_bytes = bytes([0x80 | len(length_bytes)]) + length_bytes

    return tag + length_bytes + encoded_items



# ============================================================================
# CATALYST GENERATOR
# ============================================================================

class CatalystGenerator:
    def __init__(self, cert_dir="Cert"):
        """Initialize generator with output directory"""
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self.openssl = "openssl"
        # Track generated classical keys by family
        self.generated_classical_keys = {}
        # Track generated ML-DSA keys by family
        self.generated_mldsa_keys = {}
        # Track all generated certificates
        self.all_results = {}
        # Track key sharing statistics
        self.sharing_stats = {}

    def check_openssl_version(self):
        try:
            result = subprocess.run(
                [self.openssl, "version"],
                capture_output=True,
                text=True,
                check=True
            )
            version_str = result.stdout.strip()

            # Check for ML-DSA support
            result = subprocess.run(
                [self.openssl, "genpkey", "-help"],
                capture_output=True,
                text=True
            )
            if "ML-DSA" not in result.stdout:
                logging.info("⚠  ML-DSA support may not be available in this OpenSSL build")
                logging.info("   Ensure you're using OpenSSL")

        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.error("❌ OpenSSL not found or not accessible")
            logging.error("   Please install OpenSSL and ensure it's in PATH")
            sys.exit(1)

    def run_openssl_command(self, args, description=""):
        """Run OpenSSL command and handle errors"""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=True
            )
            return result
        except subprocess.CalledProcessError as e:
            logging.error (f"  Error: {e.stderr}")
            raise

    def generate_classical_key_family(self, family_name, alg_config):
        alg = alg_config["classical_alg"]
        key_file = alg_config["classical_key_file"]
        pub_file = alg_config["classical_pub_file"]

        priv_path = self.cert_dir / key_file
        pub_path = self.cert_dir / pub_file

        # Check if key already exists
        if priv_path.exists():
            logging.info(f"✓ Reusing existing classical key: {key_file}")
            with open(priv_path, "rb") as f:
                private_key = load_pem_private_key(f.read(), password=None)
            return private_key

        logging.info(f"Generating new classical key for family: {family_name}")

        if alg == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            logging.info(f"✓ Generated Ed25519 key (256-bit)")

        elif alg == "ed448":
            private_key = ed448.Ed448PrivateKey.generate()
            logging.info(f"✓ Generated Ed448 key (456-bit)")

        elif alg == "ecdsa":
            if alg_config["curve"] == "secp256r1":
                curve = ec.SECP256R1()
            elif alg_config["curve"] == "secp384r1":
                curve = ec.SECP384R1()
            elif alg_config["curve"] == "secp521r1":
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported ECDSA curve: {alg_config['curve']}")

            private_key = ec.generate_private_key(curve)
            logging.info(f"✓ Generated ECDSA key on {alg_config['curve']} ({alg_config['key_size']}-bit)")

            # ─────────────────────────────
            # RSA PKCS#1 and RSA-PSS-RSAE
            # SAME KEY TYPE: rsaEncryption
            # ─────────────────────────────
        elif alg in ["rsa", "rsa-pss-rsae"]:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=alg_config["key_size"],
                backend=default_backend()
            )

        # ─────────────────────────────
        # RSA-PSS-PSS  (DIFFERENT KEY TYPE!)
         # MUST USE OPENSSL
        # ─────────────────────────────
        elif alg == "rsa-pss-pss":
            key_size = alg_config["key_size"]
            hash_alg = alg_config["hash_alg"]

            cmd = [
                "openssl", "genpkey",
                "-algorithm", "RSA-PSS",
                "-pkeyopt", f"rsa_keygen_bits:{key_size}",
                "-pkeyopt", f"rsa_pss_keygen_md:{hash_alg}",
                "-pkeyopt", f"rsa_pss_keygen_mgf1_md:{hash_alg}",
                "-out", str(priv_path)
            ]

            subprocess.run(cmd, check=True)

            with open(priv_path, "rb") as f:
                private_key = load_pem_private_key(f.read(), password=None)

        else:
            raise ValueError(f"Unsupported classical algorithm: {alg}")

        # Save private key
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        logging.info(f"📁 Saved classical private key: {key_file}")
        logging.info(f"📁 Saved classical public key: {pub_file}")

        # Store in tracking
        self.generated_classical_keys[family_name] = {
            "private_key": private_key,
            "private_key_file": key_file,
            "public_key_file": pub_file,
            "algorithms": CLASSICAL_KEY_FAMILIES[family_name]
        }

        return private_key

    def generate_mldsa_key_family(self, family_name):
        """Generate ONE ML-DSA key pair for a family (ML-DSA-44/65/87)"""
        logging.info(f"\n{'=' * 60}")
        logging.info(f"Generating ML-DSA KEY FAMILY: {family_name}")

        if family_name == "mldsa44":
            openssl_alg = "ML-DSA-44"
            display_name = "ML-DSA-44 (128-bit security)"
        elif family_name == "mldsa65":
            openssl_alg = "ML-DSA-65"
            display_name = "ML-DSA-65 (192-bit security)"
        elif family_name == "mldsa87":
            openssl_alg = "ML-DSA-87"
            display_name = "ML-DSA-87 (256-bit security)"
        else:
            raise ValueError(f"Unknown ML-DSA family: {family_name}")


        # File names
        priv_name = f"pq_priv_{family_name}.pem"
        pub_name = f"pq_pub_{family_name}.pem"
        der_name = f"pq_pub_{family_name}.der"

        priv_path = self.cert_dir / priv_name
        pub_path = self.cert_dir / pub_name
        der_path = self.cert_dir / der_name

        # Check if key already exists
        if priv_path.exists():
            # Read the DER file for public key bytes
            with open(der_path, "rb") as f:
                pq_pub_bytes = f.read()

            return priv_path, pub_path, der_path, pq_pub_bytes

        # 1. Generate private key
        self.run_openssl_command([
            self.openssl, "genpkey",
            "-algorithm", openssl_alg,
            "-out", str(priv_path)
        ], f"Generating {openssl_alg} private key")

        # 2. Extract public key
        self.run_openssl_command([
            self.openssl, "pkey",
            "-in", str(priv_path),
            "-pubout",
            "-out", str(pub_path)
        ], "Extracting public key")

        # 3. Convert to DER format
        self.run_openssl_command([
            self.openssl, "pkey",
            "-in", str(pub_path),
            "-pubin",
            "-outform", "DER",
            "-out", str(der_path)
        ], "Converting to DER")

        # Read the DER file
        with open(der_path, "rb") as f:
            pq_pub_bytes = f.read()

        logging.info(f"✓ {openssl_alg} public key size: {len(pq_pub_bytes)} bytes")
        logging.info(f"📁 Saved ML-DSA private key: {priv_name}")
        logging.info(f"📁 Saved ML-DSA public key: {pub_name}")
        logging.info(f"📁 Saved ML-DSA public key (DER): {der_name}")

        # Store in tracking
        self.generated_mldsa_keys[family_name] = {
            "private_key_path": str(priv_path),
            "public_key_path": str(pub_path),
            "der_path": str(der_path),
            "public_key_bytes": pq_pub_bytes,
            "algorithms": MLDSA_KEY_FAMILIES[family_name]
        }

        return str(priv_path), str(pub_path), str(der_path), pq_pub_bytes

    def sign_with_mldsa_key(self, mldsa_priv_path, data_to_sign, sig_suffix):
        """Sign data with ML-DSA private key"""
        sig_name = f"pq_sig{sig_suffix}"
        sig_path = self.cert_dir / sig_name

        # Write data to temp file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
            tmp.write(data_to_sign)
            tmp_path = tmp.name

        try:
            # Sign using OpenSSL
            self.run_openssl_command([
                self.openssl, "pkeyutl",
                "-sign",
                "-inkey", mldsa_priv_path,
                "-in", tmp_path,
                "-out", str(sig_path),
                "-rawin"
            ], f"Signing with ML-DSA key")
        finally:
            # Clean up temp file
            os.unlink(tmp_path)

        # Read signature
        with open(sig_path, "rb") as f:
            pq_sig_bytes = f.read()
        return str(sig_path), pq_sig_bytes

    def get_classical_public_bytes(self, private_key, config):
        """Extract classical public key in appropriate format"""
        if config["classical_alg"] in ["ed25519", "ed448"]:
            # EdDSA: raw bytes
            return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            # ECDSA/RSA: DER encoding
            return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def create_catalyst_csr(self, config, classical_priv_key, pq_pub_bytes, pq_sig_bytes):
        """Create CSR with PQ extension"""
        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()

        # Set subject name
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    config["common_name"]
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    u"Catalyst Hybrid Certificates"
                ),
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME,
                    u"US"
                )
            ])
        )

        # Add subjectAltName extension
        builder = builder.add_extension(
            SubjectAlternativeName([DNSName("localhost")]),
            critical=False
        )

        # Encode PQ public key and signature
        encoded_pub = encode_octet_string(pq_pub_bytes)
        encoded_sig = encode_octet_string(pq_sig_bytes)
        extension_value_bytes = encode_sequence([encoded_pub, encoded_sig])

        # Add custom Catalyst extension
        custom_oid = ObjectIdentifier(config["oid"])
        custom_extension = x509.UnrecognizedExtension(
            custom_oid,
            extension_value_bytes
        )

        builder = builder.add_extension(
            custom_extension,
            critical=False
        )

        # Add basic constraints
        basic_constraints = x509.BasicConstraints(
            ca=False,
            path_length=None
        )
        builder = builder.add_extension(basic_constraints, critical=True)

        # Add key usage
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=(config["classical_alg"] in ["rsa", "rsa-pss-pss"]),
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        builder = builder.add_extension(key_usage, critical=True)

        # Add extended key usage for TLS
        ext_key_usage = x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ])
        builder = builder.add_extension(ext_key_usage, critical=False)
        hash_alg = get_hash_algorithm(config["hash_alg"])
        # Sign CSR with appropriate algorithm
        if config["classical_alg"] in ["ed25519", "ed448"]:
            # EdDSA: sign without explicit hash
            csr = builder.sign(
                private_key=classical_priv_key,
                algorithm=None,
                backend = default_backend()
            )
        elif config["classical_alg"] == "ecdsa":
            # ECDSA: sign with appropriate hash
                csr = builder.sign(
                    private_key=classical_priv_key,
                    algorithm=hash_alg,
                    backend=default_backend()
                )
        elif config["classical_alg"] == "rsa":
            # PKCS#1 v1.5
            csr = builder.sign(
                private_key=classical_priv_key,
                algorithm=hash_alg,
                backend=default_backend()
            )

        elif config["classical_alg"] in ["rsa-pss-rsae", "rsa-pss-pss"]:
            csr = builder.sign(
                private_key=classical_priv_key,
                algorithm=hash_alg,
                backend=default_backend()
                )

        return csr

    def create_self_signed_certificate(self, csr, classical_priv_key, config, cert_path=None):
        """Create self-signed certificate from CSR"""
        hash_alg = get_hash_algorithm(config["hash_alg"])
        key_file = config["classical_key_file"]
        priv_path = self.cert_dir / key_file

        # Load CSR to get subject
        csr_obj = x509.load_pem_x509_csr(
            csr.public_bytes(serialization.Encoding.PEM)
        )

        # Build certificate
        builder = x509.CertificateBuilder()

        builder = builder.subject_name(csr_obj.subject)
        builder = builder.issuer_name(csr_obj.subject)  # Self-signed

        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )

        builder = builder.serial_number(x509.random_serial_number())

        # Copy public key from CSR (SAME classical key for all variants in family)
        builder = builder.public_key(csr_obj.public_key())

        # Copy extensions from CSR
        for extension in csr_obj.extensions:
            builder = builder.add_extension(
                extension.value,
                critical=extension.critical
            )

        # Add subject key identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_obj.public_key()),
            critical=False
        )

        # Add authority key identifier (self-signed)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(csr_obj.public_key()),
            critical=False
        )
        csr_path = self.cert_dir / f"catalyst_csr{config['cert_suffix']}.pem"
        # Sign certificate with appropriate algorithm
        if config["classical_alg"] in ["ed25519", "ed448"]:
            cert = builder.sign(
                private_key=classical_priv_key,
                algorithm=None
            )
        elif config["classical_alg"] == "ecdsa":
            cert = builder.sign(
                private_key=classical_priv_key,
                algorithm=hash_alg,
                backend=default_backend()
            )
        elif config["classical_alg"] == "rsa":
            # PKCS#1 v1.5
            cert = builder.sign(
                private_key=classical_priv_key,
                algorithm=hash_alg,
                backend=default_backend()
            )

        elif config["classical_alg"] == "rsa-pss-rsae":
            cmd = [
                self.openssl, "x509", "-req",
                "-in", csr_path,
                "-signkey", priv_path,
                "-out", cert_path,
                "-days", "365",
                f"-{config['hash_alg']}",
                "-extensions", "v3_req",
                "-sigopt", "rsa_padding_mode:pss",
                "-copy_extensions", "copy",
                "-sigopt", "rsa_pss_saltlen:-1"            ]
            subprocess.run(cmd, check=True)
            return x509.load_pem_x509_certificate(cert_path.read_bytes())

        elif config["classical_alg"] == "rsa-pss-pss":
            # rsassaPss key → NO sigopt
            cmd = [
                self.openssl, "x509", "-req",
                "-in", csr_path,
                "-signkey", priv_path,
                "-out", cert_path,
                "-days", "365",
                "-extensions", "v3_req",
                "-copy_extensions", "copy",
                f"-{config['hash_alg']}"
            ]
            subprocess.run(cmd, check=True)
            return x509.load_pem_x509_certificate(cert_path.read_bytes())

        return cert

    def generate_catalyst_certificate(self, alg_name):
        """Generate a Catalyst certificate with DOUBLE key sharing"""
        if alg_name not in TLS_ALGORITHM_CONFIGS:
            raise ValueError(f"Unknown algorithm: {alg_name}")

        config = TLS_ALGORITHM_CONFIGS[alg_name]
        classical_family = config["classical_alg_family"]
        mldsa_family = config["pq_key_family"]

        # Check sharing statistics
        classical_sharing = len(CLASSICAL_KEY_FAMILIES.get(classical_family, []))
        mldsa_sharing = len(MLDSA_KEY_FAMILIES.get(mldsa_family, []))


        # Generate or load the classical key for this family
        if classical_family not in self.generated_classical_keys:
            classical_priv_key = self.generate_classical_key_family(classical_family, config)
        else:
            # Load existing key
            key_info = self.generated_classical_keys[classical_family]
            key_file = key_info["private_key_file"]
            priv_path = self.cert_dir / key_file

            logging.info(f"✓ Loading existing classical key: {key_file}")
            with open(priv_path, "rb") as f:
                classical_priv_key = load_pem_private_key(f.read(), password=None)


        # Generate or load the ML-DSA key for this family
        if mldsa_family not in self.generated_mldsa_keys:
            mldsa_priv_path, mldsa_pub_path, mldsa_der_path, pq_pub_bytes = self.generate_mldsa_key_family(mldsa_family)
        else:
            # Load existing ML-DSA key
            key_info = self.generated_mldsa_keys[mldsa_family]
            mldsa_priv_path = key_info["private_key_path"]
            pq_pub_bytes = key_info["public_key_bytes"]
            logging.info(f"✓ Loading existing ML-DSA key: {mldsa_family}")

        # Get classical public key bytes (SAME key for all variants in family)
        classical_pub_bytes = self.get_classical_public_bytes(classical_priv_key, config)

        # Sign classical public key with ML-DSA key
        # In Catalyst, we sign the concatenation of PQ public key + classical public key
        data_to_sign = pq_pub_bytes + classical_pub_bytes
        pq_sig_path, pq_sig_bytes = self.sign_with_mldsa_key(
            mldsa_priv_path,
            data_to_sign,
            config["pq_sig_file_suffix"]
        )

        # Create CSR with PQ extension
        csr = self.create_catalyst_csr(
            config,
            classical_priv_key,
            pq_pub_bytes,
            pq_sig_bytes
        )

        # Save CSR
        csr_path = self.cert_dir / f"catalyst_csr{config['cert_suffix']}.pem"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        logging.info(f"  📄 Saved CSR: {csr_path.name}")

        # Create self-signed certificate
        cert_path = self.cert_dir / f"catalyst_cert{config['cert_suffix']}.pem"
        cert = self.create_self_signed_certificate(csr, classical_priv_key, config, cert_path)

        # Save certificate
        if cert is not None:
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logging.info(f"  Saved Certificate: {cert_path.name}")

        # Store results
        result = {
            "classical_priv": config["classical_key_file"],
            "classical_pub": config["classical_pub_file"],
            "pq_priv": f"pq_priv_{mldsa_family}.pem",
            "pq_pub": f"pq_pub_{mldsa_family}.pem",
            "pq_pub_der": f"pq_pub_{mldsa_family}.der",
            "pq_sig": f"pq_sig{config['pq_sig_file_suffix']}",
            "csr": f"catalyst_csr{config['cert_suffix']}.pem",
            "certificate": f"catalyst_cert{config['cert_suffix']}.pem",
            "config": config,
            "classical_key_family": classical_family,
            "mldsa_key_family": mldsa_family
        }

        # Track sharing statistics
        if classical_family not in self.sharing_stats:
            self.sharing_stats[classical_family] = {
                "type": "classical",
                "key_file": config["classical_key_file"],
                "certificates": [],
                "shared_by": classical_sharing
            }
        self.sharing_stats[classical_family]["certificates"].append(alg_name)

        if mldsa_family not in self.sharing_stats:
            self.sharing_stats[mldsa_family] = {
                "type": "mldsa",
                "key_file": f"pq_priv_{mldsa_family}.pem",
                "certificates": [],
                "shared_by": mldsa_sharing
            }
        self.sharing_stats[mldsa_family]["certificates"].append(alg_name)


        return result

    def generate_family(self, family_name, algorithms):

        results = {}
        for alg_name in algorithms:
            try:
                logging.info(f"\n Processing {alg_name}...")
                results[alg_name] = self.generate_catalyst_certificate(alg_name)
            except Exception as e:
                logging.error(f"❌ Failed to generate {alg_name}: {e}")
                import traceback
                traceback.print_exc()

        return results

    def generate_all_eddsa(self):
        """Generate all EdDSA-based Catalyst certificates"""
        eddsa_algorithms = [
            "MLDSA44-Ed25519-SHA512",
            "MLDSA65-Ed25519-SHA512",
            "MLDSA65-Ed448-SHAKE256",
            "MLDSA87-Ed448-SHAKE256"
        ]
        return self.generate_family("EDDSA", eddsa_algorithms)

    def generate_all_ecdsa(self):
        """Generate all ECDSA-based Catalyst certificates"""
        ecdsa_algorithms = [
            "MLDSA44-ECDSA-P256-SHA256",
            "MLDSA65-ECDSA-P384-SHA384",
            "MLDSA65-ECDSA-P256-SHA512",
            "MLDSA65-ECDSA-P384-SHA512",
            "MLDSA87-ECDSA-P384-SHA512",
            "MLDSA87-ECDSA-P521-SHA512"
        ]
        return self.generate_family("ECDSA", ecdsa_algorithms)

    def generate_all_rsa_pss(self):
        """Generate all RSA-PSS-based Catalyst certificates"""
        rsa_pss_algorithms = [
            "MLDSA44-RSA2048-PSS-SHA256",
            "MLDSA44-RSA3072-PSS-SHA384",
            "MLDSA65-RSA3072-PSS-SHA512",
            "MLDSA87-RSA3072-PSS-SHA512",
            "MLDSA65-RSA4096-PSS-SHA512",
            "MLDSA87-RSA4096-PSS-SHA512"
        ]
        return self.generate_family("RSA-PSS", rsa_pss_algorithms)

    def generate_all_rsa_pss_pss(self):
        """Generate all RSA-PSS-PSS-based Catalyst certificates"""
        rsa_pss_pss_algorithms = [
            "MLDSA44-RSA2048-PSS-PSS-SHA256",
            "MLDSA44-RSA4096-PSS-PSS-SHA384",
            "MLDSA65-RSA4096-PSS-PSS-SHA512"
        ]
        return self.generate_family("RSA-PSS-PSS", rsa_pss_pss_algorithms)

    def generate_all_rsa_pkcs1(self):
        """Generate all RSA-PKCS1-based Catalyst certificates"""
        rsa_pkcs1_algorithms = [
            "MLDSA44-RSA2048-PKCS15-SHA256",
            "MLDSA44-RSA3072-PKCS15-SHA256",
            "MLDSA65-RSA3072-PKCS15-SHA384",
            "MLDSA65-RSA4096-PKCS15-SHA512"
        ]
        return self.generate_family("RSA-PKCS1", rsa_pkcs1_algorithms)


    def generate_all(self):
        """Generate all certificates with DOUBLE key sharing"""

        self.check_openssl_version()

        all_results = {}


        # Process by classical family to optimize key generation
        for classical_family, algorithms in CLASSICAL_KEY_FAMILIES.items():

            for alg_name in algorithms:
                try:
                    logging.info(f"\n Processing {alg_name}...")
                    all_results[alg_name] = self.generate_catalyst_certificate(alg_name)
                except Exception as e:
                    logging.error(f"❌ Failed to generate {alg_name}: {e}")
                    import traceback
                    traceback.print_exc()

        # Create comprehensive summary
        self.create_double_sharing_summary(all_results)

        return all_results

    def create_double_sharing_summary(self, results):
        """Create summary highlighting DOUBLE key sharing"""
        total_certificates = len(results)
        classical_keys = len([k for k in self.sharing_stats.values() if k["type"] == "classical"])
        mldsa_keys = len([k for k in self.sharing_stats.values() if k["type"] == "mldsa"])

        summary = """Catalyst Certificate Generator - DOUBLE KEY SHARING SUMMARY
=======================================================================

DOUBLE KEY SHARING STRATEGY:
1. Classical keys shared by classical_alg_family
2. ML-DSA keys shared by ML-DSA variant (44/65/87)

CONFIGURATION:
- Total certificates: {total_certificates}
- Classical key families: {classical_families}
- ML-DSA key families: {mldsa_families} (ONLY 3 ML-DSA key pairs!)
- Classical key sharing ratio: {classical_ratio:.1f}%
- ML-DSA key sharing: 100% (only 3 key pairs total!)

KEY SHARING BY FAMILY:
======================
""".format(
            total_certificates=total_certificates,
            classical_families=len(CLASSICAL_KEY_FAMILIES),
            mldsa_families=len(MLDSA_KEY_FAMILIES),
            classical_ratio=len(CLASSICAL_KEY_FAMILIES) / total_certificates * 100
        )

        # Classical key sharing
        summary += f"\n🔑 CLASSICAL KEY SHARING:\n"
        summary += "=" * 40 + "\n"
        for family_name, stats in sorted(self.sharing_stats.items()):
            if stats["type"] == "classical":
                summary += f"\n{family_name}:\n"
                summary += f"  Key File: {stats['key_file']}\n"
                summary += f"  Certificates using this key: {len(stats['certificates'])}\n"
                summary += f"  Shared by design: {stats['shared_by']} algorithms\n"
                for cert_name in stats['certificates']:
                    config = TLS_ALGORITHM_CONFIGS.get(cert_name, {})
                    summary += f"  • {config.get('common_name', cert_name)}\n"

        # ML-DSA key sharing
        summary += f"\n⚡ ML-DSA KEY SHARING (ONLY 3 KEY PAIRS!):\n"
        summary += "=" * 40 + "\n"
        for family_name in ["mldsa44", "mldsa65", "mldsa87"]:
            if family_name in self.sharing_stats:
                stats = self.sharing_stats[family_name]
                summary += f"\n{family_name.upper()} ({MLDSA_KEY_FAMILIES[family_name][0]}):\n"
                summary += f"  Key File: {stats['key_file']}\n"
                summary += f"  Certificates using this key: {len(stats['certificates'])}\n"
                summary += f"  Shared by: {stats['shared_by']} certificates\n"
                for cert_name in stats['certificates']:
                    config = TLS_ALGORITHM_CONFIGS.get(cert_name, {})
                    summary += f"  • {config.get('common_name', cert_name)}\n"

        # Statistics
        summary += f"\n📊 DOUBLE KEY SHARING STATISTICS:\n"
        summary += "=" * 40 + "\n"
        summary += f"Total certificates generated: {total_certificates}\n"
        summary += f"Classical keys generated: {classical_keys}\n"
        summary += f"ML-DSA keys generated: {mldsa_keys}\n"
        summary += f"Storage saved (classical): {total_certificates - classical_keys} key pairs\n"
        summary += f"Storage saved (ML-DSA): {total_certificates - mldsa_keys} key pairs\n"
        summary += f"Total storage saved: {(total_certificates - classical_keys) + (total_certificates - mldsa_keys)} key pairs\n"
        summary += f"Overall efficiency: {(classical_keys + mldsa_keys) / (total_certificates * 2) * 100:.1f}% fewer key pairs\n"

        # Examples of double sharing
        summary += f"\n🎯 EXAMPLES OF DOUBLE KEY SHARING:\n"
        summary += "=" * 40 + "\n"

        examples = [
            ("MLDSA44-Ed25519-SHA512", "Shares classical_ed25519.pem AND pq_priv_mldsa44.pem"),
            ("MLDSA65-RSA3072-PSS-SHA512", "Shares classical_rsa3072_pss.pem AND pq_priv_mldsa65.pem"),
            ("MLDSA87-ECDSA-P384-SHA512", "Shares classical_ecdsa_p384.pem AND pq_priv_mldsa87.pem"),
        ]

        for alg_name, description in examples:
            if alg_name in results:
                result = results[alg_name]
                summary += f"\n• {description}:\n"
                summary += f"  Classical key: {result['classical_priv']}\n"
                summary += f"  ML-DSA key: {result['pq_priv']}\n"
                summary += f"  Certificate: {result['certificate']}\n"

        summary_path = self.cert_dir / "DOUBLE_KEY_SHARING_SUMMARY.md"
        with open(summary_path, "w") as f:
            f.write(summary)

class CatalystValidator:

    catalyst_oids = CATALYST_OIDS_EXTENDED

    @staticmethod
    def extract_pq_extension(cert):
        """Extract PQ extension from certificate"""
        # Find Catalyst extension
        catalyst_ext = None
        catalyst_oid = None
        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string
            if oid_str in CatalystValidator.catalyst_oids:
                catalyst_ext = ext
                catalyst_oid = oid_str
                break

        if not catalyst_ext:
            logging.error("   ❌ No Catalyst PQ extension found!")
            logging.error("   Expected one of:", list(CatalystValidator.catalyst_oids.values()))
            return None, None, None

        alg_name = CatalystValidator.catalyst_oids[catalyst_oid]

        if catalyst_ext.critical:
            logging.error("   ⚠️  WARNING: Extension is critical - legacy clients would reject!")

        # Decode PQ data
        try:
            pq_pub_bytes, pq_sig_bytes = decode_sequence(catalyst_ext.value.value)

            return pq_pub_bytes, pq_sig_bytes, alg_name

        except Exception as e:
            return None, None, None

    staticmethod
    def detect_ml_dsa_algorithm(pq_pub_bytes):
        """Detect ML-DSA algorithm based on public key size"""
        key_size = len(pq_pub_bytes)

        if key_size in ML_DSA_SIZES:
            return ML_DSA_SIZES[key_size]
        else:
            # Find closest size
            closest = min(ML_DSA_SIZES.keys(), key=lambda x: abs(x - key_size))
            return ML_DSA_SIZES[closest]

    @staticmethod
    def extract_classical_public_key(cert):
        """Extract classical public key in appropriate format"""
        public_key = cert.public_key()

        # Determine algorithm type from certificate
        sig_oid = cert.signature_algorithm_oid

        if sig_oid == SignatureAlgorithmOID.ED25519:
            # Ed25519: raw bytes
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        elif sig_oid == SignatureAlgorithmOID.ED448:
            # Ed448: raw bytes
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            # ECDSA/RSA: use DER encoding
            return public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    @staticmethod
    def validate_pq_signature(pq_pub_bytes, pq_sig_bytes, data, alg_name):
        """Validate PQ signature using OpenSSL"""

        # In Catalyst, the PQ signature signs the classical public key
        data_to_verify = data

        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f_pub:
            f_pub.write(pq_pub_bytes)
            pub_path = f_pub.name

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f_sig:
            f_sig.write(pq_sig_bytes)
            sig_path = f_sig.name

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f_data:
            f_data.write(data_to_verify)
            data_path = f_data.name

        try:
            # Detect ML-DSA algorithm
            ml_dsa_algo = CatalystValidator.detect_ml_dsa_algorithm(pq_pub_bytes)

            # Try to verify using pkeyutl (for ML-DSA)
            cmd = [
                'openssl', 'pkeyutl',
                '-verify',
                '-pubin',
                '-inkey', pub_path,
                '-sigfile', sig_path,
                '-in', data_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return True
            else:

                alt_cmd = [
                    'openssl', 'dgst',
                    '-sha512',
                    '-verify', pub_path,
                    '-signature', sig_path,
                    data_path
                ]

                alt_result = subprocess.run(
                    alt_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if alt_result.returncode == 0:
                    logging.info("   ✓ ML-DSA signature: VALID (alternative method)")
                    return True
                else:
                    if result.stderr:
                        logging.error(f"   Error: {result.stderr.strip()}")
                    return False

        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            return False
        finally:
            # Cleanup temporary files
            for path in [pub_path, sig_path, data_path]:
                try:
                    os.unlink(path)
                except:
                    pass

    def _match_with_catalyst_config(self, info, cert):
        """Try to match certificate with your TLS_ALGORITHM_CONFIGS"""
        # Check for Catalyst extension OID
        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string

            # Look for OID in your config
            for config_name, config in TLS_ALGORITHM_CONFIGS.items():
                if config["oid"] == oid_str:
                    info["catalyst_config_name"] = config_name
                    info["catalyst_common_name"] = config["common_name"]
                    info["pq_alg"] = config["pq_alg"]
                    info["classical_alg_family"] = config.get("classical_alg_family")
                    info["pq_key_family"] = config.get("pq_key_family")
                    info["cert_suffix"] = config.get("cert_suffix")
                    info["security_level"] = config.get("security_level")

                    # Override TLS code from config if available
                    if "tls_code" in config:
                        info["tls_code"] = config["tls_code"]
                        info["tls_name"] = config["tls_name"]

                    return True

        # If no Catalyst extension found, try to match by classical algorithm
        for config_name, config in TLS_ALGORITHM_CONFIGS.items():
            # Match by classical algorithm type
            if info.get("classical_alg") == config["classical_alg"]:

                # For ECDSA, match curve
                if info.get("classical_alg") == "ecdsa":
                    if info.get("curve") == config.get("curve"):
                        if info.get("hash_alg") == config.get("hash_alg"):
                            info["possible_catalyst_match"] = config_name
                            info["possible_common_name"] = config["common_name"]
                            info["possible_pq_alg"] = config["pq_alg"]
                            break

                # For RSA, match key size and padding
                elif info.get("classical_alg") == "rsa":
                    if info.get("key_size") == config.get("key_size"):
                        if info.get("padding") == config.get("padding"):
                            if info.get("hash_alg") == config.get("hash_alg"):
                                info["possible_catalyst_match"] = config_name
                                info["possible_common_name"] = config["common_name"]
                                info["possible_pq_alg"] = config["pq_alg"]
                                break

        return False


# ============================================================================
# MAIN FUNCTION WITH ENHANCED ARGUMENTS
# ============================================================================



# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Catalyst Certificate Tool - Generate and validate hybrid certificates for ALL TLS 1.3 algorithms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
═════════

Generate all certificates for ALL TLS 1.3 algorithms:
  python catalyst_tool.py generate --output-dir Cert

Generate specific algorithm families:
  python catalyst_tool.py generate --family eddsa --output-dir Cert
  python catalyst_tool.py generate --family ecdsa --output-dir Cert
  python catalyst_tool.py generate --family rsa-pss --output-dir Cert
  python catalyst_tool.py generate --family rsa-pss-pss --output-dir Cert
  python catalyst_tool.py generate --family rsa-pkcs1 --output-dir Cert

Generate specific algorithm:
  python catalyst_tool.py generate --algorithm MLDSA44-RSA4096-PSS-PSS-SHA384 --output-dir certificate

        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate Catalyst certificates')
    gen_parser.add_argument('--algorithm',
                            help='Specific algorithm to generate')
    gen_parser.add_argument('--family',
                            choices=['eddsa', 'ecdsa', 'rsa-pss-rsae', 'rsa-pss-pss', 'rsa-pkcs1', 'all'],
                            default='all',
                            help='Algorithm family to generate (default: all)')
    gen_parser.add_argument('--output-dir',
                            default='Cert',
                            help='Output directory (default: Cert)')

    # Validate command
    val_parser = subparsers.add_parser('validate', help='Validate Catalyst certificate')
    val_parser.add_argument('certificate',
                            help='Certificate file to validate')
    val_parser.add_argument('--ca',
                            help='CA certificate file (optional)')

    args = parser.parse_args()

    if args.command == 'generate':
        generator = CatalystGenerator(args.output_dir)

        if args.algorithm:
            # Generate specific algorithm
            generator.generate_catalyst_certificate(args.algorithm)
        else:
            # Generate by family
            if args.family == 'eddsa':
                generator.generate_all_eddsa()
            elif args.family == 'ecdsa':
                generator.generate_all_ecdsa()
            elif args.family == 'rsa-pss-rsae':
                generator.generate_all_rsa_pss()
            elif args.family == 'rsa-pss-pss':
                generator.generate_all_rsa_pss_pss()
            elif args.family == 'rsa-pkcs1':
                generator.generate_all_rsa_pkcs1()
            else:  # 'all'
                generator.generate_all()



if __name__ == "__main__":
    main()


