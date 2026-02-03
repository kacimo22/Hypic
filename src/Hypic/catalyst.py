#!/usr/bin/env python3
"""
Enhanced TLS 1.3 Signature Algorithm Negotiation for Catalyst Certificates
with Key Sharing Family Support
"""
import subprocess
import os
import json
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from Hypic.catalyst_tool import get_certificate_algorithm_info


# ============================================================================
# TLS 1.3 SIGNATURE ALGORITHM CODES
# ============================================================================

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

    @classmethod
    def get_name(cls, code):
        """Get human-readable name for signature algorithm code"""
        mapping = {
            cls.RSA_PKCS1_SHA256: "RSA-PKCS1-SHA256",
            cls.RSA_PKCS1_SHA384: "RSA-PKCS1-SHA384",
            cls.RSA_PKCS1_SHA512: "RSA-PKCS1-SHA512",
            cls.RSA_PSS_PSS_SHA256: "RSA-PSS-PSS-SHA256",
            cls.RSA_PSS_PSS_SHA384: "RSA-PSS-PSS-SHA384",
            cls.RSA_PSS_PSS_SHA512: "RSA-PSS-PSS-SHA512",
            cls.RSA_PSS_RSAE_SHA256: "RSA-PSS-RSAE-SHA256",
            cls.RSA_PSS_RSAE_SHA384: "RSA-PSS-RSAE-SHA384",
            cls.RSA_PSS_RSAE_SHA512: "RSA-PSS-RSAE-SHA512",
            cls.ECDSA_SECP256R1_SHA256: "ECDSA-P256-SHA256",
            cls.ECDSA_SECP384R1_SHA384: "ECDSA-P384-SHA384",
            cls.ECDSA_SECP521R1_SHA512: "ECDSA-P521-SHA512",
            cls.ED25519: "ED25519",
            cls.ED448: "ED448",
        }
        return mapping.get(code, f"Unknown (0x{code:04x})")


# ============================================================================
# ENHANCED SERVER CONFIGURATION LOADER
# ============================================================================

class ServerConfigLoader:
    """Loads server configuration with key sharing family support"""

    def __init__(self, config_file: str = None):
        self.tls_setting= {}
        self.config_file = Path(config_file) if config_file else None
        self.config_data = {}
        self.directories = {}
        self.key_sharing_families = {}
        self.catalyst_configs = {}
        self.algorithm_preferences = {}

        if config_file:
            self.load_config()

    def load_config(self) -> None:
        """Load configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                self.config_data = json.load(f)

            # Load directories
            self.directories = self.config_data.get('directories', {
                'certificates': 'Cert',
                'keys': 'Cert',
                'configs': 'config',
                'logs': 'logs'
            })

            # load TLS setting
            self.tls_setting = self.config_data.get('tls_settings', {})
            # Load key sharing families
            self.key_sharing_families = self.config_data.get('key_sharing_families', {})

            # Load Catalyst configs
            self.catalyst_configs = self.config_data.get('catalyst_configs', {})

            # Load algorithm preferences
            self.algorithm_preferences = self.config_data.get('algorithm_preferences', {})

        except Exception as e:
            logging.error(f"❌ Failed to load configuration: {e}")
            raise

    def get_certificates_dir(self) -> Path:
        """Get certificates directory path"""
        return Path(self.directories.get('certificates', 'Cert'))

    def get_keys_dir(self) -> Path:
        """Get keys directory path"""
        return Path(self.directories.get('keys', 'Cert'))

    def get_pq_kem(self) -> str:
        """Get keys directory path"""
        return str(self.tls_setting.get('pq_kem', 'KYBER512'))
    def get_enable_pq(self) -> bool:
        """Get keys directory path"""
        return self.tls_setting.get('enable_pq', 'True')

    def get_enabled_configs(self) -> List[Dict]:
        """Get all enabled Catalyst configurations"""
        return [
            config for config in self.catalyst_configs.values()
            if config.get('enabled', True)
        ]

    def get_configs_for_tls_code(self, tls_code: int) -> List[Dict]:
        """Get all enabled configs for a TLS code, sorted by priority"""
        configs = [
            config for config in self.get_enabled_configs()
            if config.get('tls_code') == tls_code
        ]


        # Sort by priority (lower number = higher priority)
        configs.sort(key=lambda x: x.get('priority', 999))

        return configs

    def get_preferred_config_for_tls_code(self, tls_code: int) -> Optional[Dict]:
        """Get the highest priority config for a TLS code"""
        configs = self.get_configs_for_tls_code(tls_code)
        return configs[0] if configs else None

    def get_server_preference_order(self, classical_alg: str = None) -> List[int]:
        """Get server's TLS algorithm preference order.

        Args:
            classical_alg: Optional algorithm family name or specific algorithm.
                          If None, returns all classical algorithms in preference order.
                          If provided, returns only algorithms from that family.

        Returns:
            List of TLS algorithm codes in preference order.
        """
        # Get all algorithm families from preferences
        classical_algorithms = {
            'ed25519': self.algorithm_preferences.get('ed25519', []),
            'ed448': self.algorithm_preferences.get('ed448', []),
            'ecdsa': self.algorithm_preferences.get('ecdsa', []),
            'rsa-pss-rsae': self.algorithm_preferences.get('rsa-pss-rsae', []),
            'rsa-pss-pss': self.algorithm_preferences.get('rsa-pss-pss', []),
            'rsa': self.algorithm_preferences.get('rsa', [])
        }

        # Get the classical preference order
        classical_preference_order = self.algorithm_preferences.get('classical_preference_order', [])
        algorithm_names = []
        # If no specific algorithm requested, return all in preference order
        if classical_alg is None:
            for alg in classical_preference_order:
                if alg in classical_algorithms:
                    algorithm_names.extend(classical_algorithms[alg])
        else:
            # Check if the input is a family name
            if classical_alg in classical_algorithms:
                # Return all algorithms from this family
                algorithm_names = classical_algorithms[classical_alg]

        # Convert algorithm names to TLS codes
        tls_codes = []
        for algo_name in algorithm_names:
            tls_code = self._algorithm_name_to_code(algo_name)
            if tls_code:
                tls_codes.append(tls_code)
            else:
                logging.warning(f"⚠️ No TLS code mapping for algorithm '{algo_name}'")

        return tls_codes

    @staticmethod
    def _algorithm_name_to_code(algo_name: str) -> Optional[int]:
        """Convert algorithm name string to TLS code"""
        mapping = {
            'ED25519': SignatureAlgorithm.ED25519,
            'ED448': SignatureAlgorithm.ED448,
            'ECDSA_SECP256R1_SHA256': SignatureAlgorithm.ECDSA_SECP256R1_SHA256,
            'ECDSA_SECP384R1_SHA384': SignatureAlgorithm.ECDSA_SECP384R1_SHA384,
            'ECDSA_SECP521R1_SHA512': SignatureAlgorithm.ECDSA_SECP521R1_SHA512,
            'RSA_PSS_RSAE_SHA256': SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
            'RSA_PSS_RSAE_SHA384': SignatureAlgorithm.RSA_PSS_RSAE_SHA384,
            'RSA_PSS_RSAE_SHA512': SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
            'RSA_PSS_PSS_SHA256': SignatureAlgorithm.RSA_PSS_PSS_SHA256,
            'RSA_PSS_PSS_SHA384': SignatureAlgorithm.RSA_PSS_PSS_SHA384,
            'RSA_PSS_PSS_SHA512': SignatureAlgorithm.RSA_PSS_PSS_SHA512,
            'RSA_PKCS1_SHA256': SignatureAlgorithm.RSA_PKCS1_SHA256,
            'RSA_PKCS1_SHA384': SignatureAlgorithm.RSA_PKCS1_SHA384,
            'RSA_PKCS1_SHA512': SignatureAlgorithm.RSA_PKCS1_SHA512,
        }

        return mapping.get(algo_name)

    def get_key_file_for_config(self, config: Dict, key_type: str) -> str:
        """
        Get the correct key file for a config, considering key sharing families

        Args:
            config: Catalyst configuration dictionary
            key_type: 'classical_private', 'classical_public', 'pq_private', 'pq_public', 'pq_pub_der'

        Returns:
            Key file name
        """
        classical_family = config.get('classical_alg_family')
        pq_family = config.get('pq_key_family')

        if key_type == 'classical_private':
            if classical_family and classical_family in self.key_sharing_families.get('classical', {}):
                return self.key_sharing_families['classical'][classical_family]['key_file']
            return config.get('classical_key_file', '')

        elif key_type == 'classical_public':
            if classical_family and classical_family in self.key_sharing_families.get('classical', {}):
                return self.key_sharing_families['classical'][classical_family]['pub_file']
            return config.get('classical_pub_file', '')

        elif key_type == 'pq_private':
            if pq_family and pq_family in self.key_sharing_families.get('pq', {}):
                return self.key_sharing_families['pq'][pq_family]['key_file']
            return config.get('pq_key_file', '')

        elif key_type == 'pq_public':
            if pq_family and pq_family in self.key_sharing_families.get('pq', {}):
                return self.key_sharing_families['pq'][pq_family]['pub_file']
            return config.get('pq_pub_file', '')

        elif key_type == 'pq_pub_der':
            if pq_family and pq_family in self.key_sharing_families.get('pq', {}):
                return self.key_sharing_families['pq'][pq_family].get('pub_der_file', '')
            return config.get('pq_pub_der_file', '')

        return ''


    def find_config_for_certificate(self, certificate: x509.Certificate) -> Optional[Dict]:
        """
        Find Catalyst config by analyzing certificate object

        Args:
            certificate: X509 certificate object

        Returns:
            Matching Catalyst config or None
        """
        try:
            # Get TLS algorithm from certificate
            alg_info = get_certificate_algorithm_info(cert=certificate)
            tls_code = alg_info["tls_code"]

            if not tls_code:
                return None

            # Get all configs for this TLS code
            configs = self.get_configs_for_tls_code(tls_code)

            if not configs:
                return None

            # If multiple, return highest priority
            return configs[0]  # Already sorted by priority

        except Exception as e:
            return None


# ============================================================================
# KEY-SHARING AWARE CATALYST NEGOTIATOR
# ============================================================================

class CatalystNegotiator:
    """
    Catalyst negotiator with intelligent key sharing support
    """

    def __init__(self, server_config: ServerConfigLoader):
        """Initialize with server configuration"""
        self.server_config = server_config
        self.certificates_dir = server_config.get_certificates_dir()
        self.keys_dir = server_config.get_keys_dir()

        # Cache for loaded keys (shared keys loaded once)
        self._classical_keys_cache = {}  # classical_family -> private_key
        self._pq_keys_cache = {}  # pq_family -> pq_key_data
        self._certificates_cache = {}  # cert_file -> certificate_chain

        # Server preference order
        self.server_preference = server_config.get_server_preference_order()

    def select_signature_algorithm(self, server_preference: List[int], client_algorithms: List[int]) -> Tuple[Optional[int], Optional[Dict]]:
        """
        Select the best signature algorithm considering priority, security, and key sharing

        Args:
            client_algorithms: List of TLS signature algorithm codes from client

        Returns:
            Tuple of (selected_tls_code, selected_config)
        """
        # Get intersection in server preference order
        for tls_code in server_preference:
            if tls_code in client_algorithms:
                configs = self.server_config.get_configs_for_tls_code(tls_code)
                if configs:
                    # Select highest priority config
                    selected_config = configs[0]
                    logging.info(f"✅ Selected {SignatureAlgorithm.get_name(tls_code)} "
                                 f"with {selected_config.get('pq_alg')} "
                                 f"(priority: {selected_config.get('priority')})")
                    return tls_code, selected_config

        return None, None

    def load_classical_private_key(self, config: Dict) -> Tuple[Any, Path]:
        """
        Load classical private key with caching for shared keys

        Args:
            config: Selected Catalyst configuration

        Returns:
            Tuple of (private_key_object, key_file_path)
        """
        try:
            # Get the actual key file considering sharing
            classical_family = config.get('classical_alg_family')
            key_file = self.server_config.get_key_file_for_config(config, 'classical_private')

            if not key_file:
                raise ValueError(f"No classical key file for config {config.get('config_id')}")

            # Check cache first (shared keys)
            if classical_family and classical_family in self._classical_keys_cache:
                return self._classical_keys_cache[classical_family], self.keys_dir / key_file

            # Load from file
            key_path = self.keys_dir / key_file
            if not key_path.exists():
                raise FileNotFoundError(f"Classical private key file not found: {key_path}")

            with open(key_path, 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)

            # Cache it if shared
            if classical_family:
                self._classical_keys_cache[classical_family] = private_key
                logging.debug(f"Cached classical key for family: {classical_family}")
            logging.debug(f"  Family: {classical_family}, Algorithm: {config.get('classical_alg')}")

            return private_key, key_path

        except Exception as e:
            logging.error(f"❌ Failed to load classical private key: {e}")
            raise

    def load_pq_private_key(self, config: Dict) -> Path:
        try:
            # Get the actual key file considering sharing
            pq_family = config.get('pq_key_family')
            pq_key_file = self.server_config.get_key_file_for_config(config, 'pq_private')

            if not pq_key_file:
                raise ValueError(f"No pq key file for config {config.get('config_id')}")

            # Check cache first (shared keys)
            if pq_family and pq_family in self._pq_keys_cache:
                logging.info(f"Using cached pq key from family: {pq_family}")
                return self.keys_dir / pq_key_file

            # Load from file
            pq_key_path = self.keys_dir / pq_key_file
            if not pq_key_path.exists():
                raise FileNotFoundError(f"pq private key file not found: {pq_key_path}")

            # Cache it if shared
            if pq_family:
                self._pq_keys_cache[pq_family] = pq_key_path
                logging.debug(f"Cached pq key for family: {pq_family}")
            return pq_key_path

        except Exception as e:
            logging.error(f"❌ Failed to load pq private key: {e}")
            raise

    def load_certificate_chain(self, config: Dict) -> Tuple[List[x509.Certificate], Path]:
        """
        Load certificate chain for the selected configuration

        Args:
            config: Selected Catalyst configuration

        Returns:
            Tuple of (certificate_chain_list, cert_file_path)
        """
        try:
            # Get certificate file
            cert_file = config.get('cert_file', '')
            if not cert_file:
                # Fallback to cert_suffix pattern
                cert_suffix = config.get('cert_suffix', '')
                cert_file = f"catalyst_cert{cert_suffix}.pem"

            cert_path = self.certificates_dir / cert_file

            if not cert_path.exists():
                raise FileNotFoundError(f"Certificate file not found: {cert_path}")

            # Check cache
            cache_key = str(cert_path)
            if cache_key in self._certificates_cache:
                logging.info(f" Using cached certificate: {cert_file}")
                return self._certificates_cache[cache_key], cert_path

            # Load certificate chain
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            # Parse PEM certificate chain
            certificates = []
            pem_blocks = cert_data.split(b'-----BEGIN CERTIFICATE-----')

            for block in pem_blocks[1:]:  # Skip first empty split
                cert_pem = b'-----BEGIN CERTIFICATE-----' + block
                certificate = x509.load_pem_x509_certificate(cert_pem)
                certificates.append(certificate)

            if not certificates:
                raise ValueError(f"No certificates found in {cert_file}")

            # Cache it
            self._certificates_cache[cache_key] = certificates

            logging.info(f"📜 Loaded certificate: {cert_file}")
            subject = certificates[0].subject.rfc4514_string()
            logging.debug(f"  Subject: {subject[:60]}..." if len(subject) > 60 else f"  Subject: {subject}")

            return certificates, cert_path

        except Exception as e:
            logging.error(f"❌ Failed to load certificate: {e}")
            raise

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
            raise

    def sign_with_mldsa(self, data_to_sign, config: dict) -> bytes:
        pq_priv_key_path=self.load_pq_private_key(config)
        # Write data to temp file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f_data:
            f_data.write(data_to_sign)
            data_path = f_data.name

        # Create temporary file for signature
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f_sig:
            sig_path = f_sig.name

        try:
            # Sign using OpenSSL
            self.run_openssl_command([
                "openssl", "pkeyutl",
                "-sign",
                "-inkey", str(pq_priv_key_path),
                "-in", data_path,
                "-out", str(sig_path),
                "-rawin"
            ], f"Signing with ML-DSA key")

            # Read signature
            with open(sig_path, "rb") as f:
                pq_sig_bytes = f.read()

            return pq_sig_bytes

        finally:
            # Clean up temp files
            for path in [data_path, sig_path]:
                try:
                    os.unlink(path)
                except:
                    pass


# ============================================================================
# CATALYST TLS HANDSHAKE MANAGER
# ============================================================================

class CatalystTLSManager:
    """Manages Catalyst TLS handshake with key sharing support"""

    def __init__(self, config_file: str):
        """Initialize with configuration file"""
        # Load configuration
        self.server_config = ServerConfigLoader(config_file)
        self.negotiator = CatalystNegotiator(self.server_config)

        # Current handshake state
        self.current_config = None
        self.current_private_key = None
        self.current_certificate_chain = None
