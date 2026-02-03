# Hypic

**Hypic** is a Python library that extends the existing `aioquic` QUIC implementation to provide **post-quantum security** while maintaining **backward compatibility**.  

## Acknowledgments
Hypic is based on and extends the **aioquic** QUIC implementation by Jeremy Lainé and its contributors (see AUTHORS.txt).

Modifications and extensions by Imine Belkacem.

---

The library introduces a **hybrid key establishment** combining classical ECDHE with **ML-KEM (Kyber)** to protect session keys against future quantum adversaries.  
It supports **two types of clients**:

- **Legacy clients**: use standard QUIC/TLS 1.3 mechanisms.  
- **Post-quantum–aware clients**: negotiate hybrid classical–post-quantum key exchange and post-quantum session resumption.

Hypic also integrates **Catalyst certificates** for **post-quantum authentication**, avoiding reliance on classical-only signatures while remaining interoperable with existing certificate infrastructures.

---

## Requirements

- Python >= 3.9  
- OpenSSL >= 3.5  
- pip dependencies will be installed automatically  

> ⚠️ Hypic will check the OpenSSL version at runtime and exit if it is below 3.5.

---

## Installation

### From PyPI (after release)

```bash
pip install hypic

---

## Runing the protocol
The server_config.json contains the server configuration.
1- Get into the Hypic directory
2- Run the command: source .venv/bin/activate
3- pip install -e .

4- Run the server: python3 examples/http3_server.py --catalyst-config server_config.json
5- To run a legacy client: python3 examples/http3_client.py --insecure  https://localhost:4433/ 
6-To run a PQ-aware client with initial handshake: 
python3 examples/http3_client.py --insecure  https://localhost:4433/ --enable-pq  kyber768 --max-rpqh-period 3600 ## this run the client with initial hanshake, sending a clientHello with kyber768 public key.
----------------------------------------------------------------------------------------------------------
7-A fter runing the PQ initial handshake, a session_ticket is stored at the Client for session resumption. The session_ticket contains a new server PQ public key. 

8-To run a PQ-aware client with resumed handshake: 
python3 examples/http3_client.py --insecure  https://localhost:4433/ --enable-pq  kyber768 --max-rpqh-period 3600 --session-ticket ## this run the client with resumed hanshake, sending a clientHello with kyber768 public key.

