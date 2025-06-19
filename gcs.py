import socket
import json
import time
import logging
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from constants import ECC_CURVE, AES_KEY_SIZE, LOG_FILE, AES_NONCE_SIZE

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(message)s')
logging.getLogger().addHandler(logging.StreamHandler())

def main():
    gcs_private_key = ec.generate_private_key(ECC_CURVE)
    gcs_public_key = gcs_private_key.public_key()
    gcs_public_bytes = gcs_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 65432))
        s.listen(1)
        print("[GCS] Waiting for UAV to connect...")
        conn, addr = s.accept()
        with conn:
            print(f"[GCS] UAV connected from {addr}")
            conn.sendall(gcs_public_bytes)

            conn.settimeout(15)
            uav_public_bytes = conn.recv(1024)
            uav_public_key = serialization.load_pem_public_key(uav_public_bytes)

            shared_key = gcs_private_key.exchange(ec.ECDH(), uav_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=b'uav session key',
            ).derive(shared_key)
            aesgcm = AESGCM(derived_key)

            while True:
                try:
                    coords = input("Enter coordinates (lat,lon,alt): ")
                    lat, lon, alt = map(float, coords.split(','))

                    command = {
                        "timestamp": time.time(),
                        "command": f"{lat},{lon},{alt}"
                    }

                    plaintext = json.dumps(command).encode()
                    nonce = os.urandom(AES_NONCE_SIZE)
                    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

                    packet = {
                        "nonce": nonce.hex(),
                        "ciphertext": ciphertext.hex()
                    }

                    conn.sendall(json.dumps(packet).encode())
                    logging.info(f"Sent command to UAV: {command}")

                except Exception as e:
                    print(f"[GCS] Error: {e}")
                    break

if __name__ == "__main__":
    main()