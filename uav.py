import socket
import json
import time
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import airsim
from constants import ECC_CURVE, AES_KEY_SIZE, SESSION_TIMEOUT, LOG_FILE, MAX_FAILED_ATTEMPTS, MAX_PACKET_SIZE, SOCKET_TIMEOUT, AES_NONCE_SIZE

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(message)s')
logging.getLogger().addHandler(logging.StreamHandler())

def send_alert(conn, alert_msg):
    alert = {
        "timestamp": time.time(),
        "alert": alert_msg
    }
    try:
        conn.sendall(json.dumps(alert).encode())
        logging.info(f"Sent alert to GCS: {alert_msg}")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")

def fly_to_checkpoint(client, last_checkpoint):
    print(f"[UAV] Intruder detected! Returning to checkpoint at {last_checkpoint}")
    logging.info(f"Intruder detected! Returning to checkpoint at {last_checkpoint}")
    client.moveToPositionAsync(
        last_checkpoint.x_val,
        last_checkpoint.y_val,
        last_checkpoint.z_val,
        5
    ).join()

def main():
    client = airsim.MultirotorClient()
    client.confirmConnection()
    client.enableApiControl(True)
    client.armDisarm(True)
    client.takeoffAsync().join()

    last_checkpoint = client.getMultirotorState().kinematics_estimated.position

    uav_private_key = ec.generate_private_key(ECC_CURVE)
    uav_public_key = uav_private_key.public_key()
    uav_public_bytes = uav_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(SOCKET_TIMEOUT)
        try:
            s.connect(('localhost', 65432))
            logging.info("[UAV] Connected to GCS.")
        except Exception as e:
            print(f"[UAV] Failed to connect to GCS: {e}")
            return

        try:
            gcs_public_bytes = s.recv(MAX_PACKET_SIZE)
            gcs_public_key = serialization.load_pem_public_key(gcs_public_bytes)
            s.sendall(uav_public_bytes)

            shared_key = uav_private_key.exchange(ec.ECDH(), gcs_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=b'uav session key',
            ).derive(shared_key)
            aesgcm = AESGCM(derived_key)
            print("[UAV] Session key derived.")

        except Exception as e:
            print(f"[UAV] Key exchange failed: {e}")
            return

        s.settimeout(SESSION_TIMEOUT)
        failed_attempts = 0

        while True:
            try:
                try:
                    data = s.recv(MAX_PACKET_SIZE)
                    if not data:
                        print("[UAV] Connection closed by GCS.")
                        break
                except socket.timeout:
                    print("[UAV] No command received (timeout). Waiting...")
                    continue

                payload = json.loads(data.decode())
                if 'nonce' not in payload or 'ciphertext' not in payload:
                    raise ValueError("Missing required fields")

                nonce = bytes.fromhex(payload['nonce'])
                ciphertext = bytes.fromhex(payload['ciphertext'])

                if len(nonce) != AES_NONCE_SIZE:
                    raise ValueError("Invalid nonce length")

                message = aesgcm.decrypt(nonce, ciphertext, None)
                command_data = json.loads(message.decode())

                timestamp = command_data.get('timestamp', 0)
                command = command_data.get('command', "")

                if abs(time.time() - timestamp) > SESSION_TIMEOUT:
                    raise ValueError("Timestamp outside allowed window")

                lat, lon, alt = map(float, command.split(','))
                print(f"[UAV] Executing command: Fly to ({lat}, {lon}, {alt})")
                logging.info(f"Executing command: Fly to ({lat}, {lon}, {alt})")

                client.moveToPositionAsync(lat, lon, alt, 5).join()
                last_checkpoint = client.getMultirotorState().kinematics_estimated.position
                print("[UAV] Reached new checkpoint.")
                logging.info("Reached new checkpoint.")
                failed_attempts = 0

            except Exception as e:
                failed_attempts += 1
                alert_msg = f"Intruder command detected: {e}"
                print(f"[UAV] ALERT: {alert_msg}")
                logging.warning(alert_msg)
                send_alert(s, alert_msg)
                fly_to_checkpoint(client, last_checkpoint)

                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    print("[UAV] Too many failed attempts. Disconnecting.")
                    logging.error("Too many failed attempts - disconnecting.")
                    break

if __name__ == "__main__":
    main()