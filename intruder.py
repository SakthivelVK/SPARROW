import socket
import json
import time
import random

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect(('localhost', 65432))
            print("[INTRUDER] Connected to UAV (simulated).")

            while True:
                coords = input("Enter fake coordinates (lat,lon,alt): ")
                lat, lon, alt = map(float, coords.split(','))
                fake_packet = {
                    "nonce": "badnonce",
                    "ciphertext": f"invalid_ciphertext_{random.randint(1000, 9999)}"
                }
                s.sendall(json.dumps(fake_packet).encode())
                print("[INTRUDER] Sent malicious command.")

        except Exception as e:
            print(f"[INTRUDER] Connection failed or rejected: {e}")

if __name__ == "__main__":
    main()