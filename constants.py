from cryptography.hazmat.primitives.asymmetric import ec

ECC_CURVE = ec.SECP256R1()
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
SESSION_TIMEOUT = 5 
LOG_FILE = "uav_system.log"
MAX_FAILED_ATTEMPTS = 5
MAX_PACKET_SIZE = 2048
SOCKET_TIMEOUT = 10
