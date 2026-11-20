import socket
import ssl
import json
import os
import hashlib
import hmac
import logging
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5000

CERT_FILE = "/certs/server.crt"
KEY_FILE = "/certs/server.key"

AUTH_USER = os.getenv("AUTH_USER", "student")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "SecurePass123!")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("/logs/server.log"),
        logging.StreamHandler()
    ]
)

def send_response(conn, data):
    conn.sendall(
        (json.dumps(data) + "\n").encode("utf-8")
    )

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen()

        logging.info("TLS server started on port %s", PORT)

        with context.wrap_socket(listener, server_side=True) as server:
            while True:
                try:
                    conn, addr = server.accept()

                    with conn:
                        logging.info(
                            "Connection established from %s:%s",
                            addr[0], addr[1]
                        )

                        logging.info(
                            "TLS=%s | Cipher=%s",
                            conn.version(),
                            conn.cipher()[0]
                        )

                        file = conn.makefile("rb")
                        raw_data = file.readline(65537)

                        if not raw_data or len(raw_data) > 65536:
                            logging.warning("Empty or oversized request")
                            continue

                        try:
                            request = json.loads(raw_data.decode("utf-8"))
                        except (ValueError, UnicodeDecodeError):
                            logging.warning("Invalid request format")
                            send_response(conn, {
                                "status": "error",
                                "message": "Invalid request"
                            })
                            continue

                        username = request.get("username")
                        password = request.get("password")

                        if not (
                            isinstance(username, str)
                            and isinstance(password, str)
                            and hmac.compare_digest(username, AUTH_USER)
                            and hmac.compare_digest(password, AUTH_PASSWORD)
                        ):
                            logging.warning(
                                "Authentication failed from %s",
                                addr[0]
                            )
                            send_response(conn, {
                                "status": "error",
                                "message": "Authentication failed"
                            })
                            continue

                        logging.info(
                            "Authentication successful for user %s",
                            username
                        )

                        message = request.get("message")
                        received_hash = request.get("sha256")

                        if not isinstance(message, str):
                            send_response(conn, {
                                "status": "error",
                                "message": "Invalid message"
                            })
                            continue

                        calculated_hash = hashlib.sha256(
                            message.encode("utf-8")
                        ).hexdigest()

                        if not isinstance(received_hash, str) or not hmac.compare_digest(
                            calculated_hash, received_hash
                        ):
                            logging.warning(
                                "Integrity verification failed from %s",
                                addr[0]
                            )
                            send_response(conn, {
                                "status": "error",
                                "message": "Integrity check failed"
                            })
                            continue

                        logging.info(
                            "Message received successfully. SHA-256 verified."
                        )

                        response = {
                            "status": "success",
                            "message": "Message received securely",
                            "received_message": message,
                            "sha256": calculated_hash,
                            "time": datetime.now().isoformat(timespec="seconds")
                        }

                        send_response(conn, response)

                except ssl.SSLError as error:
                    logging.error("TLS error: %s", error)

                except OSError as error:
                    logging.error("Network error: %s", error)


if __name__ == "__main__":
    main()
