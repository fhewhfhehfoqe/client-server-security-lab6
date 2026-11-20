import os
import socket
import ssl
import json
import hashlib
import logging
import getpass

SERVER_HOST = "server"
SERVER_PORT = 5000
CA_FILE = os.environ.get("CA_FILE", "/certs/ca.crt")

logging.basicConfig(
    filename="/logs/client.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def main():
    username = input("Login: ")
    password = getpass.getpass("Password: ")
    message = input("Enter a message for the server: ")

    digest = hashlib.sha256(
        message.encode("utf-8")
    ).hexdigest()

    request = {
        "username": username,
        "password": password,
        "message": message,
        "sha256": digest
    }

    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA_FILE
    )

    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (SERVER_HOST, SERVER_PORT),
            timeout=5
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=SERVER_HOST
            ) as client:

                print("TLS established:", client.version())
                print("Cipher:", client.cipher()[0])

                certificate = client.getpeercert()

                print("Certificate subject:", certificate.get("subject"))
                print("Certificate issuer:", certificate.get("issuer"))

                logging.info(
                    "TLS connection established. Version=%s Cipher=%s",
                    client.version(),
                    client.cipher()[0]
                )

                client.sendall(
                    (json.dumps(request) + "\n").encode("utf-8")
                )

                response_file = client.makefile("rb")
                response_data = response_file.readline(65537)

                response = json.loads(response_data.decode("utf-8"))

                print("\nServer response:")
                print(json.dumps(response, indent=4, ensure_ascii=False))

                if response.get("status") == "success":
                    print("\nAuthentication and integrity check successful.")
                    logging.info("Authentication and message transfer successful.")
                else:
                    print("\nRequest rejected:", response.get("message"))
                    logging.warning(
                        "Server rejected request: %s",
                        response.get("message")
                    )

    except ssl.SSLCertVerificationError as error:
        print("Certificate verification failed:", error)
        logging.error("Certificate verification failed: %s", error)

    except ssl.SSLError as error:
        print("TLS error:", error)
        logging.error("TLS error: %s", error)

    except (OSError, ValueError) as error:
        print("Connection or data error:", error)
        logging.error("Connection or data error: %s", error)


if __name__ == "__main__":
    main()

