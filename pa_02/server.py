import argparse
import random
import signal
import socket
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# signal handling for SIGINT


def signal_handler(sig, frame):
    global s
    s.close()
    print("\nConnection closed")
    exit(0)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def dhke(client_secret: int, conn) -> int:
    """
    Performs the Diffie-Hellman key exchange with the client.
    :param client_secret: The server's secret (int) during the DH key exchange
    :param conn: The connection to the client
    :return: The shared secret (int) between the client and the server
    """

    # waiting for client to send public key
    data = conn.recv(1024)

    # read first 32 bytes as n
    n = int.from_bytes(data[:32], "big")

    # read next byte as g
    g = int.from_bytes(data[32:33], "big")

    # read next 32 bytes as client public key
    client_public_key = int.from_bytes(data[33:], "big")

    # sending public key to client
    public_key = pow(g, client_secret, n)
    message = public_key.to_bytes(32, "big")
    conn.sendall(message)

    shared_secret = pow(client_public_key, client_secret, n)

    return shared_secret


class HkdfLabel():
    length: int = 0
    label_length: int = 0
    label: str = ""
    context_length: int = 0
    context: str = ""
    _bytes = b""

    def add(self, x, length):
        self.bytes += x.to_bytes(length, 'big')

    def __bytes__(self):
        hkdf_label = struct.pack("!H", self.length)
        hkdf_label += struct.pack("B", len(self.label))
        hkdf_label += self.label.encode()
        hkdf_label += struct.pack("B", len(self.context))
        hkdf_label += self.context.encode()
        return hkdf_label


def hkdf_expand(secret: int, info: HkdfLabel, length: int) -> bytes:
    """
    Performs the HKDF expand function.
    :param secret: The secret (int) to expand
    :param info: The info (HkdfLabel) to expand the secret with
    :param length: The length of the expanded secret
    :return: The expanded secret (bytes)
    """

    hkdf = HKDFExpand(
        algorithm=hashes.SHA384(),
        length=length,
        info=bytes(info),
        backend=default_backend()
    )

    secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, "big")

    return hkdf.derive(secret_bytes)


def hkdf_expand_label(secret: int, label: str, context: str, length: int) -> bytes:
    """
    Performs the HKDF expand label function.
    :param secret: The secret to expand
    :param label: The label to expand the secret with
    :param context: The context to expand the secret with
    :param length: The length of the expanded secret
    :return: The expanded secret
    """

    info = HkdfLabel()
    info.length = length
    info.label = "tls13 " + label
    info.label_length = len(info.label)
    info.context = context
    info.context_length = len(info.context)

    return hkdf_expand(secret, info, length)


def adg(message):
    opaque_type = 23
    additional_data = opaque_type.to_bytes(
        1, "big") + b"\x03\x03" + len(message).to_bytes(1, "big")
    return additional_data


def client_connection(conn, y):
    # perform DHKE
    print("[STATUS] Establishing a shared secret using DH")
    shared_secret = dhke(y, conn)

    print(f"[INFO] established_secret: {shared_secret}")

    print("[STATUS] Deriving Keys and IVs")
    key_length = 32
    iv_length = 12
    client_write_key = hkdf_expand_label(
        shared_secret, "client" + " ap traffic key", "", key_length)
    client_write_iv = hkdf_expand_label(
        shared_secret, "client" + " ap traffic iv", "", iv_length)

    server_write_key = hkdf_expand_label(
        shared_secret, "server" + " ap traffic key", "", key_length)
    server_write_iv = hkdf_expand_label(
        shared_secret, "server" + " ap traffic iv", "", iv_length)

    print(f"[INFO] client_key: {client_write_key}")
    print(f"[INFO] server_key: {server_write_key}")
    print(f"[INFO] client_iv: {client_write_iv}")
    print(f"[INFO] server_iv: {server_write_iv}")

    sequence_number = 0

    while True:
        # waiting for client to send data
        print("[STATUS] waiting to receive a message from the client")
        data = conn.recv(1024)
        # not all recv always worked for some reason. This is just a confirmation that the server received the message and the client is waiting for the servers response
        conn.sendall("received".encode())
        additional_data = conn.recv(1024)
        conn.sendall("received".encode())
        nonce = conn.recv(1024)
        conn.sendall("received".encode())

        print(f"[INFO] received_data: {data}")
        print(f"[INFO] additional_data_receiving: {additional_data}")
        print(f"[INFO] nonce_receiving: {nonce}")

        int.from_bytes(data[:1], "big")

        # read remaining bytes as encrypted message
        encrypted_message = data[1:]

        # decrypt message
        cipher = AESGCM(client_write_key)
        decrypted_message = cipher.decrypt(
            nonce, encrypted_message, additional_data).decode()
        print(f"[INFO] received_decrypted_message: {decrypted_message}")

        print("[STATUS] sending an answer message to the client")

        # nonce calculation
        padded_sequence_number = sequence_number.to_bytes(8, "big")
        padded_sequence_number = b"\x00" * 4 + padded_sequence_number
        nonce = bytes([a ^ b for a, b in zip(
            server_write_iv, padded_sequence_number)])
        sequence_number += 1

        # encrypt message
        decrypted_message = "echo: " + decrypted_message
        additional_data = adg(decrypted_message)
        cipher = AESGCM(server_write_key)

        cipher_message = cipher.encrypt(
            nonce, decrypted_message.encode(), additional_data)
        print(f"[INFO] message_to_send: {decrypted_message}")

        conn.sendall(len(decrypted_message).to_bytes(
            1, "big") + cipher_message)
        conn.recv(1024)

        print(f"[INFO] additional_data_sending: {additional_data}")
        conn.sendall(additional_data)
        conn.recv(1024)

        print(f"[INFO] nonce_sending: {nonce}")
        conn.sendall(nonce)
        conn.recv(1024)


if __name__ == '__main__':
    # add signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # ArgumentParser
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port", help="Port number, where the server is waiting for connection requests", required=True, type=int)
    rnds = random.SystemRandom()
    parser.add_argument("--y", help="The server's secret (int) during the DH key exchange",
                        required=False, type=int, default=rnds.randint(1, 2**10))

    args = parser.parse_args()

    s.bind(('', args.port))

    while True:
        print("[STATUS] waiting for a new connection")
        s.listen(1)
        conn, addr = s.accept()
        print(f"[STATUS] accepted connection from {addr}")

        try:
            client_connection(conn, args.y)
        except:
            pass

        conn.close()
