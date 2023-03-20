import argparse
import random
import signal
import socket
import struct
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

n = 2**256 - 189
g = 2
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# signal handling for SIGINT


def signal_handler(sig, frame):
    global s
    s.close()
    print("\nConnection closed")
    exit(0)


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


def dhke(client_secret: int) -> int:
    """
    Performs the Diffie-Hellman key exchange with the server.
    :param client_secret: The client's secret (int) during the DH key exchange
    :return: The shared secret (int) between the client and the server
    """

    public_key = pow(g, client_secret, n)

    message = n.to_bytes(32, "big") + g.to_bytes(1, "big") + \
        public_key.to_bytes(32, "big")

    s.sendall(message)

    data = s.recv(1024)
    server_public_key = int.from_bytes(data, "big")

    shared_secret = pow(server_public_key, client_secret, n)

    return shared_secret


def adg(message):
    opaque_type = 23
    additional_data = opaque_type.to_bytes(
        1, "big") + b"\x03\x03" + len(message).to_bytes(1, "big")
    return additional_data


if __name__ == '__main__':
    # add signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # ArgumentParser
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--serv", help="IPv4 address of your server", required=True, type=str)
    parser.add_argument(
        "--port", help="Port number, where your server is waiting for connection requests", required=True, type=int)
    rnds = random.SystemRandom()
    parser.add_argument("--x", help="The client's secret (int) during the DH key exchange",
                        required=False, type=int, default=rnds.randint(1, 2**10))

    args = parser.parse_args()

    print(f"[STATUS] Connecting to {args.serv}:{args.port}")

    while True:
        try:
            s.connect((args.serv, args.port))
            break
        except:
            print("[STATUS] Connection failed. Trying again...")
            time.sleep(2)

    print("[STATUS] Establishing a shared secret using DH")
    shared_secret = dhke(args.x)
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
        plain_message = input(
            "[STATUS] Please type in a message that should be send...\n")
        if len(plain_message) < 1 or len(plain_message) > 100:
            print("[ERROR] Message is too long or too short")
            continue

        # additional data
        additional_data = adg(plain_message)

        # nonce calculation
        padded_sequence_number = sequence_number.to_bytes(8, "big")
        padded_sequence_number = b"\x00" * 4 + padded_sequence_number
        # xor the client_write_iv with the padded_sequence_number
        nonce = bytes([a ^ b for a, b in zip(
            client_write_iv, padded_sequence_number)])
        sequence_number += 1

        # encrypt the plain message using AESGCM and the key, nonce and additional data
        cipher = AESGCM(client_write_key)
        cipher_message = cipher.encrypt(
            nonce, plain_message.encode(), additional_data)

        # send the cipher message to the server
        print("[STATUS] Sending the cipher message to the server...")
        print(f"[INFO] message_to_send: {plain_message}")
        print(f"[INFO] additional_data_sending: {additional_data}")
        print(f"[INFO] nonce_sending: {nonce}")

        s.sendall(len(plain_message).to_bytes(1, "big") + cipher_message)
        # wait until the server has received the message
        s.recv(1024)    # see server why this is necessary
        s.sendall(additional_data)
        s.recv(1024)
        s.sendall(nonce)
        s.recv(1024)

        # receive the cipher message from the server
        print("[STATUS] Waiting for the answer message...")

        cipher_message = s.recv(1024)
        s.sendall("received".encode())
        additional_data = s.recv(1024)
        s.sendall("received".encode())
        nonce = s.recv(1024)
        s.sendall("received".encode())

        print(f"[INFO] received_data: {cipher_message}")
        print(f"[INFO] additional_data_receiving: {additional_data}")
        print(f"[INFO] nonce_receiving: {nonce}")

        message_length = int.from_bytes(cipher_message[:1], "big")

        # read remaining bytes as encrypted message
        encrypted_message = cipher_message[1:]

        # decrypt the cipher message using AESGCM and the key, nonce and additional data
        cipher = AESGCM(server_write_key)
        plain_message = cipher.decrypt(
            nonce, encrypted_message, additional_data).decode()
        print(f"[INFO] received_decrypted_message: {plain_message}")
