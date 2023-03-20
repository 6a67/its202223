import subprocess

import base_class


class Certifier(base_class.Connector):
    def __init__(self):
        super().__init__()

        """
            using subprocess to call openssl to create a keypair
            using RSA with 4096 bit key length
            subject is the username
            the key is stored in client.key and the certificate in client.csr
        """
        subprocess.call(["openssl", "req", "-newkey", "rsa:4096", "-nodes", "-keyout",
                        "client.key", "-out", "client.csr", "-sha512", "-subj", f"/CN={self.username}"])

        # these subs do not work
        self.subscribe(f"/pki/sign_response/{self.username}")
        self.on_connect_subscribe(f"/pki/sign_response/{self.username}")

        self.on_message(self.retrieve_cert)
        self.connect()
        # I don't really know why, but it does not seem to work if I subscribe to the topic "before" connecting
        self.subscribe(f"/pki/sign_response/{self.username}")

    def retrieve_cert(self, client, userdata, msg):
        print("Certificate received")
        with open("client.pem", "wb") as f:
            f.write(msg.payload)
        self.disconnect()
        self.loop_stop()

    def certify(self):
        with open("client.csr", "rb") as f:
            self.publish(f"/pki/sign_request/{self.username}", f.read())


if __name__ == "__main__":
    certifier = Certifier()
    certifier.certify()
    certifier.loop_forever()
