import argparse
import logging
import os
import signal
import ssl

import paho.mqtt.client as mqtt

logging.basicConfig(level=logging.DEBUG)


class Connector:

    parser = argparse.ArgumentParser()

    def __init__(self):
        self.client = mqtt.Client()

        # ArgumentParser
        self.parser.add_argument("-H", help="hostname of the broker",
                                 required=False, type=str, default="vm076.rz.uos.de")
        self.parser.add_argument(
            "-p", help="port of the broker", required=False, type=int, default=1883)
        self.parser.add_argument(
            "-u", help="username", required=True, type=str)
        self.parser.add_argument(
            "-P", help="password", required=False, type=str)
        self.parser.add_argument(
            "--ca", help="certificate of our own certificate authority", required=False, type=str)

        # Task 3 arguments
        self.parser.add_argument(
            "--cert", help="certificate of the client", required=False, type=str)
        self.parser.add_argument(
            "--key", help="key of the client", required=False, type=str)

        self.args = self.parser.parse_args()

        self.host = self.args.H
        self.port = self.args.p
        self.username = self.args.u

        # check if the files provided exist
        if self.args.cert and os.path.isfile(self.args.cert):
            self.cert = self.args.cert
        else:
            self.cert = None

        if self.args.key and os.path.isfile(self.args.key):
            self.key = self.args.key
        else:
            self.key = None

        if self.args.ca:
            if not os.path.isfile(self.args.ca):
                print("Provided CA certificate file does not exist")
                exit(1)

        if self.cert or self.key:
            if not (self.args.ca and self.cert and self.key):
                print("Please provide the --ca, --cert, and --key arguments together")
                exit(1)

            # set the client certificate and key
            self.client.tls_set(ca_certs=self.args.ca,
                                certfile=self.cert, keyfile=self.key)
        else:
            if not self.args.P:
                print("Please provide a password")
                exit(1)

        if self.args.P:
            self.password = self.args.P
            self.client.username_pw_set(self.username, self.password)

        if self.args.ca and not self.cert:
            self.client.tls_set(ca_certs=self.args.ca)

        # add signal handler for SIGINT
        signal.signal(signal.SIGINT, self.__signal_handler)

    def connect(self):
        try:
            self.client.connect(self.host, self.port, 60)
        except ssl.SSLCertVerificationError:
            print("SSL Certificate Verification Error")
            exit(1)
        except ConnectionResetError:
            print("Connection Reset Error - Server might not support certificates")
            exit(1)

    def publish(self, topic, payload):
        self.client.publish(topic, payload)

    def subscribe(self, topic):
        self.client.subscribe(topic)

    def __on_message(self, client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))

    def on_message(self, callback):
        self.client.on_message = callback

    def __on_connect_subscribe(self, client, userdata, flags, rc):
        for topic in self.topics:
            self.subscribe(topic)

    def on_connect_subscribe(self, *topics):
        self.client.on_connect = self.__on_connect_subscribe
        self.topics = topics

    def loop_forever(self):
        self.client.loop_forever()

    def loop_stop(self):
        self.client.loop_stop()

    def disconnect(self):
        self.client.disconnect()

    def __signal_handler(self, sig, frame):
        self.disconnect()
