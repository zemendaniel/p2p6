import time

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import threading
import socket
import json
from pydantic import BaseModel


class SenderMetadata(BaseModel):
    filename: str
    file_size: int
    friendly_name: str
    file_hash: str


class ReceivePeer:
    def __init__(self, friendly_name: str, api_url: str, port):
        self.friendly_name = friendly_name
        self.api_url = api_url
        self.private_key, self.public_key = ReceivePeer.__generate_rsa_pair()
        self.peer_id = self.__register()
        self.port = port

        self.sock = None
        self.is_listening = False
        self.conn = None
        self.listen_thread = None
        self.sender_metadata = None
        self.aes_key = None
        self.fernet = None

        self.__start_listening()

    @staticmethod
    def __generate_rsa_pair():
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pub_key = priv_key.public_key()
        return priv_key, pub_key

    def __register(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        response = requests.post(
            f"{self.api_url}/peers/register",
            json={"public_key": public_key_pem, "friendly_name": self.friendly_name}
        ).json()

        p_id = response.get("peer_id")
        if not p_id:
            raise Exception("Something went wrong registering the peer.")
        return p_id

    def __start_listening(self):
        self.is_listening = True
        self.listen_thread = threading.Thread(target=self.__listening_loop)
        self.listen_thread.start()

    def __stop_listening(self):
        self.is_listening = False
        if self.sock:
            self.sock.close()
        if self.conn:
            self.conn.close()
        if self.listen_thread:
            self.listen_thread.join(timeout=5)
        print("Stopped listening.")

    def __listening_loop(self):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sock.bind(("::", self.port))
        self.sock.listen(1)
        # print(f"Listening on port {self.port}...")
        self.conn, self.addr = self.sock.accept()

        with self.conn:
            while self.is_listening:
                header = b""
                while not header.endswith(b"\n"):
                    chunk = self.conn.recv(1)   # todo what if no chunk
                    header += chunk

                header = header.decode().strip()
                msg_type, length_str = header.split("|")
                length = int(length_str)
                payload = self.__receive_exact(length)  # todo what if no payload

                match msg_type:
                    case "ctrl":
                        print(f"[Receiver] Received control message: {payload.decode()}")
                        command = payload.decode()
                        if command == "done":
                            # todo validate the file hash
                            self.__stop_listening()
                            # todo graceful stop

                    case "key":
                        if self.aes_key:
                            continue
                        aes_key = self.private_key.decrypt(
                            payload,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        self.aes_key = aes_key
                        self.fernet = Fernet(aes_key)

                    case "metadata":
                        if self.sender_metadata:
                            continue
                        decrypted_bytes = self.fernet.decrypt(payload)
                        metadata = json.loads(decrypted_bytes.decode())
                        self.sender_metadata = SenderMetadata(**metadata)
                        print(f"{self.sender_metadata.friendly_name} wants to send you a file: {self.sender_metadata.filename}.")
                        # todo accept or reject

                    case "file":
                        decrypted_data = self.fernet.decrypt(payload)
                        with open(self.sender_metadata.filename, "wb") as f:
                            f.write(decrypted_data)

    def __handle_data(self, data):
        pass

    def __receive_exact(self, length):
        data = b""
        while len(data) < length:
            packet = self.conn.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data


