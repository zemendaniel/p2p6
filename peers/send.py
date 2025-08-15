from hashlib import sha256
import os
import json
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import BaseModel, ConfigDict
from cryptography.hazmat.primitives import serialization, hashes
import queue
import socket
import threading


class PeerData(BaseModel):
    ip: str
    public_key: RSAPublicKey
    friendly_name: str

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SendPeer:
    def __init__(self, receiver_peer_id: str, file_path: str, friendly_name: str, port: int, api_url: str):
        self.receiver_peer_id = receiver_peer_id
        self.file_path = file_path
        self.api_url = api_url
        self.friendly_name = friendly_name
        self.port = port

        self.aes_key = Fernet.generate_key()
        self.fernet = Fernet(self.aes_key)
        self.receiver_peer: PeerData = self.__get_peer_data()

        self.sock = None
        # self.send_queue = queue.Queue()
        # self.is_sending = False
        self.send_thread = None
        self.conn = None

        self.__start_sending()

    def __get_peer_data(self):
        resp = requests.get(f"{self.api_url}/peers/{self.receiver_peer_id}")
        if not resp.ok:
            raise Exception("Failed to fetch peer data")
        response_data = resp.json()
        pem_str = response_data["public_key"]

        public_key_obj = serialization.load_pem_public_key(
            pem_str.encode(),
            backend=default_backend()
        )

        response_data["public_key"] = public_key_obj
        return PeerData(**response_data)

    def __construct_metadata(self):
        file_size = os.path.getsize(self.file_path)
        filename = os.path.basename(self.file_path)
        file_hash = self.__compute_file_hash()

        metadata = {
            "filename": filename,
            "file_size": file_size,
            "friendly_name": self.friendly_name,
            "file_hash": file_hash
        }
        metadata_bytes = json.dumps(metadata).encode()
        encrypted_metadata = self.fernet.encrypt(metadata_bytes)
        return encrypted_metadata

    def __compute_file_hash(self):
        hasher = sha256()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def __start_sending(self):
        # self.is_sending = True
        self.send_thread = threading.Thread(target=self.__start_send_thread)
        self.send_thread.start()

    # def __stop_sending(self):
    #     # self.is_sending = False
    #     if self.sock:
    #         self.sock.close()
    #     if self.conn:
    #         self.conn.close()
    #     if self.send_queue:
    #         self.send_queue.empty()
    #     if self.send_thread:
    #         self.send_thread.join(timeout=5)

    def __send_message(self, msg_type, data_bytes):
        header = f"{msg_type}|{len(data_bytes)}\n".encode()
        self.sock.sendall(header + data_bytes)

    def __start_send_thread(self):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        with self.sock:
            self.sock.connect((self.receiver_peer.ip, self.port))
            print(f"You have connected to: {self.receiver_peer.friendly_name}.")

            encrypted_aes_key = self.receiver_peer.public_key.encrypt(
                self.aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.__send_message("key", encrypted_aes_key)
            metadata = self.__construct_metadata()
            self.__send_message("metadata", metadata)

            with open(self.file_path, "rb") as f:
                data = f.read()
                encrypted_data = self.fernet.encrypt(data)
                self.__send_message("file", encrypted_data)

            self.__send_message("ctrl", b"done")

            if self.conn:
                self.conn.close()
            if self.sock:
                self.sock.close()

            print("You have successfully transferred the file.")

