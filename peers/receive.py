import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import threading
import socket


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
        self.listen_thread = threading.Thread(target=self.__handle_start)
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

    def __handle_start(self):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sock.bind(("::", self.port))
        self.sock.listen(1)
        print(f"Listening on port {self.port}...")
        self.conn, self.addr = self.sock.accept()

        while self.is_listening:
            try:
                data = self.conn.recv(4096)
                if not data:
                    print("[Receiver] Client disconnected")
                    break
                print(f"[Receiver] Received: {data!r}")
            except ConnectionResetError:
                print("[Receiver] Connection reset by peer")
                break

        # todo i was here