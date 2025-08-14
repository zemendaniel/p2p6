import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import BaseModel, ConfigDict
from cryptography.hazmat.primitives import serialization


class PeerData(BaseModel):
    ip: str
    public_key: RSAPublicKey
    friendly_name: str

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SendPeer:
    def __init__(self, receiver_peer_id: str, file_path: str, api_url: str):
        self.receiver_peer_id = receiver_peer_id
        self.file_path = file_path
        self.api_url = api_url

        self.aes_key = Fernet.generate_key()
        self.receiver_peer: PeerData = self.__get_peer_data()
        print(f"You are connecting to: {self.receiver_peer.friendly_name}")

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

