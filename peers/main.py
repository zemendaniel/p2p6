import receive
import send
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PORT = 59031
PROD = not bool(os.environ.get("DEV"))
if PROD:
    API_URL = "http://p2p6.zemendaniel.hu:8000"
else:
    API_URL = os.environ.get("API_URL")


def main():
    decision = input("Do you want to send or receive a file? (s/r): ")
    if PROD:
        friendly_name = input("Enter a nickname: ")
    else:
        friendly_name = "test"

    if decision == "r":
        if PROD:
            save_path = input("Enter the path where you want to save the file: ")
        else:
            save_path = os.environ.get("SAVE_PATH")
        receive.ReceivePeer(friendly_name=friendly_name, save_path=save_path, api_url=API_URL, port=PORT)
    elif decision == "s":
        peer_id = input("Enter the peer ID you received: ")
        if PROD:
            file_path = input("Enter the path to the file you want to send: ")
        else:
            file_path = os.environ.get("TEST_FILE")

        send.SendPeer(receiver_peer_id=peer_id, file_path=file_path, friendly_name=friendly_name, port=PORT, api_url=API_URL)


if __name__ == "__main__":
    main()
