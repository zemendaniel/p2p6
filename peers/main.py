import receive
import send
import os

PORT = 59031
API_URL = "http://[::1]:8000"


def main():
    decision = input("Do you want to send or receive a file? (s/r): ")
    friendly_name = input("Enter a nickname: ")

    if decision == "r":
        save_path = input("Enter the path where you want to save the file: ") or r"C:\Users\zemen\Desktop"
        receive.ReceivePeer(friendly_name=friendly_name, save_path=save_path, api_url=API_URL, port=PORT)
    elif decision == "s":
        peer_id = input("Enter the peer ID you received: ")
        file_path = input("Enter the path to the file you want to send: ") or r"C:\Users\zemen\PycharmProjects\p2p6\test.txt"
        send.SendPeer(receiver_peer_id=peer_id, file_path=file_path, friendly_name=friendly_name, port=PORT, api_url=API_URL)


if __name__ == "__main__":
    main()
