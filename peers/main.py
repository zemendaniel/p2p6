import receive
import send

PORT = 59031
API_URL = "http://[::1]:8000"


def main():
    decision = input("Do you want to send or receive a file? (s/r): ")
    friendly_name = input("Enter a nickname: ")

    if decision == "r":
        peer_id = receive.ReceivePeer(friendly_name=friendly_name, api_url=API_URL, port=PORT).peer_id
        print(f"Your peer ID is: {peer_id}\nSend this ID to the person who will send you the file.")
    elif decision == "s":
        peer_id = input("Enter the peer ID you received: ")
        file_path = input("Enter the path to the file you want to send: ")
        send_peer = send.SendPeer(receiver_peer_id=peer_id, file_path=file_path, api_url="http://[::1]:8000")


if __name__ == "__main__":
    main()
