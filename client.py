import socket
import threading

# Client configuration
HOST = '127.0.0.1'  # Server IP address (use localhost if running on same machine)
PORT = 12345  # Server port

# Function to handle sending messages
def send_message(client):
    while True:
        message = input("")
        client.send(message.encode())

# Function to handle receiving messages
def receive_message(client):
    while True:
        try:
            message = client.recv(1024).decode()
            if message:
                print(message)
            else:
                break
        except:
            print("Connection closed.")
            break

# Main client function
def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    # Start threads for sending and receiving messages
    send_thread = threading.Thread(target=send_message, args=(client,))
    receive_thread = threading.Thread(target=receive_message, args=(client,))

    send_thread.start()
    receive_thread.start()

if __name__ == "__main__":
    start_client()
 
