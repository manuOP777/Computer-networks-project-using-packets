import socket
import threading

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 12345  # Port to listen on

# Initialize a list to store connected clients
clients = []

# Function to handle client connections
def handle_client(conn, addr):
    print(f"New connection: {addr}")
    conn.send("Welcome to the chatroom!".encode())

    while True:
        try:
            message = conn.recv(1024).decode()
            if message:
                print(f"{addr}: {message}")
                broadcast(message, conn)
            else:
                remove_client(conn)
                break
        except:
            remove_client(conn)
            break

# Function to broadcast messages to all clients
def broadcast(message, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.send(message.encode())
            except:
                remove_client(client)

# Function to remove a client
def remove_client(conn):
    if conn in clients:
        clients.remove(conn)

# Main server function
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server listening on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
