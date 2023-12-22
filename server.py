import socket
import threading

def handle_client(client_socket):
    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                break

            # Print the received data on the server side
            print(f"Received: {data.decode('utf-8')}")

            # Echo back the received data to the client
            client_socket.sendall(data)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('127.0.0.1', 5555))

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server listening on port 5555")

    try:
        while True:
            # Accept a connection from a client
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Start a new thread to handle the client
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

    except KeyboardInterrupt:
        print("Server shutting down.")
        server_socket.close()

if __name__ == "__main__":
    start_server()
