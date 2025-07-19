import socket
import threading

def handle_client(client_socket, client_address, reply_message):
    """Handle individual client connections"""
    try:
        print(f"Connection from {client_address}")
        
        # Receive data from client
        data = client_socket.recv(1024).decode('utf-8')
        if data:
            print(f"Received: {data}")
            
            # Send reply message
            client_socket.send(reply_message.encode('utf-8'))
            print(f"Sent reply to {client_address}")
        
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()

def start_server(port=8082, reply_message="Hello from server!"):
    """Start the TCP server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow reuse of address
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind to localhost and specified port
        server_socket.bind(('localhost', port))
        server_socket.listen(5)
        
        print(f"Server listening on localhost:{port}")
        print(f"Reply message: '{reply_message}'")
        print("Press Ctrl+C to stop the server")
        
        while True:
            # Accept incoming connections
            client_socket, client_address = server_socket.accept()
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, reply_message)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    # You can customize the reply message here
    custom_message = "Welcome! Your message was received."
    start_server(port=8082, reply_message=custom_message)