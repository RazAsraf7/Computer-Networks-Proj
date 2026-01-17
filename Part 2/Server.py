import socket
import threading

local_hostname = socket.gethostname()

ip_addresses = socket.gethostbyname_ex(local_hostname)[2]

filtered_ips = [ip for ip in ip_addresses if not ip.startswith("127.")]

first_ip = filtered_ips[:1]

HOST = first_ip[0]
PORT = 15432
clients = {}

def handle_client(conn, addr):
    print(f"client connected in : {addr}")
    username = ""

    try:
        conn.send("Enter your username: ".encode("utf-8"))
        username = conn.recv(1024).decode("utf-8").strip()

        while username in clients:
            conn.send(f"Username '{username}' is already taken. Try another: ".encode("utf-8"))
            username = conn.recv(1024).decode("utf-8").strip()
        
        clients[username] = conn
        print(f"User {username} added to clients list")
        conn.send("Connected! Use format: @username message\nSend \'exit\' when you want to leave".encode("utf-8"))

        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            data_d = data.decode('utf-8').strip()
            
            if data_d.startswith("@"):
                parts = data_d.split(" ", 1)
                
                if len(parts) > 1:
                    target_tag, msg = parts
                    target = target_tag[1:]
                    
                    target_socket = clients.get(target)
                    if target_socket:
                        target_socket.send(f"[{username}] {msg}".encode("utf-8"))
                    else:
                        conn.send(f"System: User '{target}' not found.\n".encode("utf-8"))
                else:
                    conn.send("System: Error - Message cannot be empty.\n".encode("utf-8"))
            
            else:
                error_msg = "System: Invalid format. Please use '@username message' to chat.\n"
                conn.send(error_msg.encode("utf-8"))

            print(f"Log: {username} sent: {data_d}")

    except ConnectionResetError:
        print(f"client disconnected {addr}")
    except Exception as e:
        print(f"Error: {e}")
        
    finally:
        if username in clients:
            clients.pop(username)
        conn.close()
        print(f"Connection with {addr} closed")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"server is listening on: {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
        print(f"Active connections: {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()