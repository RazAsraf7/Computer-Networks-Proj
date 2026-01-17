import socket
import sys
import threading
import ipaddress
import tkinter as tk
from tkinter import scrolledtext
import tkinter.messagebox as messagebox

USER_COLORS = ["red", "green", "blue", "magenta", "orange", "purple", "brown", "cyan"]
user_color_map = {}

local_hostname = socket.gethostname()

ip_addresses = socket.gethostbyname_ex(local_hostname)[2]

filtered_ips = [ip for ip in ip_addresses if not ip.startswith("127.")]

first_ip = filtered_ips[:1]

def get_connection_details():
    host, port, username = None, None, None

    def on_submit():
        nonlocal host, port, username
        temp_host = ip_entry.get().strip()
        temp_port = port_entry.get().strip()
        temp_user = user_entry.get().strip()

        try:
            ipaddress.IPv4Address(temp_host)
            host = temp_host
        except ValueError:
            messagebox.showerror("IP Error", f"The address '{temp_host}' is not a valid IPv4 address.")
            return

        try:
            p = int(temp_port)
            if 0 <= p <= 65535:
                port = p
            else: raise ValueError
        except ValueError:
            messagebox.showerror("Port Error", "Please enter a valid port (0-65535).")
            return

        if not temp_user:
            messagebox.showerror("Username Error", "A username is required.")
            return
        
        if " " in temp_user:
            messagebox.showerror("Username Error", "A username cannot contain spaces")
            return
        
        username = temp_user
        login_root.destroy()

    login_root = tk.Tk()
    login_root.title("Connect to Server")
    login_root.geometry("300x350")
    login_root.eval('tk::PlaceWindow . center')
    login_root.configure(bg="#f0f0f0") 

    label_style = {'font': ('Arial', 10, 'bold'), 'bg': "#f0f0f0"}
    entry_style = {'justify': 'center', 'font': ('Arial', 10)}

    tk.Label(login_root, text="Server IPv4:", **label_style).pack(pady=(15, 5))
    ip_entry = tk.Entry(login_root, **entry_style)
    ip_entry.insert(0, f"{first_ip[0]}")
    ip_entry.pack(pady=5)

    tk.Label(login_root, text="Server Port:", **label_style).pack(pady=5)
    port_entry = tk.Entry(login_root, **entry_style)
    port_entry.insert(0, "15432")
    port_entry.pack(pady=5)

    tk.Label(login_root, text="Your Username:", **label_style).pack(pady=5)
    user_entry = tk.Entry(login_root, **entry_style)
    user_entry.pack(pady=5)
    user_entry.focus_set()

    button_frame = tk.Frame(login_root, bg="#f0f0f0")
    button_frame.pack(pady=30)

    tk.Button(button_frame, text="Connect", command=on_submit, 
              bg="#4CAF50", fg="white", width=12, font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)

    tk.Button(button_frame, text="Exit", command=sys.exit, 
              bg="#f44336", fg="white", width=12, font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)

    login_root.protocol("WM_DELETE_WINDOW", sys.exit)

    login_root.mainloop()
    return host, port, username

def update_chat(chat_area, message):
    chat_area.config(state='normal')
    
    if message.startswith("Connected") or message.startswith("System:") or message.startswith("[!]"):
        chat_area.insert(tk.END, message + '\n', "system")
        chat_area.tag_config("system", foreground="blue", font=('Arial', 10, 'bold'))
    
    elif message.startswith("[") and "] " in message:
        parts = message.split("] ", 1)
        username = parts[0][1:]  
        content = parts[1]
        
        if username not in user_color_map:
            color = USER_COLORS[len(user_color_map) % len(USER_COLORS)]
            user_color_map[username] = color
            chat_area.tag_config(username, foreground=color, font=('Arial', 10, 'bold'))
        
        chat_area.insert(tk.END, f"[{username}] ", username)
        chat_area.insert(tk.END, f"{content}\n")
    
    else:
        chat_area.insert(tk.END, message + '\n')
        
    chat_area.config(state='disabled')
    chat_area.yview(tk.END)         

def send_message(sock, msg_entry, chat_area):
    message = msg_entry.get().strip()
    if message:
        try:
            sock.sendall(message.encode('utf-8'))
            
            if message.startswith("@") and " " in message:
                parts = message.split(" ", 1)
                target_user = parts[0][1:] 
                content = parts[1]
                
                update_chat(chat_area, f"To [{target_user}]: {content}")
            else:
                update_chat(chat_area, f"You: {message}")
            
            msg_entry.delete(0, tk.END) 
            
            if message.lower() == 'exit':
                sock.close()
                sys.exit() 
                
        except Exception as e:
            update_chat(chat_area, f"System: Error sending message: {e}")

def receive_messages(sock, chat_area):
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if not message:
                update_chat(chat_area, "[!] Disconnected from server.")
                break
            
            update_chat(chat_area, message.strip())
            
        except ConnectionAbortedError:
            break
        except Exception as e:
            update_chat(chat_area, f"[!] Error receiving message: {e}")
            break

def start_client(host, port, username):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        client_socket.recv(1024) 
        client_socket.send(username.encode("utf-8")) 

        response = client_socket.recv(1024).decode("utf-8")
        if "already taken" in response:
            messagebox.showerror("Error", "Username already taken!")
            return False
        
        root = tk.Tk()
        root.title(f"Chat Client - {username}")
        root.geometry("600x500")
        root.configure(bg="#f0f0f0") 

        chat_area = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD, font=('Arial', 10))
        chat_area.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

        input_frame = tk.Frame(root, bg="#f0f0f0")
        input_frame.pack(padx=15, pady=10, fill=tk.X, side=tk.BOTTOM)

        msg_entry = tk.Entry(input_frame, font=('Arial', 10))
        msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10), ipady=3)
        msg_entry.bind("<Return>", lambda e: send_message(client_socket, msg_entry,chat_area))

        send_button = tk.Button(input_frame, text="Send", width=12,
                               bg="#4CAF50", fg="white", font=('Arial', 9, 'bold'),
                               command=lambda: send_message(client_socket, msg_entry,chat_area))
        send_button.pack(side=tk.RIGHT)

        update_chat(chat_area, response)
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, chat_area))
        receive_thread.daemon = True
        receive_thread.start()

        root.mainloop()
        return True

    except Exception as e:
        messagebox.showerror("Connection Error", f"Lost connection: {e}")
        return False


if __name__ == "__main__":
    while True:

        details = get_connection_details()

        HOST, PORT, USERNAME = details

        success = start_client(HOST,PORT,USERNAME)

        if success:
            break
    
