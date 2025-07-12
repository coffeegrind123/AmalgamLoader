# AutoInject - Simplified TF2 Auto-Injector

This is a streamlined version of Xenos that automatically targets `tf_win64.exe` for DLL injection.

## Features

- **No GUI**: Runs completely in the background
- **System Tray**: Minimized icon in the system tray (taskbar notification area)
- **Auto-targeting**: Automatically targets `tf_win64.exe` process
- **Auto-injection**: Automatically injects when the process is found
- **Auto-monitoring**: Continuously monitors for new tf_win64.exe processes
- **Auto-reinjection**: Injects into new instances when tf_win64.exe restarts

## How to Use

1. Place any DLL you want to inject in the same directory as `AutoInject.exe`
2. Run `AutoInject.exe` as Administrator
3. The program will:
   - Start minimized to system tray
   - Look for the first `.dll` file in its directory
   - Monitor for `tf_win64.exe` processes
   - Automatically inject the DLL when found
   - Continue monitoring for new processes

## System Tray

- The program shows an icon in the system tray
- Right-click the icon to exit the program
- Tooltip shows current status:
  - "Waiting for tf_win64.exe" - Process not found
  - "Injected into tf_win64.exe" - Successfully injected

## Requirements

- Windows 10/11
- Administrator privileges (required for DLL injection)
- A DLL file in the same directory as the executable

## Building

This project is part of the Xenos solution. Build the `AutoInject` project in Visual Studio.

## Notes

- Only targets 64-bit tf_win64.exe processes
- Uses normal DLL injection method (not manual mapping)
- Continuously monitors for process restart and re-injects automatically
- Will exit if no DLL files are found in the directory