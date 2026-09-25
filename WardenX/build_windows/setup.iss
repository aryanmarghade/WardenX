[Setup]
AppName=WardenX
AppVersion=1.0
DefaultDirName={autopf}\WardenX
DefaultGroupName=WardenX
UninstallDisplayIcon={app}\WardenX.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=WardenX_Installer

[Files]
Source: "WardenX.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "WardenX"; ValueData: """{app}\WardenX.exe"""; Flags: uninsdeletevalue

[Icons]
Name: "{group}\WardenX"; Filename: "{app}\WardenX.exe"
Name: "{autodesktop}\WardenX"; Filename: "{app}\WardenX.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\WardenX.exe"; Description: "Launch WardenX"; Flags: nowait postinstall skipifsilent
