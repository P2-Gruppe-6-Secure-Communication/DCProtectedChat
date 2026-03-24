[Setup]
AppName=P2Chat
AppVersion=1.0
DefaultDirName={autopf}\P2Chat
OutputBaseFilename=P2ChatSetup
OutputDir=installer_dist
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
; Bundle the entire PyInstaller output
Source: "dist\P2Chat\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs
; Bundle the VC++ redistributable
Source: "vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Run]
; Install VC++ runtime silently first
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/quiet /norestart"; StatusMsg: "Installing Visual C++ Runtime..."; Flags: waituntilterminated
; Launch the app after install finishes
Filename: "{app}\P2Chat.exe"; Description: "Launch P2Chat"; Flags: nowait postinstall skipifsilent

[Icons]
Name: "{autoprograms}\P2Chat"; Filename: "{app}\P2Chat.exe"
Name: "{autodesktop}\P2Chat"; Filename: "{app}\P2Chat.exe"
