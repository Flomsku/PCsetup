#--------------------------------------------------------------------------------- 
# UserAccountControl flags
# Property 							flag Value in hexadecimal	Value in decimal
# SCRIPT	                        0x0001						1
# ACCOUNTDISABLE	                0x0002						2
# HOMEDIR_REQUIRED	                0x0008						8
# LOCKOUT	                        0x0010						16
# PASSWD_NOTREQD	                0x0020						32
# PASSWD_CANT_CHANGE                0x0040						64
# Note You cannot assign this permission by directly modifying the UserAccountControl attribute. For information about how to set the permission programmatically, see the "Property flag descriptions" section. 	
# ENCRYPTED_TEXT_PWD_ALLOWED	    0x0080						128
# TEMP_DUPLICATE_ACCOUNT	        0x0100						256
# NORMAL_ACCOUNT	                0x0200						512
# INTERDOMAIN_TRUST_ACCOUNT	        0x0800						2048
# WORKSTATION_TRUST_ACCOUNT	        0x1000						4096
# SERVER_TRUST_ACCOUNT	            0x2000						8192
# DONT_EXPIRE_PASSWORD	            0x10000						65536
# MNS_LOGON_ACCOUNT	                0x20000						131072
# SMARTCARD_REQUIRED	            0x40000						262144
# TRUSTED_FOR_DELEGATION	        0x80000						524288
# NOT_DELEGATED	                    0x100000					1048576
# USE_DES_KEY_ONLY					0x200000					2097152
# DONT_REQ_PREAUTH					0x400000					4194304
# PASSWORD_EXPIRED					0x800000					8388608
# TRUSTED_TO_AUTH_FOR_DELEGATION	0x1000000	    			16777216
# PARTIAL_SECRETS_ACCOUNT	        0x04000000  				67108864
#--------------------------------------------------------------------------------- 

# Avaa Powershell ISE "Run As Administrator" ja avaa tämä script "Open Script" -painikkeella. 
# Tämän jälkeen aja "Set-ExecutionPolicy RemoteSigned" erillisenä rivillä (maalaa rivi ja paina F8)
# Vastaa policy change popup-ikkunaan "Yes to all"
# Tarkista $Content-muuttujan polku, jotta se täsmää
# Tämän jälkeen scriptin voi ajaa normaalisti (F5)


Set-ExecutionPolicy RemoteSigned
#Set-ExecutionPolicy Restricted
Get-ExecutionPolicy



$Content = Get-Content -Path "C:\Users\oskum\Desktop\Työnhaku\IPsAndNames.txt" #path missä .csv tekstitiedosto IP-osotteista lepää TARKISTA tämä
$DNSServer1 = "123.123.123.1"  #DNSServer address for index 1
$DNSServer2 = "123.123.123.2" #DNSServer address for index 2
$DNSServer3 = "123.123.123.3" #DNSServer address for index 3
$Wins = "123.123.123.4"



# Windows Features - mm. Message Queuing, IIS
# HUOM! Windows Serverin kanssa avaa Server Manager / Add Roles and Features
#optionalfeatures
#ServerManager
#


# Windowsin palomuuri pois
#firewall.cpl
#


# Hibernate-tila pois kaytosta
powercfg -h off
#


# Kellon ja aikavyohykkeen asetukset 
#timedate.cpl 
#
Set-TimeZone -Name "FLE Standard Time"
# Set-TimeZone -ID "FLE Standard Time" -PassThru
pause



### CREATING GREENSHOT SHORTCUT TO ALL DESKTOPS START ###
$pDesktopPath = "C:\Users\Public\Desktop\Greenshot.lnk" # Public desktop path => all users receive files dropped here
$ProgramPath = "C:\Program Files\Greenshot\Greenshot.exe" #Program which is used to create the shortcut

$WshShell = New-Object -ComObject WScript.Shell # creating object
$Shortcut = $WshShell.CreateShortcut($pDesktopPath) # Creating shortcut via object and where it is created
$Shortcut.TargetPath = $ProgramPath # path to use creating the shortcut
$Shortcut.Save() # saving the creation
### CREATING SNIP SHORTCUT TO ALL DESKTOPS END ###
Write-Host("Greenshot shortcut created")
pause
### CREATING CCCLEANER SHORTCUT TO ALL DESKTOPS START ###
$pDesktopPath = "C:\Users\Public\Desktop\CCCleaner.lnk" # Public desktop path => all users receive files dropped here
$ProgramPath = "C:\Program Files (x86)\Siemens\WINCC\bin\CCCleaner.exe" #Program which is used to create the shortcut

$WshShell = New-Object -ComObject WScript.Shell # creating object
$Shortcut = $WshShell.CreateShortcut($pDesktopPath) # Creating shortcut via object and where it is created
$Shortcut.TargetPath = $ProgramPath # path to use creating the shortcut
$Shortcut.Save() # saving the creation
### CREATING CCCLEANER SHORTCUT TO ALL DESKTOPS END ###
Write-Host("CCCleaner shortcut created")

### CREATING VNCViewer SHORTCUT TO ALL DESKTOPS START ###
$pDesktopPath = "C:\Users\Public\Desktop\VNC Viewer.lnk" # Public desktop path => all users receive files dropped here
$ProgramPath = "C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe" #Program which is used to create the shortcut

$WshShell = New-Object -ComObject WScript.Shell # creating object
$Shortcut = $WshShell.CreateShortcut($pDesktopPath) # Creating shortcut via object and where it is created
$Shortcut.TargetPath = $ProgramPath # path to use creating the shortcut
$Shortcut.Save() # saving the creation
### CREATING VNCViewer SHORTCUT TO ALL DESKTOPS END ###
Write-Host("VNC Viewer shortcut created")
pause

### DEFAULT USER MODIFICATION START ###
REG LOAD HKU\DEFAULTUSER C:\Users\Default\NTUSER.DAT
New-PSDrive -name Test -PSProvider Registry -root HKEY_USERS\DEFAULTUSER #Handle opened to Loaded hive "Default user"
cd Test: 
pause


pause
#Color settings to default user
New-item -path "\Software\Microsoft\Windows\CurrentVersion\Explorer\" -name "Accent" -ItemType Directory -force #Creating folder "personalize" in HKU
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "0xffd77800" /f # Active Windows Borders
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "a6d8ff0076b9ed00429ce3000078d700005a9e000042750000264200f7630c00" /f #Color
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "StartColorMenu" /t REG_DWORD /d "0xff9e5a00" /f # Show accent color before login
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "0x00000001" /f # Show accent color on Start, taskbar and action center
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0x00000000" /f # Transparency effects
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d "0xffd77800" /f # Active Window title bar
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "0x00000001" /f # Show accent color on title bars

#Explorer settings
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0x00000000" /f #Sharing wizard on: 1 = enabled/on, 0 = disabled/off
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0x00000000" /f #Hide file extensions: 1 = hidden/on, 0 = show ext./on
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0x00000000" /f #Quick access show recent
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0x00000000" /f #Quick access show frequent
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "0x00000001" /f # 0 = quick access, 1 = this pc

#taskbar settings
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d "0x00000002" /f #Combine buttons 0,1,2
reg add "HKU\DEFAULTUSER\Software\Microsoft\TabletTip\1.7" /v "TipbandDesiredVisibility" /t REG_DWORD /d "0x00000001" /f #Show touch keyboard on taskbar
reg add "HKU\DEFAULTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0x00000000" /f #people button in task bar 0 = disabled, 1 = enabled


reg delete "HKU\DEFAULTUSER\Control Panel\International\User Profile\en-US" /v "0409:00000409" /f #Delete language 0409 = english US, keyboard ..0409 = English US
reg add "HKU\DEFAULTUSER\Control Panel\International\User Profile\en-US" /v "0409:0000040B" /f #Add language 0409 = english US, ...040B = Finnish 
cd C: 

pause
Remove-PSDrive Test #Removing the handle
[gc]::Collect() #garbage collector

REG UNLOAD HKU\DEFAULTUSER #unloading hive
pause
### DEFAULT USER MODIFICATION END ###

### HKCU Combine taskbar buttons: Never START ### 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarGlomLevel -Value 2  # value (0 = always combine, 1 = when full, 2 = never)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0x00000000" /f #Hide file extensions: 0 = show ext, 1 = hide ext
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0x00000000" /f # Sharing wizard on: 0 = disabled, 1 = enabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0x00000000" /f #people button in task bar 0 = disabled, 1 = enabled
#reg add "HKCU\Control Panel\International\Geo\" /v "Name" /t REG_SZ /d "FI" /f
#reg add "HKCU\Control Panel\International\Geo\Nation" /v "Nation" /t REG_SZ /d "77" /f

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0 # Disable Quick Access: Recent Files
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0 # Disable Quick Access: Frequent Folders
Set-ItemProperty -Path HKCU:\Software\Microsoft\TabletTip\1.7 -Name TipbandDesiredVisibility -Type DWord -Value 1 # show touch keyboard on taskbar
### HKCU Combine taskbar buttons: Never END ###

##

### HKCU Show accent color on surfaces Start, taskbar, action center START ###
$RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'

$ColorPrevalenceKey = @{
	Key   = 'ColorPrevalence';
	Type  = "REG_DWORD";
	Value = '0x00000001'
}



If($Null -eq (Get-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -PropertyType $ColorPrevalenceKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -Force
}
### HKCU Show accent color on surfaces Start, taskbar, action center END ###

pause

### HKCU Transparency SCRIPT START ###
$RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'


$EnableTransparencyKey = @{
	Key   = 'EnableTransparency';
	Type  = "REG_DWORD";
	Value = '0x00000000'
}

If($Null -eq (Get-ItemProperty -Path $RegPath -Name $EnableTransparencyKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $EnableTransparencyKey.Key -Value $EnableTransparencyKey.Value -PropertyType $EnableTransparencyKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $EnableTransparencyKey.Key -Value $EnableTransparencyKey.Value -Force
}
### HKCU Transparency SCRIPT END ###

pause

### HKCU ColorPrevalence SCRIPT START Accent color on title bar ###
$RegPath = 'HKCU:\Software\Microsoft\Windows\DWM'

$ColorPrevalenceKey = @{
	Key   = 'ColorPrevalence';
	Type  = "REG_DWORD";
	Value = '0x00000001'
}


If($Null -eq (Get-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -PropertyType $ColorPrevalenceKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -Force
}
### HKCU ColorPrevalence Accent color on title bar SCRIPT END ###

pause

### HKCU SHOW ACCENT COLOR ON TITLE BAR START ###
$RegPath = 'HKCU:\Software\Microsoft\Windows\DWM'

$ColorPrevalenceKey = @{
	Key   = 'ColorPrevalence';
	Type  = "REG_DWORD";
	Value = '0x00000001'
}


If($Null -eq (Get-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -PropertyType $ColorPrevalenceKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $ColorPrevalenceKey.Key -Value $ColorPrevalenceKey.Value -Force
}
### HKCU SHOW ACCENT COLOR ON TITLE BAR END ###

pause

### HKCU COLOR SCRIPT START ###
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"


#Accent Color Menu Key START#
$AccentColorMenuKey = @{
	Key   = 'AccentColorMenu';
	Type  = "REG_DWORD";
	Value = '0xffd77800'
}

If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -PropertyType $AccentColorMenuKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -Force
}


#Accent Palette Key START#
$AccentPaletteKey = @{
	Key   = 'AccentPalette';
	Type  = "REG_BINARY";
	Value = 'a6,d8,ff,00,76,b9,ed,00,42,9c,e3,00,00,78,d7,00,00,5a,9e,00,00,42,75,00,00,26,42,00,f7,63,0c,00'
}
$hexified = $AccentPaletteKey.Value.Split(',') | ForEach-Object { "0x$_" }

If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -PropertyType Binary -Value ([byte[]]$hexified)
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -Value ([byte[]]$hexified) -Force
}

#Start Color Menu Key START#
$StartMenuKey = @{
	Key   = 'StartColorMenu';
	Type  = "REG_DWORD";
	Value = '0xff9e5a00'
}

If ($Null -eq (Get-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -PropertyType $StartMenuKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -Force
}
#Accent Color Menu Key END#
#Accent Palette Key END#
#Start Color Menu Key END#
### HKCU COLOR SCRIPT END ###

pause 

#Explorer.exe Boot required to update the changes
Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue # Boots explorer.exe so colors are updated
          
pause 

# Installed SIMATIC Software - tarkista ja aja updatet
#"C:\Program Files (x86)\Common Files\Siemens\S7AVERSX\s7aversx.exe"


# --- Regional settings for the current user

Set-WinCultureFromLanguageListOptOut 1 #Format to English United States

Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value dd.MM.yyyy
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sLongDate -Value "dddd, MMMM dd, yyyy"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value HH:mm
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value HH:mm:ss
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name iFirstDayOfWeek -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sCurrency -Value €
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name iMeasure -Value 0

# Keyboard settings (0000040b = Finnish, 00000409 = English default)
#REG ADD "HKCU\Keyboard Layout\Preload" /v "1" /t REG_SZ /d "0000040b" /f


pause

# Deleting extra languages 
$LangList = Get-WinUserLanguageList #OLD
$LangList.RemoveAll({ $args[0].LanguageTag -clike '*'}) #NEW
$LangList.Add("en-US") #NEW
$LangList[0].InputMethodTips.Clear() #NEW
$LangList[0].InputMethodTips.Add('0409:0000040B') #keyboard layout inputmethodtips NEW
Set-WinUserLanguageList -LanguageList $LangList -force #NEW


#$MarkedLang = $LangList | where LanguageTag -eq "LANGUAGETAG" #OLD
#$LangList.Remove($MarkedLang) #OLD
#Set-WinUserLanguageList $LangList -Force #OLD

#Homelocation Finland
Set-WinHomeLocation -GeoId 0x4D #Finland

pause

# Change User Account Control Settings to "Never Notify"
<#REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "00000000" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "00000000" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "00000000" /f

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "00000003" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "00000001" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "00000001" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "00000000" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "00000000" /f
#>

# REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "00000000" /f


# Default user settings
REG LOAD HKU\DefaultUser C:\Users\Default\NTUSER.DAT
REG ADD "HKU\DefaultUser\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd.MM.yyyy" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "sLongDate" /t REG_SZ /d "dddd, MMMM dd, yyyy" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "HH:mm:ss" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d "0" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "sCurrency" /t REG_SZ /d "€" /f
REG ADD "HKU\DefaultUser\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f
REG ADD "HKU\DefaultUser\Keyboard Layout\Preload" /v "1" /t REG_SZ /d "0000040b" /f
REG UNLOAD HKU\DefaultUser

# Administrator credentials for making changes to remote machines
$CredUser = 'Administrator'
$CredPass = 'admin'

# Convert password to securestring
$pass = ConvertTo-SecureString -AsPlainText $CredPass -Force

# $Cred can be passed as the credential to any command that takes a credential parameter.
$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $CredUser,$pass  # Use hardcoded credentials
# $Cred = Get-Credential # Ask or credentials once when running

# Username and password for the user to be created
$Username = 'User1'
$Password = '1234'

Write-Host "Creating $Username"

[ADSI]$server="WinNT://$(hostname)"
$User=$server.Create("User", "$Username")
$User.SetPassword("$Password")
$User.put("description","")
$User.UserFlags=66048; # NORMAL_ACCOUNT = 512, PASSWD_CANT_CHANGE = 64, DONT_EXPIRE_PASSWORD = 65536 => 66112
$User.SetInfo()
[ADSI]$admins="WinNT://$(hostname)/Administrators"
$admins.add("WinNT://$(hostname)/$Username")
Write-Host "Done"

# Username and password for the user to be created
$Username = 'User2'
$Password = '1234'

Write-Host "Creating $Username"

[ADSI]$server="WinNT://$(hostname)"
$User=$server.Create("User", "$Username")
$User.SetPassword("$Password")
$User.put("description","")
$User.UserFlags=66048; # NORMAL_ACCOUNT = 512, PASSWD_CANT_CHANGE = 64, DONT_EXPIRE_PASSWORD = 65536 => 66112
$User.SetInfo()
Write-Host "Done"
[ADSI]$admins="WinNT://$(hostname)/Users"
$admins.add("WinNT://$(hostname)/$Username")
pause


# Windows autologin netplwiz
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$DefaultUsername = "User1"
$DefaultPassword = "1234"
Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String
Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String



#Setting password age
Set-LocalUser -Name "Administrator" -PasswordNeverExpires 1
Set-LocalUser -Name "User1" -PasswordNeverExpires 1
Set-LocalUser -Name "User2" -PasswordNeverExpires 1

#Network configurations
netsh advfirewall set allprofiles state off


### CHANGE THE IPV4 ADDRESS DEPENDING ON THE PC ###
$CurrentHostName= [System.Net.Dns]::GetHostName() #haetaan koneen nimi
$Array = $Content.split(";")
$length = $Content.Length # rivien määrä
$HostList = @() #Array
$IPList = @() #Array
$GatewayList = @() #Array
$SubnetList = @() #Array
$MAPList = @(($HostList),($IPList), ($SubnetList),($GatewayList)) #Multidimensional array
$InputPCname = $CurrentHostName #$CurrentHostName #Syötä tähän halutun tietokoneen nimi, tai jätä $currenhostname niin hakee local system nimen
$NetInterfaceName = "X1 P1" #Syötä tähän verkkokortin nimi

Write-Host("syötetään ip koneelle:", $InputPCname)
pause

for ($j = 4; $j -lt $Array.length - 1;$j+=4) #CREATING HOST LIST
{
      $HostList += ($Array[$j]) #Lista PC nimistä
}
for ($k =5;$k -lt $array.length -1; $k+=4) #CREATING IP LIST
{
    $IPList += ($Array[$k]) #Lista IPeistä
}
for ($i = 7; $i -lt $Array.length - 1;$i+=4) #CREATING GATEWAYLIST
{
      $GatewayList += ($Array[$i]) #Lista Gatewaysta
      }
for ($a = 6; $a -lt $Array.length - 1;$a+=4) #CREATING GATEWAYLIST
{
      $SubnetList += ($Array[$a]) #Lista Subneteistä
      }
      Write-host($HostList)
      Write-host($IPList)
      Write-host($GatewayList)
      pause

$MAPList = @(($HostList),($IPList), ($SubnetList),($GatewayList)) #Multidimensional array
$HostLength = $HostList.Length #PCnimi listan pituus
$IPLength = $IPList.Length #IPlistan pituus
$GatewayLength = $GatewayList.Length #Gatewaylistan pituus
$SubnetLength = $SubnetList.Length #Subnetlistan pituus
Write-host("PC nimien määrä listassa:", $HostLength)
Write-host("IPeiden määrä listassa:", $IPLength)
Write-host("Gateway -osotteiden määrä listassa:", $GatewayLength)
Write-host("Subnet -osotteiden määrä listassa:", $SubnetLength)
If($HostLength -ceq $IPLength) #Listojen pituuksien vertailu
{write-host("Nimiä ja IPeitä on saman verran")
            if($SubnetLength -ceq $IPLength ){ write-host("Subnet-osotteita ja IPeitä on saman verran")
            for($j=0; $j -le $HostList.Length; $j++) #loopataan Pcnimi lista läpi
            {
    
                if($InputPCname -ceq $MAPList[0][$j]) #etsitään löytyykö system namelle nimeä listasta
                {
                    pause
                    Write-host("Maplist: ", $MAPList[0][$j])
                    pause
                    Write-host("IP löytyi, Syötetään IP...")
                    $Ipvalue = $MAPList[1][$j] #siirretään Pcnimeä vastaava IP IpValueen
                    
                    Write-host("IP: ", $Ipvalue)
                    
                    $GatewayValue = $MAPList[3][$j] #siirretään Pcnimeä vastaava Gateway Gatewayvalueen
                    Write-host("Gateway: ", $GatewayValue)
                    
                    $SubnetValue = $MAPList[2][$j] #Siirretään pcnimeä vastaava subnet-osoite $subnet valueen
                    Write-host("Subnet: ", $SubnetValue)
                    pause
                    netsh interface ipv4 set address $NetInterfaceName static $Ipvalue $SubnetValue $GatewayValue
                    netsh interface ipv4 add dnsserver $NetInterfaceName address=$DNSServer1 index=1
                    netsh interface ipv4 add dnsserver $NetInterfaceName address=$DNSServer2 index=2
                    netsh interface ipv4 add dnsserver $NetInterfaceName address=$DNSServer3 index=3
                    netsh interface ipv4 set wins name= $NetInterfaceName source=static addr=$Wins
                }
              }
        
       }

 }


pause


Write-Host($SubnetValue)
Write-Host($Ipvalue)
Write-Host($GatewayValue)

Write-Host("tarkista IP/DNS/WINS X1 P1")

pause
### DISABLE ETHERNET ADAPTERS START ###
#netsh interface set interface "Interface Name" disable. #CMD line
Disable-NetAdapter -Name "X2 P1" -Confirm:$false
Disable-NetAdapter -Name "X3 P1" -Confirm:$false
### DISABLE ETHERNET ADAPTERS END ###



# Create WINCC folder or PCS7 folder
#New-Item D:\PCS7 -type directory # creating folder
New-Item D:\Backup_images -type directory # creating folder

# Folder share C and D
pause

#New-SMBShare –Name "C" –Path "C:\" –FullAccess "Everyone" 
New-SMBShare –Name "D" –Path "D:\" –FullAccess "Everyone" 

# Enable MSMQ # Tehty käsin ennen WinCC asennusta
#dism /Enable-Feature /FeatureName:MSMQ-Container /Online
#dism /Enable-Feature /FeatureName:MSMQ-Server /Online

#ADDING USERS TO GROUPS
$Username = 'User1'
[ADSI]$admins="WinNT://$(hostname)/SIMATIC HMI"
$admins.add("WinNT://$(hostname)/$Username")
[ADSI]$admins="WinNT://$(hostname)/SIMATIC NET"
$admins.add("WinNT://$(hostname)/$Username")


pause

$Username = 'User2'
[ADSI]$admins="WinNT://$(hostname)/SIMATIC HMI"
$admins.add("WinNT://$(hostname)/$Username")
[ADSI]$admins="WinNT://$(hostname)/SIMATIC NET"
$admins.add("WinNT://$(hostname)/$Username")
<#

# PG/PC Interface (jos tarpeen)
C:\Windows\SysWOW64\s7epatsx.exe -App=Simatic
Write-host("TCP/IP.1 -> OK")
pause

# Region asetukset Copy settings to new users & welcome screen
Write-host("Administrative -> Copy settings -> welcome screen system accounts & new users")
intl.cpl
pause
C:\Windows\System32\UserAccountControlSettings.exe
pause #>

Set-ExecutionPolicy Restricted
Get-ExecutionPolicy
pause