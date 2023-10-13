# OSCP-Notes
Cheatsheet/Notes from PEN-200 Learning Platform for the OSCP Exam
Web App Pentest
  D
    Command Injection
      Check if CMD or PowerShell we have:
        (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
        
