& 'C:\Program Files\BOINC\boinccmd.exe' --project http://www.boincserver.com/boincserver detach
$API_KEY = (( & 'C:\Program Files\BOINC\boinccmd.exe' --create_account http://www.boincserver.com/boincserver your@email.com Passw0rD admin)[-1].split(":"))[-1]
& 'C:\Program Files\BOINC\boinccmd.exe' --project_attach http://www.boincserver.com/boincserver $API_KEY
Start-Sleep 5