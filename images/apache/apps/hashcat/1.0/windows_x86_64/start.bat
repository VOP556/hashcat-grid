powershell.exe -command foreach ($argument in (get-content options).split(':')) {start-process -filepath hashcat-3.5.0\hashcat64.exe -argumentlist $argument -wait -nonewwindow}
powershell.exe -command if (!(test-path -path .\debug)) {set-content -path .\debug -value "0"}

EXIT /B 0
