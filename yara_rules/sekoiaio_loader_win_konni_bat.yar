rule sekoiaio_loader_win_konni_bat {
    meta:
        id = "e8921336-6c91-4b46-bd3f-3cf4a9b31082"
        version = "1.0"
        description = "Detect the BAT files (named trap.bat or yup.bat) used by KONNI"
        source = "Sekoia.io"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "del /f /q \"%~dp0\\*.zip\" > nul"
        $ = "del /f /q \"%~dp0\\*.xml\" > nul"
        $ = "del /f /q \"%~dp0\\wpnprv*.dll\" > nul"
        $ = "del /f /q \"%~dp0\\*.bat\" > nul"
        $ = "del /f /q \"%~dpnx0\" > nul"
        $ = "echo %~dp0 | findstr /i \"system32\" > nul"
        $ = "if %ERRORLEVEL% equ 0 (goto INSTALL) else (goto COPYFILE)"
        $ = "if exist \"%ProgramFiles(x86)%\" ("
        
    condition:
        3 of them and filesize < 3KB
}
        