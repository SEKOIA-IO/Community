rule apt_buhtrap_maldocx {
    meta:
        id = "4aaba2f1-fafd-4e3f-8b18-7beda11464d1"
        version = "1.0"
        description = "Detect the malicious DOCX used by Buhtrap"
        author = "Sekoia.io"
        creation_date = "2022-02-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<xm:macrosheet xmlns=" ascii fullword
        $ = "CALL(\"kernel32\",\"VirtualFree"
        $ = "CALL(\"kernel32\",\"CreateFileA"
        $ = "CALL(\"kernel32\",\"WriteFile"
        $ = "CALL(\"kernel32\",\"VirtualAlloc"
        $ = "CALL(\"kernel32\",\"WinExec"
        $ = "CALL(\"kernel32\",\"lstrcatA"
        $ = "CALL(\"kernel32\",\"CreateFileA"
        $ = "CALL(\"kernel32\",\"VirtualFree"
        $ = "CALL(\"kernel32\",\"ExpandEnvironmentStringsA"
        $ = "CALL(\"kernel32\",\"CloseHandle"
        
    condition:
        all of them
}
        