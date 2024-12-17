rule sekoiaio_apt_badmagic_ld_dll_loader_pshscript {
    meta:
        id = "d4a23afc-693f-4fab-b2c4-15eecba047f7"
        version = "1.0"
        description = "Detects BadMagic DLL Loader powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$ModulePath = \"$folder_path\\$name"
        $ = "$ModuleExport ="
        $ = "start-job -ScriptBlock $ScriptBlock"
        $ = "Invoke-WebRequest -Uri"
        
    condition:
        all of them and filesize < 1KB
}
        