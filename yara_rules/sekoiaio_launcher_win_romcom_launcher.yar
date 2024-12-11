rule sekoiaio_launcher_win_romcom_launcher {
    meta:
        id = "e8fa8239-a763-4be2-8f34-8e112e65b35e"
        version = "1.0"
        description = "Detect the launcher of RomCom malware"
        source = "Sekoia.io"
        creation_date = "2022-11-04"
        classification = "TLP:CLEAR"
        
    strings:
        // C:\Users\123\source\repos\ins_asi\Win32\Release\setup.pdb
        $ = {43 3a 5c 55 73 65 72 73 5c 31 32 33 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 69 6e 73 5f 61 73 69 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 73 65 74 75 70 2e 70 64 62}
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        