rule loader_win_squirrelwaffle_doc {
    meta:
        id = "caadeac3-d4c7-4d84-b539-c03cc4c6c274"
        version = "1.0"
        description = "Detect the Squirrelwaffle malicious document (not xls)"
        author = "Sekoia.io"
        creation_date = "2021-09-20"
        classification = "TLP:CLEAR"
        
    strings:
        // OK1 = "cmd /c rundll32.exe C:\ProgramData\www1.dll,ldr"
        $s1 = {4f4b31203d2022636d64202f632072756e646c6c33322e65786520433a5c50726f6772616d446174615c777777312e646c6c2c6c647222}
        // AERO BIZ COM COOP EDU GOV INFO INT MIL MUSEUM NAME NET ORG PRO
        $s2 = {4145524f2042495a20434f4d20434f4f502045445520474f5620494e464f20494e54204d494c204d555345554d204e414d45204e4554204f52472050524f}
        
    condition:
        any of them and filesize > 100KB
}
        