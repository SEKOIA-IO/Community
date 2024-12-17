rule sekoiaio_implant_mul_alchimist {
    meta:
        version = "1.0"
        description = "Detect the Alchimist implant based on strings"
        author = "Sekoia.io"
        creation_date = "2022-10-18"
        id = "66330cc6-a7da-4717-9977-0cede48f46f5"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "POST /users/loginpage.html HTTP/1.1" ascii
        $str02 = "pm3/apps/Insekt/main.go" ascii
        $str03 = "generate new insekt err" ascii
        $str04 = "[SHELLCODE][filesize]:[scan]" ascii
        $str05 = "\\Device\\NamedPipe\\cygwinbad" ascii
        $str06 = "pm3/utils.GetTmpDir" ascii
        $str07 = "os/exec.Command" ascii
        
    condition:
        (uint16(0)==0x5A4D or uint32(0)==0x464C457F) and 5 of them
}
        