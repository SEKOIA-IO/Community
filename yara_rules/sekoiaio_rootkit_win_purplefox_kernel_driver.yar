import "pe"
        
rule sekoiaio_rootkit_win_purplefox_kernel_driver {
    meta:
        id = "798dc20b-76cd-4e31-b9ee-f363fb39cd58"
        version = "1.0"
        description = "Detect the Purple Fox trojan"
        author = "Sekoia.io"
        creation_date = "2022-03-28"
        classification = "TLP:CLEAR"
        reference = "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/c/purple-fox-uses-new-arrival-vector-and-improves-malware-arsenal/IOCs-Purple-Fox.txt"
        
    strings:
        $ = "\\DosDevices\\Global\\MyDriver" wide
        $ = "IOCTL_IO_KILL_PROCESS" ascii
        $ = "IOCTL_IO_DELET_FILE" ascii
        $ = "IOCTL_IO_COPY_FILE" ascii
        $ = "IOCTL_IO_KILL_MINIFITER" ascii
        
    condition:
        //Native
        uint16(0)==0x5A4D and all of them
        
        // Console
        or (
            pe.rich_signature.toolid(171, 30319)
            and pe.rich_signature.toolid(158, 30319)
            and pe.rich_signature.toolid(170, 30319)
            and pe.rich_signature.toolid(147, 30729)
            and pe.rich_signature.toolid(1, 0)
        )
        and for any i in (0..pe.number_of_signatures-1) : (
            pe.signatures[i].thumbprint == "c7939f8303ca22effb28246e970b13bee6cb8043"
        )
}
        