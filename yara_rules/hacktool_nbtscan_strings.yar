rule hacktool_nbtscan_strings {
    meta:
        id = "8883b56c-a085-459c-9ec6-a139ad5a2671"
        version = "1.0"
        description = "Detects NBTScan hacktool based on strings, ELF & PE variants"
        author = "Sekoia.io"
        creation_date = "2022-02-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "CHT:nfp:bt:vw:mVO:1P"
        $ = "usage: %s [options] target [targets...]"
        $ = "Targets are lists of IP addresses, DNS names, or address"
        $ = "net bits [%d] must be 1..32"
        $ = "subnet /%d is too large (%d max)"
        $ = "[%s] is invalid IP address"
        $ = "[%s] is an invalid target (bad IP/hostname)"
        
    condition:
        uint16be(0) == 0x4d5a and 5 of them
}
        