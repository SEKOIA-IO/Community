rule sekoiaio_hacktool_sharpview_strings {
    meta:
        id = "585ead98-36d0-402c-b527-4dec308cb1c9"
        version = "1.0"
        description = "Detects SharpView based on strings."
        source = "Sekoia.io"
        creation_date = "2022-02-14"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Args_Get_DomainGPOComputerLocalGroupMapping"
        $ = "Args_Get_ForestGlobalCatalog"
        $ = "Args_Find_DomainLocalGroupMember"
        $ = "Args_Get_DomainFileServer"
        $ = "Ex: SharpView.exe Method-Name" wide
        $ = "[Get-PathAcl] error: {0}" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 800KB and
        5 of them
}
        