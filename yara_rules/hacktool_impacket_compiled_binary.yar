rule hacktool_impacket_compiled_binary {
    meta:
        id = "43936dcc-0d74-43dd-996a-c27a28cef283"
        version = "1.0"
        description = "Detects generic PE embbeding impacket"
        author = "Sekoia.io"
        creation_date = "2022-02-28"
        classification = "TLP:CLEAR"
        
    strings:
        $i1 = "impacket.crypto" fullword
        $i2 = "impacket.dcerpc" fullword
        $i3 = "impacket.ese" fullword
        $i4 = "impacket.hresult_errors" fullword
        $i5 = "impacket.krb5" fullword
        $i6 = "impacket.nmb" fullword
        $i7 = "impacket.nt_errors" fullword
        $i8 = "impacket.ntlm" fullword
        $i9 = "impacket.smb" fullword
        $i10 = "impacket.smb3" fullword
        $i11 = "impacket.smb3structs" fullword
        $i12 = "impacket.smbconnection" fullword
        $i13 = "impacket.spnego" fullword
        $i14 = "impacket.structure" fullword
        $i15 = "impacket.system_errors" fullword
        $i16 = "impacket.tds" fullword
        $i17 = "impacket.uuid" fullword
        $i18 = "impacket.version" fullword
        $i19 = "impacket.winregistry" fullword
        $py = "PYZ-00.pyz"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 1MB and
        3 of ($i*) and $py
}
        