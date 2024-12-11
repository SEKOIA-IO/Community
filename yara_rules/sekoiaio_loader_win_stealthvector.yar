import "pe"
import "hash"
        
rule sekoiaio_loader_win_stealthvector {
    meta:
        id = "ecf6421a-f492-43c4-9ed7-eb4724d24779"
        version = "1.0"
        description = "Detect the StealthVector malware, updated in July 2024"
        source = "Sekoia.io"
        creation_date = "2021-08-26"
        modification_date = "2024-07-15"
        classification = "TLP:CLEAR"
        hash1 = "166b6dcdac31f4bf51e4b20a7c3f7d4f7017ca0c30fa123d5591e25c3fa66107"
        hash2 = "ab56501167fe689fe55f6e6ddc3bb91952299bd5c3ef004b02bf1c3b4061c7cf"
        hash3 = "0faddbe1713455e3fc9777ec45adf07b28e24f4c3ddca37586c2aa6b539898c0"
        hash4 = "1c88150ec85a07c3db5f18c5eedcb0b653467b897af01d690ed996e5e07ba8e3"
        hash5 = "ec10a9396dca694fe64366e0dab82d046cf92457f97efd50a68ceb85adef6b74"
        
    strings:
        $s1 = "Global\\kREwdFrOlvASgP4zWZyV89m6T2K0bIno" ascii
        $s2 = "Global\\v5EPQFOImpTLaGZes3Nl1JSKHku8AyCw" ascii
        
    condition:
        uint16(0)==0x5A4D and 1 of them

        // Imphash
        or pe.imphash() == "0cd7b92b97ccc7e255df1f46b5299986"
        or pe.imphash() == "be777e91e3c42ac62471cfb7239be471"
        
        // Rich PE Header
        or hash.md5(pe.rich_signature.clear_data) == "fcc67611d136cce0e785029bbb879b45"
}
        