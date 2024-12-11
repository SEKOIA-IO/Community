import "pe"
import "hash"
        
rule sekoiaio_apt_mustang_panda_toneshell {
    meta:
        id = "bf7c68a9-dddc-494a-a603-c2311ed712a4"
        version = "1.0"
        description = "Detect the TONESHELL implant used by Mustang Panda from specific functions"
        source = "Sekoia.io"
        creation_date = "2022-11-28"
        classification = "TLP:CLEAR"
        
    strings:
        /*    GetTEB
        result = NtCurrentTeb();
        dword_1007CA38 = (int)result;
        return result;
        */
        $func1 = {
        55
        89 E5
        64 A1 18 00 00 00
        A3 ?? ?? ?? ??
        5D
        C3
        }
        
        /*memcpy
        v5 = a1;
        while ( a3-- )
        *a1++ = *a2++;
        return v5;
        */
        $func2 =  {
        55
        89 E5
        50
        8B 45 ??
        8B 45 ??
        8B 45 ??
        8B 45 ??
        89 45 ??
        8B 45 ??
        89 C1
        83 C1 FF
        89 4D ??
        83 F8 00
        0F 84 ?? ?? ?? ??
        8B 45 ??
        8A 08
        8B 45 ??
        88 08
        8B 45 ??
        83 C0 01
        89 45 ??
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        8B 45 ??
        83 C4 04
        5D
        C3
        }
        
        /* Decryptionroutine
        result = a1;
        for ( i = 0; i < 32; ++i )
        {
        *(_BYTE *)(a1 + i) ^= 0x7Eu;
        result = i + 1;
        }
        return result;
        */
        $decryption_routine1 = {
        8B 45 ??
        C7 45 ?? 00 00 00 00
        83 7D ?? 20
        0F 8D ?? ?? ?? ??
        8B 45 ??
        8B 4D ??
        0F BE 04 08
        83 F0 ??
        88 C2
        8B 45 ??
        8B 4D ??
        88 14 08
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        83 C4 04
        }
        
        /*
        v6 = 0;
        for ( i = 0; ; ++i )
        {
        result = v6;
        if ( v6 >= a2 )
        break;
        *(_BYTE *)(a1 + v6) ^= *(_BYTE *)(a3 + i);
        if ( i == a4 - 1 )
        i = 0;
        ++v6;
        }
        return result;
        */
        $decryption_routine2 = {
        55
        89 E5
        83 EC 08
        8B 45 ??
        8B 45 ??
        8B 45 ??
        8B 45 ??
        C7 45 ?? 00 00 00 00
        C7 45 ?? 00 00 00 00
        8B 45 ??
        3B 45 ??
        0F 8D ?? ?? ?? ??
        8B 45 ??
        8B 4D ??
        0F BE 04 08
        8B 4D ??
        8B 55 ??
        0F BE 0C 11
        31 C8
        88 C2
        8B 45 ??
        8B 4D ??
        88 14 08
        8B 45 ??
        8B 4D ??
        83 E9 01
        39 C8
        0F 85 ?? ?? ?? ??
        C7 45 ?? 00 00 00 00
        E9 ?? ?? ?? ??
        8B 45 ??
        83 C0 01
        89 45 ??
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        83 C4 08
        5D
        C3
        }
        
    condition:
        uint16be(0) == 0x4d5a and 
        filesize < 8MB and
        for all i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) != "69f400d3ff4679294e63fb8a8ca97dbb"
        ) and 
        3 of them and
        true
}
        