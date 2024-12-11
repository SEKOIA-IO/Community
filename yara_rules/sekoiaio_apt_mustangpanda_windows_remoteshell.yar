rule sekoiaio_apt_mustangpanda_windows_remoteshell {
    meta:
        id = "cffdd11e-9700-462e-a965-f9f51db63f0b"
        version = "1.0"
        description = "Detects Remote Shell of Mustang Panda by detecting internal structure intialization"
        source = "Sekoia.io"
        creation_date = "2022-12-06"
        classification = "TLP:CLEAR"
        
    strings:
        /*
        *p_dword101a4 = 12;
        this->encrypted[5] = 3;
        *(_DWORD *)&this->encrypted[6] = this->dword10198;
        *(_WORD *)&this->encrypted[10] = this->dword1019c;
        */
        
        $chunk_1 = {
        C7 45 ?? 0C 00 00 00
        8D 4E ??
        C6 01 03
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        }
        /*
        *p_dword101a4 = 12;
        this->encrypted[5] = 2;
        *(_DWORD *)&this->encrypted[6] = this->dword10198;
        *(_WORD *)&this->encrypted[10] = this->dword1019c;
        cme_crypt(&this->encrypted[5], *p_dword101a4 - 5);
        */
        
        $chunk_2 = {
        C7 45 ?? 0C 00 00 00
        8D 4E ??
        C6 01 02
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        8B 45 ??
        83 E8 05
        50
        51
        E8 ?? ?? ?? ??
        }
        /*
        
        this->dword101a0 = 1;
        *p_dword101a4 = 12;
        this->encrypted[5] = 4;
        *(_DWORD *)&this->encrypted[6] = this->dword10198;
        *(_WORD *)&this->encrypted[10] = this->dword1019c;
        cme_crypt(&this->encrypted[5], *p_dword101a4 - 5);
        */
        $chunk_3 = {
        C7 87 ?? ?? ?? ?? 01 00 00 00
        8D 4E ??
        C7 45 ?? 0C 00 00 00
        C6 01 04
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        8B 45 ??
        83 E8 05
        50
        51
        E8 ?? ?? ?? ??
        }
        
        /*
        for ( i = 0; i < size; ++i )
        encrypt[i] ^= v3[i % 0x70u];
        for ( j = 0; ; ++j )
        {
        result = j;
        if ( j >= size )
        break;
        encrypt[j] ^= v5[j % 0x64u];
        }
        
        */
        
        $chunk_4 = {
        83 65 ?? ??
        EB ??
        8B 45 ??
        40
        89 45 ??
        8B 45 ??
        3B 45 ??
        7D ??
        8B 45 ??
        03 45 ??
        0F B6 08
        8B 45 ??
        33 D2
        6A ??
        5E
        F7 F6
        0F B6 84 15 ?? ?? ?? ??
        33 C8
        8B 45 ??
        03 45 ??
        88 08
        EB ??
        83 65 ?? ??
        EB ??
        8B 45 ??
        40
        89 45 ??
        8B 45 ??
        }
        
    condition:
        filesize < 8MB and
        3 of them
}
        