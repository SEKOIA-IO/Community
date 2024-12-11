rule sekoiaio_ransomware_linux_icefire_2023 {
    meta:
        id = "b04964f4-3fdc-4745-9f4a-95a5a79bc7e1"
        version = "1.0"
        description = "Rule to detect Linux IceFire ransomware samples."
        source = "Sekoia.io"
        creation_date = "2023-02-13"
        classification = "TLP:CLEAR"
        hash1 = "e9cc7fdfa3cf40ff9c3db0248a79f4817b170f2660aa2b2ed6c551eae1c38e0b"
        
    strings:
        $string01 = "********************Your network has been infected!!!********************"
        $string02 = "IMPORTANT : DO NOT DELETE THIS FILE UNTIL ALL YOUR DATA HAVE BEEN RECOVERED!!!"
        $string03 = "username:"
        $string04 = "password:"
        $string05 = ".cfg.o.sh.img.txt.xml.jar.pid.ini.pyc.a.so.run.env.cache.xmlb"
        $string06 = "./boot./dev./etc./lib./proc./srv./sys./usr./var./run"
        $string07 = "/iFire-readme.txt"
        $string08 = ".iFire"
        $string09 = "iFire.pid"
        
    condition:
        uint32be(0) == 0x7F454C46  and all of them
}
        