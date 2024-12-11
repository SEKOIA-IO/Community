import "pe"
import "hash"
        
rule sekoiaio_wiper_win_nominatus_toxicbattery {
    meta:
        id = "0262378f-f509-4ea4-a3eb-cd0183c4361d"
        version = "1.0"
        description = "Detect the Nominatus_ToxicBattery malware"
        source = "Sekoia.io"
        creation_date = "2022-11-21"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "DISK"
        $ = "FileNaME"
        $ = "FILNAME"
        $ = "runCommand"
        $ = "HAHAH"
        $ = "Damage"
        $ = "fastInfector"
        $ = "d:\\again\\SharpDevelop Projects\\RInjector\\Virus.win32RozbehStrike\\obj\\Debug\\Nominatus_ToxicBattery.pdb"
        $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $ = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide
        $ = "\\Antivirus.bat" wide
        $ = "\\Antivirus3.vbs" wide
        $ = "vssadmin Delete Shadows /all /quiet" wide
        
    condition:
        // Strings
        uint16(0)==0x5A4D and 10 of them

        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "e7f35c173c34b7080d437a90ec90a982"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "2e25c5d3baba182f008a5a15c6f06403"
        )

        //Resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "70b1c002e4c0c9782c7ce1ef4a13c58ec1da54a26fd06dd7821a71f29431da82"
        )
}
        