rule sekoiaio_ransomware_win_blackcat {
    meta:
        id = "873355f7-3942-4171-9df7-f524bb6b6903"
        description = "Detect the BlackCat ransomware (Windows version)"
        author = "Sekoia.io"
        creation_date = "2022-01-19"
        classification = "TLP:CLEAR"
        version = "1.1"
        
    strings:
        $s1 = "desktop_image::set_desktop_wallpaper=" ascii
        $s2 = "C:\\Users\\Public\\All Usersdeploy_note_and_image_for_all_users=" ascii
        $s3 = "propagate::none" ascii
        $s4 = "propagate::failed=" ascii
        $s5 = "propagate::ok=" ascii
        $s6 = "query_status_process::ok=" ascii
        $s7 = "enum_dependent_services::ok=" ascii
        $s8 = "enum_dependent_services::error=" ascii
        $s9 = "try_stop=" ascii
        $s10 = "try_stop::ok=" ascii
        $s11 = "try_stop::failed=" ascii
        $s12 = "stop=" ascii
        $s13 = "dependent_service_name=" ascii
        $s14 = "kill_all=" ascii
        $s15 = "detach=" ascii
        
    condition:
        uint16(0)==0x5A4D
        and filesize > 2MB and filesize < 4MB
        and all of them
}
        