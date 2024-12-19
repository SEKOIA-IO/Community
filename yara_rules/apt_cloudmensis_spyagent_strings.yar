rule apt_cloudmensis_spyagent_strings {
    meta:
        id = "c2df8373-6698-4b23-9d77-8e7968bd69f0"
        version = "1.0"
        description = "Detects CloudMensis SpyAgent"
        author = "Sekoia.io"
        creation_date = "2022-07-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[control_thread loop_DirStructure:]"
        $ = "[screen_keylog getScreenShotData]"
        $ = "[screen_keylog loop_usb]"
        $ = "[Management UploadFilebyPath:destination:]"
        $ = "[control_thread loop_pwd:]"
        
    condition:
        uint32be(0) == 0xcafebabe and 
        filesize < 2MB and
        all of them
}
        