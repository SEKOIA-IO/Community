rule sekoiaio_backdoor_mul_sparkrat {
    meta:
        id = "cd818207-f8ec-41fa-abef-c29d481c7897"
        version = "1.0"
        description = "Detect SparkRAT using string found in the source code"
        author = "Sekoia.io"
        creation_date = "2023-01-30"
        classification = "TLP:CLEAR"
        reference = "https://github.com/XZB-1248/Spark"
        
    strings:
        $ = "2006/01/02 15:04:05" wide ascii
        $ = "can not find secret header" wide ascii
        $ = "${i18n|COMMON.UNKNOWN_ERROR}" wide ascii
        $ = "/api/client/update" wide ascii
        $ = "application/octet-stream" wide ascii
        $ = "${i18n|COMMON.OPERATION_NOT_SUPPORTED}" wide ascii
        $ = "no IP address found" wide ascii
        $ = "failed to read network io counters" wide ascii
        $ = "failed to read cpu info" wide ascii
        $ = "PING" wide ascii
        $ = "OFFLINE" wide ascii
        $ = "LOCK" wide ascii
        $ = "LOGOFF" wide ascii
        $ = "HIBERNATE" wide ascii
        $ = "SUSPEND" wide ascii
        $ = "RESTART" wide ascii
        $ = "SHUTDOWN" wide ascii
        $ = "SCREENSHOT" wide ascii
        $ = "TERMINAL_INIT" wide ascii
        $ = "TERMINAL_INPUT" wide ascii
        $ = "TERMINAL_RESIZE" wide ascii
        $ = "TERMINAL_PING" wide ascii
        $ = "TERMINAL_KILL" wide ascii
        $ = "FILES_LIST" wide ascii
        $ = "FILES_FETCH" wide ascii
        $ = "FILES_REMOVE" wide ascii
        $ = "FILES_UPLOAD" wide ascii
        $ = "FILE_UPLOAD_TEXT" wide ascii
        $ = "PROCESSES_LIST" wide ascii
        $ = "PROCESS_KILL" wide ascii
        $ = "DESKTOP_INIT" wide ascii
        $ = "DESKTOP_PING" wide ascii
        $ = "DESKTOP_KILL" wide ascii
        $ = "DESKTOP_SHOT" wide ascii
        $ = "COMMAND_EXEC" wide ascii
        $ = "DEVICE_UPDATE" wide ascii
        $ = "${i18n|COMMON.INVALID_PARAMETER}" wide ascii
        $ = "${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}" wide ascii
        $ = "SPARK COMMIT: " wide ascii
        $ = "${i18n|COMMON.DISCONNECTED}" wide ascii
        $ = "${i18n|DESKTOP.NO_DISPLAY_FOUND}" wide ascii
        $ = "/api/bridge/push" wide ascii
        $ = "${i18n|COMMON.OPERATION_NOT_SUPPORTED}" wide ascii
        
    condition:
        17 of them
        and filesize > 4MB
}
        