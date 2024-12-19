rule apt_unc4990_emptyspace_pyc {
    meta:
        id = "d970fd9c-1ce5-471c-96a1-146250f36b89"
        version = "1.0"
        description = "Detects Python Bytecode of EmptySpace"
        author = "Sekoia.io"
        creation_date = "2024-02-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "PYBOOTSTRAP"
        $ = "http://google.com/generate_204"
        $ = "from"
        $ = "pathZ"
        $ = "usernamez"
        $ = "timeZ"
        $ = "win32api"
        $ = "base64Z"
        $ = "json"
        $ = "marshalZ"
        $ = "BOOTSTRAP_VERSION"
        $ = "getZ"
        $ = "sleepZ    b64encode"
        $ = "dumps"
        $ = "executableZ"
        $ = "GetUserNameExZ"
        $ = "NameSamCompatible"
        $ = "encode"
        $ = "decodeZ"
        $ = "request_dataZ"
        $ = "server"
        $ = "post"
        $ = "raise_for_status"
        $ = "exec"
        $ = "loadsZ    b64decode"
        $ = "text"
        $ = "globals"
        $ = "bootstrap.py"
        $ = "<module>"
        
    condition:
        uint32be(0) == 0x420d0d0a and all of them
}
        