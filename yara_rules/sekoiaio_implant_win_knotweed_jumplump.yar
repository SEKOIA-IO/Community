import "pe"
        
rule sekoiaio_implant_win_knotweed_jumplump {
    meta:
        id = "8f8cec7a-624b-4306-87f4-bde8ccc3a2d0"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2022-07-27"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "DllCanUnloadNow"
        $s2 = "DllGetClassObject"
        $s3 = "_initterm"
        $s4 = "__C_specific_handler"
        $s5 = "HeapFree"
        $s6 = "EnterCriticalSection"
        $s7 = "EventUnregister"
        $s8 = "LeaveCriticalSection"
        $s9 = "WaitForSingleObject"
        $s10 = "GetCurrentThreadId"
        $s11 = "GetLastError"
        $s12 = "CloseHandle"
        $s13 = "HeapAlloc"
        $s14 = "EventRegister"
        $s15 = "GetProcAddress"
        $s16 = "DeleteCriticalSection"
        $s17 = "GetCurrentProcessId"
        $s18 = "GetProcessHeap"
        $s19 = "DisableThreadLibraryCalls"
        $s20 = "Sleep"
        $s21 = "RtlCaptureContext"
        $s22 = "RtlLookupFunctionEntry"
        $s23 = "RtlVirtualUnwind"
        $s24 = "UnhandledExceptionFilter"
        $s25 = "SetUnhandledExceptionFilter"
        $s26 = "GetCurrentProcess"
        $s27 = "TerminateProcess"
        $s28 = "QueryPerformanceCounter"
        $s29 = "GetSystemTimeAsFileTime"
        $s30 = "GetTickCount"
        $s31 = "CoCreateInstance"
        $s32 = "RegCloseKey"
        $s33 = "GetModuleFileNameW"
        $s34 = "RegCreateKeyExW"
        $s35 = "RegSetValueExW"
        $s36 = "LocalFree"
        $s37 = "RegOpenKeyExW"
        $s38 = "OLEAUT32.dll"
        $s39 = "memcpy"
        $s40 = "memcmp"
        $s41 = "memset"
        $s42 = "LoadLibraryW"
        $s43 = "OpenProcessToken"
        $s44 = "DllRegisterServer"
        $s45 = "DllUnregisterServer"
        $s46 = "040904B0" wide
        
        $api_hash1 = {5D 44 11 FF} //GetModuleFileNameW
        $api_hash2 = {4C 77 D6 07} //LoadLibraryW
        $api_hash3 = {38 68 0D 16} //CreateThread
        $api_hash4 = {40 DE CE 72} //GetWindowsDirectoryW
        $api_hash5 = {08 87 1D 60} //WaitForSingleObject
        $api_hash6 = {26 C6 0B 1B} //OpenProcessToken
        $api_hash7 = {0C DC 67 55} //GetTokenInformation
        $api_hash8 = {AA C5 E2 5D} //GetLastError
        $api_hash9 = {C6 96 87 52} //CloseHandle
        $api_hash10 = {F8 8E C2 92} //IsWellKnownSid
        
    condition:
        uint16(0)==0x5A4D
        and pe.number_of_sections == 7
        and all of ($s*)
        and 1 of ($api_hash*)
}
        