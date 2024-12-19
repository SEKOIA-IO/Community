rule shell_win_danfuan {
    meta:
        id = "d1cf9988-270b-4a22-bdd5-f40b625715a8"
        version = "1.0"
        description = "Detect the Danfuan malware"
        author = "Sekoia.io"
        creation_date = "2022-11-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<%@ WebHandler Language=\"C#\" class=\"DynamicCodeCompiler\"%>"
        $ = "CompilerResults compilerResults = compiler.CompileAssemblyFromSource(comPara, SourceText(txt))"
        $ = "MethodInfo objMifo = objInstance.GetType().GetMethod("
        
    condition:
        filesize < 15KB
        and all of them
}
        