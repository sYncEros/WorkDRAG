Option Explicit

Dim fso, shell, root, pythonw, scriptPath, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

root = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))
pythonw = root & "\python_portable\pythonw.exe"
scriptPath = root & "\mini_console.pyw"

If Not fso.FileExists(pythonw) Then
    MsgBox "No se encontró python_portable\pythonw.exe", vbCritical, "WorkDRAG"
    WScript.Quit 1
End If

If Not fso.FileExists(scriptPath) Then
    MsgBox "No se encontró mini_console.pyw", vbCritical, "WorkDRAG"
    WScript.Quit 1
End If

cmd = Chr(34) & pythonw & Chr(34) & " " & Chr(34) & scriptPath & Chr(34)
shell.Run cmd, 0, False
